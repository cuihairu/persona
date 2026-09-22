//! pull 物化层（E2EE_SYNC_DESIGN §5/§7）——把 oplog 主位落进本地主库。
//!
//! 阶段 2 的 `pull_cycle` 只把远端 op 记入本地 oplog 表；本模块补上「写主库」
//! 的最后一步：对每个 item 用 [`item_view`] 从 **op 集合**推导主位（终态只
//! 取决于 op 集合，与到达顺序无关），再按 §7 落库：
//!
//! - 主位 put：group key 拆出 item key → 解快照密文 → 重包 item key 到本机
//!   主密钥（各设备主密码不同步，同步密文与主密码解耦）→ 写凭据行。
//! - 主位 tombstone：删本地行（无 payload 可解）。
//! - 主位是**本机** op：主库已是事实源（写路径直接写入），跳过。
//! - 真冲突的败方不物化——冲突副本留驻 oplog（[`item_view`] 的 `conflicts`），
//!   由阶段 3 的裁决 UI 展示；「采纳」会经写路径产生新 lamport 的 put，
//!   自然赢回主位。
//!
//! 幂等且可反复跑：物化失败（如快照引用的身份尚未同步）的 op **留在 oplog**，
//! 下轮重跑自动补齐。身份缺失是常规状态（Identity 条目的同步在阶段 3 后续
//! 批次），不是错误——用 [`MaterializeOutcome::SkippedPendingIdentity`] 诚实
//! 上报。同步是尽力而为的旁路：本层任何单 item 失败只计入报告，不中断整体。

use uuid::Uuid;

use crate::crypto::encryption::EncryptionService;
use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::Credential;
use crate::storage::sync_repository::SyncRepository;
use crate::storage::{CredentialRepository, IdentityRepository, Repository};
use crate::sync::keys::unwrap_item_key_with_group;
use crate::sync::keys::GroupKey;
use crate::sync::oplog::{item_view, ItemKind, OpType};
use crate::sync::snapshot::SyncItemSnapshot;
use crate::{Database, Result};

/// 单个 item 的物化结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeOutcome {
    /// 远端 put 落库（新建或覆盖既有行）。
    Written,
    /// 远端 tombstone 落地（本地行已删除，或本就不存在）。
    Tombstoned,
    /// 主位是本机 op——主库已是事实源，无需物化。
    SkippedLocalPrimary,
    /// 快照引用的身份本地还没有（Identity 同步在后续批次）——留待下轮。
    SkippedPendingIdentity { identity_id: Uuid },
    /// 非 Credential 条目（Identity/Passkey 的捕获与物化在后续批次）。
    SkippedUnsupportedKind,
    /// oplog 无该 item 的 op（防御：调用方枚举与查询竞态）。
    NoPrimary,
}

/// 一轮全量物化的汇总。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaterializeReport {
    pub written: usize,
    pub tombstoned: usize,
    pub skipped_local_primary: usize,
    pub skipped_unsupported_kind: usize,
    pub no_primary: usize,
    /// (item_id, identity_id)：等身份同步后重跑即可补齐。
    pub pending_identity: Vec<(Uuid, Uuid)>,
}

/// oplog → 主库的物化器。持有仓储句柄；主密钥与 group key 逐调用传入
/// （主密钥随解锁会话生灭，group key 只属于同步装配层）。
pub struct Materializer {
    credential_repo: CredentialRepository,
    identity_repo: IdentityRepository,
    sync_repo: SyncRepository,
}

impl Materializer {
    pub fn new(db: Database) -> Self {
        Self {
            credential_repo: CredentialRepository::new(db.clone()),
            identity_repo: IdentityRepository::new(db.clone()),
            sync_repo: SyncRepository::new(db),
        }
    }

    /// 物化 oplog 中全部 item（幂等，可反复跑）。`local_device_id` 用来
    /// 识别「主位是本机 op」的跳过情形。
    pub async fn materialize_all(
        &self,
        master: &EncryptionService,
        group: &GroupKey,
        local_device_id: Uuid,
    ) -> Result<MaterializeReport> {
        let mut report = MaterializeReport::default();
        for item_id in self.sync_repo.item_ids().await? {
            match self
                .materialize_item(&item_id, master, group, local_device_id)
                .await
            {
                Ok(MaterializeOutcome::Written) => report.written += 1,
                Ok(MaterializeOutcome::Tombstoned) => report.tombstoned += 1,
                Ok(MaterializeOutcome::SkippedLocalPrimary) => report.skipped_local_primary += 1,
                Ok(MaterializeOutcome::SkippedUnsupportedKind) => {
                    report.skipped_unsupported_kind += 1
                }
                Ok(MaterializeOutcome::NoPrimary) => report.no_primary += 1,
                Ok(MaterializeOutcome::SkippedPendingIdentity { identity_id }) => {
                    report.pending_identity.push((item_id, identity_id));
                }
                Err(e) => {
                    // 尽力而为：单 item 失败（如快照损坏）不中断整体，
                    // op 仍在 oplog，可排查后重跑。
                    tracing::warn!(item_id = %item_id, error = %e, "materialize item failed; kept in oplog");
                }
            }
        }
        Ok(report)
    }

    /// 物化单个 item 的主位。
    pub async fn materialize_item(
        &self,
        item_id: &Uuid,
        master: &EncryptionService,
        group: &GroupKey,
        local_device_id: Uuid,
    ) -> Result<MaterializeOutcome> {
        let ops = self.sync_repo.item_ops(*item_id).await?;
        let state = item_view(ops);
        let Some(primary) = state.primary else {
            return Ok(MaterializeOutcome::NoPrimary);
        };
        if primary.device_id == local_device_id {
            return Ok(MaterializeOutcome::SkippedLocalPrimary);
        }
        if primary.kind != ItemKind::Credential {
            return Ok(MaterializeOutcome::SkippedUnsupportedKind);
        }
        match primary.op {
            OpType::Delete => {
                self.credential_repo.delete(item_id).await?;
                Ok(MaterializeOutcome::Tombstoned)
            }
            OpType::Put => {
                let Some(payload) = primary.payload else {
                    // 协议不变量违反（put 必带 payload）：fail-closed，不写库。
                    tracing::warn!(item_id = %item_id, "remote put without payload; ignored");
                    return Ok(MaterializeOutcome::NoPrimary);
                };
                self.materialize_put(
                    item_id,
                    &payload.ciphertext,
                    &payload.wrapped_item_key,
                    master,
                    group,
                )
                .await
            }
        }
    }

    async fn materialize_put(
        &self,
        item_id: &Uuid,
        ciphertext: &[u8],
        wrapped_item_key: &[u8],
        master: &EncryptionService,
        group: &GroupKey,
    ) -> Result<MaterializeOutcome> {
        let item_key = unwrap_item_key_with_group(wrapped_item_key, group)?;
        let snapshot = SyncItemSnapshot::open(ciphertext, &item_key)?;

        if self
            .identity_repo
            .find_by_id(&snapshot.identity_id)
            .await?
            .is_none()
        {
            return Ok(MaterializeOutcome::SkippedPendingIdentity {
                identity_id: snapshot.identity_id,
            });
        }

        // 重包：同一把 item key 改由本机主密钥包裹（附件不变量维持——
        // item key 不变，已封存的附件照常可解）。
        let hierarchy = KeyHierarchy::new(master);
        let wrapped_local = master.encrypt(&item_key).map_err(|e| {
            crate::PersonaError::CryptographicError(format!("failed to wrap item key: {e}"))
        })?;
        let encrypted_data =
            hierarchy.encrypt_with_item_key(&item_key, &snapshot.data.to_bytes()?)?;

        match self.credential_repo.find_by_id(item_id).await? {
            Some(mut row) => {
                row.identity_id = snapshot.identity_id;
                row.name = snapshot.name;
                row.credential_type = snapshot.credential_type;
                row.security_level = snapshot.security_level;
                row.url = snapshot.url;
                row.username = snapshot.username;
                row.notes = snapshot.notes;
                row.tags = snapshot.tags;
                row.metadata = snapshot.metadata;
                row.is_favorite = snapshot.is_favorite;
                row.is_active = snapshot.is_active;
                row.encrypted_data = encrypted_data;
                row.wrapped_item_key = Some(wrapped_local);
                row.touch();
                self.credential_repo.update(&row).await?;
            }
            None => {
                let mut credential = Credential::new(
                    snapshot.identity_id,
                    snapshot.name,
                    snapshot.credential_type,
                    snapshot.security_level,
                    encrypted_data,
                    Some(wrapped_local),
                );
                credential.id = *item_id;
                credential.url = snapshot.url;
                credential.username = snapshot.username;
                credential.notes = snapshot.notes;
                credential.tags = snapshot.tags;
                credential.metadata = snapshot.metadata;
                credential.is_favorite = snapshot.is_favorite;
                credential.is_active = snapshot.is_active;
                self.credential_repo.create(&credential).await?;
            }
        }
        Ok(MaterializeOutcome::Written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        CredentialData, CredentialType, Identity, IdentityType, PasswordCredentialData,
        SecurityLevel,
    };
    use crate::sync::keys::{wrap_item_key_with_group, GroupKey};
    use crate::sync::oplog::{SyncOp, SyncPayload};
    use chrono::Utc;

    fn password_data(secret: &str) -> CredentialData {
        CredentialData::Password(PasswordCredentialData {
            password: secret.to_string(),
            email: Some("alice@example.com".to_string()),
            security_questions: vec![],
        })
    }

    fn put_op(
        item_id: Uuid,
        device_id: Uuid,
        lamport: u64,
        snapshot: &SyncItemSnapshot,
        group: &GroupKey,
    ) -> SyncOp {
        let item_key = EncryptionService::generate_key();
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Credential,
            op: OpType::Put,
            lamport,
            device_id,
            timestamp: Some(Utc::now()),
            payload: Some(SyncPayload {
                ciphertext: snapshot.seal(&item_key).unwrap(),
                wrapped_item_key: wrap_item_key_with_group(&item_key, group),
            }),
        }
    }

    fn delete_op(item_id: Uuid, device_id: Uuid, lamport: u64) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Credential,
            op: OpType::Delete,
            lamport,
            device_id,
            timestamp: Some(Utc::now()),
            payload: None,
        }
    }

    async fn setup() -> (Database, Materializer, IdentityRepository, GroupKey, Uuid) {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let identity_repo = IdentityRepository::new(db.clone());
        let identity = Identity::new("Alice".to_string(), IdentityType::Personal);
        identity_repo.create(&identity).await.unwrap();
        (
            db.clone(),
            Materializer::new(db),
            identity_repo,
            GroupKey::generate().unwrap(),
            identity.id,
        )
    }

    #[tokio::test]
    async fn remote_put_materializes_row_and_rewraps_key_under_local_master() {
        let (db, materializer, _identity_repo, group, identity_id) = setup().await;
        let master_key = EncryptionService::generate_key();
        let master = EncryptionService::new(&master_key);

        let item_id = Uuid::new_v4();
        let snapshot = SyncItemSnapshot {
            identity_id,
            name: "远端邮箱".to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::High,
            url: Some("https://remote.example".to_string()),
            username: Some("bob@remote.example".to_string()),
            notes: None,
            tags: vec!["synced".to_string()],
            metadata: Default::default(),
            is_favorite: true,
            is_active: true,
            data: password_data("remote-secret"),
        };
        let op = put_op(item_id, Uuid::new_v4(), 7, &snapshot, &group);
        Materializer::new(db.clone())
            .sync_repo
            .record_remote_op(&op)
            .await
            .unwrap();

        let outcome = materializer
            .materialize_item(&item_id, &master, &group, Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(outcome, MaterializeOutcome::Written);

        let row = materializer
            .credential_repo
            .find_by_id(&item_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.name, "远端邮箱");
        assert_eq!(row.username.as_deref(), Some("bob@remote.example"));
        assert_eq!(row.tags, vec!["synced".to_string()]);
        assert!(row.is_favorite);

        // item key 被本机主密钥重包，数据可正常解密。
        let hierarchy = KeyHierarchy::new(&master);
        let plaintext = hierarchy
            .decrypt_with_wrapped_key(row.wrapped_item_key.as_ref().unwrap(), &row.encrypted_data)
            .unwrap();
        let data = CredentialData::from_bytes(&plaintext).unwrap();
        assert_eq!(
            data.to_bytes().unwrap(),
            password_data("remote-secret").to_bytes().unwrap()
        );
    }

    #[tokio::test]
    async fn tombstone_deletes_local_row() {
        let (db, materializer, _identity_repo, group, identity_id) = setup().await;
        let master = EncryptionService::new(&EncryptionService::generate_key());
        let item_id = Uuid::new_v4();
        let snapshot = SyncItemSnapshot {
            identity_id,
            name: "待删".to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::Medium,
            url: None,
            username: None,
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: password_data("x"),
        };
        let remote = Uuid::new_v4();
        Materializer::new(db.clone())
            .sync_repo
            .record_remote_op(&put_op(item_id, remote, 3, &snapshot, &group))
            .await
            .unwrap();
        Materializer::new(db.clone())
            .sync_repo
            .record_remote_op(&delete_op(item_id, remote, 4))
            .await
            .unwrap();

        let outcome = materializer
            .materialize_item(&item_id, &master, &group, Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(outcome, MaterializeOutcome::Tombstoned);
        assert!(materializer
            .credential_repo
            .find_by_id(&item_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn local_primary_is_skipped() {
        let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
        let master = EncryptionService::new(&EncryptionService::generate_key());
        let local_device = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let snapshot = SyncItemSnapshot {
            identity_id,
            name: "本机写入".to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::Medium,
            url: None,
            username: None,
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: password_data("local"),
        };
        // 主位是本机 op（device_id 相同）：主库是事实源，物化必须让路。
        materializer
            .sync_repo
            .record_remote_op(&put_op(item_id, local_device, 9, &snapshot, &group))
            .await
            .unwrap();

        let outcome = materializer
            .materialize_item(&item_id, &master, &group, local_device)
            .await
            .unwrap();
        assert_eq!(outcome, MaterializeOutcome::SkippedLocalPrimary);
        assert!(materializer
            .credential_repo
            .find_by_id(&item_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn pending_identity_defers_materialization() {
        let (db, materializer, _identity_repo, group, _identity_id) = setup().await;
        let master = EncryptionService::new(&EncryptionService::generate_key());
        let item_id = Uuid::new_v4();
        let snapshot = SyncItemSnapshot {
            identity_id: Uuid::new_v4(), // 未知身份：Identity 条目尚未同步
            name: "悬空凭据".to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::Medium,
            url: None,
            username: None,
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: password_data("y"),
        };
        materializer
            .sync_repo
            .record_remote_op(&put_op(item_id, Uuid::new_v4(), 2, &snapshot, &group))
            .await
            .unwrap();

        let outcome = materializer
            .materialize_item(&item_id, &master, &group, Uuid::new_v4())
            .await
            .unwrap();
        match outcome {
            MaterializeOutcome::SkippedPendingIdentity { .. } => {}
            other => panic!("expected pending identity, got {other:?}"),
        }
        assert!(materializer
            .credential_repo
            .find_by_id(&item_id)
            .await
            .unwrap()
            .is_none());
        // op 留在 oplog，下轮可补齐
        assert_eq!(
            materializer
                .sync_repo
                .item_ops(item_id)
                .await
                .unwrap()
                .len(),
            1
        );
        let _ = db; // keep db alive
    }

    #[tokio::test]
    async fn true_conflict_materializes_winner_only() {
        let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
        let master = EncryptionService::new(&EncryptionService::generate_key());
        let item_id = Uuid::new_v4();
        let mk = |name: &str| SyncItemSnapshot {
            identity_id,
            name: name.to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::Medium,
            url: None,
            username: None,
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: password_data(name),
        };
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        // 同 lamport 异设备 = 真冲突；主位 = device_id 大者（§7 降序）。
        let (winner_device, loser_device) = if device_a > device_b {
            (device_a, device_b)
        } else {
            (device_b, device_a)
        };
        let winner_name = if winner_device == device_a {
            "win-A"
        } else {
            "win-B"
        };
        materializer
            .sync_repo
            .record_remote_op(&put_op(item_id, device_a, 5, &mk("win-A"), &group))
            .await
            .unwrap();
        materializer
            .sync_repo
            .record_remote_op(&put_op(item_id, device_b, 5, &mk("win-B"), &group))
            .await
            .unwrap();

        let outcome = materializer
            .materialize_item(&item_id, &master, &group, Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(outcome, MaterializeOutcome::Written);

        let row = materializer
            .credential_repo
            .find_by_id(&item_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.name, winner_name);
        // 败方留驻 oplog 冲突区，等阶段 3 裁决 UI。
        let view = item_view(materializer.sync_repo.item_ops(item_id).await.unwrap());
        assert_eq!(view.primary.unwrap().device_id, winner_device);
        assert_eq!(view.conflicts.len(), 1);
        assert_eq!(view.conflicts[0].device_id, loser_device);
        let _ = winner_device; // 已通过名称断言
    }

    #[tokio::test]
    async fn materialize_all_reports_and_is_idempotent() {
        let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
        let master = EncryptionService::new(&EncryptionService::generate_key());
        let local_device = Uuid::new_v4();

        let item_a = Uuid::new_v4();
        let item_b = Uuid::new_v4();
        let snap = |name: &str, iid: Uuid| SyncItemSnapshot {
            identity_id: iid,
            name: name.to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::Medium,
            url: None,
            username: None,
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: password_data(name),
        };
        materializer
            .sync_repo
            .record_remote_op(&put_op(
                item_a,
                Uuid::new_v4(),
                1,
                &snap("A", identity_id),
                &group,
            ))
            .await
            .unwrap();
        materializer
            .sync_repo
            .record_remote_op(&delete_op(item_b, Uuid::new_v4(), 1))
            .await
            .unwrap();

        let report = materializer
            .materialize_all(&master, &group, local_device)
            .await
            .unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.tombstoned, 1);
        assert!(report.pending_identity.is_empty());

        // 重跑幂等：同样的结果，不重复也不报错。
        let again = materializer
            .materialize_all(&master, &group, local_device)
            .await
            .unwrap();
        assert_eq!(again, report);
    }
}
