use uuid::Uuid;

use crate::crypto::encryption::EncryptionService;
use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::Credential;
use crate::storage::sync_repository::SyncRepository;
use crate::storage::{
    AuditLogRepository, CredentialRepository, IdentityRepository, PasskeyRepository, Repository,
};
use crate::sync::keys::unwrap_item_key_with_group;
use crate::sync::keys::GroupKey;
use crate::sync::oplog::{item_view, ItemKind, OpType};
use std::sync::Arc;

use crate::models::PasskeyItem;
use crate::sync::snapshot::{SyncItemSnapshot, SyncPasskeySnapshot};
use crate::{Database, Result};

use super::report::{MaterializeOutcome, MaterializeReport};

/// oplog → 主库的物化器。持有仓储句柄；主密钥与 group key 逐调用传入
/// （主密钥随解锁会话生灭，group key 只属于同步装配层）。
pub struct Materializer {
    pub(super) credential_repo: CredentialRepository,
    pub(super) identity_repo: IdentityRepository,
    pub(super) passkey_repo: PasskeyRepository,
    pub(super) sync_repo: SyncRepository,
    pub(super) audit_repo: AuditLogRepository,
}

impl Materializer {
    pub fn new(db: Database) -> Self {
        Self {
            credential_repo: CredentialRepository::new(db.clone()),
            identity_repo: IdentityRepository::new(db.clone()),
            passkey_repo: PasskeyRepository::new(Arc::new(db.clone())),
            sync_repo: SyncRepository::new(db.clone()),
            audit_repo: AuditLogRepository::new(db),
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
        match primary.kind {
            ItemKind::Credential => match primary.op {
                OpType::Delete => {
                    self.materialize_delete(item_id).await?;
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
            },
            ItemKind::Passkey => match primary.op {
                OpType::Delete => {
                    // passkeys 表无入站 FK，无需摘引用
                    self.passkey_repo.delete(item_id).await?;
                    Ok(MaterializeOutcome::Tombstoned)
                }
                OpType::Put => {
                    let Some(payload) = primary.payload else {
                        tracing::warn!(
                            item_id = %item_id,
                            "remote passkey put without payload; ignored"
                        );
                        return Ok(MaterializeOutcome::NoPrimary);
                    };
                    self.materialize_passkey_put(
                        item_id,
                        &payload.ciphertext,
                        &payload.wrapped_item_key,
                        master,
                        group,
                    )
                    .await
                }
            },
            // Identity 的捕获与物化在后续批次；未知 kind 不产生本地写
            ItemKind::Identity | ItemKind::Unknown => {
                Ok(MaterializeOutcome::SkippedUnsupportedKind)
            }
        }
    }

    /// 物化一个 tombstone 主位：先摘掉 audit_logs 对该凭据的引用再删行
    /// （audit 的 FK 是 NO ACTION，不先 detach 会 787 拒删）。公开给冲突
    /// 裁决复用：采纳 delete 副本走同一条删行路径。
    pub async fn materialize_delete(&self, item_id: &Uuid) -> Result<()> {
        self.audit_repo.clear_credential_reference(item_id).await?;
        self.credential_repo.delete(item_id).await?;
        Ok(())
    }

    /// 物化一个 put 主位进主库（重包 item key 到本机主密钥）。公开给
    /// 冲突裁决复用：采纳 put 副本走同一条落库路径（[`super::resolve`]）。
    pub async fn materialize_put(
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

    /// 物化一个 passkey put 主位进主库。私钥信封原样搬运：item key 字节
    /// 不变（group 信封拆出后重包到本机主密钥），物化后的行照常可解私钥；
    /// 设备本地使用态（`created_at`/`sign_count`/`last_used_at`）由
    /// [`PasskeyRepository::upsert_synced`] 保留，远端不携带。
    async fn materialize_passkey_put(
        &self,
        item_id: &Uuid,
        ciphertext: &[u8],
        wrapped_item_key: &[u8],
        master: &EncryptionService,
        group: &GroupKey,
    ) -> Result<MaterializeOutcome> {
        let item_key = unwrap_item_key_with_group(wrapped_item_key, group)?;
        let snapshot = SyncPasskeySnapshot::open(ciphertext, &item_key)?;

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

        // 重包：同一把 item key 改由本机主密钥包裹（私钥信封不变量维持）。
        let wrapped_local = master.encrypt(&item_key).map_err(|e| {
            crate::PersonaError::CryptographicError(format!("failed to wrap item key: {e}"))
        })?;

        let mut item = PasskeyItem::new(
            snapshot.identity_id,
            snapshot.rp_id,
            snapshot.user_handle,
            snapshot.credential_id,
            snapshot.encrypted_private_key,
            wrapped_local,
            snapshot.public_key_cose,
        );
        item.id = *item_id;
        item.rp_name = snapshot.rp_name;
        item.user_name = snapshot.user_name;
        item.user_display_name = snapshot.user_display_name;
        item.alg = snapshot.alg;
        item.uv_initialized = snapshot.uv_initialized;
        item.export_allowed = snapshot.export_allowed;
        item.tags = snapshot.tags;

        self.passkey_repo.upsert_synced(&item).await?;
        Ok(MaterializeOutcome::Written)
    }
}
