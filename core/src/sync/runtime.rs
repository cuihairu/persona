//! 同步会话装配（E2EE_SYNC_DESIGN 阶段 3b）：把设备身份、oplog 引擎、
//! 物化层与存量数据在宿主的一次「立即同步」调用里串起来。
//!
//! 分层口径：协议/密码学/编排全在 core，宿主（desktop/CLI）只提供
//! 参数（设备身份、服务器 url/token、travel 闸值）与持久化槽位。宿主
//! 不直接触碰 [`SyncEngine`] / [`Materializer`]。
//!
//! 会话生命周期 = 单次 `sync_now` 调用：`open`（拆信封装配）→
//! `backfill_existing`（存量灌入，幂等）→ `run_cycle`（pull → materialize
//! → push）→ `capture`（把 [`OplogCapture`] 挂上 service，让后续本地写
//! 自动入队）。会话对象可弃；引擎状态全在本地库（local_lamport/游标/
//! pending op 不随实例走）。travel 闸值由宿主在调用前评估一次（cycle 是
//! 短过程，中途不变；travel 激活期间 cycle 侧自行拒绝，见 engine 模块）。

use std::sync::Arc;

use uuid::Uuid;

use super::capture::OplogCapture;
#[cfg(feature = "remote-auth")]
use super::device::DeviceIdentity;
use super::engine::{SyncEngine, SyncRemote};
use super::keys::{wrap_item_key_with_group, GroupKey};
use super::materialize::{MaterializeOutcome, Materializer};
use super::oplog::{item_view, ItemKind, OpType, SyncPayload};
use super::resolve::{self, ConflictEntry};
use super::snapshot::SyncItemSnapshot;
use crate::crypto::encryption::EncryptionService;
use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::credential::CredentialData;
use crate::storage::sync_repository::SyncRepository;
use crate::storage::{CredentialRepository, Database, Repository};
use crate::PersonaError;
use crate::Result;

/// 一次 `sync_now` 的汇总（字段全部是计数，供宿主 UI 展示）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncNowReport {
    /// 新拉取落库的远端 op 条数。
    pub pulled: usize,
    /// 物化进主库的条目数（新行或更新）。
    pub materialized: usize,
    /// 冲突败方留驻 oplog 的条目数（数据不丢，裁决 UI 消费）。
    pub conflicts: usize,
    /// 因身份未同步而挂起的条目数（下轮补齐）。
    pub pending_identity: usize,
    /// push 出去的本地 op 条数。
    pub pushed: usize,
    /// 本次灌入 oplog 的存量凭据条数（通常只在首次同步非零）。
    pub backfilled: u64,
}

/// 一次同步会话。宿主用完即弃，状态在库。
pub struct SyncSession<R: SyncRemote> {
    engine: Arc<SyncEngine<R>>,
    sync_repo: SyncRepository,
    db: Database,
    group_key: GroupKey,
    device_id: Uuid,
}

#[cfg(feature = "remote-auth")]
impl SyncSession<super::remote::HttpSyncRemote> {
    /// 装配会话：从服务器取全部信封，拆出本机的那份得 group key。
    /// 本机信封缺失（未授权）或拆不开（fail-closed：信封不是包给这把
    /// 私钥的/被篡改）一律 Err——未授权设备拿不到同步能力。
    pub async fn open(
        db: &Database,
        identity: &DeviceIdentity,
        base_url: &str,
        token: &str,
        travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self> {
        let admin = super::remote::SyncAdminApi::new(base_url, token)?;
        let keys = admin.group_keys().await?;
        let own = keys
            .iter()
            .find(|k| k.device_id == identity.device_id)
            .ok_or_else(|| {
                PersonaError::NotFound(
                    "this device has no group key envelope yet (pending authorization)".to_string(),
                )
            })?;
        let group_bytes =
            super::envelope::open_group_key(&own.envelope, identity.key_pair.secret_bytes())
                .map_err(|e| {
                    PersonaError::CryptographicError(format!(
                        "failed to open own group key envelope: {e}"
                    ))
                })?;
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            super::remote::HttpSyncRemote::new(base_url, token)?,
            identity.device_id,
            travel_active,
        ));
        Ok(Self {
            engine,
            sync_repo: SyncRepository::new(db.clone()),
            db: db.clone(),
            group_key: GroupKey::from_bytes(group_bytes),
            device_id: identity.device_id,
        })
    }
}

impl<R: SyncRemote> SyncSession<R> {
    /// 存量灌入：主库存在但 oplog 缺席的凭据逐条生成 put。以 oplog 的
    /// item 集为准跳过已入队条目，因此重复调用幂等（通常只有首次同步
    /// 灌入非零条）。legacy 凭据（无 wrapped_item_key）无法取出 item key，
    /// 跳过并 warn（与捕获缝同语义——先编辑一次升级加密形态）。
    pub async fn backfill_existing(&self, master: &EncryptionService) -> Result<u64> {
        let cred_repo = CredentialRepository::new(self.db.clone());
        let all = cred_repo.list_all().await?;
        let queued: std::collections::HashSet<Uuid> =
            self.sync_repo.item_ids().await?.into_iter().collect();
        let hierarchy = KeyHierarchy::new(master);
        let mut count: u64 = 0;
        for credential in all {
            if queued.contains(&credential.id) {
                continue;
            }
            let Some(wrapped) = credential.wrapped_item_key.as_ref() else {
                tracing::warn!(
                    credential_id = %credential.id,
                    "legacy credential without wrapped item key; sync backfill skipped"
                );
                continue;
            };
            // 失败逐条跳过（坏行不阻断整批），与捕获缝的容错口径一致
            let item_key = match hierarchy.unwrap_item_key(wrapped) {
                Ok(item_key) => item_key,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "item key unwrap failed; backfill skipped");
                    continue;
                }
            };
            let plaintext = match hierarchy
                .decrypt_with_wrapped_key(wrapped, &credential.encrypted_data)
            {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "credential decrypt failed; backfill skipped");
                    continue;
                }
            };
            let data = match CredentialData::from_bytes(&plaintext) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "malformed credential data; backfill skipped");
                    continue;
                }
            };
            let sealed = match SyncItemSnapshot::from_credential(&credential, &data).seal(&item_key)
            {
                Ok(sealed) => sealed,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "snapshot seal failed; backfill skipped");
                    continue;
                }
            };
            let payload = SyncPayload {
                ciphertext: sealed,
                wrapped_item_key: wrap_item_key_with_group(&item_key, &self.group_key),
            };
            match self
                .engine
                .record_local_change(
                    credential.id,
                    ItemKind::Credential,
                    OpType::Put,
                    Some(payload),
                )
                .await
            {
                Ok(_) => count += 1,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "oplog record failed; backfill skipped");
                }
            }
        }
        Ok(count)
    }

    /// 完整周期：pull（远端 op 攒进本地 oplog）→ materialize（oplog 主位
    /// 物化进主库）→ push（本地 pending op 推上服务器）。
    pub async fn run_cycle(&self, master: &EncryptionService) -> Result<SyncNowReport> {
        let pull = self.engine.pull_cycle().await?;
        let materialize = Materializer::new(self.db.clone())
            .materialize_all(master, &self.group_key, self.device_id)
            .await?;
        let push = self.engine.push_cycle().await?;
        Ok(SyncNowReport {
            pulled: pull.applied,
            materialized: materialize.written,
            // 待裁决冲突条目数（从 oplog 现算真值；3b 曾错用
            // skipped_local_primary——那是「主位是本机 op」的跳过计数）。
            conflicts: self.conflict_item_count().await?,
            pending_identity: materialize.pending_identity.len(),
            pushed: push.pushed,
            backfilled: 0,
        })
    }

    /// 本会话的捕获缝（挂上 service 后，本地写路径自动产 oplog put/
    /// tombstone）。会话丢弃后 capture 依然有效（持 engine Arc）。
    pub fn capture(&self) -> Arc<OplogCapture<R>> {
        Arc::new(OplogCapture::new(
            self.engine.clone(),
            self.group_key.clone(),
        ))
    }

    /// 冲突裁决视图（阶段 3c）：全部待裁决条目（主位 + 副本的解密快照）。
    /// 任一版本解不开（损坏）的条目整条跳过——不可裁决但留驻 oplog，
    /// 不阻塞其余条目的展示。
    pub async fn list_conflicts(&self) -> Result<Vec<ConflictEntry>> {
        let mut entries = Vec::new();
        for item_id in self.sync_repo.item_ids().await? {
            let ops = self.sync_repo.item_ops(item_id).await?;
            if let Some(entry) = resolve::conflict_entry(item_id, &ops, &self.group_key) {
                entries.push(entry);
            }
        }
        entries.sort_by_key(|entry| entry.item_id);
        Ok(entries)
    }

    /// 当前待裁决的冲突条目数（run_cycle 报告的 `conflicts` 真值）。
    pub async fn conflict_item_count(&self) -> Result<usize> {
        Ok(self.list_conflicts().await?.len())
    }

    /// 裁决：采纳一个冲突副本。副本内容以本机新 lamport 重新入账
    /// （put 复用副本 payload 字节——快照与 wrapped item key 都是 group 域
    /// 的，设备无关；tombstone 复用空 payload），并按其内容写主库。新
    /// lamport 严格大于冲突双方 → LWW 自然赢回主位，其余版本全部淘汰出
    /// 裁决视图（oplog append-only，数据不丢，只是不再出现在视图里）。
    ///
    /// 写序 = 先主库后 oplog（见 [`super::resolve`] 模块文档）：主库失败
    /// 即 Err（oplog 未动，重试安全）；oplog 失败可重试（重写主库幂等）。
    /// 副本引用的身份尚未同步时主库写不了 → Err 且绝不记账（记 op 不写
    /// 主库 = 静默分叉，下一轮同步补齐身份后再裁决）。
    pub async fn resolve_conflict(
        &self,
        master: &EncryptionService,
        item_id: Uuid,
        adopt_op_id: Uuid,
    ) -> Result<()> {
        let view = item_view(self.sync_repo.item_ops(item_id).await?);
        let Some(adopted) = view.conflicts.iter().find(|op| op.op_id == adopt_op_id) else {
            // 副本不存在 = 已被裁决过（采纳任一版本后其余版本淘汰出视图）
            // 或 op_id 打错——同一句话报给调用方。
            return Err(PersonaError::NotFound(format!(
                "conflict copy {adopt_op_id} not found for item {item_id} (already resolved?)"
            ))
            .into());
        };
        if adopted.kind != ItemKind::Credential {
            return Err(PersonaError::InvalidInput(format!(
                "conflict resolution only supports credential entries, got {:?}",
                adopted.kind
            ))
            .into());
        }
        let (kind, op, payload) = (adopted.kind, adopted.op, adopted.payload.clone());

        // 先主库后 oplog。
        match op {
            OpType::Put => {
                let Some(payload) = payload.as_ref() else {
                    return Err(PersonaError::InvalidInput(
                        "cannot adopt a put copy without payload".to_string(),
                    )
                    .into());
                };
                let outcome = Materializer::new(self.db.clone())
                    .materialize_put(
                        &item_id,
                        &payload.ciphertext,
                        &payload.wrapped_item_key,
                        master,
                        &self.group_key,
                    )
                    .await?;
                if let MaterializeOutcome::SkippedPendingIdentity { identity_id } = outcome {
                    return Err(PersonaError::Validation(format!(
                        "adopted copy references identity {identity_id} that is not synced yet; \
                         resolve again after the next sync"
                    ))
                    .into());
                }
            }
            OpType::Delete => {
                CredentialRepository::new(self.db.clone())
                    .delete(&item_id)
                    .await?;
            }
        }

        // 入账前防御性时钟推进：保证本机新 op 的 lamport 严格大于被采纳
        // 副本。正常流程 pull 已 bump 过时钟（record 的 local+1 已够大）；
        // 直连裁决（不经 run_cycle）时本机时钟可能仍停在副本同高，先 MAX
        // 推进。放在主库写之后——前置校验失败（上方 Err 臂）零副作用。
        let local = self.sync_repo.get_state().await?.local_lamport;
        if local <= adopted.lamport {
            self.sync_repo.bump_lamport(adopted.lamport + 1).await?;
        }

        // oplog 记账：本机新 lamport 的采纳 op 入 push 队列，随下轮推走。
        self.engine
            .record_local_change(item_id, kind, op, payload)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::credential::{
        Credential, CredentialType, PasswordCredentialData, SecurityLevel,
    };
    use crate::models::identity::{Identity, IdentityType};
    use crate::storage::repository::IdentityRepository;
    use crate::storage::Repository;
    use crate::sync::capture::SyncCapture as _;
    use crate::sync::oplog::SyncOp;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// 内存远端：push 收集（Arc 共享给测试断言）、pull 返回空页。
    struct MemRemote {
        pushed: Arc<Mutex<Vec<SyncOp>>>,
    }

    #[async_trait::async_trait]
    impl SyncRemote for MemRemote {
        async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
            let n = ops.len() as u64;
            self.pushed.lock().unwrap().extend(ops.iter().cloned());
            Ok((n, 0))
        }

        async fn pull_ops(
            &self,
            _since: Option<&str>,
            _limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            Ok((Vec::new(), None))
        }
    }

    fn no_travel() -> Box<dyn Fn() -> bool + Send + Sync> {
        Box::new(|| false)
    }

    async fn seeded_db() -> (Database, Identity, EncryptionService) {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let identity_repo = IdentityRepository::new(db.clone());
        let identity = Identity::new("seed".to_string(), IdentityType::Personal);
        identity_repo.create(&identity).await.unwrap();
        let master = EncryptionService::new(&EncryptionService::generate_key());
        (db, identity, master)
    }

    fn data(secret: &str) -> CredentialData {
        CredentialData::Password(PasswordCredentialData {
            password: secret.to_string(),
            email: None,
            security_questions: vec![],
        })
    }

    async fn store_credential(
        cred_repo: &CredentialRepository,
        identity_id: Uuid,
        name: &str,
        master: &EncryptionService,
        secret: &str,
    ) {
        let item_key = EncryptionService::generate_key();
        let wrapped = master.encrypt(&item_key).unwrap();
        let ciphertext = KeyHierarchy::new(master)
            .encrypt_with_item_key(&item_key, &data(secret).to_bytes().unwrap())
            .unwrap();
        let cred = Credential::new(
            identity_id,
            name.to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            ciphertext,
            Some(wrapped),
        );
        cred_repo.create(&cred).await.unwrap();
    }

    fn session_for(
        db: &Database,
        device_id: Uuid,
        group_key: GroupKey,
    ) -> (SyncSession<MemRemote>, Arc<Mutex<Vec<SyncOp>>>) {
        let remote = MemRemote {
            pushed: Arc::new(Mutex::new(Vec::new())),
        };
        let pushed_log = remote.pushed.clone();
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            remote,
            device_id,
            no_travel(),
        ));
        let session = SyncSession {
            engine,
            sync_repo: SyncRepository::new(db.clone()),
            db: db.clone(),
            group_key,
            device_id,
        };
        (session, pushed_log)
    }

    // 会话编排核心：backfill 幂等（首次灌入 N 条，再跑 0 条）+ run_cycle
    // 把本地 pending 推上远端 + capture 产出的 put 随下一轮周期推走。
    #[tokio::test]
    async fn session_backfills_pushes_and_captures() {
        let (db, identity, master) = seeded_db().await;
        let cred_repo = CredentialRepository::new(db.clone());
        store_credential(&cred_repo, identity.id, "cred-one", &master, "one").await;
        store_credential(&cred_repo, identity.id, "cred-two", &master, "two").await;

        let (session, pushed_log) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());

        // 首次灌入 2 条，重复调用幂等（0 条）
        let first = session.backfill_existing(&master).await.unwrap();
        assert_eq!(first, 2);
        let second = session.backfill_existing(&master).await.unwrap();
        assert_eq!(second, 0);

        // 周期推走 2 条 pending
        let report = session.run_cycle(&master).await.unwrap();
        assert_eq!(report.pushed, 2);
        assert_eq!(report.pulled, 0);
        assert_eq!(report.backfilled, 0);

        // capture 产出的新 put 随下一轮周期推走（capture 持 engine Arc，
        // 与 run_cycle 共享同一 pending 队列）
        let capture = session.capture();
        let item_key = EncryptionService::generate_key();
        let sealed = SyncItemSnapshot::from_credential(
            &Credential::new(
                identity.id,
                "fresh".to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                Vec::new(),
                None,
            ),
            &data("fresh-secret"),
        )
        .seal(&item_key)
        .unwrap();
        capture
            .capture(
                Uuid::new_v4(),
                ItemKind::Credential,
                OpType::Put,
                Some(sealed),
                Some(Zeroizing::new(item_key)),
            )
            .await;
        let report = session.run_cycle(&master).await.unwrap();
        assert_eq!(report.pushed, 1);
        assert_eq!(pushed_log.lock().unwrap().len(), 3);
    }

    // legacy 凭据（无 wrapped_item_key）：backfill 跳过不报错
    #[tokio::test]
    async fn backfill_skips_legacy_credentials() {
        let (db, identity, master) = seeded_db().await;
        let cred_repo = CredentialRepository::new(db.clone());
        store_credential(&cred_repo, identity.id, "modern", &master, "secret").await;
        let legacy = Credential::new(
            identity.id,
            "legacy".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            master.encrypt(b"legacy-bytes").unwrap(),
            None,
        );
        cred_repo.create(&legacy).await.unwrap();

        let (session, _) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
        let count = session.backfill_existing(&master).await.unwrap();
        assert_eq!(count, 1, "legacy 行跳过，modern 行灌入");
    }

    /// backfill 对坏行逐条跳过不阻断：unwrap 失败、密文坏、明文非
    /// CredentialData 三种损坏各一条，全部 skip（返回 0，远端零推送）。
    #[tokio::test]
    async fn backfill_skips_corrupt_credentials_one_by_one() {
        let (db, identity, master) = seeded_db().await;
        let cred_repo = CredentialRepository::new(db.clone());

        // wrapped key 是垃圾字节 → item key unwrap 失败
        cred_repo
            .create(&Credential::new(
                identity.id,
                "bad-unwrap".to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                vec![1, 2, 3],
                Some(vec![9; 48]),
            ))
            .await
            .unwrap();

        // wrapped 合法但密文坏 → credential decrypt 失败
        let item_key = EncryptionService::generate_key();
        cred_repo
            .create(&Credential::new(
                identity.id,
                "bad-ciphertext".to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                vec![7; 64],
                Some(master.encrypt(&item_key).unwrap()),
            ))
            .await
            .unwrap();

        // 可解密但明文不是 CredentialData → from_bytes 失败
        let ciphertext = KeyHierarchy::new(&master)
            .encrypt_with_item_key(&item_key, b"not credential data")
            .unwrap();
        cred_repo
            .create(&Credential::new(
                identity.id,
                "bad-data".to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                ciphertext,
                Some(master.encrypt(&item_key).unwrap()),
            ))
            .await
            .unwrap();

        let (session, pushed_log) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
        let count = session.backfill_existing(&master).await.unwrap();
        assert_eq!(count, 0, "三条坏行全部跳过");
        assert!(pushed_log.lock().unwrap().is_empty());
    }

    // open 的密码学半步：坏信封 fail-closed
    #[cfg(feature = "remote-auth")]
    #[test]
    fn open_own_envelope_rejects_malformed() {
        let identity = DeviceIdentity::generate("d").unwrap();
        assert!(
            super::super::envelope::open_group_key(b"short", identity.key_pair.secret_bytes())
                .is_err()
        );
        // 80B 但不是包给这把私钥的（随机字节）——认证必失败
        assert!(super::super::envelope::open_group_key(
            &[0x5Au8; 80],
            identity.key_pair.secret_bytes()
        )
        .is_err());
    }

    // ---- 冲突裁决（阶段 3c）----

    use chrono::Utc as TestUtc;

    fn snapshot(name: &str, identity_id: Uuid) -> SyncItemSnapshot {
        SyncItemSnapshot {
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
            data: data(name),
        }
    }

    fn conflict_put_op(
        item_id: Uuid,
        device_id: Uuid,
        lamport: u64,
        snap: &SyncItemSnapshot,
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
            timestamp: Some(TestUtc::now()),
            payload: Some(SyncPayload {
                ciphertext: snap.seal(&item_key).unwrap(),
                wrapped_item_key: wrap_item_key_with_group(&item_key, group),
            }),
        }
    }

    fn conflict_delete_op(item_id: Uuid, device_id: Uuid, lamport: u64) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Credential,
            op: OpType::Delete,
            lamport,
            device_id,
            timestamp: Some(TestUtc::now()),
            payload: None,
        }
    }

    /// 造一对真冲突（同 item、同 lamport、异设备），按全序返回
    /// (主位 op, 副本 op)。
    fn seeded_conflict(item_id: Uuid, group: &GroupKey, identity_id: Uuid) -> (SyncOp, SyncOp) {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (winner, loser) = if a > b { (a, b) } else { (b, a) };
        let primary = conflict_put_op(
            item_id,
            winner,
            5,
            &snapshot("primary-name", identity_id),
            group,
        );
        let copy = conflict_put_op(
            item_id,
            loser,
            5,
            &snapshot("copy-name", identity_id),
            group,
        );
        (primary, copy)
    }

    fn assert_variant(err: anyhow::Error, ok: impl Fn(&PersonaError) -> bool) {
        assert!(
            err.downcast_ref::<PersonaError>().is_some_and(ok),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn list_conflicts_exposes_both_versions_and_count() {
        let (db, identity, _master) = seeded_db().await;
        let item = Uuid::new_v4();
        let group = GroupKey::generate().unwrap();
        let (primary, copy) = seeded_conflict(item, &group, identity.id);
        let sync_repo = SyncRepository::new(db.clone());
        sync_repo.record_remote_op(&primary).await.unwrap();
        sync_repo.record_remote_op(&copy).await.unwrap();

        let (session, _) = session_for(&db, Uuid::new_v4(), group.clone());
        let entries = session.list_conflicts().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].item_id, item);
        assert_eq!(
            entries[0].primary.snapshot.as_ref().unwrap().name,
            "primary-name"
        );
        assert!(!entries[0].primary.deleted);
        assert_eq!(entries[0].copies.len(), 1);
        assert_eq!(
            entries[0].copies[0].snapshot.as_ref().unwrap().name,
            "copy-name"
        );
        assert_eq!(session.conflict_item_count().await.unwrap(), 1);

        // 无冲突条目（单版本）不进裁决视图
        sync_repo
            .record_remote_op(&conflict_put_op(
                Uuid::new_v4(),
                Uuid::new_v4(),
                1,
                &snapshot("lone", identity.id),
                &group,
            ))
            .await
            .unwrap();
        assert_eq!(session.list_conflicts().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resolve_adopted_put_writes_row_and_wins_primary() {
        let (db, identity, master) = seeded_db().await;
        let item = Uuid::new_v4();
        let group = GroupKey::generate().unwrap();
        let (primary, copy) = seeded_conflict(item, &group, identity.id);
        let sync_repo = SyncRepository::new(db.clone());
        sync_repo.record_remote_op(&primary).await.unwrap();
        sync_repo.record_remote_op(&copy).await.unwrap();

        let local_device = Uuid::new_v4();
        let (session, _) = session_for(&db, local_device, group);
        session
            .resolve_conflict(&master, item, copy.op_id)
            .await
            .unwrap();

        // 主库行 = 被采纳副本的内容（含重包后可解的 CredentialData）
        let cred_repo = CredentialRepository::new(db.clone());
        let row = cred_repo.find_by_id(&item).await.unwrap().unwrap();
        assert_eq!(row.name, "copy-name");
        let plaintext = KeyHierarchy::new(&master)
            .decrypt_with_wrapped_key(row.wrapped_item_key.as_ref().unwrap(), &row.encrypted_data)
            .unwrap();
        match CredentialData::from_bytes(&plaintext).unwrap() {
            CredentialData::Password(p) => assert_eq!(p.password, "copy-name"),
            other => panic!("expected password data, got {other:?}"),
        }

        // oplog：本机新 lamport 的采纳 op 赢回主位，冲突区清空
        let view = item_view(sync_repo.item_ops(item).await.unwrap());
        let new_primary = view.primary.unwrap();
        assert_eq!(new_primary.device_id, local_device);
        assert!(new_primary.lamport > 5);
        assert!(view.conflicts.is_empty());

        // 采纳 op 已入 push 队列且 payload 字节复用副本（设备无关）
        let pending = sync_repo.pending_ops(500).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].payload, copy.payload);

        // 裁决视图清空
        assert!(session.list_conflicts().await.unwrap().is_empty());
        assert_eq!(session.conflict_item_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn resolve_adopted_delete_removes_row_and_wins_primary() {
        let (db, identity, master) = seeded_db().await;
        let item = Uuid::new_v4();
        let group = GroupKey::generate().unwrap();
        let local_device = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (winner, loser) = if a > b { (a, b) } else { (b, a) };
        let put = conflict_put_op(item, winner, 5, &snapshot("alive", identity.id), &group);
        let del = conflict_delete_op(item, loser, 5);
        let sync_repo = SyncRepository::new(db.clone());
        sync_repo.record_remote_op(&put).await.unwrap();
        sync_repo.record_remote_op(&del).await.unwrap();

        let (session, _) = session_for(&db, local_device, group.clone());
        // 先物化主位 put（行存在），再采纳 delete 副本
        Materializer::new(db.clone())
            .materialize_all(&master, &group, local_device)
            .await
            .unwrap();
        let cred_repo = CredentialRepository::new(db.clone());
        assert!(cred_repo.find_by_id(&item).await.unwrap().is_some());

        session
            .resolve_conflict(&master, item, del.op_id)
            .await
            .unwrap();
        assert!(cred_repo.find_by_id(&item).await.unwrap().is_none());
        let view = item_view(sync_repo.item_ops(item).await.unwrap());
        assert!(view.primary.unwrap().is_tombstone());
        assert!(view.conflicts.is_empty());
        assert_eq!(session.conflict_item_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn resolve_rejects_unknown_primary_and_stale_op_ids() {
        let (db, identity, master) = seeded_db().await;
        let item = Uuid::new_v4();
        let group = GroupKey::generate().unwrap();
        let (primary, copy) = seeded_conflict(item, &group, identity.id);
        let sync_repo = SyncRepository::new(db.clone());
        sync_repo.record_remote_op(&primary).await.unwrap();
        sync_repo.record_remote_op(&copy).await.unwrap();

        let (session, _) = session_for(&db, Uuid::new_v4(), group);

        // 采纳主位（不是副本）与未知 op_id → NotFound
        let err = session
            .resolve_conflict(&master, item, primary.op_id)
            .await
            .unwrap_err();
        assert_variant(err, |e| matches!(e, PersonaError::NotFound(_)));
        let err = session
            .resolve_conflict(&master, item, Uuid::new_v4())
            .await
            .unwrap_err();
        assert_variant(err, |e| matches!(e, PersonaError::NotFound(_)));

        // 裁决一次后：剩余版本淘汰出视图，再裁决同 item → NotFound
        session
            .resolve_conflict(&master, item, copy.op_id)
            .await
            .unwrap();
        let err = session
            .resolve_conflict(&master, item, primary.op_id)
            .await
            .unwrap_err();
        assert_variant(err, |e| matches!(e, PersonaError::NotFound(_)));
    }

    /// 副本引用未同步身份：主库写不了 → Validation 错误，且 oplog/时钟/
    /// 裁决视图零副作用（绝不记 op 不写主库 = 防静默分叉）。
    #[tokio::test]
    async fn resolve_with_pending_identity_errors_without_side_effects() {
        let (db, identity, master) = seeded_db().await;
        let item = Uuid::new_v4();
        let group = GroupKey::generate().unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (winner, loser) = if a > b { (a, b) } else { (b, a) };
        let primary = conflict_put_op(item, winner, 5, &snapshot("primary", identity.id), &group);
        // 副本引用未知身份
        let copy = conflict_put_op(
            item,
            loser,
            5,
            &snapshot("dangling", Uuid::new_v4()),
            &group,
        );
        let sync_repo = SyncRepository::new(db.clone());
        sync_repo.record_remote_op(&primary).await.unwrap();
        sync_repo.record_remote_op(&copy).await.unwrap();

        let (session, _) = session_for(&db, Uuid::new_v4(), group);
        let lamport_before = sync_repo.get_state().await.unwrap().local_lamport;

        let err = session
            .resolve_conflict(&master, item, copy.op_id)
            .await
            .unwrap_err();
        assert_variant(err, |e| matches!(e, PersonaError::Validation(_)));

        assert!(sync_repo.pending_ops(500).await.unwrap().is_empty());
        assert_eq!(
            sync_repo.get_state().await.unwrap().local_lamport,
            lamport_before
        );
        assert_eq!(session.list_conflicts().await.unwrap().len(), 1);
    }

    /// run_cycle 报告的 conflicts 是待裁决条目数（真值），不是 3b 误用的
    /// 「本机主位跳过计数」：灌入一条冲突后跑周期，报告 conflicts == 1。
    #[tokio::test]
    async fn run_cycle_reports_conflict_count_truth() {
        let (db, identity, master) = seeded_db().await;
        let item = Uuid::new_v4();
        let group = GroupKey::generate().unwrap();
        let (primary, copy) = seeded_conflict(item, &group, identity.id);
        let sync_repo = SyncRepository::new(db.clone());
        sync_repo.record_remote_op(&primary).await.unwrap();
        sync_repo.record_remote_op(&copy).await.unwrap();

        let (session, _) = session_for(&db, Uuid::new_v4(), group);
        let report = session.run_cycle(&master).await.unwrap();
        assert_eq!(report.conflicts, 1);
        // 物化主位落库（远端内容），裁决等用户
        assert_eq!(report.materialized, 1);
    }
}
