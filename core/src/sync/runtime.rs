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
use super::materialize::Materializer;
use super::oplog::{ItemKind, OpType, SyncPayload};
use super::snapshot::SyncItemSnapshot;
use crate::crypto::encryption::EncryptionService;
use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::credential::CredentialData;
use crate::storage::sync_repository::SyncRepository;
use crate::storage::{CredentialRepository, Database};
#[cfg(feature = "remote-auth")]
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
            conflicts: materialize.skipped_local_primary,
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
}
