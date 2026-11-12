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

//!
//! 拆分（LAY-021）：会话核心（open/backfill/snapshot/run_cycle/status/gc/
//! capture）留在本文件；rewrap/rotate 见 `rotate.rs`，冲突裁决见
//! `conflicts.rs`，测试按域分在 `tests/`。
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
use super::snapshot::{LibrarySnapshotPayload, SyncItemSnapshot, UPLOAD_THRESHOLD_OPS};
use crate::crypto::encryption::EncryptionService;
use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::credential::CredentialData;
use crate::storage::sync_repository::SyncRepository;
use crate::storage::{CredentialRepository, Database};
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

/// 一次 group key 轮换的汇总。轮换 = 换信封 + 全量重包（E2EE_SYNC_DESIGN
/// DR-3「安全轮换」、§11 开放问题 2 的 v1 答案）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncRotateReport {
    /// 以新组密钥重新入账的凭据条数（每条一个新 lamport 的 put）。
    pub rewrapped: u64,
    /// 主库凭据中因 legacy（无 wrapped item key）/解密失败跳过的条数——
    /// 这些条目轮换后仍只有旧组密文，对只有新信封的设备不可见。
    pub skipped: u64,
    /// 轮换全程（前置清队列 + 重包批次）push 出去的 op 总条数。
    pub pushed: u64,
}

/// 一轮 oplog 清理的汇总（[`SyncSession::gc_oplog`]）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcReport {
    /// 清理的 oplog 行数（已消费的历史版本 + 过保留窗口的 tombstone）。
    pub removed_ops: u64,
}

/// GC 默认的 tombstone 保留窗口：主位 tombstone 在 ack 后保留这么久才清，
/// 给慢设备/游标重置留重放余地。chrono 的 Duration 无 const 构造，走函数。
pub fn default_tombstone_retention() -> chrono::Duration {
    chrono::Duration::try_days(30).expect("30 days always fits in chrono::Duration")
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
    /// 打包本机 oplog 视图充分集为库级快照明文（S2）：逐 item 取
    /// [`item_view`] 的主位（put/tombstone）+ 未裁决冲突副本。凭据表
    /// 行打包会丢 pending identity / 冲突副本 / tombstone，oplog 原封
    /// 搬运才能保证「快照起步 + 点后增量 == 全量重放」。
    pub async fn snapshot_payload(&self) -> Result<LibrarySnapshotPayload> {
        let mut ops = Vec::new();
        for item_id in self.sync_repo.item_ids().await? {
            let view = item_view(self.sync_repo.item_ops(item_id).await?);
            if let Some(primary) = view.primary {
                ops.push(primary);
            }
            ops.extend(view.conflicts);
        }
        Ok(LibrarySnapshotPayload {
            created_at: chrono::Utc::now().to_rfc3339(),
            ops,
        })
    }
    /// 装包回调本体：group key 拆包（fail-closed）→ 视图充分处理 op_id
    /// 幂等入本地 oplog（record_remote_op，acked——这些位点已被压缩进
    /// 快照，不该再推）。装包前游标不动，失败整体不收敛。
    #[allow(dead_code)]
    async fn install_snapshot_ops(&self, _seq: i64, sealed: Vec<u8>) -> Result<()> {
        let payload = LibrarySnapshotPayload::open(&sealed, &self.group_key)?;
        for op in &payload.ops {
            self.sync_repo.record_remote_op(op).await?;
        }
        Ok(())
    }
    /// 完整周期：pull（远端 op 攒进本地 oplog）→ materialize（oplog 主位
    /// 物化进主库）→ push（本地 pending op 推上服务器）。
    pub async fn run_cycle(&self, master: &EncryptionService) -> Result<SyncNowReport> {
        // bootstrap：本机从未拉过（首次/新设备）时先试装库级快照——
        // 装上则游标推到覆盖位点，pull 只拿增量；无快照/失败游标不动，
        // 走全量重放（fail-closed，与 engine 原语约定一致）。
        if self.sync_repo.get_state().await?.last_pull_cursor.is_none() {
            if let Err(e) = self
                .engine
                .install_library_snapshot(|seq, sealed| self.install_snapshot_ops(seq, sealed))
                .await
            {
                // 装包失败不收敛游标——全量重放兜底，仅记日志。
                tracing::warn!(error = %e, "snapshot install failed; full replay");
            }
        }
        let pull = self.engine.pull_cycle().await?;
        let materialize = Materializer::new(self.db.clone())
            .materialize_all(master, &self.group_key, self.device_id)
            .await?;
        let push = self.engine.push_cycle().await?;
        // 机会主义清理已消费的 oplog 历史（§11 开放问题 3 客户端半边）；
        // 失败不阻断同步——增长治理不是同步正确性的前置条件。
        if let Err(e) = self.gc_oplog(default_tombstone_retention()).await {
            tracing::warn!(error = %e, "oplog gc skipped");
        }
        // 快照触发（S2）：head − 上次快照位点 > 阈值才重打包。失败仅记
        // 日志不阻断——快照是优化层，缺位只是回退全量重放。
        if let Ok(true) = self
            .engine
            .library_snapshot_needed(UPLOAD_THRESHOLD_OPS)
            .await
        {
            match self.snapshot_payload().await {
                Ok(payload) => match payload.seal(&self.group_key) {
                    Ok(sealed) => {
                        if let Err(e) = self.engine.upload_library_snapshot(&sealed).await {
                            tracing::warn!(error = %e, "snapshot upload skipped");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "snapshot pack failed"),
                },
                Err(e) => tracing::warn!(error = %e, "snapshot payload failed"),
            }
        }
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
    /// 同步状态快照（sync-group-mode §二.5.5 设置页显示的数据面）：组最新
    /// 版本号、本机已同步水位、落后条数、待推条数、最近同步时间。只读，
    /// 不跑周期——「立即同步」仍走 [`Self::run_cycle`]。
    pub async fn status(&self) -> Result<super::engine::SyncStatusReport> {
        self.engine.sync_status().await
    }
    /// oplog 增长治理（E2EE_SYNC_DESIGN §11 开放问题 3 的客户端半边）。
    /// 本地 oplog 是 append-only 密文日志，长期使用无界增长；本方法按保守
    /// 谓词只清「再无消费方」的历史版本：
    ///
    /// - **保护集**：push 队列未 ack 的本地 op（推数窗口，动了就丢改动）；
    ///   未裁决冲突副本（`item_view` 推导的 conflicts——裁决采纳后其余版本
    ///   以更大 lamport 赢回主位，败方自动落出副本集，下一轮 GC 可清）；
    ///   主位 put（活条目的视图锚，永不清理）。
    /// - **可清集**：acked 且既非主位也非副本的旧版本；以及 ack 且超过
    ///   `tombstone_retention` 的主位 tombstone（条目已删，仅留重放余地；
    ///   timestamp 缺失视为不清——无法证明足够老）。
    ///
    /// 被清 op 若因游标重置被重拉，按 op_id 幂等 upsert 重建，收敛不受影响；
    /// 主库零触碰（GC 只作用于 oplog）。
    pub async fn gc_oplog(&self, tombstone_retention: chrono::Duration) -> Result<GcReport> {
        let pending = self.sync_repo.pending_op_ids().await?;
        let now = chrono::Utc::now();
        let mut to_remove = Vec::new();
        for item_id in self.sync_repo.item_ids().await? {
            let ops = self.sync_repo.item_ops(item_id).await?;
            let view = item_view(ops.clone());
            let Some(primary) = &view.primary else {
                continue;
            };
            for op in &ops {
                if pending.contains(&op.op_id) {
                    continue;
                }
                if op.op_id == primary.op_id {
                    // 主位：仅「超过保留窗口的 tombstone」可清。
                    if primary.is_tombstone() {
                        if let Some(ts) = primary.timestamp {
                            if now - ts > tombstone_retention {
                                to_remove.push(op.op_id);
                            }
                        }
                    }
                    continue;
                }
                if view.conflicts.iter().any(|c| c.op_id == op.op_id) {
                    continue;
                }
                to_remove.push(op.op_id);
            }
        }
        let removed = self.sync_repo.delete_ops(&to_remove).await?;
        if removed > 0 {
            tracing::info!(event = "oplog_gc", removed, "pruned consumed oplog history");
        }
        Ok(GcReport {
            removed_ops: removed,
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

mod conflicts;
mod rotate;
#[cfg(test)]
mod tests;
