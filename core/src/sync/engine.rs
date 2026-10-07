//! 同步引擎编排（E2EE_SYNC_DESIGN 阶段 2 批 4）：push/pull 循环、Lamport
//! 时钟维护、travel 闸。
//!
//! 引擎只依赖 [`SyncRemote`]（远端中继的最小接口）与 [`SyncRepository`]：
//! HTTP 细节在 [`super::remote`]（cfg remote-auth），测试用内存实现。
//!
//! **travel 闸**（设计稿 §8）：travel 激活期间 `push_cycle`/`pull_cycle`
//! 双停——enter 的批量删除若推上去会把 tombstone 灌到其他设备毁库，pull
//! 则可能把被移出身份写回主库。`record_local_change` **不设闸**（travel
//! 期间本地普通写照常入队，退出后随 push 周期补推；travel enter 自身的
//! 批量删除走 travel.rs，不经过普通写捕获点——阶段 3 接线时保持此约定）。
//!
//! **主密码零耦合**（§4 密钥层级）：引擎全链路只接触 oplog 密文与
//! `(lamport, device_id)`，从不接触主密码派生材料——换主密码不影响同步
//! 状态（local_lamport/游标/oplog 全在库），宿主重建 engine 实例即续用。

use chrono::Utc;
use uuid::Uuid;

use crate::storage::sync_repository::SyncRepository;
use crate::sync::oplog::{ItemKind, OpType, SyncOp, SyncPayload};
use crate::{PersonaError, Result};

/// 单轮 pull 的页大小（与 server PULL_DEFAULT_LIMIT 对齐）。
pub const PULL_PAGE: u32 = 200;

/// 快照续拉游标的哨兵 op_id（S2）：op_id 是 UUID 串（hex 字符集），字典
/// 序恒大于 `"0"`。游标 `(快照 seq, "0")` 经服务器的 `(seq, op_id) >`
/// 复合比较精确表达「恢复位点 = 快照覆盖位点」——seq ≤ S 的行已被快照
/// 上传压缩删除，语义无差；好处是水位（cursor 解回 seq）直读快照位点。
pub const SNAPSHOT_RESUME_OP_ID: &str = "0";

/// 远端中继的最小接口。返回的 op 已是 [`SyncOp`] 形态（wire 解析在实现
/// 内完成；未知 kind → [`ItemKind::Unknown`]，条目级损坏 → 跳过该条）。
#[async_trait::async_trait]
pub trait SyncRemote: Send + Sync {
    /// push 一段 op；服务器按 op_id 幂等，返回 (accepted, duplicates)。
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)>;
    /// pull 一页增量：返回 (ops, next_cursor)。`since`/next_cursor 是服务
    /// 器 seq 游标，原样透传给 [`SyncRepository::set_last_pull_cursor`]。
    async fn pull_ops(
        &self,
        since: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<SyncOp>, Option<String>)>;
    /// 组当前指令流水位（sync-group-mode §二.5.5「组最新版本号」）——服务
    /// 器 oplog 最大 seq；空组为 0。
    async fn head_seq(&self) -> Result<i64>;
    /// 上传库级快照（S2，E2EE_SYNC_DESIGN §5）：group key 整包密文 +
    /// 覆盖位点 seq。服务器单快照 upsert 并在同事务删 `seq ≤ S` 的 ops，
    /// 返回被压缩的 op 条数（仅展示）。失败必须报错——覆盖区间可能已被
    /// 压缩，静默丢快照 = 空库新设备无事实源可补的真数据洞。
    async fn put_library_snapshot(
        &self,
        seq: i64,
        device_id: &str,
        ciphertext: &[u8],
    ) -> Result<u64>;
    /// 取库级快照：`Ok(None)` = 服务器无快照可取（新服务器尚未上传过、
    /// 或老服务器没有这条路由），两个成因在客户端行为上收敛——都退回
    /// 全量重放。返回 (覆盖位点 seq, group key 密文)。
    async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushCycleReport {
    pub pushed: usize,
    pub skipped_travel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullCycleReport {
    /// 新落库的远端 op 条数（去重后）。
    pub applied: usize,
    pub skipped_travel: bool,
}

pub struct SyncEngine<R: SyncRemote> {
    repo: SyncRepository,
    remote: R,
    /// 本设备 id（注册时定；本地 op 的 device_id 与时钟归属都靠它）。
    device_id: Uuid,
    /// travel 闸（见模块文档）。构造时注入，宿主读 WorkspaceSettings。
    travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    pull_page: u32,
}

impl<R: SyncRemote> SyncEngine<R> {
    pub fn new(
        repo: SyncRepository,
        remote: R,
        device_id: Uuid,
        travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            repo,
            remote,
            device_id,
            travel_active,
            pull_page: PULL_PAGE,
        }
    }

    /// 本地写捕获（service 写路径调用）：lamport = 本机 + 1，op 入 push
    /// 队列。**不设 travel 闸**（见模块文档）。
    pub async fn record_local_change(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        payload: Option<SyncPayload>,
    ) -> Result<SyncOp> {
        let lamport = self.repo.get_state().await?.local_lamport + 1;
        let sync_op = SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind,
            op,
            lamport,
            device_id: self.device_id,
            timestamp: Some(Utc::now()),
            payload,
        };
        // 先推时钟再落队列：两者间崩溃会留一个「时钟已过但 op 丢失」的
        // 空洞——无害（lamport 只需全序，不需要连续），反序则可能产生
        // 重复 lamport（同设备同 lamport 的两条 op 是协议越界）。
        self.repo.bump_lamport(lamport).await?;
        self.repo.append_local_op(&sync_op).await?;
        Ok(sync_op)
    }

    /// 推平本地 push 队列（≤500 条/批，单轮一批；余量下轮再推）。
    pub async fn push_cycle(&self) -> Result<PushCycleReport> {
        if (self.travel_active)() {
            return Ok(PushCycleReport {
                pushed: 0,
                skipped_travel: true,
            });
        }
        let pending = self.repo.pending_ops(500).await?;
        if pending.is_empty() {
            return Ok(PushCycleReport {
                pushed: 0,
                skipped_travel: false,
            });
        }
        let (_accepted, _duplicates) = self.remote.push_ops(&pending).await?;
        // 全部标记 acked：服务器已收的不再推；万一服务器实际没收到
        //（响应丢失被误判成功），INSERT OR IGNORE 保证下轮重推幂等安全。
        let ids: Vec<Uuid> = pending.iter().map(|op| op.op_id).collect();
        self.repo.mark_acked(&ids).await?;
        Ok(PushCycleReport {
            pushed: pending.len(),
            skipped_travel: false,
        })
    }

    /// 拉取远端增量并落本地 oplog（视图由 item_view 随时推导，落库本身
    /// 不做 LWW 物化）。游标推进 + 时钟推进（`max` 语义）。
    pub async fn pull_cycle(&self) -> Result<PullCycleReport> {
        if (self.travel_active)() {
            return Ok(PullCycleReport {
                applied: 0,
                skipped_travel: true,
            });
        }
        let mut applied = 0usize;
        let mut max_lamport_seen = 0u64;
        loop {
            let since = self.repo.get_state().await?.last_pull_cursor;
            let (ops, next_cursor) = self
                .remote
                .pull_ops(since.as_deref(), self.pull_page)
                .await?;
            if ops.is_empty() {
                break;
            }
            let ids: Vec<Uuid> = ops.iter().map(|op| op.op_id).collect();
            let seen = self.repo.existing_op_ids(&ids).await?;
            for op in ops {
                max_lamport_seen = max_lamport_seen.max(op.lamport);
                if seen.contains(&op.op_id) {
                    continue; // 重放/重复投递（存储层幂等的第二道防线）
                }
                self.repo.record_remote_op(&op).await?;
                applied += 1;
            }
            match next_cursor {
                Some(cursor) => self.repo.set_last_pull_cursor(Some(&cursor)).await?,
                None => break, // 已到最后一页
            }
        }
        if max_lamport_seen > 0 {
            self.repo.bump_lamport(max_lamport_seen).await?;
        }
        // 完整跑完一轮 pull（哪怕无新 op）= 与组对过账，记最近同步时间。
        self.repo.mark_synced(Utc::now()).await?;
        Ok(PullCycleReport {
            applied,
            skipped_travel: false,
        })
    }

    /// 库级快照上传原语（S2，E2EE_SYNC_DESIGN §5）：调用方（service 层，
    /// 持密钥层）把整库打包成 group key 密文传入，引擎负责收敛与覆盖位点
    /// 的确定——先推平本机待推队列（上云拿到 seq）再拉平远端增量，然后以
    /// 「本机已同步水位」为覆盖位点 S 上云。先 push 后 pull 的周期顺序保证
    /// 服务器上 seq ≤ S 的每条 op 都已反映进本机状态（pull 按 (seq, op_id)
    /// 全序分页，拉到空页 = 水位即当时的 head），快照声称的覆盖区间因此
    /// 成立（周期顺序消竞态，无需快照点协议）。成功后记
    /// `last_snapshot_seq`（触发阈值基线）。
    /// 返回 (覆盖位点 S, 服务器压缩的 op 条数)。
    pub async fn upload_library_snapshot(&self, ciphertext: &[u8]) -> Result<(i64, u64)> {
        if (self.travel_active)() {
            return Err(PersonaError::InvalidInput(
                "library snapshot upload is blocked while travel mode is active".to_string(),
            )
            .into());
        }
        self.push_cycle().await?;
        self.pull_cycle().await?;
        let seq = self.repo.local_watermark().await?;
        let pruned = self
            .remote
            .put_library_snapshot(seq, &self.device_id.to_string(), ciphertext)
            .await?;
        self.repo.set_last_snapshot_seq(seq).await?;
        Ok((seq, pruned))
    }

    /// 库级快照安装原语（S2 bootstrap 第一步）：取服务器快照 → 整包密文交
    /// 回调（装配层持密钥：group key 拆包 + 视图充分集按 op_id 幂等入本地
    /// oplog）→ 回调成功后才把 pull 游标推进到覆盖位点并记
    /// `last_snapshot_seq`，后续 pull 只拿增量。回调失败或服务器无快照
    /// 一律不动游标，全量重放路径保持原状——fail-closed：游标先动而装包
    /// 失败 = 覆盖区间已被压缩、本机又没装上，数据洞不可挽回。
    /// travel 激活期间整体跳过（装包把远端数据写进 oplog/主库，与 pull
    /// 同向，travel 期间不得发生；退 travel 后下次 bootstrap 照装——游标
    /// 未动）。返回 `Some(覆盖位点 seq)`；无快照或 travel 跳过为 `None`
    /// （两者行为一致：都退回全量重放路径，游标决定下次是否还试）。
    pub async fn install_library_snapshot<F>(&self, install: F) -> Result<Option<i64>>
    where
        F: AsyncFnOnce(i64, Vec<u8>) -> Result<()>,
    {
        if (self.travel_active)() {
            return Ok(None);
        }
        let Some((seq, ciphertext)) = self.remote.get_library_snapshot().await? else {
            return Ok(None);
        };
        install(seq, ciphertext).await?;
        self.repo
            .set_last_pull_cursor(Some(&crate::sync::cursor::encode_cursor(
                seq,
                SNAPSHOT_RESUME_OP_ID,
            )))
            .await?;
        self.repo.set_last_snapshot_seq(seq).await?;
        Ok(Some(seq))
    }

    /// 快照上传触发判定（E2EE_SYNC_DESIGN §5「触发时机」）：`head − 上次
    /// 快照位点 > threshold` 才值得重打包（防频繁重打包）。travel 恒 false
    /// （不上传）；从未有过快照基线记 0。判定与 [`Self::upload_library_snapshot`]
    /// 分开：触发只是可能，上传仍要过收敛周期——调用方在 push ack 后询问。
    pub async fn library_snapshot_needed(&self, threshold: i64) -> Result<bool> {
        if (self.travel_active)() {
            return Ok(false);
        }
        let head = self.remote.head_seq().await?;
        let last = self.repo.get_state().await?.last_snapshot_seq;
        Ok(head - last > threshold)
    }

    /// 同步状态（sync-group-mode §二.5.5）：组最新版本号、本机已同步水位、
    /// 落后条数、待推条数与最近同步时间。只读，不动任何周期状态。
    pub async fn sync_status(&self) -> Result<SyncStatusReport> {
        let head_seq = self.remote.head_seq().await?;
        let local_watermark = self.repo.local_watermark().await?;
        let pending_push = self.repo.pending_count().await?;
        let last_sync_at = self.repo.get_state().await?.last_sync_at;
        Ok(SyncStatusReport {
            head_seq,
            local_watermark,
            behind: (head_seq - local_watermark).max(0),
            pending_push,
            last_sync_at,
        })
    }
}

/// 组同步水位快照（设置页状态显示的数据面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatusReport {
    /// 组最新版本号（服务器 oplog 最大 seq；空组 0）。
    pub head_seq: i64,
    /// 本机已同步水位（已拉到的 seq；从未拉过 0）。
    pub local_watermark: i64,
    /// 落后组多少条指令（head − local，不取负）。
    pub behind: i64,
    /// 本机已产生、尚未推上组的指令数。
    pub pending_push: i64,
    /// 最近一次成功同步周期；None = 从未同步。
    pub last_sync_at: Option<chrono::DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PersonaError;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    /// 内存远端：op 原样累积；pull 忽略游标全量返回（重放由 engine 的
    /// existing_op_ids 去重兜住——游标语义本身由 server 集成测试锁定）。
    struct MemorySyncRemote {
        state: Mutex<MemState>,
    }

    struct MemState {
        ops: Vec<SyncOp>,
        fail_push: bool,
        /// 库级快照（S2）：(覆盖位点, 密文)；None = 尚未上传过。
        snapshot: Option<(i64, Vec<u8>)>,
    }

    impl MemorySyncRemote {
        fn new() -> Self {
            Self {
                state: Mutex::new(MemState {
                    ops: Vec::new(),
                    fail_push: false,
                    snapshot: None,
                }),
            }
        }

        fn add(&self, ops: Vec<SyncOp>) {
            self.state.lock().unwrap().ops.extend(ops);
        }
    }

    #[async_trait::async_trait]
    impl SyncRemote for MemorySyncRemote {
        async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
            let mut state = self.state.lock().unwrap();
            if state.fail_push {
                return Err(PersonaError::Io("push failed".to_string()).into());
            }
            let existing: HashSet<Uuid> = state.ops.iter().map(|op| op.op_id).collect();
            let mut accepted = 0u64;
            let mut duplicates = 0u64;
            for op in ops {
                if existing.contains(&op.op_id) {
                    duplicates += 1;
                } else {
                    accepted += 1;
                }
            }
            state.ops.extend(ops.iter().cloned());
            Ok((accepted, duplicates))
        }

        async fn pull_ops(
            &self,
            since: Option<&str>,
            limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            // 游标语义与 server 同构：cursor 位点 = 已返回条数，next 指向下
            // 一页起点；拉到最后一页返回 None（否则引擎循环永不收尾）。
            let state = self.state.lock().unwrap();
            let start = match since {
                Some(raw) => crate::sync::cursor::decode_cursor(raw)
                    .map(|(seq, _)| seq as usize)
                    .unwrap_or(0),
                None => 0,
            };
            let total = state.ops.len();
            let end = start.saturating_add(limit as usize).min(total);
            let page = state.ops[start.min(total)..end].to_vec();
            // 与 server 同语义：非空页恒返回该页最后一行的游标（空页 null，
            // 客户端按「空页才停」循环）——水位因此总能推进到已消费位点。
            let next = (end > start).then(|| {
                crate::sync::cursor::encode_cursor(
                    end as i64,
                    &state.ops[end - 1].op_id.to_string(),
                )
            });
            Ok((page, next))
        }

        async fn head_seq(&self) -> Result<i64> {
            // 内存远端的「服务器 seq」= 累计 op 条数（push 进几条 head 涨几条）
            Ok(self.state.lock().unwrap().ops.len() as i64)
        }

        async fn put_library_snapshot(
            &self,
            seq: i64,
            _device_id: &str,
            ciphertext: &[u8],
        ) -> Result<u64> {
            // 单快照 upsert；返回值记账「将被压缩的 op 条数」。内存远端保持
            // append-only——真删除的 seq 语义（rowid 单调、游标绝对）用数组
            // 模拟会分叉，server 侧已由集成测试锁定
            //（snapshot_put_get_roundtrip_and_prunes_covered_ops）。
            let mut state = self.state.lock().unwrap();
            let pruned = (seq as usize).min(state.ops.len());
            state.snapshot = Some((seq, ciphertext.to_vec()));
            Ok(pruned as u64)
        }

        async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
            Ok(self.state.lock().unwrap().snapshot.clone())
        }
    }

    /// 引擎持 Arc 共享内存远端（orphan 规则允许：local trait for Arc<T>）。
    #[async_trait::async_trait]
    impl<T: SyncRemote + ?Sized> SyncRemote for Arc<T> {
        async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
            self.as_ref().push_ops(ops).await
        }

        async fn pull_ops(
            &self,
            since: Option<&str>,
            limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            self.as_ref().pull_ops(since, limit).await
        }

        async fn head_seq(&self) -> Result<i64> {
            self.as_ref().head_seq().await
        }

        async fn put_library_snapshot(
            &self,
            seq: i64,
            device_id: &str,
            ciphertext: &[u8],
        ) -> Result<u64> {
            self.as_ref()
                .put_library_snapshot(seq, device_id, ciphertext)
                .await
        }

        async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
            self.as_ref().get_library_snapshot().await
        }
    }

    async fn fixture(travel: bool) -> (SyncEngine<Arc<MemorySyncRemote>>, Arc<MemorySyncRemote>) {
        let db = crate::storage::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let remote = Arc::new(MemorySyncRemote::new());
        let engine = SyncEngine::new(
            SyncRepository::new(db),
            remote.clone(),
            Uuid::new_v4(),
            Box::new(move || travel),
        );
        (engine, remote)
    }

    fn put_payload(tag: u8) -> Option<SyncPayload> {
        Some(SyncPayload {
            ciphertext: vec![tag; 8],
            wrapped_item_key: vec![tag; 32],
        })
    }

    fn remote_put(lamport: u64, tag: u8, kind: ItemKind) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            kind,
            op: OpType::Put,
            lamport,
            device_id: Uuid::new_v4(),
            timestamp: None,
            payload: put_payload(tag),
        }
    }

    #[tokio::test]
    async fn record_local_change_increments_clock_and_enqueues() {
        let (engine, _remote) = fixture(false).await;
        let device = engine.device_id;
        let item = Uuid::new_v4();

        let first = engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(1))
            .await
            .unwrap();
        let second = engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(2))
            .await
            .unwrap();

        assert_eq!((first.lamport, second.lamport), (1, 2));
        assert_eq!(first.device_id, device);
        let pending = engine.repo.pending_ops(100).await.unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 2);
    }

    #[tokio::test]
    async fn push_cycle_drains_queue_and_marks_acked() {
        let (engine, remote) = fixture(false).await;
        let item = Uuid::new_v4();
        for tag in 1..=3u8 {
            engine
                .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(tag))
                .await
                .unwrap();
        }
        let report = engine.push_cycle().await.unwrap();
        assert_eq!(report.pushed, 3);
        assert!(!report.skipped_travel);
        assert!(engine.repo.pending_ops(100).await.unwrap().is_empty());
        assert_eq!(remote.state.lock().unwrap().ops.len(), 3);

        // 再推一轮：空队列 no-op
        let again = engine.push_cycle().await.unwrap();
        assert_eq!(again.pushed, 0);
    }

    #[tokio::test]
    async fn push_failure_keeps_queue_for_retry() {
        let (engine, remote) = fixture(false).await;
        let item = Uuid::new_v4();
        engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(1))
            .await
            .unwrap();

        remote.state.lock().unwrap().fail_push = true;
        assert!(engine.push_cycle().await.is_err());
        assert_eq!(engine.repo.pending_ops(100).await.unwrap().len(), 1);

        remote.state.lock().unwrap().fail_push = false;
        assert_eq!(engine.push_cycle().await.unwrap().pushed, 1);
        assert!(engine.repo.pending_ops(100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn travel_gate_stops_push_and_pull_both() {
        let (engine, remote) = fixture(true).await;
        let item = Uuid::new_v4();
        engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(1))
            .await
            .unwrap();

        let push = engine.push_cycle().await.unwrap();
        assert!(push.skipped_travel);
        assert_eq!(push.pushed, 0);
        assert_eq!(engine.repo.pending_ops(100).await.unwrap().len(), 1); // 队列原样保留

        remote.add(vec![remote_put(9, 1, ItemKind::Credential)]);
        let pull = engine.pull_cycle().await.unwrap();
        assert!(pull.skipped_travel);
        assert_eq!(pull.applied, 0);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 1); // 时钟未被远端推进
    }

    #[tokio::test]
    async fn pull_lands_remote_ops_and_advances_clock() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(5, 1, ItemKind::Credential),
            remote_put(7, 2, ItemKind::Identity),
        ]);

        let report = engine.pull_cycle().await.unwrap();
        assert_eq!(report.applied, 2);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 7);

        // 重放同一远端：全量去重
        let replay = engine.pull_cycle().await.unwrap();
        assert_eq!(replay.applied, 0);
    }

    #[tokio::test]
    async fn pull_unknown_kind_still_lands_and_counts_for_clock() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![remote_put(4, 1, ItemKind::Unknown)]);

        let report = engine.pull_cycle().await.unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 4);
    }

    #[tokio::test]
    async fn local_write_after_pull_continues_from_max() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![remote_put(7, 1, ItemKind::Credential)]);
        engine.pull_cycle().await.unwrap();

        // 拉到远端 lamport 7 后，本地写下一条必须接 8（时钟 = max）
        let op = engine
            .record_local_change(
                Uuid::new_v4(),
                ItemKind::Credential,
                OpType::Put,
                put_payload(1),
            )
            .await
            .unwrap();
        assert_eq!(op.lamport, 8);
    }

    // ---- sync_status（sync-group-mode §二.5.5 状态显示）----

    #[tokio::test]
    async fn sync_status_tracks_head_watermark_pending_and_last_sync() {
        let (engine, remote) = fixture(false).await;

        // 初始：组 head=0，本机水位 0，从未同步
        let s = engine.sync_status().await.unwrap();
        assert_eq!(
            (s.head_seq, s.local_watermark, s.behind, s.pending_push),
            (0, 0, 0, 0)
        );
        assert_eq!(s.last_sync_at, None);

        // 组里出现 5 条指令 + 本机离线写 2 条：落后 5、待推 2
        remote.add(
            (1..=5)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );
        for _ in 0..2 {
            engine
                .record_local_change(
                    Uuid::new_v4(),
                    ItemKind::Credential,
                    OpType::Put,
                    put_payload(1),
                )
                .await
                .unwrap();
        }
        let before = engine.sync_status().await.unwrap();
        assert_eq!(
            (
                before.head_seq,
                before.local_watermark,
                before.behind,
                before.pending_push,
                before.last_sync_at.is_none()
            ),
            (5, 0, 5, 2, true)
        );

        // pull 完成：水位到 5、落后清零、记下同步时间；待推不受 pull 影响
        engine.pull_cycle().await.unwrap();
        let after = engine.sync_status().await.unwrap();
        assert_eq!(after.local_watermark, 5);
        assert_eq!(after.behind, 0);
        assert_eq!(after.pending_push, 2);
        assert!(after.last_sync_at.is_some());

        // push 完成：待推清零；head 不含未推前的 2 条时是 5，推完远端变 7
        engine.push_cycle().await.unwrap();
        let final_status = engine.sync_status().await.unwrap();
        assert_eq!(final_status.head_seq, 7, "推上的 2 条计入组流水位");
        assert_eq!(final_status.pending_push, 0);
        assert_eq!(final_status.behind, 2, "远端又被自己推进(自推自) → 还差拉");
    }

    #[tokio::test]
    async fn pull_again_never_loops_and_watermark_reaches_head() {
        // 大批次跨页拉取：水位必须一路推进到 head（位点续传）
        let (engine, remote) = fixture(false).await;
        remote.add(
            (1..=450)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );
        let report = engine.pull_cycle().await.unwrap();
        assert_eq!(report.applied, 450);
        let s = engine.sync_status().await.unwrap();
        assert_eq!((s.local_watermark, s.behind), (450, 0));
        // 游标推进到头后，下一轮 pull 是一次空页往返
        let again = engine.pull_cycle().await.unwrap();
        assert_eq!(again.applied, 0);
    }

    // ---- 库级快照原语（S2，E2EE_SYNC_DESIGN §5）----

    #[tokio::test]
    async fn upload_snapshot_converges_then_stamps_watermark() {
        // 覆盖位点语义：先推平本机队列再拉平远端，水位 = 服务器已消费位点
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(1, 1, ItemKind::Credential),
            remote_put(2, 2, ItemKind::Identity),
            remote_put(3, 3, ItemKind::Passkey),
        ]);
        let item = Uuid::new_v4();
        for tag in 1..=2u8 {
            engine
                .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(tag))
                .await
                .unwrap();
        }

        let (seq, pruned) = engine.upload_library_snapshot(&[7u8; 5]).await.unwrap();
        assert_eq!(seq, 5, "远端 3 条 + 本机推上的 2 条 = 水位 5");
        assert_eq!(pruned, 5, "服务器压缩了覆盖区间内的全部 ops");
        assert_eq!(
            remote.state.lock().unwrap().snapshot,
            Some((5, vec![7u8; 5])),
            "单快照 upsert，密文与覆盖位点原样入库"
        );
        assert_eq!(
            remote.state.lock().unwrap().ops.len(),
            5,
            "内存远端 append-only（真删除由 server 集成测试锁定），只记账"
        );
        assert_eq!(
            engine.repo.get_state().await.unwrap().last_snapshot_seq,
            5,
            "上传成功记触发阈值基线"
        );

        // 快照后继续增量续拉：游标绝对位点（绝对 seq）不受压缩影响
        remote.add(vec![remote_put(4, 4, ItemKind::Credential)]);
        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 1, "只拉到快照点之后的增量");
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 6);
    }

    #[tokio::test]
    async fn upload_snapshot_blocked_during_travel() {
        let (engine, remote) = fixture(true).await;
        let err = engine
            .upload_library_snapshot(&[1u8; 4])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("travel"), "{err}");
        assert!(remote.state.lock().unwrap().snapshot.is_none());
    }

    #[tokio::test]
    async fn install_snapshot_advances_cursor_and_pulls_only_increment() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(1, 1, ItemKind::Credential),
            remote_put(2, 2, ItemKind::Identity),
            remote_put(3, 3, ItemKind::Credential),
        ]);
        remote.state.lock().unwrap().snapshot = Some((3, vec![9u8; 4]));

        let mut installed = None;
        let seq = engine
            .install_library_snapshot(async |s, bytes| {
                installed = Some((s, bytes));
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(seq, Some(3));
        assert_eq!(installed, Some((3, vec![9u8; 4])));
        assert_eq!(
            engine.repo.local_watermark().await.unwrap(),
            3,
            "游标直读快照位点"
        );
        assert_eq!(
            engine.repo.get_state().await.unwrap().last_snapshot_seq,
            3,
            "装包成功记触发阈值基线"
        );

        // 快照点后的增量照常续拉——哨兵游标 (3, "0") 起拉
        remote.add(vec![remote_put(4, 4, ItemKind::Credential)]);
        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 1, "只拉 seq > 3 的增量，不重放已装快照");
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 4);
    }

    #[tokio::test]
    async fn install_without_snapshot_keeps_full_replay_path() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![remote_put(1, 1, ItemKind::Credential)]);

        let seq = engine
            .install_library_snapshot(async |_, _| panic!("无快照不得调用装包回调"))
            .await
            .unwrap();
        assert_eq!(seq, None);
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 0);

        // 全量重放路径原状可用
        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 1);
    }

    #[tokio::test]
    async fn install_callback_failure_leaves_cursor_untouched() {
        // fail-closed 主场景：装包失败游标不动——覆盖区间虽已在服务器压缩，
        // 本机仍从零全量重放剩余 ops（缩水子集也收敛），不留半装状态
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(1, 1, ItemKind::Credential),
            remote_put(2, 2, ItemKind::Credential),
        ]);
        remote.state.lock().unwrap().snapshot = Some((2, vec![5u8; 4]));

        let err = engine
            .install_library_snapshot(async |_, _| {
                Err(PersonaError::CryptographicError("wrong group key".to_string()).into())
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("wrong group key"), "{err}");
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 0, "游标未动");

        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 2, "剩余 ops 仍可全量重放");
    }

    #[tokio::test]
    async fn install_snapshot_skipped_during_travel() {
        // travel 期间装包整体跳过（装包把远端数据写进 oplog，与 pull 同闸）：
        // 回调不得被调、游标与水位基线都不动——退 travel 后下次 bootstrap
        // 还会再试
        let (engine, remote) = fixture(true).await;
        remote.state.lock().unwrap().snapshot = Some((3, vec![1u8; 2]));
        let seq = engine
            .install_library_snapshot(async |_, _| panic!("travel 期间不得装包"))
            .await
            .unwrap();
        assert_eq!(seq, None);
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 0);
        assert_eq!(engine.repo.get_state().await.unwrap().last_snapshot_seq, 0);
    }

    #[tokio::test]
    async fn library_snapshot_needed_tracks_threshold_and_travel() {
        let (engine, remote) = fixture(false).await;
        remote.add(
            (1..=5)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );

        // 从未有过快照（基线 0）：head 5 超阈值 3 触发；严格大于——阈值 5 不触发
        assert!(engine.library_snapshot_needed(3).await.unwrap());
        assert!(!engine.library_snapshot_needed(5).await.unwrap());

        // 上传后基线 = 水位 5：head 5 − 5 = 0，任何阈值都不再触发
        engine.upload_library_snapshot(&[1u8; 3]).await.unwrap();
        assert!(!engine.library_snapshot_needed(0).await.unwrap());

        // 组继续前进：head 8 − 基线 5 = 3 → 超 2 触发、等于 3 不触发
        remote.add(
            (6..=8)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );
        assert!(engine.library_snapshot_needed(2).await.unwrap());
        assert!(!engine.library_snapshot_needed(3).await.unwrap());

        // travel 激活：恒不触发（不上传）
        let (travel_engine, travel_remote) = fixture(true).await;
        travel_remote.add(vec![remote_put(1, 1, ItemKind::Credential)]);
        assert!(!travel_engine.library_snapshot_needed(0).await.unwrap());
    }
}
