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
use crate::Result;

/// 单轮 pull 的页大小（与 server PULL_DEFAULT_LIMIT 对齐）。
pub const PULL_PAGE: u32 = 200;

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
        Ok(PullCycleReport {
            applied,
            skipped_travel: false,
        })
    }
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
    }

    impl MemorySyncRemote {
        fn new() -> Self {
            Self {
                state: Mutex::new(MemState {
                    ops: Vec::new(),
                    fail_push: false,
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
            _since: Option<&str>,
            _limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            Ok((self.state.lock().unwrap().ops.clone(), None))
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
}
