//! Emitter：同步入队 + 后台批量 flush + 指数退避的审计事件上报器。

use crate::events::wire::{build_batch, limits, WireEvent};
use crate::models::AuditLog;
use crate::Result;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Notify;

/// 单次上报结果（对齐 server 202 响应体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendReport {
    pub accepted: u64,
    pub duplicates: u64,
}

/// 上报目的地。收到的一定是已过预校验的合法批；`Err` 表示整批未确认，
/// 由 Emitter 负责退避重试。
#[async_trait]
pub trait EventSink: Send + Sync + 'static {
    async fn send(&self, events: Vec<WireEvent>) -> Result<SendReport>;
}

/// Emitter 行为参数（默认值见 [`EmitterConfig::default`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitterConfig {
    /// 队列达到此数立即唤醒 flush（clamp 到 server 单批上限 500）。
    pub batch_size: usize,
    /// 兜底 flush 周期（主触发是 Notify，见 flush 循环注释）。
    pub flush_interval: Duration,
    /// 内存队列上界；超出丢最旧并计入 dropped_total。
    pub max_queue: usize,
    /// send 失败的首次退避时长，之后逐次倍增。
    pub initial_backoff: Duration,
    /// 退避上界；任一批成功后重置回 initial_backoff。
    pub max_backoff: Duration,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            flush_interval: Duration::from_secs(30),
            max_queue: 10_000,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5 * 60),
        }
    }
}

/// 审计事件上报器：本地 sqlite 审计库是持久存证源，这里只是尽力而为的
/// 异步复制——进程崩溃即丢未 flush 的内存批，不回补（无持久 outbox）。
///
/// Clone 共享同一队列与后台任务；上报绝不阻塞审计写入（emit 纯同步入队）。
#[derive(Clone)]
pub struct Emitter {
    inner: Arc<EmitterInner>,
}

struct EmitterInner {
    sink: Arc<dyn EventSink>,
    config: EmitterConfig,
    queue: Mutex<VecDeque<AuditLog>>,
    /// 队列达 batch_size 时唤醒 flush。注意 Notify 许领会合并：
    /// drain 必须清空式（见 `drain_and_send`），否则合并唤醒会滞留事件。
    notify: Notify,
    /// 后台任务槽位（防重复 start）。std Mutex：guard 不跨 await。
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    dropped_total: AtomicU64,
}

impl std::fmt::Debug for Emitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Arc<dyn EventSink> 无 Debug：只打观测面，不打 sink。
        f.debug_struct("Emitter")
            .field("config", &self.inner.config)
            .field("queued", &self.queued())
            .field("dropped_total", &self.dropped_total())
            .finish()
    }
}

impl Emitter {
    pub fn new(sink: Arc<dyn EventSink>) -> Self {
        Self::with_config(sink, EmitterConfig::default())
    }

    pub fn with_config(sink: Arc<dyn EventSink>, config: EmitterConfig) -> Self {
        let mut config = config;
        // server 单批 ≤500（server MAX_BATCH_SIZE）；超配 clamp 而非 panic。
        config.batch_size = config.batch_size.clamp(1, limits::MAX_BATCH_SIZE);
        Self {
            inner: Arc::new(EmitterInner {
                sink,
                config,
                queue: Mutex::new(VecDeque::new()),
                notify: Notify::new(),
                task: Mutex::new(None),
                dropped_total: AtomicU64::new(0),
            }),
        }
    }

    /// 同步入队（可在 async 上下文直调；内部不 await、不 block）。
    /// 队满丢最旧 + warn + 计数：上报是尽力而为，绝不阻塞审计写入。
    pub fn emit(&self, log: &AuditLog) {
        {
            let mut queue = self.lock_queue();
            queue.push_back(log.clone());
            if queue.len() > self.inner.config.max_queue {
                queue.pop_front();
                self.inner.dropped_total.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    total = self.inner.dropped_total.load(Ordering::Relaxed),
                    "event queue full: dropping oldest audit event"
                );
            }
            if queue.len() >= self.inner.config.batch_size {
                self.inner.notify.notify_one();
            }
        }
    }

    /// 启动后台 flush 任务（幂等：已在跑则忽略）。调用方负责 [`Emitter::stop`]。
    pub fn start(&self) {
        let mut task = self.lock_task();
        if task.is_some() {
            return;
        }
        // Weak：Emitter 全部 drop 后后台任务自行退出，不构成 self-referential 泄漏。
        let inner = Arc::downgrade(&self.inner);
        *task = Some(tokio::spawn(async move { flush_loop(inner).await }));
    }

    /// 停止上报：abort 后台任务 + 尽力最终 flush（失败丢弃 + warn）。
    /// 从未 start 时只做最终 flush，重复调用幂等。
    ///
    /// 丢失窗口：被 abort 的任务可能已取走一批尚未发出（上限 batch_size），
    /// 这批 stop 收不回；上报本就是尽力而为，本地 sqlite 审计库是存证源。
    pub async fn stop(&self) {
        let handle = self.lock_task().take();
        if let Some(handle) = handle {
            handle.abort();
        }
        if let Err(error) = drain_and_send(&self.inner).await {
            tracing::warn!(%error, "final event flush failed; dropping remaining queue");
        }
    }

    /// 当前队列长度（观测用）。
    pub fn queued(&self) -> usize {
        self.lock_queue().len()
    }

    /// 累计因队满被丢弃的最旧事件数（观测用）。
    pub fn dropped_total(&self) -> u64 {
        self.inner.dropped_total.load(Ordering::Relaxed)
    }

    fn lock_queue(&self) -> std::sync::MutexGuard<'_, VecDeque<AuditLog>> {
        self.inner
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_task(&self) -> std::sync::MutexGuard<'_, Option<tokio::task::JoinHandle<()>>> {
        self.inner
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// flush 任务主体。Emitter 全部 drop（Weak 失效）即退出。
async fn flush_loop(inner: std::sync::Weak<EmitterInner>) {
    let Some(inner) = inner.upgrade() else {
        return;
    };
    let mut backoff = inner.config.initial_backoff;
    let mut ticker = tokio::time::interval(inner.config.flush_interval);
    ticker.tick().await; // interval 首个 tick 立即完成，消费掉（照 auto_lock 惯例）

    loop {
        match drain_and_send(&inner).await {
            Ok(()) => backoff = inner.config.initial_backoff,
            Err(error) => {
                tracing::warn!(
                    %error,
                    backoff_ms = backoff.as_millis() as u64,
                    "event flush failed; backing off"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(inner.config.max_backoff);
            }
        }
        // Notify 许可合并 + select 随机分支都不丢事件：许可存在 Notify 内部
        // 直到被消费，而 drain 是清空式的。
        tokio::select! {
            _ = ticker.tick() => {}
            _ = inner.notify.notified() => {}
        }
    }
}

/// 清空式 drain：把队列发到空（按 batch_size 分片）。send 失败时整批按
/// 原序回队首并返回 Err（保幂等键与可观测顺序；锁只在取批/回推的同步
/// 作用域内存活，不跨 await）。
async fn drain_and_send(inner: &EmitterInner) -> Result<()> {
    while !inner.is_empty() {
        let batch = inner.take_batch();
        let (events, rejected) = build_batch(&batch);
        for (index, issues) in rejected {
            tracing::warn!(index, ?issues, "dropping invalid audit event before send");
        }
        if events.is_empty() {
            continue; // 整片毒丸：丢弃后继续下一片
        }
        match inner.sink.send(events).await {
            Ok(report) => {
                tracing::debug!(
                    accepted = report.accepted,
                    duplicates = report.duplicates,
                    "audit events flushed"
                );
            }
            Err(error) => {
                inner.restore_batch(batch);
                return Err(error);
            }
        }
    }
    Ok(())
}

impl EmitterInner {
    fn is_empty(&self) -> bool {
        self.lock_queue().is_empty()
    }

    fn take_batch(&self) -> Vec<AuditLog> {
        let mut queue = self.lock_queue();
        let take = queue.len().min(self.config.batch_size);
        queue.drain(..take).collect()
    }

    /// send 失败的批按原序回队首（逆序 push_front）；与 emit 的 push_back
    /// 在锁内互斥，旧事件仍先于新事件发出。
    fn restore_batch(&self, batch: Vec<AuditLog>) {
        let mut queue = self.lock_queue();
        for log in batch.into_iter().rev() {
            queue.push_front(log);
        }
    }

    fn lock_queue(&self) -> std::sync::MutexGuard<'_, VecDeque<AuditLog>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::testing::{eventually, FakeSink};
    use crate::models::{AuditAction, ResourceType};
    use std::sync::atomic::Ordering;

    fn test_config() -> EmitterConfig {
        EmitterConfig {
            batch_size: 2,
            flush_interval: Duration::from_secs(60), // 测试走 notify/stop，不靠 interval
            max_queue: 10,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        }
    }

    fn audit_log(marker: &str) -> AuditLog {
        AuditLog::new(AuditAction::Login, ResourceType::User, true)
            .with_user_id(Some(marker.into()))
    }

    fn emitter(sink: Arc<FakeSink>) -> Emitter {
        Emitter::with_config(sink, test_config())
    }

    #[tokio::test]
    async fn emit_only_queues_until_flush_is_triggered() {
        let sink = Arc::new(FakeSink::default());
        let emitter = emitter(sink.clone());

        emitter.emit(&audit_log("a"));
        assert_eq!(emitter.queued(), 1);
        assert_eq!(sink.call_count(), 0);

        emitter.emit(&audit_log("b"));
        assert_eq!(sink.call_count(), 0); // emit 纯入队：不 start/stop 就不发送

        emitter.stop().await;
        let batches = sink.batches();
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[0][0].user_id.as_deref(), Some("a"));
        assert_eq!(batches[0][1].user_id.as_deref(), Some("b"));
        assert_eq!(emitter.queued(), 0);
    }

    #[tokio::test]
    async fn queue_overflow_drops_oldest_and_counts() {
        let sink = Arc::new(FakeSink::default());
        let emitter = Emitter::with_config(
            sink.clone(),
            EmitterConfig {
                batch_size: 4, // 低于队列内容量不触发 notify
                max_queue: 2,
                ..test_config()
            },
        );

        emitter.emit(&audit_log("first"));
        emitter.emit(&audit_log("second"));
        emitter.emit(&audit_log("third"));
        assert_eq!(emitter.queued(), 2);
        assert_eq!(emitter.dropped_total(), 1);

        // stop 的最终 flush 只含未丢的两条，最旧的 first 已被丢
        emitter.stop().await;
        let batches = sink.batches();
        assert_eq!(batches.len(), 1);
        let markers: Vec<_> = batches[0]
            .iter()
            .map(|e| e.user_id.clone().unwrap())
            .collect();
        assert_eq!(markers, vec!["second".to_owned(), "third".to_owned()]);
        assert_eq!(emitter.queued(), 0);
    }

    #[tokio::test]
    async fn failed_send_requeues_batch_in_order() {
        let sink = Arc::new(FakeSink::default());
        sink.fail_next.store(1, Ordering::SeqCst);
        let emitter = emitter(sink.clone());
        emitter.start();

        emitter.emit(&audit_log("a"));
        emitter.emit(&audit_log("b")); // 触发 flush → 失败 → 按原序回队
                                       // 第一次失败 + 1ms 退避后重试成功（attempts=2）→ 队列已清空
        eventually(|| sink.attempts() >= 2).await;
        assert_eq!(sink.call_count(), 1);

        emitter.emit(&audit_log("c"));
        emitter.emit(&audit_log("d")); // 重新达到 batch_size → 再触发
        eventually(|| sink.call_count() >= 2).await;
        let batches = sink.batches();
        let markers = |batch: &[WireEvent]| -> Vec<String> {
            batch.iter().map(|e| e.user_id.clone().unwrap()).collect()
        };
        assert_eq!(markers(&batches[0]), vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(markers(&batches[1]), vec!["c".to_owned(), "d".to_owned()]);
        assert_eq!(emitter.queued(), 0);
        emitter.stop().await;
    }

    #[tokio::test]
    async fn stop_flushes_remaining_without_start() {
        let sink = Arc::new(FakeSink::default());
        let emitter = emitter(sink.clone());
        emitter.emit(&audit_log("only"));
        emitter.stop().await;
        assert_eq!(sink.call_count(), 1);
        assert_eq!(sink.batches()[0][0].user_id.as_deref(), Some("only"));
    }

    #[tokio::test]
    async fn stop_after_start_is_safe_and_idempotent() {
        let sink = Arc::new(FakeSink::default());
        let emitter = emitter(sink.clone());
        emitter.start();
        emitter.start(); // 幂等
        emitter.emit(&audit_log("x"));
        emitter.stop().await;
        emitter.stop().await; // 幂等
        let total: usize = sink.batches().iter().map(Vec::len).sum();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn invalid_events_are_filtered_not_sent() {
        let sink = Arc::new(FakeSink::default());
        let emitter = emitter(sink.clone());

        emitter.emit(&audit_log("good"));
        // 毒丸：Custom action 129 字节超限——server 全有或全无，必须客户端丢弃
        emitter.emit(&AuditLog::new(
            AuditAction::Custom("x".repeat(129)),
            ResourceType::User,
            true,
        ));
        emitter.stop().await;

        let batches = sink.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].user_id.as_deref(), Some("good"));
        assert_eq!(emitter.queued(), 0);
    }

    #[tokio::test]
    async fn clones_share_queue_and_sink() {
        let sink = Arc::new(FakeSink::default());
        let emitter = emitter(sink.clone());
        let clone = emitter.clone();

        emitter.emit(&audit_log("a"));
        clone.emit(&audit_log("b"));
        emitter.stop().await;

        let total: usize = sink.batches().iter().map(Vec::len).sum();
        assert_eq!(total, 2);
    }
}
