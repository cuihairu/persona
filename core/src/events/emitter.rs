//! Emitter: audit event reporter with synchronous enqueue, background batched flush, and exponential backoff.

use crate::events::wire::{build_batch, limits, WireEvent};
use crate::models::AuditLog;
use crate::Result;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Notify;

/// Result of a single report (aligned with the server 202 response body).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendReport {
    pub accepted: u64,
    pub duplicates: u64,
}

/// Reporting destination. It only ever receives pre-validated, legal
/// batches; `Err` means the whole batch went unacknowledged and the Emitter
/// is responsible for backing off and retrying.
#[async_trait]
pub trait EventSink: Send + Sync + 'static {
    async fn send(&self, events: Vec<WireEvent>) -> Result<SendReport>;
}

/// Emitter behavior parameters (defaults in [`EmitterConfig::default`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitterConfig {
    /// Reaching this queue size immediately wakes a flush (clamped to the server's 500-per-batch cap).
    pub batch_size: usize,
    /// Fallback flush period (the primary trigger is the Notify; see the flush loop comments).
    pub flush_interval: Duration,
    /// In-memory queue cap; on overflow the oldest entries are dropped and counted into dropped_total.
    pub max_queue: usize,
    /// Initial backoff duration after a send failure, doubling on each subsequent failure.
    pub initial_backoff: Duration,
    /// Backoff ceiling; reset back to initial_backoff after any batch succeeds.
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

/// Audit event reporter: the local sqlite audit database is the durable
/// source of record, this is only best-effort async replication — a
/// process crash loses the unflushed in-memory batch and nothing is
/// replayed (no durable outbox).
///
/// Clones share the same queue and background task; reporting never blocks
/// audit writes (emit is purely synchronous enqueue).
#[derive(Clone)]
pub struct Emitter {
    inner: Arc<EmitterInner>,
}

struct EmitterInner {
    sink: Arc<dyn EventSink>,
    config: EmitterConfig,
    queue: Mutex<VecDeque<AuditLog>>,
    /// Wakes the flush when the queue reaches batch_size. Note that Notify permits coalesce:
    /// drain must be exhaustive (see `drain_and_send`), otherwise a coalesced wake would leave events stranded.
    notify: Notify,
    /// Background task slot (prevents duplicate starts). std Mutex: the guard does not span an await.
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    dropped_total: AtomicU64,
}

impl std::fmt::Debug for Emitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Arc<dyn EventSink> has no Debug: print only the observability surface, not the sink.
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
        // Server batches are ≤500 (server MAX_BATCH_SIZE); an over-large setting is clamped rather than panicking.
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

    /// Synchronous enqueue (can be called directly in async context; no internal await or blocking).
    /// On a full queue the oldest is dropped with a warning and a count: reporting is
    /// best-effort and must never block audit writes.
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

    /// Start the background flush task (idempotent: ignored if already running). The caller is responsible for [`Emitter::stop`].
    pub fn start(&self) {
        let mut task = self.lock_task();
        if task.is_some() {
            return;
        }
        // Weak: the background task exits by itself once all Emitters are dropped, so there is no self-referential leak.
        let inner = Arc::downgrade(&self.inner);
        *task = Some(tokio::spawn(async move { flush_loop(inner).await }));
    }

    /// Stop reporting: abort the background task plus a best-effort final flush (discard + warn on failure).
    /// If never started, only the final flush runs; repeated calls are idempotent.
    ///
    /// Loss window: an aborted task may already have taken a batch it has not
    /// sent yet (up to batch_size), and this batch cannot be recovered by
    /// stop; reporting is best-effort and the local sqlite audit database is the source of record.
    pub async fn stop(&self) {
        let handle = self.lock_task().take();
        if let Some(handle) = handle {
            handle.abort();
        }
        if let Err(error) = drain_and_send(&self.inner).await {
            tracing::warn!(%error, "final event flush failed; dropping remaining queue");
        }
    }

    /// Current queue length (for observability).
    pub fn queued(&self) -> usize {
        self.lock_queue().len()
    }

    /// Total number of oldest events dropped due to a full queue (for observability).
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

/// Body of the flush task. Exits once all Emitters are dropped (the Weak goes dead).
async fn flush_loop(inner: std::sync::Weak<EmitterInner>) {
    let Some(inner) = inner.upgrade() else {
        return;
    };
    let mut backoff = inner.config.initial_backoff;
    let mut ticker = tokio::time::interval(inner.config.flush_interval);
    ticker.tick().await; // the interval's first tick completes immediately — consume it (following the auto_lock convention)

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
        // Notify permit coalescing plus select's random branch never loses events: permits
        // live inside the Notify until consumed, and drain is exhaustive.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = inner.notify.notified() => {}
        }
    }
}

/// Exhaustive drain: send the queue until empty (sliced by batch_size). On a
/// send failure the whole batch is requeued at the front in its original
/// order and Err is returned (preserving idempotency keys and observable
/// order; the lock only lives across the synchronous take/requeue scope, not
/// an await).
async fn drain_and_send(inner: &EmitterInner) -> Result<()> {
    while !inner.is_empty() {
        let batch = inner.take_batch();
        let (events, rejected) = build_batch(&batch);
        for (index, issues) in rejected {
            tracing::warn!(index, ?issues, "dropping invalid audit event before send");
        }
        if events.is_empty() {
            continue; // the whole slice is a poison pill: drop it and move on to the next slice
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

    /// A batch that failed to send goes back to the front in its original order (reversed push_front);
    /// it is mutually exclusive with emit's push_back under the lock, so old events still go out
    /// before new ones.
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
            flush_interval: Duration::from_secs(60), // tests go through notify/stop, not the interval
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
        assert_eq!(sink.call_count(), 0); // emit only enqueues: nothing is sent without start/stop

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
                batch_size: 4, // does not reach the queue size, so no notify
                max_queue: 2,
                ..test_config()
            },
        );

        emitter.emit(&audit_log("first"));
        emitter.emit(&audit_log("second"));
        emitter.emit(&audit_log("third"));
        assert_eq!(emitter.queued(), 2);
        assert_eq!(emitter.dropped_total(), 1);

        // The final flush on stop only holds the two undropped entries; the oldest one, first, was dropped
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
        emitter.emit(&audit_log("b")); // triggers flush → failure → requeue in original order
                                       // retry after the first failure + 1ms backoff succeeds (attempts=2) → queue drained
        eventually(|| sink.attempts() >= 2).await;
        assert_eq!(sink.call_count(), 1);

        emitter.emit(&audit_log("c"));
        emitter.emit(&audit_log("d")); // batch_size is reached again → triggers again
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
        emitter.start(); // idempotent
        emitter.emit(&audit_log("x"));
        emitter.stop().await;
        emitter.stop().await; // idempotent
        let total: usize = sink.batches().iter().map(Vec::len).sum();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn invalid_events_are_filtered_not_sent() {
        let sink = Arc::new(FakeSink::default());
        let emitter = emitter(sink.clone());

        emitter.emit(&audit_log("good"));
        // Poison pill: a Custom action at 129 bytes exceeds the limit — the server is all-or-nothing,
        // so the client must discard it
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

    /// A reporting destination that always fails (for the stop final-flush failure path).
    struct FailingSink;

    #[async_trait::async_trait]
    impl EventSink for FailingSink {
        async fn send(&self, _events: Vec<WireEvent>) -> Result<SendReport> {
            Err(anyhow::anyhow!("sink down"))
        }
    }

    // Debug rendering goes through the queued()/dropped_total() readings; Emitter::new is a
    // convenience entry point for with_config's default parameters.
    #[tokio::test]
    async fn debug_and_convenience_new_render_queue_state() {
        let sink = Arc::new(FakeSink::default());
        let emitter = Emitter::new(sink.clone());
        let text = format!("{emitter:?}");
        assert!(text.contains("Emitter"), "{text}");

        emitter.emit(&audit_log("dbg"));
        let text = format!("{emitter:?}");
        assert!(text.contains("queued: 1"), "{text}");

        emitter.stop().await;
        assert_eq!(emitter.queued(), 0);
        assert_eq!(sink.batches().len(), 1);
    }

    // Stop's final flush fails: warn and give up only (the local sqlite audit database is the
    // source of record); never panic. The failed batch stays in the queue, observability still
    // works, and repeated stops are idempotent.
    #[tokio::test]
    async fn stop_with_failing_sink_still_stops_and_keeps_queue() {
        let emitter = Emitter::with_config(Arc::new(FailingSink), test_config());
        emitter.emit(&audit_log("lost"));
        emitter.stop().await;
        assert_eq!(emitter.queued(), 1, "failed batch must stay queued");
        emitter.stop().await; // a second stop is still clean
    }
}
