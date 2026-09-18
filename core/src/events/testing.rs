//! Emitter 单测共享辅助（`#[cfg(test)]` 编译，pub(crate) 仅供同 crate 测试）。

use crate::events::emitter::{EventSink, SendReport};
use crate::events::wire::WireEvent;
use crate::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

/// 记录成功批的假 sink：`fail_next` 置 N 时，接下来 N 次调用返回 Err
/// （模拟 server 不可达/5xx），之后恢复正常。
#[derive(Default)]
pub(crate) struct FakeSink {
    attempts: AtomicUsize,
    calls: Mutex<Vec<Vec<WireEvent>>>,
    pub(crate) fail_next: AtomicUsize,
}

#[async_trait::async_trait]
impl EventSink for FakeSink {
    async fn send(&self, events: Vec<WireEvent>) -> Result<SendReport> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail_next.load(Ordering::SeqCst) > 0 {
            self.fail_next.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("fake sink unavailable");
        }
        let accepted = events.len() as u64;
        self.lock_calls().push(events);
        Ok(SendReport {
            accepted,
            duplicates: 0,
        })
    }
}

impl FakeSink {
    /// 总调用次数（含失败）。
    pub(crate) fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    /// 成功送达的批数。
    pub(crate) fn call_count(&self) -> usize {
        self.lock_calls().len()
    }

    /// 成功送达批的快照（批内保持发送顺序）。
    pub(crate) fn batches(&self) -> Vec<Vec<WireEvent>> {
        self.lock_calls().clone()
    }

    fn lock_calls(&self) -> std::sync::MutexGuard<'_, Vec<Vec<WireEvent>>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// 轮询等待条件成立（5000 × 1ms，超时 panic），替代裸 sleep 等后台任务。
pub(crate) async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..5000 {
        if check() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    panic!("eventually: condition not met within 5s");
}
