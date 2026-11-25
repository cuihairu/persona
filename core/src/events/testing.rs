//! Helpers shared by Emitter unit tests (compiled under `#[cfg(test)]`, pub(crate) for this crate's tests only).

use crate::events::emitter::{EventSink, SendReport};
use crate::events::wire::WireEvent;
use crate::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

/// Fake sink that records successful batches: with `fail_next` set to N,
/// the next N calls return Err (simulating an unreachable server / 5xx),
/// then behaviour returns to normal.
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
    /// Total number of calls (including failures).
    pub(crate) fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    /// Number of batches delivered successfully.
    pub(crate) fn call_count(&self) -> usize {
        self.lock_calls().len()
    }

    /// Snapshot of the successfully delivered batches (send order preserved within a batch).
    pub(crate) fn batches(&self) -> Vec<Vec<WireEvent>> {
        self.lock_calls().clone()
    }

    fn lock_calls(&self) -> std::sync::MutexGuard<'_, Vec<Vec<WireEvent>>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Poll until the condition holds (5000 × 1ms, panics on timeout) instead of bare sleeping while waiting on background tasks.
pub(crate) async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..5000 {
        if check() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    panic!("eventually: condition not met within 5s");
}
