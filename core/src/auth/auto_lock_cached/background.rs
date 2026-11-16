use super::{CachedAutoLockManager, EventCallback, PerformanceMetrics};
use crate::auth::auto_lock::{AutoLockEvent, LockReason};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

impl CachedAutoLockManager {
    /// Start the background monitoring loop using the configured interval.
    pub async fn start_background_monitoring(&self) -> Result<(), String> {
        let interval = Duration::from_secs(self.config.background_check_interval_secs.max(1));
        self.start_background_monitoring_with_interval(interval)
            .await
    }

    /// Start background monitoring with a custom check interval. Each pass
    /// emits a single `LockPending` warning for sessions approaching the
    /// inactivity deadline, then locks expired or idle sessions and reports
    /// `Locked` with the matching reason.
    pub async fn start_background_monitoring_with_interval(
        &self,
        interval: Duration,
    ) -> Result<(), String> {
        let mut task_slot = self.background_task.lock().await;
        if task_slot.is_some() {
            return Ok(()); // already running
        }

        let sessions = Arc::clone(&self.sessions);
        let callbacks = Arc::clone(&self.callbacks);
        let metrics = Arc::clone(&self.performance_metrics);
        let inactivity_timeout = Duration::from_secs(self.config.base.inactivity_timeout_secs);
        let warning_window = Duration::from_secs(self.config.warning_time_secs);
        let enable_warnings = self.config.enable_warnings;
        let interval = interval.max(Duration::from_millis(1));

        let handle = tokio::spawn(async move {
            loop {
                let start = Instant::now();

                let mut pending = Vec::new();
                let mut locked = Vec::new();
                {
                    let mut map = sessions.write().await;
                    for (id, info) in map.iter_mut() {
                        if !info.session.locked && info.session.is_expired() {
                            info.session.lock();
                            locked.push((id.clone(), LockReason::AbsoluteTimeout));
                            continue;
                        }
                        if inactivity_timeout.as_secs() > 0
                            && !info.session.locked
                            && info.session.is_idle(inactivity_timeout)
                        {
                            info.session.lock();
                            locked.push((id.clone(), LockReason::Inactivity));
                            continue;
                        }
                        if enable_warnings
                            && inactivity_timeout > warning_window
                            && !info.warning_sent
                            && info.session.is_idle(inactivity_timeout - warning_window)
                        {
                            info.warning_sent = true;
                            info.last_warning_time = Some(SystemTime::now());
                            let remaining = inactivity_timeout
                                .as_secs()
                                .saturating_sub(info.session.get_idle_seconds());
                            pending.push((id.clone(), remaining));
                        }
                    }
                }

                for (session_id, seconds_remaining) in pending {
                    dispatch_event(
                        &callbacks,
                        AutoLockEvent::LockPending {
                            session_id,
                            seconds_remaining,
                        },
                    )
                    .await;
                }
                for (session_id, reason) in locked {
                    dispatch_event(&callbacks, AutoLockEvent::Locked { session_id, reason }).await;
                }

                record_background_check(&metrics, start.elapsed()).await;

                tokio::time::sleep(interval).await;
            }
        });

        *task_slot = Some(handle);
        Ok(())
    }

    /// Stop the background monitoring loop (no-op when not running).
    pub async fn stop_background_monitoring(&self) {
        if let Some(handle) = self.background_task.lock().await.take() {
            handle.abort();
        }
    }
}

/// Fan an event out to every registered callback (each on its own task).
pub(super) async fn dispatch_event(
    callbacks: &Arc<RwLock<Vec<EventCallback>>>,
    event: AutoLockEvent,
) {
    let callbacks = callbacks.read().await;
    for callback in callbacks.iter() {
        tokio::spawn({
            let callback = callback.clone();
            let event = event.clone();
            async move { callback(event) }
        });
    }
}

/// Record one background check's duration into the shared metrics.
async fn record_background_check(metrics: &Arc<RwLock<PerformanceMetrics>>, duration: Duration) {
    let mut metrics = metrics.write().await;
    metrics.background_checks_performed += 1;

    let time_us = duration.as_micros() as f64;
    let total_checks = metrics.background_checks_performed;

    if total_checks > 1 {
        metrics.background_check_time_us =
            (metrics.background_check_time_us * (total_checks - 1) as f64 + time_us)
                / total_checks as f64;
    } else {
        metrics.background_check_time_us = time_us;
    }
}
