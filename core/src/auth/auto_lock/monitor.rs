//! 后台监控任务：周期巡检触发警告与自动上锁，以及任务所需的
//! 纯判定 helper（warning / auto-lock / 距上锁秒数）。

use std::time::{Duration, SystemTime};

use crate::models::AuditAction;
use crate::storage::Repository;

use super::config::EnhancedAutoLockConfig;
use super::events::{AutoLockEvent, LockReason};
use super::session_audit_log;
use super::{AutoLockManager, SessionInfo};

impl AutoLockManager {
    /// Start background monitoring task
    pub async fn start_background_monitoring(&self) {
        let (interval, config) = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                Duration::from_secs(config.background_check_interval_secs),
                config.clone(),
            )
        };
        let sessions = self.sessions.clone();
        let callbacks = self.callbacks.clone();
        let audit_repo = self.audit_repo.clone();
        let event_emitter = self.event_emitter.clone();
        let current_user = self.current_user.clone();

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // Skip first tick

            loop {
                ticker.tick().await;

                let sessions_to_check: Vec<String> = {
                    let sessions_read = sessions.read().await;
                    sessions_read.keys().cloned().collect()
                };

                for session_id in sessions_to_check {
                    let mut sessions_write = sessions.write().await;
                    if let Some(session_info) = sessions_write.get_mut(&session_id) {
                        let should_warn = should_send_warning(&config, session_info);
                        let should_lock = should_auto_lock(&config, session_info);

                        if should_warn && !session_info.warning_sent {
                            let seconds_remaining = get_seconds_until_lock(&config, session_info);

                            // Emit warning event
                            let callbacks_read = callbacks.read().await;
                            for callback in callbacks_read.iter() {
                                tokio::spawn({
                                    let callback = callback.clone();
                                    let event = AutoLockEvent::LockPending {
                                        session_id: session_id.clone(),
                                        seconds_remaining,
                                    };
                                    async move { callback(event) }
                                });
                            }

                            session_info.warning_sent = true;
                            session_info.last_warning_time = Some(SystemTime::now());
                        }

                        if should_lock {
                            // Only report Inactivity when the idle check is
                            // actually enabled (0 disables it).
                            let lock_reason = if config.base.inactivity_timeout_secs > 0
                                && session_info.session.is_idle(Duration::from_secs(
                                    config.base.inactivity_timeout_secs,
                                )) {
                                LockReason::Inactivity
                            } else {
                                LockReason::AbsoluteTimeout
                            };

                            session_info.session.lock();
                            drop(sessions_write);

                            // Emit lock event
                            let callbacks_read = callbacks.read().await;
                            for callback in callbacks_read.iter() {
                                tokio::spawn({
                                    let callback = callback.clone();
                                    let event = AutoLockEvent::Locked {
                                        session_id: session_id.clone(),
                                        reason: lock_reason.clone(),
                                    };
                                    async move { callback(event) }
                                });
                            }

                            // Log audit event if repository available（带全
                            // session 上下文，与 helper 三处一致；写库后尽力上报）
                            if let Some(ref repo) = audit_repo {
                                let user = *current_user.read().await;
                                let lock_details = match lock_reason {
                                    LockReason::Inactivity => "Inactivity timeout",
                                    LockReason::AbsoluteTimeout => "Absolute timeout",
                                    _ => "Auto lock",
                                };
                                let log = session_audit_log(
                                    &session_id,
                                    user,
                                    AuditAction::SessionLocked,
                                    lock_details,
                                );
                                let _ = repo.create(&log).await;
                                if let Some(ref emitter) = event_emitter {
                                    emitter.emit(&log);
                                }
                            }
                        }
                    }
                }
            }
        });

        let mut task = self.background_task.lock().await;
        *task = Some(handle);
    }

    /// Stop background monitoring task
    pub async fn stop_background_monitoring(&self) {
        let mut task = self.background_task.lock().await;
        if let Some(handle) = task.take() {
            handle.abort();
        }
    }
}
// Helper functions for background task

pub(super) fn should_send_warning(
    config: &EnhancedAutoLockConfig,
    session_info: &SessionInfo,
) -> bool {
    if !config.enable_warnings || config.warning_time_secs == 0 {
        return false;
    }

    let warning_threshold = Duration::from_secs(
        config
            .base
            .inactivity_timeout_secs
            .saturating_sub(config.warning_time_secs),
    );

    if session_info.session.is_idle(warning_threshold) && !session_info.warning_sent {
        return true;
    }

    false
}

fn should_auto_lock(config: &EnhancedAutoLockConfig, session_info: &SessionInfo) -> bool {
    // Check inactivity timeout
    if config.base.inactivity_timeout_secs > 0 {
        let inactivity = Duration::from_secs(config.base.inactivity_timeout_secs);
        if session_info.session.is_idle(inactivity) {
            return true;
        }
    }

    // Check absolute timeout
    if config.base.absolute_timeout_secs > 0 {
        let absolute = Duration::from_secs(config.base.absolute_timeout_secs);
        if session_info.session.get_lifetime_seconds() > absolute.as_secs() {
            return true;
        }
    }

    false
}

pub(super) fn get_seconds_until_lock(
    config: &EnhancedAutoLockConfig,
    session_info: &SessionInfo,
) -> u64 {
    if config.base.inactivity_timeout_secs > 0 {
        let idle_seconds = session_info.session.get_idle_seconds();
        if idle_seconds < config.base.inactivity_timeout_secs {
            return config.base.inactivity_timeout_secs - idle_seconds;
        }
    }
    0
}
