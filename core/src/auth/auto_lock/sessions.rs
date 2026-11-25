//! Session lifecycle and activity timing: session intake and removal,
//! activity and sensitive-activity refresh, sensitive-timeout force-lock,
//! and the grace period.

use std::time::{Duration, SystemTime};

use crate::models::AuditAction;

use super::events::{AutoLockEvent, LockReason};
use super::{AutoLockManager, Session, SessionInfo};

impl AutoLockManager {
    /// Add a new session to manage
    pub async fn add_session(&self, session: Session) -> Result<(), String> {
        let session_id = session.id.clone();
        let user_id = session.user_id.clone();

        // Check concurrent session limit
        let max_concurrent_sessions = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .max_concurrent_sessions;
        {
            let sessions = self.sessions.read().await;
            let user_sessions = sessions
                .values()
                .filter(|s| s.session.user_id == user_id && s.session.is_valid())
                .count();

            if user_sessions >= max_concurrent_sessions {
                return Err(format!(
                    "Maximum concurrent sessions ({max_concurrent_sessions}) exceeded"
                ));
            }
        }

        let session_info = SessionInfo {
            session,
            last_warning_time: None,
            warning_sent: false,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session_info);
        }

        self.emit_event(AutoLockEvent::Activity {
            session_id: session_id.clone(),
        })
        .await;

        Ok(())
    }

    /// Remove a session from management
    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }

    /// Update session activity
    pub async fn update_activity(&self, session_id: &str) -> Result<(), String> {
        let grace_period_secs = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .activity_grace_period_secs;
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            // Apply grace period for rapid successive calls
            let now = SystemTime::now();
            if let Ok(elapsed) = now.duration_since(session_info.session.last_activity) {
                if elapsed.as_secs() < grace_period_secs {
                    return Ok(());
                }
            }

            session_info.session.touch();
            session_info.warning_sent = false; // Reset warning on activity
            drop(sessions);

            self.emit_event(AutoLockEvent::Activity {
                session_id: session_id.to_string(),
            })
            .await;

            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Refresh sensitive activity and activity timing, and clear a session
    /// lock caused by the sensitive timeout (**without doing any force-lock
    /// evaluation**).
    ///
    /// Intended for the token authentication surface only (called per-request
    /// by the Connect middleware): presenting a scoped token counts as
    /// re-authentication (revocable, expiring, audited), so the desktop
    /// semantics of `force_lock_sensitive` — "sensitive operation timeout →
    /// lock the session and demand re-authentication" — do not apply to the
    /// token surface. Otherwise an unattended serve would get a permanent 500
    /// on its first ciphertext read 5 minutes after login, with no
    /// re-authentication path (observed: `fleet-apply --check` hit
    /// `update_sensitive_activity`).
    pub async fn refresh_sensitive(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            session_info.session.touch_sensitive();
            session_info.session.unlock(); // Clear sensitive-timeout lock + refresh activity
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Test helper: backdate the session's sensitive activity time to before
    /// `ago` (visible to same-crate unit tests only).
    #[cfg(test)]
    pub(crate) async fn backdate_sensitive_for_test(&self, session_id: &str, ago: Duration) {
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            session_info.session.backdate_sensitive_for_test(ago);
        }
    }

    /// Update sensitive operation activity
    pub async fn update_sensitive_activity(&self, session_id: &str) -> Result<(), String> {
        let (force_lock_sensitive, sensitive_timeout_secs) = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                config.force_lock_sensitive,
                config.base.sensitive_operation_timeout_secs,
            )
        };
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            // Force lock if enabled and a stale sensitive timestamp exists.
            // A session with no sensitive history (freshly unlocked) has not
            // timed out - its first sensitive operation just refreshes the
            // timer instead of locking it out.
            if force_lock_sensitive && session_info.session.has_sensitive_history() {
                let timeout = Duration::from_secs(sensitive_timeout_secs);
                if session_info.session.requires_sensitive_reauth(timeout) {
                    session_info.session.lock();
                    drop(sessions);

                    self.emit_event(AutoLockEvent::Locked {
                        session_id: session_id.to_string(),
                        reason: LockReason::SecurityViolation,
                    })
                    .await;

                    self.log_audit_event(
                        session_id,
                        AuditAction::SessionLocked,
                        "Sensitive operation timeout",
                    )
                    .await;

                    return Err("Session locked due to sensitive operation timeout".to_string());
                }
            }

            // Only update if not locked
            session_info.session.touch_sensitive();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }
}
