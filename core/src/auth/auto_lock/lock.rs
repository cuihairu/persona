//! 面板流转：手动上/解锁、可用性判定、敏感操作再认证门槛与会话查询。

use std::time::Duration;

use crate::models::AuditAction;

use super::events::{AutoLockEvent, LockReason};
use super::{AutoLockManager, Session};

impl AutoLockManager {
    /// Manually lock a session
    pub async fn lock_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            session_info.session.lock();
            drop(sessions);

            self.emit_event(AutoLockEvent::Locked {
                session_id: session_id.to_string(),
                reason: LockReason::Manual,
            })
            .await;

            self.log_audit_event(session_id, AuditAction::SessionLocked, "Manual lock")
                .await;

            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Unlock a session
    pub async fn unlock_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            session_info.session.unlock();
            session_info.warning_sent = false;
            drop(sessions);

            self.emit_event(AutoLockEvent::Unlocked {
                session_id: session_id.to_string(),
            })
            .await;

            self.log_audit_event(session_id, AuditAction::SessionUnlocked, "Manual unlock")
                .await;

            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Check if a session is valid and not locked
    pub async fn is_session_valid(&self, session_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session_info) = sessions.get(session_id) {
            session_info.session.is_valid() && !self.should_lock_session(&session_info.session)
        } else {
            false
        }
    }

    /// Check if session requires re-authentication for sensitive operations
    pub async fn requires_sensitive_auth(&self, session_id: &str) -> bool {
        let (require_reauth_sensitive, sensitive_timeout_secs) = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                config.base.require_reauth_sensitive,
                config.base.sensitive_operation_timeout_secs,
            )
        };
        if !require_reauth_sensitive {
            return false;
        }

        let sessions = self.sessions.read().await;
        if let Some(session_info) = sessions.get(session_id) {
            session_info
                .session
                .requires_sensitive_reauth(Duration::from_secs(sensitive_timeout_secs))
        } else {
            true // No session = require auth
        }
    }

    /// Get session information
    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|si| si.session.clone())
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(&self, user_id: &str) -> Vec<Session> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|si| si.session.user_id == user_id && si.session.is_valid())
            .map(|si| si.session.clone())
            .collect()
    }
}
