use std::collections::HashMap;
use std::sync::{Arc, RwLock as SyncRwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};

use crate::events::Emitter;
use crate::models::{AuditAction, ResourceType};
use crate::storage::{AuditLogRepository, Repository};
use uuid::Uuid;

use super::Session;

mod config;
mod events;
mod lock;
mod manager;
mod monitor;
mod sessions;

pub use config::EnhancedAutoLockConfig;
pub use events::{AutoLockCallback, AutoLockEvent, LockReason};
pub use manager::AutoLockStatistics;

#[cfg(test)]
use monitor::{get_seconds_until_lock, should_send_warning};

#[cfg(test)]
mod tests;

/// Enhanced auto-lock manager with advanced features
pub struct AutoLockManager {
    /// Configuration snapshot. The lock exists to support runtime updates
    /// (`update_base_config`): the service layer pushes command-line settings
    /// in here, and the manager must not be rebuilt — a rebuild would lose the
    /// tracked sessions, background task, and callbacks. All reads are short
    /// synchronous critical sections, so a std lock suffices (never held
    /// across an await).
    config: SyncRwLock<EnhancedAutoLockConfig>,
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    callbacks: Arc<RwLock<Vec<AutoLockCallback>>>,
    audit_repo: Option<AuditLogRepository>,
    /// Audit event emitter (None = no reporting). Injected via propagation
    /// from [`crate::PersonaService::set_event_emitter`] — the service is the
    /// single injection point; hosts (desktop/CLI) only deal with the service.
    event_emitter: Option<Emitter>,
    background_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    current_user: Arc<RwLock<Option<Uuid>>>,
}

/// Extended session information for auto-lock management
#[derive(Debug, Clone)]
struct SessionInfo {
    session: Session,
    last_warning_time: Option<SystemTime>,
    warning_sent: bool,
}

impl AutoLockManager {
    // Private helper methods

    fn should_lock_session(&self, session: &Session) -> bool {
        let config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Check inactivity timeout
        if config.base.inactivity_timeout_secs > 0 {
            let inactivity = Duration::from_secs(config.base.inactivity_timeout_secs);
            if session.is_idle(inactivity) {
                return true;
            }
        }

        // Check absolute timeout
        if config.base.absolute_timeout_secs > 0 {
            let absolute = Duration::from_secs(config.base.absolute_timeout_secs);
            if session.get_lifetime_seconds() > absolute.as_secs() {
                return true;
            }
        }

        false
    }

    async fn emit_event(&self, event: AutoLockEvent) {
        let callbacks = self.callbacks.read().await;
        for callback in callbacks.iter() {
            tokio::spawn({
                let callback = callback.clone();
                let event = event.clone();
                async move { callback(event) }
            });
        }
    }

    async fn log_audit_event(&self, session_id: &str, action: AuditAction, reason: &str) {
        if let Some(ref repo) = self.audit_repo {
            let current_user = *self.current_user.read().await;
            let log = session_audit_log(session_id, current_user, action, reason);
            let _ = repo.create(&log).await;
            // Write to the local database first, then best-effort reporting
            // (same ordering as PersonaService::log_audit)
            if let Some(ref emitter) = self.event_emitter {
                emitter.emit(&log);
            }
        }
    }
}
/// Build an audit log row with session context (shared by the helper and the
/// background monitoring task — the latter is a 'static closure that cannot
/// reference `self`, so only the data this function needs is cloned into it).
fn session_audit_log(
    session_id: &str,
    current_user: Option<Uuid>,
    action: AuditAction,
    reason: &str,
) -> crate::models::AuditLog {
    let mut log = crate::models::AuditLog::new(action, ResourceType::Session, true)
        .with_session_id(Some(session_id.to_string()))
        .with_details(Some(reason.to_string()));
    if let Some(user_id) = current_user {
        log = log.with_user_id(Some(user_id.to_string()));
    }
    log
}
