use super::{session::AutoLockConfig, Session};
use crate::models::{AuditAction, ResourceType};
use crate::storage::{AuditLogRepository, Repository};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Auto-lock event types for callbacks
#[derive(Debug, Clone, PartialEq)]
pub enum AutoLockEvent {
    /// Session will be locked soon (warning)
    LockPending {
        session_id: String,
        seconds_remaining: u64,
    },
    /// Session has been locked
    Locked {
        session_id: String,
        reason: LockReason,
    },
    /// Session has been unlocked
    Unlocked { session_id: String },
    /// Activity detected
    Activity { session_id: String },
}

/// Reasons for auto-locking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LockReason {
    /// Inactivity timeout reached
    Inactivity,
    /// Absolute session timeout reached
    AbsoluteTimeout,
    /// Manual lock
    Manual,
    /// Security policy violation
    SecurityViolation,
    /// System shutdown
    SystemShutdown,
}

/// Enhanced auto-lock configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAutoLockConfig {
    /// Base auto-lock configuration
    #[serde(flatten)]
    pub base: AutoLockConfig,

    /// Warning time before lock (seconds)
    #[serde(default = "default_warning_time")]
    pub warning_time_secs: u64,

    /// Maximum number of concurrent sessions per user
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,

    /// Enable lock warnings
    #[serde(default)]
    pub enable_warnings: bool,

    /// Force lock on sensitive operations after timeout
    #[serde(default)]
    pub force_lock_sensitive: bool,

    /// Activity grace period - small grace period for rapid operations
    #[serde(default = "default_grace_period")]
    pub activity_grace_period_secs: u64,

    /// Background check interval
    #[serde(default = "default_check_interval")]
    pub background_check_interval_secs: u64,
}

fn default_warning_time() -> u64 {
    60
} // 1 minute warning
fn default_max_sessions() -> usize {
    5
}
fn default_grace_period() -> u64 {
    5
} // 5 seconds grace period
fn default_check_interval() -> u64 {
    30
} // Check every 30 seconds

impl Default for EnhancedAutoLockConfig {
    fn default() -> Self {
        Self {
            base: AutoLockConfig::default(),
            warning_time_secs: default_warning_time(),
            max_concurrent_sessions: default_max_sessions(),
            enable_warnings: true,
            force_lock_sensitive: false,
            activity_grace_period_secs: default_grace_period(),
            background_check_interval_secs: default_check_interval(),
        }
    }
}

impl From<AutoLockConfig> for EnhancedAutoLockConfig {
    fn from(base: AutoLockConfig) -> Self {
        Self {
            base,
            ..Default::default()
        }
    }
}

/// Callback type for auto-lock events
pub type AutoLockCallback = Arc<dyn Fn(AutoLockEvent) + Send + Sync>;

/// Enhanced auto-lock manager with advanced features
pub struct AutoLockManager {
    config: EnhancedAutoLockConfig,
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    callbacks: Arc<RwLock<Vec<AutoLockCallback>>>,
    audit_repo: Option<AuditLogRepository>,
    background_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    current_user: Arc<RwLock<Option<Uuid>>>,
}

/// Extended session information for auto-lock management
#[derive(Debug, Clone)]
struct SessionInfo {
    session: Session,
    last_warning_time: Option<SystemTime>,
    warning_sent: bool,
    created_at: SystemTime,
}

impl AutoLockManager {
    /// Create a new auto-lock manager
    pub fn new(config: EnhancedAutoLockConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            callbacks: Arc::new(RwLock::new(Vec::new())),
            audit_repo: None,
            background_task: Arc::new(Mutex::new(None)),
            current_user: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with basic auto-lock config
    pub fn with_basic_config(config: AutoLockConfig) -> Self {
        Self::new(config.into())
    }

    /// Set audit repository for logging
    pub fn with_audit_repo(mut self, audit_repo: AuditLogRepository) -> Self {
        self.audit_repo = Some(audit_repo);
        self
    }

    /// Register a callback for auto-lock events
    pub async fn register_callback(&self, callback: AutoLockCallback) {
        let mut callbacks = self.callbacks.write().await;
        callbacks.push(callback);
    }

    /// Add a new session to manage
    pub async fn add_session(&self, session: Session) -> Result<(), String> {
        let session_id = session.id.clone();
        let user_id = session.user_id.clone();

        // Check concurrent session limit
        {
            let sessions = self.sessions.read().await;
            let user_sessions = sessions
                .values()
                .filter(|s| s.session.user_id == user_id && s.session.is_valid())
                .count();

            if user_sessions >= self.config.max_concurrent_sessions {
                return Err(format!(
                    "Maximum concurrent sessions ({}) exceeded",
                    self.config.max_concurrent_sessions
                ));
            }
        }

        let session_info = SessionInfo {
            session,
            last_warning_time: None,
            warning_sent: false,
            created_at: SystemTime::now(),
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
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            // Apply grace period for rapid successive calls
            let now = SystemTime::now();
            if let Ok(elapsed) = now.duration_since(session_info.session.last_activity) {
                if elapsed.as_secs() < self.config.activity_grace_period_secs {
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

    /// Update sensitive operation activity
    pub async fn update_sensitive_activity(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            // Force lock if enabled and sensitive timeout is reached
            if self.config.force_lock_sensitive {
                let timeout =
                    Duration::from_secs(self.config.base.sensitive_operation_timeout_secs);
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
        if !self.config.base.require_reauth_sensitive {
            return false;
        }

        let sessions = self.sessions.read().await;
        if let Some(session_info) = sessions.get(session_id) {
            session_info
                .session
                .requires_sensitive_reauth(Duration::from_secs(
                    self.config.base.sensitive_operation_timeout_secs,
                ))
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

    /// Get auto-lock statistics
    pub async fn get_statistics(&self) -> AutoLockStatistics {
        let sessions = self.sessions.read().await;
        let total_sessions = sessions.len();
        let active_sessions = sessions.values().filter(|si| si.session.is_valid()).count();
        let locked_sessions = sessions.values().filter(|si| si.session.locked).count();
        let idle_sessions = sessions
            .values()
            .filter(|si| {
                si.session.is_valid()
                    && si.session.is_idle(Duration::from_secs(
                        self.config.base.inactivity_timeout_secs,
                    ))
            })
            .count();

        AutoLockStatistics {
            total_sessions,
            active_sessions,
            locked_sessions,
            idle_sessions,
            max_concurrent_sessions: self.config.max_concurrent_sessions,
        }
    }

    /// Start background monitoring task
    pub async fn start_background_monitoring(&self) {
        let interval = Duration::from_secs(self.config.background_check_interval_secs);
        let sessions = self.sessions.clone();
        let callbacks = self.callbacks.clone();
        let config = self.config.clone();
        let audit_repo = self.audit_repo.clone();

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick(); // Skip first tick

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
                            let lock_reason = if session_info
                                .session
                                .is_idle(Duration::from_secs(config.base.inactivity_timeout_secs))
                            {
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

                            // Log audit event if repository available
                            if let Some(ref repo) = audit_repo {
                                let _ = repo
                                    .create(&crate::models::AuditLog::new(
                                        AuditAction::SessionLocked,
                                        ResourceType::Session,
                                        true,
                                    ))
                                    .await;
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

    /// Set current user context
    pub async fn set_current_user(&self, user_id: Uuid) {
        let mut current_user = self.current_user.write().await;
        *current_user = Some(user_id);
    }

    /// Clear current user context
    pub async fn clear_current_user(&self) {
        let mut current_user = self.current_user.write().await;
        *current_user = None;
    }

    /// Force cleanup of expired sessions
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();

        sessions.retain(|_, session_info| {
            !session_info.session.is_expired()
                || (session_info.session.locked && session_info.session.get_idle_seconds() > 3600)
        });

        initial_count - sessions.len()
    }

    // Private helper methods

    fn should_lock_session(&self, session: &Session) -> bool {
        // Check inactivity timeout
        if self.config.base.inactivity_timeout_secs > 0 {
            let inactivity = Duration::from_secs(self.config.base.inactivity_timeout_secs);
            if session.is_idle(inactivity) {
                return true;
            }
        }

        // Check absolute timeout
        if self.config.base.absolute_timeout_secs > 0 {
            let absolute = Duration::from_secs(self.config.base.absolute_timeout_secs);
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
            let current_user = self.current_user.read().await;
            let mut log = crate::models::AuditLog::new(action, ResourceType::Session, true)
                .with_session_id(Some(session_id.to_string()))
                .with_details(Some(reason.to_string()));

            if let Some(user_id) = *current_user {
                log = log.with_user_id(Some(user_id.to_string()));
            }

            let _ = repo.create(&log).await;
        }
    }
}

// Helper functions for background task

fn should_send_warning(config: &EnhancedAutoLockConfig, session_info: &SessionInfo) -> bool {
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

fn get_seconds_until_lock(config: &EnhancedAutoLockConfig, session_info: &SessionInfo) -> u64 {
    if config.base.inactivity_timeout_secs > 0 {
        let idle_seconds = session_info.session.get_idle_seconds();
        if idle_seconds < config.base.inactivity_timeout_secs {
            return config.base.inactivity_timeout_secs - idle_seconds;
        }
    }
    0
}

/// Auto-lock statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoLockStatistics {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub locked_sessions: usize,
    pub idle_sessions: usize,
    pub max_concurrent_sessions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::AutoLockConfig;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_auto_lock_manager_creation() {
        let config = AutoLockConfig::default();
        let manager = AutoLockManager::with_basic_config(config);

        let stats = manager.get_statistics().await;
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.active_sessions, 0);
    }

    #[tokio::test]
    async fn test_session_management() {
        let config = AutoLockConfig::default();
        let manager = AutoLockManager::with_basic_config(config);

        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();

        // Add session
        assert!(manager.add_session(session).await.is_ok());
        assert!(manager.is_session_valid(&session_id).await);

        // Update activity
        assert!(manager.update_activity(&session_id).await.is_ok());

        // Lock session
        assert!(manager.lock_session(&session_id).await.is_ok());
        assert!(!manager.is_session_valid(&session_id).await);

        // Unlock session
        assert!(manager.unlock_session(&session_id).await.is_ok());
        assert!(manager.is_session_valid(&session_id).await);

        // Remove session
        manager.remove_session(&session_id).await;
        assert!(!manager.is_session_valid(&session_id).await);
    }

    #[tokio::test]
    async fn test_callback_registration() {
        let config = AutoLockConfig::default();
        let manager = AutoLockManager::with_basic_config(config);

        let callback_count = Arc::new(AtomicU32::new(0));
        let callback_count_clone = callback_count.clone();

        let callback: AutoLockCallback = Arc::new(move |_| {
            callback_count_clone.fetch_add(1, Ordering::Relaxed);
        });

        manager.register_callback(callback).await;

        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();

        manager.add_session(session).await.unwrap();
        manager.lock_session(&session_id).await.unwrap();

        // Give some time for async callbacks
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(callback_count.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn test_concurrent_session_limit() {
        let mut config = EnhancedAutoLockConfig::default();
        config.max_concurrent_sessions = 2;

        let manager = AutoLockManager::new(config);

        let session1 = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session2 = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session3 = Session::new("user123".to_string(), Duration::from_secs(3600));

        // Should be able to add 2 sessions
        assert!(manager.add_session(session1).await.is_ok());
        assert!(manager.add_session(session2).await.is_ok());

        // Third session should fail
        assert!(manager.add_session(session3).await.is_err());
    }

    #[tokio::test]
    async fn test_sensitive_activity_timeout() {
        let mut config = EnhancedAutoLockConfig::default();
        config.base.sensitive_operation_timeout_secs = 1;
        config.force_lock_sensitive = true;

        let manager = AutoLockManager::new(config);

        let mut session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();

        // First perform a sensitive operation to set the timestamp
        session.touch_sensitive();
        manager.add_session(session).await.unwrap();

        // Wait for sensitive timeout
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Sensitive activity should now fail
        assert!(manager
            .update_sensitive_activity(&session_id)
            .await
            .is_err());
        assert!(!manager.is_session_valid(&session_id).await);
    }

    #[tokio::test]
    async fn test_requires_sensitive_auth_flag() {
        let mut base = AutoLockConfig::default();
        base.require_reauth_sensitive = true;
        base.sensitive_operation_timeout_secs = 1;
        let mut config = EnhancedAutoLockConfig::default();
        config.base = base;

        let manager = AutoLockManager::new(config);
        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();

        manager.add_session(session).await.unwrap();

        // Without any sensitive activity recorded we should require re-auth.
        assert!(manager.requires_sensitive_auth(&session_id).await);

        // Update sensitive activity to reset timer.
        manager
            .update_sensitive_activity(&session_id)
            .await
            .unwrap();
        assert!(!manager.requires_sensitive_auth(&session_id).await);

        // Wait past the sensitive timeout to trigger re-auth again.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(manager.requires_sensitive_auth(&session_id).await);
    }
}
