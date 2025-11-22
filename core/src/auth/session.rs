use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// User session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: String,

    /// User ID associated with this session
    pub user_id: String,

    /// Session creation time
    pub created_at: SystemTime,

    /// Last activity time
    pub last_activity: SystemTime,

    /// Session expiration time
    pub expires_at: SystemTime,

    /// Last sensitive operation time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sensitive_op: Option<SystemTime>,

    /// Whether the session is currently locked
    #[serde(default)]
    pub locked: bool,

    /// Session metadata
    pub metadata: SessionMetadata,
}

/// Session metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Client IP address
    pub client_ip: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Session permissions
    pub permissions: Vec<String>,
}

impl Session {
    /// Create a new session
    pub fn new(user_id: String, timeout: Duration) -> Self {
        let now = SystemTime::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            created_at: now,
            last_activity: now,
            expires_at: now + timeout,
            last_sensitive_op: None,
            locked: false,
            metadata: SessionMetadata {
                client_ip: None,
                user_agent: None,
                permissions: Vec::new(),
            },
        }
    }

    /// Check if the session is still valid
    pub fn is_valid(&self) -> bool {
        !self.locked && SystemTime::now() < self.expires_at
    }

    /// Check if the session is expired (time-based only)
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Check if session is idle (no activity for given duration)
    pub fn is_idle(&self, inactivity_duration: Duration) -> bool {
        if let Ok(elapsed) = SystemTime::now().duration_since(self.last_activity) {
            elapsed > inactivity_duration
        } else {
            false
        }
    }

    /// Update the last activity time
    pub fn touch(&mut self) {
        self.last_activity = SystemTime::now();
    }

    /// Update the last sensitive operation time
    pub fn touch_sensitive(&mut self) {
        self.last_sensitive_op = Some(SystemTime::now());
        self.touch(); // Also update general activity
    }

    /// Check if sensitive operation requires re-authentication
    pub fn requires_sensitive_reauth(&self, timeout: Duration) -> bool {
        if let Some(last_sensitive) = self.last_sensitive_op {
            if let Ok(elapsed) = SystemTime::now().duration_since(last_sensitive) {
                return elapsed > timeout;
            }
        }
        // No sensitive operation recorded - require auth
        true
    }

    /// Lock the session
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the session and reset timers
    pub fn unlock(&mut self) {
        self.locked = false;
        self.touch();
    }

    /// Extend the session expiration
    pub fn extend(&mut self, duration: Duration) {
        self.expires_at = SystemTime::now() + duration;
        self.touch();
    }

    /// Check if the session has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.metadata.permissions.contains(&permission.to_string())
    }

    /// Add a permission to the session
    pub fn add_permission(&mut self, permission: String) {
        if !self.metadata.permissions.contains(&permission) {
            self.metadata.permissions.push(permission);
        }
    }

    /// Remove a permission from the session
    pub fn remove_permission(&mut self, permission: &str) {
        self.metadata.permissions.retain(|p| p != permission);
    }

    /// Get idle time in seconds
    pub fn get_idle_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.last_activity)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Get session lifetime in seconds
    pub fn get_lifetime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.created_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Auto-lock configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoLockConfig {
    /// Inactivity timeout in seconds (0 = disabled)
    #[serde(default = "default_inactivity_timeout")]
    pub inactivity_timeout_secs: u64,

    /// Absolute session timeout in seconds (0 = disabled)
    #[serde(default = "default_absolute_timeout")]
    pub absolute_timeout_secs: u64,

    /// Whether to require re-authentication for sensitive operations
    #[serde(default)]
    pub require_reauth_sensitive: bool,

    /// Sensitive operation timeout in seconds
    #[serde(default = "default_sensitive_timeout")]
    pub sensitive_operation_timeout_secs: u64,
}

fn default_inactivity_timeout() -> u64 {
    900 // 15 minutes
}

fn default_absolute_timeout() -> u64 {
    3600 // 1 hour
}

fn default_sensitive_timeout() -> u64 {
    300 // 5 minutes
}

impl Default for AutoLockConfig {
    fn default() -> Self {
        Self {
            inactivity_timeout_secs: default_inactivity_timeout(),
            absolute_timeout_secs: default_absolute_timeout(),
            require_reauth_sensitive: false,
            sensitive_operation_timeout_secs: default_sensitive_timeout(),
        }
    }
}

/// Session manager for tracking and managing sessions with auto-lock
pub struct SessionManager {
    sessions: Arc<RwLock<std::collections::HashMap<String, Session>>>,
    config: AutoLockConfig,
}

impl SessionManager {
    /// Create a new session manager with default configuration
    pub fn new() -> Self {
        Self::with_config(AutoLockConfig::default())
    }

    /// Create a new session manager with custom configuration
    pub fn with_config(config: AutoLockConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            config,
        }
    }

    /// Create a new session
    pub async fn create_session(&self, user_id: String) -> Session {
        let timeout = Duration::from_secs(if self.config.absolute_timeout_secs > 0 {
            self.config.absolute_timeout_secs
        } else {
            3600 // Default 1 hour
        });

        let session = Session::new(user_id, timeout);
        let session_id = session.id.clone();

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session.clone());

        session
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Update session activity
    pub async fn touch(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            // Check if session should be auto-locked
            self.check_and_lock(session)?;
            session.touch();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Update sensitive operation timestamp
    pub async fn touch_sensitive(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            self.check_and_lock(session)?;
            session.touch_sensitive();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Lock a session
    pub async fn lock_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.lock();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Unlock a session
    pub async fn unlock_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.unlock();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    /// Remove a session
    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }

    /// Check if session is valid
    pub async fn is_valid(&self, session_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            session.is_valid() && !self.should_auto_lock(session)
        } else {
            false
        }
    }

    /// Check if session requires sensitive operation re-authentication
    pub async fn requires_sensitive_auth(&self, session_id: &str) -> bool {
        if !self.config.require_reauth_sensitive {
            return false;
        }

        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            session.requires_sensitive_reauth(Duration::from_secs(
                self.config.sensitive_operation_timeout_secs,
            ))
        } else {
            true // No session = require auth
        }
    }

    /// Clean up expired and locked sessions
    pub async fn cleanup(&self) {
        let mut sessions = self.sessions.write().await;

        // Collect session IDs to remove
        let to_remove: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.is_expired() || (s.locked && s.get_idle_seconds() > 3600))
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_remove {
            sessions.remove(&id);
        }
    }

    /// Get total number of active sessions
    pub async fn active_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.values().filter(|s| s.is_valid()).count()
    }

    // Internal: Check if session should be auto-locked
    fn should_auto_lock(&self, session: &Session) -> bool {
        // Check inactivity timeout
        if self.config.inactivity_timeout_secs > 0 {
            let inactivity = Duration::from_secs(self.config.inactivity_timeout_secs);
            if session.is_idle(inactivity) {
                return true;
            }
        }

        // Check absolute timeout
        if self.config.absolute_timeout_secs > 0 {
            let absolute = Duration::from_secs(self.config.absolute_timeout_secs);
            if session.get_lifetime_seconds() > absolute.as_secs() {
                return true;
            }
        }

        false
    }

    // Internal: Check and lock session if needed
    fn check_and_lock(&self, session: &mut Session) -> Result<(), String> {
        if self.should_auto_lock(session) {
            session.lock();
            return Err("Session automatically locked due to inactivity or timeout".to_string());
        }
        Ok(())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        assert_eq!(session.user_id, "user123");
        assert!(!session.locked);
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_lock_unlock() {
        let mut session = Session::new("user123".to_string(), Duration::from_secs(3600));

        session.lock();
        assert!(session.locked);
        assert!(!session.is_valid());

        session.unlock();
        assert!(!session.locked);
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_touch_sensitive() {
        let mut session = Session::new("user123".to_string(), Duration::from_secs(3600));
        assert!(session.last_sensitive_op.is_none());

        session.touch_sensitive();
        assert!(session.last_sensitive_op.is_some());
    }

    #[test]
    fn test_session_requires_sensitive_reauth() {
        let mut session = Session::new("user123".to_string(), Duration::from_secs(3600));

        // Should require auth initially
        assert!(session.requires_sensitive_reauth(Duration::from_secs(300)));

        // After touch_sensitive, should not require auth
        session.touch_sensitive();
        assert!(!session.requires_sensitive_reauth(Duration::from_secs(300)));
    }

    #[tokio::test]
    async fn test_session_manager_creation() {
        let manager = SessionManager::new();
        let session = manager.create_session("user123".to_string()).await;

        assert_eq!(session.user_id, "user123");
        assert!(manager.is_valid(&session.id).await);
    }

    #[tokio::test]
    async fn test_session_manager_touch() {
        let manager = SessionManager::new();
        let session = manager.create_session("user123".to_string()).await;

        assert!(manager.touch(&session.id).await.is_ok());
        assert!(manager.is_valid(&session.id).await);
    }

    #[tokio::test]
    async fn test_session_manager_lock_unlock() {
        let manager = SessionManager::new();
        let session = manager.create_session("user123".to_string()).await;

        manager.lock_session(&session.id).await.ok();
        assert!(!manager.is_valid(&session.id).await);

        manager.unlock_session(&session.id).await.ok();
        assert!(manager.is_valid(&session.id).await);
    }
}
