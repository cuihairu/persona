use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

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
            metadata: SessionMetadata {
                client_ip: None,
                user_agent: None,
                permissions: Vec::new(),
            },
        }
    }
    
    /// Check if the session is still valid
    pub fn is_valid(&self) -> bool {
        SystemTime::now() < self.expires_at
    }
    
    /// Update the last activity time
    pub fn touch(&mut self) {
        self.last_activity = SystemTime::now();
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
}