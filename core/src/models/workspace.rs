use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Persona workspace configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// Unique workspace ID
    pub id: Uuid,
    
    /// Workspace root path
    pub path: PathBuf,
    
    /// Workspace name
    pub name: String,
    
    /// Current active identity ID
    pub active_identity_id: Option<Uuid>,
    
    /// Workspace settings
    pub settings: WorkspaceSettings,
    
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Workspace configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    /// Enable encryption for sensitive data
    pub encryption_enabled: bool,
    
    /// Auto-backup interval in hours (0 = disabled)
    pub auto_backup_hours: u32,
    
    /// Maximum number of backups to keep
    pub backup_retention_count: u32,
    
    /// Session timeout in seconds
    pub session_timeout_seconds: u32,
    
    /// Require confirmation for destructive operations
    pub require_confirmation: bool,
    
    /// Default identity type for new identities
    pub default_identity_type: String,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            encryption_enabled: true,
            auto_backup_hours: 24,
            backup_retention_count: 7,
            session_timeout_seconds: 3600,
            require_confirmation: true,
            default_identity_type: "personal".to_string(),
        }
    }
}

impl Workspace {
    /// Create a new workspace
    pub fn new<P: Into<PathBuf>>(path: P, name: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4(),
            path: path.into(),
            name,
            active_identity_id: None,
            settings: WorkspaceSettings::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the last access timestamp
    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }

    /// Switch to a different identity
    pub fn switch_identity(&mut self, identity_id: Uuid) {
        self.active_identity_id = Some(identity_id);
        self.touch();
    }

    /// Clear the active identity
    pub fn clear_active_identity(&mut self) {
        self.active_identity_id = None;
        self.touch();
    }
    
    /// Get the database path for this workspace
    pub fn database_path(&self) -> PathBuf {
        self.path.join("identities.db")
    }
    
    /// Get the config path for this workspace
    pub fn config_path(&self) -> PathBuf {
        self.path.join("config.toml")
    }
    
    /// Get the backup directory path
    pub fn backup_path(&self) -> PathBuf {
        self.path.join("backups")
    }
}