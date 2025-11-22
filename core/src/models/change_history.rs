use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Change history entry for tracking modifications
/// 用于追踪所有数据变更的历史记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeHistory {
    /// Unique identifier
    pub id: Uuid,

    /// Type of entity that changed
    pub entity_type: EntityType,

    /// ID of the entity that changed
    pub entity_id: Uuid,

    /// Type of change
    pub change_type: ChangeType,

    /// User who made the change
    pub user_id: Option<String>,

    /// Previous state (JSON snapshot)
    pub previous_state: Option<serde_json::Value>,

    /// New state (JSON snapshot)
    pub new_state: Option<serde_json::Value>,

    /// Changes summary (field-level diff)
    pub changes_summary: HashMap<String, FieldChange>,

    /// Reason for change (optional)
    pub reason: Option<String>,

    /// IP address of the change origin
    pub ip_address: Option<String>,

    /// User agent
    pub user_agent: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Timestamp of the change
    pub timestamp: DateTime<Utc>,

    /// Version number
    pub version: u32,

    /// Is this change reversible
    pub is_reversible: bool,
}

impl ChangeHistory {
    /// Create a new change history entry
    pub fn new(entity_type: EntityType, entity_id: Uuid, change_type: ChangeType) -> Self {
        Self {
            id: Uuid::new_v4(),
            entity_type,
            entity_id,
            change_type,
            user_id: None,
            previous_state: None,
            new_state: None,
            changes_summary: HashMap::new(),
            reason: None,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
            timestamp: Utc::now(),
            version: 1,
            is_reversible: true,
        }
    }

    /// Set the user who made the change
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set previous and new states
    pub fn with_states(
        mut self,
        previous: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
    ) -> Self {
        self.previous_state = previous;
        self.new_state = new;
        self
    }

    /// Add a field change
    pub fn add_field_change(&mut self, field: String, old: String, new: String) {
        let field_name = field.clone();
        self.changes_summary.insert(
            field,
            FieldChange {
                field_name,
                old_value: old,
                new_value: new,
            },
        );
    }

    /// Set change reason
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Set version number
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set reversibility
    pub fn set_reversible(mut self, reversible: bool) -> Self {
        self.is_reversible = reversible;
        self
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Type of entity that can have history
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Identity,
    Credential,
    Attachment,
    Workspace,
    UserAuth,
    Config,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityType::Identity => write!(f, "identity"),
            EntityType::Credential => write!(f, "credential"),
            EntityType::Attachment => write!(f, "attachment"),
            EntityType::Workspace => write!(f, "workspace"),
            EntityType::UserAuth => write!(f, "user_auth"),
            EntityType::Config => write!(f, "config"),
        }
    }
}

impl std::str::FromStr for EntityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "identity" => Ok(EntityType::Identity),
            "credential" => Ok(EntityType::Credential),
            "attachment" => Ok(EntityType::Attachment),
            "workspace" => Ok(EntityType::Workspace),
            "user_auth" => Ok(EntityType::UserAuth),
            "config" => Ok(EntityType::Config),
            _ => Err(format!("Unknown entity type: {}", s)),
        }
    }
}

/// Type of change
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Created,
    Updated,
    Deleted,
    Restored,
    Archived,
    Activated,
    Deactivated,
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeType::Created => write!(f, "created"),
            ChangeType::Updated => write!(f, "updated"),
            ChangeType::Deleted => write!(f, "deleted"),
            ChangeType::Restored => write!(f, "restored"),
            ChangeType::Archived => write!(f, "archived"),
            ChangeType::Activated => write!(f, "activated"),
            ChangeType::Deactivated => write!(f, "deactivated"),
        }
    }
}

impl std::str::FromStr for ChangeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "created" => Ok(ChangeType::Created),
            "updated" => Ok(ChangeType::Updated),
            "deleted" => Ok(ChangeType::Deleted),
            "restored" => Ok(ChangeType::Restored),
            "archived" => Ok(ChangeType::Archived),
            "activated" => Ok(ChangeType::Activated),
            "deactivated" => Ok(ChangeType::Deactivated),
            _ => Err(format!("Unknown change type: {}", s)),
        }
    }
}

/// Field-level change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field_name: String,
    pub old_value: String,
    pub new_value: String,
}

/// Query options for change history
#[derive(Debug, Clone, Default)]
pub struct ChangeHistoryQuery {
    pub entity_type: Option<EntityType>,
    pub entity_id: Option<Uuid>,
    pub change_type: Option<ChangeType>,
    pub user_id: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl ChangeHistoryQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entity_type(mut self, entity_type: EntityType) -> Self {
        self.entity_type = Some(entity_type);
        self
    }

    pub fn entity_id(mut self, entity_id: Uuid) -> Self {
        self.entity_id = Some(entity_id);
        self
    }

    pub fn change_type(mut self, change_type: ChangeType) -> Self {
        self.change_type = Some(change_type);
        self
    }

    pub fn user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn date_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.from_date = Some(from);
        self.to_date = Some(to);
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Statistics for change history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeHistoryStats {
    pub total_changes: usize,
    pub by_entity_type: HashMap<EntityType, usize>,
    pub by_change_type: HashMap<String, usize>,
    pub by_user: HashMap<String, usize>,
    pub recent_changes: Vec<ChangeHistory>,
}

impl Default for ChangeHistoryStats {
    fn default() -> Self {
        Self {
            total_changes: 0,
            by_entity_type: HashMap::new(),
            by_change_type: HashMap::new(),
            by_user: HashMap::new(),
            recent_changes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_change_history() {
        let entity_id = Uuid::new_v4();
        let history = ChangeHistory::new(EntityType::Identity, entity_id, ChangeType::Created)
            .with_user("user123".to_string())
            .with_reason("Initial creation".to_string());

        assert_eq!(history.entity_type, EntityType::Identity);
        assert_eq!(history.entity_id, entity_id);
        assert_eq!(history.change_type, ChangeType::Created);
        assert_eq!(history.user_id, Some("user123".to_string()));
    }

    #[test]
    fn test_field_change() {
        let mut history =
            ChangeHistory::new(EntityType::Credential, Uuid::new_v4(), ChangeType::Updated);

        history.add_field_change(
            "password".to_string(),
            "old_pass".to_string(),
            "new_pass".to_string(),
        );

        assert_eq!(history.changes_summary.len(), 1);
        assert!(history.changes_summary.contains_key("password"));
    }

    #[test]
    fn test_entity_type_parsing() {
        assert_eq!(
            "identity".parse::<EntityType>().unwrap(),
            EntityType::Identity
        );
        assert_eq!(
            "credential".parse::<EntityType>().unwrap(),
            EntityType::Credential
        );
    }

    #[test]
    fn test_change_type_display() {
        assert_eq!(ChangeType::Created.to_string(), "created");
        assert_eq!(ChangeType::Updated.to_string(), "updated");
    }
}
