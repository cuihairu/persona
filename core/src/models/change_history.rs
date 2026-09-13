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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChangeHistoryStats {
    pub total_changes: usize,
    pub by_entity_type: HashMap<EntityType, usize>,
    pub by_change_type: HashMap<String, usize>,
    pub by_user: HashMap<String, usize>,
    pub recent_changes: Vec<ChangeHistory>,
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

    #[test]
    fn test_builder_methods_and_metadata() {
        let previous = serde_json::json!({"name": "old"});
        let new = serde_json::json!({"name": "new"});

        let mut history =
            ChangeHistory::new(EntityType::Credential, Uuid::new_v4(), ChangeType::Updated)
                .with_states(Some(previous.clone()), Some(new.clone()))
                .with_version(7)
                .set_reversible(false);

        history.add_metadata("origin".to_string(), "cli".to_string());

        assert_eq!(history.previous_state, Some(previous));
        assert_eq!(history.new_state, Some(new));
        assert_eq!(history.version, 7);
        assert!(!history.is_reversible);
        assert_eq!(history.metadata.get("origin"), Some(&"cli".to_string()));
    }

    #[test]
    fn test_with_states_accepts_none() {
        let history =
            ChangeHistory::new(EntityType::Workspace, Uuid::new_v4(), ChangeType::Deleted)
                .with_states(None, None);

        assert!(history.previous_state.is_none());
        assert!(history.new_state.is_none());
        // Defaults from `new`.
        assert_eq!(history.version, 1);
        assert!(history.is_reversible);
    }

    #[test]
    fn test_entity_type_display_and_parse_all_variants() {
        let types = vec![
            EntityType::Identity,
            EntityType::Credential,
            EntityType::Attachment,
            EntityType::Workspace,
            EntityType::UserAuth,
            EntityType::Config,
        ];

        for entity_type in types {
            let text = entity_type.to_string();
            assert_eq!(text.parse::<EntityType>().unwrap(), entity_type);
        }

        let err = "galaxy".parse::<EntityType>().unwrap_err();
        assert_eq!(err, "Unknown entity type: galaxy");
    }

    #[test]
    fn test_entity_type_hash_keyed_map() {
        let mut counts = std::collections::HashMap::new();
        counts.insert(EntityType::Identity, 3usize);
        counts.insert(EntityType::Config, 1usize);

        assert_eq!(counts.get(&EntityType::Identity), Some(&3));
        assert_eq!(counts.get(&EntityType::Config), Some(&1));
    }

    #[test]
    fn test_change_type_display_and_parse_all_variants() {
        let types = vec![
            ChangeType::Created,
            ChangeType::Updated,
            ChangeType::Deleted,
            ChangeType::Restored,
            ChangeType::Archived,
            ChangeType::Activated,
            ChangeType::Deactivated,
        ];

        for change_type in types {
            let text = change_type.to_string();
            assert_eq!(text.parse::<ChangeType>().unwrap(), change_type);
        }

        let err = "exploded".parse::<ChangeType>().unwrap_err();
        assert_eq!(err, "Unknown change type: exploded");
    }

    #[test]
    fn test_change_history_query_builders() {
        let from = Utc::now();
        let to = from + chrono::Duration::hours(1);

        let query = ChangeHistoryQuery::new()
            .entity_type(EntityType::Credential)
            .entity_id(Uuid::new_v4())
            .change_type(ChangeType::Updated)
            .user("user-9".to_string())
            .date_range(from, to)
            .limit(50)
            .offset(10);

        assert_eq!(query.entity_type, Some(EntityType::Credential));
        assert!(query.entity_id.is_some());
        assert_eq!(query.change_type, Some(ChangeType::Updated));
        assert_eq!(query.user_id, Some("user-9".to_string()));
        assert_eq!(query.from_date, Some(from));
        assert_eq!(query.to_date, Some(to));
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(10));
    }

    #[test]
    fn test_change_history_stats_default() {
        let stats = ChangeHistoryStats::default();
        assert_eq!(stats.total_changes, 0);
        assert!(stats.by_entity_type.is_empty());
        assert!(stats.by_change_type.is_empty());
        assert!(stats.by_user.is_empty());
        assert!(stats.recent_changes.is_empty());
    }

    #[test]
    fn test_change_history_serde_roundtrip() {
        let mut history =
            ChangeHistory::new(EntityType::UserAuth, Uuid::new_v4(), ChangeType::Restored)
                .with_user("admin".to_string())
                .with_states(
                    Some(serde_json::json!({"active": false})),
                    Some(serde_json::json!({"active": true})),
                )
                .with_reason("account recovery".to_string());

        history.add_field_change(
            "active".to_string(),
            "false".to_string(),
            "true".to_string(),
        );
        history.add_metadata("ip".to_string(), "10.0.0.1".to_string());

        let json = serde_json::to_string(&history).unwrap();
        let decoded: ChangeHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, history.id);
        assert_eq!(decoded.entity_type, EntityType::UserAuth);
        assert_eq!(decoded.change_type, ChangeType::Restored);
        assert_eq!(decoded.user_id, Some("admin".to_string()));
        assert_eq!(decoded.reason, Some("account recovery".to_string()));
        assert_eq!(decoded.changes_summary.len(), 1);
        let field = decoded.changes_summary.get("active").unwrap();
        assert_eq!(field.field_name, "active");
        assert_eq!(field.old_value, "false");
        assert_eq!(field.new_value, "true");
        assert_eq!(decoded.version, 1);
        assert!(decoded.is_reversible);
    }
}
