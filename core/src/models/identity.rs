use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Digital identity representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier for the identity
    pub id: Uuid,

    /// Human-readable name
    pub name: String,

    /// Identity type (personal, work, social, etc.)
    pub identity_type: IdentityType,

    /// Optional description
    pub description: Option<String>,

    /// Primary email address
    pub email: Option<String>,

    /// Phone number
    pub phone: Option<String>,

    /// SSH public key
    pub ssh_key: Option<String>,

    /// GPG public key
    pub gpg_key: Option<String>,

    /// Tags for categorization
    pub tags: Vec<String>,

    /// Custom attributes
    pub attributes: HashMap<String, String>,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last modification timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Whether this identity is currently active
    pub is_active: bool,

    /// 旅行模式标记：travel mode 进入时该身份的数据随身份一起移出本设备
    /// （打包进加密 sidecar 后从库中删除），退出时原样恢复
    #[serde(default)]
    pub travel_marked: bool,
}

/// Types of digital identities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IdentityType {
    Personal,
    Work,
    Social,
    Financial,
    Gaming,
    Custom(String),
}

impl std::str::FromStr for IdentityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Personal" => Ok(IdentityType::Personal),
            "Work" => Ok(IdentityType::Work),
            "Social" => Ok(IdentityType::Social),
            "Financial" => Ok(IdentityType::Financial),
            "Gaming" => Ok(IdentityType::Gaming),
            other => Ok(IdentityType::Custom(other.to_string())),
        }
    }
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityType::Personal => write!(f, "Personal"),
            IdentityType::Work => write!(f, "Work"),
            IdentityType::Social => write!(f, "Social"),
            IdentityType::Financial => write!(f, "Financial"),
            IdentityType::Gaming => write!(f, "Gaming"),
            IdentityType::Custom(name) => write!(f, "{}", name),
        }
    }
}

impl Identity {
    /// Create a new identity
    pub fn new(name: String, identity_type: IdentityType) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            identity_type,
            description: None,
            email: None,
            phone: None,
            ssh_key: None,
            gpg_key: None,
            tags: Vec::new(),
            attributes: HashMap::new(),
            created_at: now,
            updated_at: now,
            is_active: true,
            travel_marked: false,
        }
    }

    /// Update the identity's modification timestamp
    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }

    /// Add a tag to the identity
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.touch();
        }
    }

    /// Remove a tag from the identity
    pub fn remove_tag(&mut self, tag: &str) {
        if let Some(pos) = self.tags.iter().position(|t| t == tag) {
            self.tags.remove(pos);
            self.touch();
        }
    }

    /// Set a custom attribute
    pub fn set_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
        self.touch();
    }

    /// Get a custom attribute
    pub fn get_attribute(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)
    }

    /// Remove a custom attribute
    pub fn remove_attribute(&mut self, key: &str) {
        if self.attributes.remove(key).is_some() {
            self.touch();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_type_parse_and_display_roundtrip() {
        let parsed: IdentityType = "Personal".parse().unwrap();
        assert_eq!(parsed, IdentityType::Personal);
        assert_eq!(parsed.to_string(), "Personal");

        let parsed: IdentityType = "Work".parse().unwrap();
        assert_eq!(parsed, IdentityType::Work);

        let parsed: IdentityType = "CustomType".parse().unwrap();
        assert_eq!(parsed, IdentityType::Custom("CustomType".to_string()));
        assert_eq!(parsed.to_string(), "CustomType");
    }

    #[test]
    fn identity_tag_operations_are_idempotent() {
        let mut identity = Identity::new("Alice".to_string(), IdentityType::Personal);
        identity.tags.clear();

        identity.add_tag("dev".to_string());
        identity.add_tag("dev".to_string());
        assert_eq!(identity.tags, vec!["dev".to_string()]);

        identity.remove_tag("dev");
        assert!(identity.tags.is_empty());

        // Removing non-existent tag should not panic.
        identity.remove_tag("missing");
    }

    #[test]
    fn identity_attributes_roundtrip() {
        let mut identity = Identity::new("Alice".to_string(), IdentityType::Personal);
        identity.attributes.clear();

        let old_updated = identity.updated_at;
        identity.set_attribute("team".to_string(), "core".to_string());
        assert_eq!(
            identity.get_attribute("team").map(|s| s.as_str()),
            Some("core")
        );
        assert!(identity.updated_at >= old_updated);

        identity.remove_attribute("team");
        assert!(identity.get_attribute("team").is_none());

        // Removing an attribute that is already gone must be a no-op.
        let before = identity.updated_at;
        identity.remove_attribute("team");
        assert!(identity.get_attribute("team").is_none());
        assert_eq!(identity.updated_at, before);
    }

    #[test]
    fn identity_type_parse_and_display_remaining_variants() {
        for name in ["Work", "Social", "Financial", "Gaming"] {
            let parsed: IdentityType = name.parse().unwrap();
            assert_eq!(parsed.to_string(), name);
        }

        // Custom roundtrips an empty name too.
        let parsed: IdentityType = "".parse().unwrap();
        assert_eq!(parsed, IdentityType::Custom(String::new()));
    }

    #[test]
    fn identity_new_sets_defaults() {
        let identity = Identity::new("Bob".to_string(), IdentityType::Work);

        assert_eq!(identity.name, "Bob");
        assert_eq!(identity.identity_type, IdentityType::Work);
        assert!(identity.description.is_none());
        assert!(identity.email.is_none());
        assert!(identity.phone.is_none());
        assert!(identity.ssh_key.is_none());
        assert!(identity.gpg_key.is_none());
        assert!(identity.tags.is_empty());
        assert!(identity.attributes.is_empty());
        assert_eq!(identity.created_at, identity.updated_at);
        assert!(identity.is_active);
    }

    #[test]
    fn identity_touch_refreshes_updated_at() {
        let mut identity = Identity::new("Bob".to_string(), IdentityType::Work);

        let before = identity.updated_at;
        identity.touch();
        assert!(identity.updated_at >= before);
    }

    #[test]
    fn identity_serde_roundtrip() {
        let mut identity = Identity::new("Alice".to_string(), IdentityType::Financial);
        identity.description = Some("primary".to_string());
        identity.email = Some("alice@example.com".to_string());
        identity.phone = Some("+86 138 0000 0000".to_string());
        identity.ssh_key = Some("ssh-ed25519 AAAA".to_string());
        identity.gpg_key = Some("gpg-key".to_string());
        identity.tags = vec!["core".to_string()];
        identity.set_attribute("team".to_string(), "core".to_string());

        let json = serde_json::to_string(&identity).unwrap();
        let decoded: Identity = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, identity.id);
        assert_eq!(decoded.identity_type, IdentityType::Financial);
        assert_eq!(decoded.email, identity.email);
        assert_eq!(decoded.tags, identity.tags);
        assert_eq!(decoded.attributes, identity.attributes);
    }
}
