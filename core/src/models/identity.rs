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
