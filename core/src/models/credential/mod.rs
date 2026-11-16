//! 凭据主实体：`Credential` 行模型与结构化自定义字段附属类型。
//!
//! # 模块布局
//!
//! 枚举与字符串解析在 [`types`]，多类型 payload 与脱敏 Debug、bincode
//! 编解码在 [`payloads`]；此处只留主实体。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

mod payloads;
mod types;

pub use payloads::*;
pub use types::{CredentialType, SecurityLevel};

#[cfg(test)]
mod tests;

/// Core credential structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Unique identifier
    pub id: Uuid,

    /// Identity this credential belongs to
    pub identity_id: Uuid,

    /// Human-readable name
    pub name: String,

    /// Type of credential
    pub credential_type: CredentialType,

    /// Security level
    pub security_level: SecurityLevel,

    /// Website or service URL
    pub url: Option<String>,

    /// Username or account identifier
    pub username: Option<String>,

    /// Encrypted credential data
    pub encrypted_data: Vec<u8>,

    /// Item-level encryption key wrapped by the master key (None for legacy rows)
    pub wrapped_item_key: Option<Vec<u8>>,

    /// Notes about this credential
    pub notes: Option<String>,

    /// Tags for organization
    pub tags: Vec<String>,

    /// Custom metadata
    pub metadata: HashMap<String, String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,

    /// Last accessed timestamp
    pub last_accessed: Option<DateTime<Utc>>,

    /// Whether this credential is active
    pub is_active: bool,

    /// Whether this credential is marked as favorite
    pub is_favorite: bool,
}

/// Structured custom field attached to a credential (1Password parity).
///
/// Stored sealed (per-item key) as one metadata blob — see
/// `crate::custom_fields`; never in the bincode payload, so old
/// ciphertexts stay readable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustomField {
    /// Stable id (uuid string) so edits can address a field
    pub id: String,
    /// User-facing label
    pub label: String,
    /// Field value (for `Concealed` this is a secret)
    pub value: String,
    /// Display/behavior type
    pub field_type: CustomFieldType,
    /// Optional 1Password-style section grouping
    #[serde(default)]
    pub section: Option<String>,
}

/// Custom field type: plain text, hidden (secret) value, or date.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CustomFieldType {
    Text,
    Concealed,
    Date,
}

impl Credential {
    /// Create a new credential
    pub fn new(
        identity_id: Uuid,
        name: String,
        credential_type: CredentialType,
        security_level: SecurityLevel,
        encrypted_data: Vec<u8>,
        wrapped_item_key: Option<Vec<u8>>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            identity_id,
            name,
            credential_type,
            security_level,
            url: None,
            username: None,
            encrypted_data,
            wrapped_item_key,
            notes: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
            last_accessed: None,
            is_active: true,
            is_favorite: false,
        }
    }

    /// Update the modification timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Mark as accessed
    pub fn mark_accessed(&mut self) {
        self.last_accessed = Some(Utc::now());
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.touch();
        }
    }

    /// Remove a tag
    pub fn remove_tag(&mut self, tag: &str) {
        if let Some(pos) = self.tags.iter().position(|t| t == tag) {
            self.tags.remove(pos);
            self.touch();
        }
    }

    /// Set metadata value
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
        self.touch();
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Remove metadata
    pub fn remove_metadata(&mut self, key: &str) {
        if self.metadata.remove(key).is_some() {
            self.touch();
        }
    }
}
