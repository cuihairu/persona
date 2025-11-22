use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Different types of credentials that can be stored
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CredentialType {
    /// Username and password combination
    Password,
    /// Cryptocurrency wallet information
    CryptoWallet,
    /// SSH key pairs
    SshKey,
    /// API keys and tokens
    ApiKey,
    /// Bank card information
    BankCard,
    /// Game account credentials
    GameAccount,
    /// Server configuration
    ServerConfig,
    /// Digital certificates
    Certificate,
    /// Two-factor authentication codes
    TwoFactor,
    /// Custom credential type
    Custom(String),
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::Password => write!(f, "Password"),
            CredentialType::CryptoWallet => write!(f, "CryptoWallet"),
            CredentialType::SshKey => write!(f, "SshKey"),
            CredentialType::ApiKey => write!(f, "ApiKey"),
            CredentialType::BankCard => write!(f, "BankCard"),
            CredentialType::GameAccount => write!(f, "GameAccount"),
            CredentialType::ServerConfig => write!(f, "ServerConfig"),
            CredentialType::Certificate => write!(f, "Certificate"),
            CredentialType::TwoFactor => write!(f, "TwoFactor"),
            CredentialType::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Security level for credentials
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityLevel {
    /// Critical security (crypto wallets, bank info)
    Critical,
    /// High security (passwords, SSH keys)
    High,
    /// Medium security (game accounts, social media)
    Medium,
    /// Low security (subscription services)
    Low,
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Critical => write!(f, "Critical"),
            SecurityLevel::High => write!(f, "High"),
            SecurityLevel::Medium => write!(f, "Medium"),
            SecurityLevel::Low => write!(f, "Low"),
        }
    }
}

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

/// Specific credential data structures for different types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCredentialData {
    pub password: String,
    pub email: Option<String>,
    pub security_questions: Vec<SecurityQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityQuestion {
    pub question: String,
    pub answer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoWalletData {
    pub wallet_type: String,
    pub mnemonic_phrase: Option<String>,
    pub private_key: Option<String>,
    pub public_key: String,
    pub address: String,
    pub network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyData {
    pub private_key: String,
    pub public_key: String,
    pub key_type: String, // rsa, ed25519, etc.
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyData {
    pub api_key: String,
    pub api_secret: Option<String>,
    pub token: Option<String>,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankCardData {
    pub card_number: String,
    pub cardholder_name: String,
    pub expiry_date: String,
    pub cvv: String,
    pub bank_name: String,
    pub card_type: String, // visa, mastercard, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigData {
    pub hostname: String,
    pub ip_address: Option<String>,
    pub port: u16,
    pub protocol: String, // ssh, rdp, vnc, etc.
    pub username: String,
    pub password: Option<String>,
    pub ssh_key_id: Option<Uuid>,
    pub additional_config: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorData {
    pub secret_key: String,
    pub issuer: String,
    pub account_name: String,
    pub algorithm: String, // SHA1, SHA256, etc.
    pub digits: u8,
    pub period: u32,
}

/// Helper enum for strongly-typed credential data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialData {
    Password(PasswordCredentialData),
    CryptoWallet(CryptoWalletData),
    SshKey(SshKeyData),
    ApiKey(ApiKeyData),
    BankCard(BankCardData),
    ServerConfig(ServerConfigData),
    TwoFactor(TwoFactorData),
    Raw(Vec<u8>),
}

impl CredentialData {
    /// Serialize credential data to bytes for encryption
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize credential data from bytes after decryption
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}
