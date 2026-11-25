//! Credential type enums and string parsing: `Display` / `FromStr` round-trip with the storage-layer strings.

use serde::{Deserialize, Serialize};

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
    /// Encrypted secure note (1Password parity; body in `CredentialData::SecureNote`)
    SecureNote,
    /// Personal identity information (1Password「Identity」: name, address, documents)
    Identity,
    /// Software license keys (1Password「Software License」)
    SoftwareLicense,
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
            CredentialType::SecureNote => write!(f, "SecureNote"),
            CredentialType::Identity => write!(f, "Identity"),
            CredentialType::SoftwareLicense => write!(f, "SoftwareLicense"),
            CredentialType::Custom(name) => write!(f, "{}", name),
        }
    }
}

impl std::str::FromStr for CredentialType {
    type Err = String;

    /// Aligned with [`Display`](std::fmt::Display) / storage-layer string round-trip: unknown
    /// strings fall into `Custom` (same strategy as `row_to_credential`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Password" => CredentialType::Password,
            "CryptoWallet" => CredentialType::CryptoWallet,
            "SshKey" => CredentialType::SshKey,
            "ApiKey" => CredentialType::ApiKey,
            "BankCard" => CredentialType::BankCard,
            "GameAccount" => CredentialType::GameAccount,
            "ServerConfig" => CredentialType::ServerConfig,
            "Certificate" => CredentialType::Certificate,
            "TwoFactor" => CredentialType::TwoFactor,
            "SecureNote" => CredentialType::SecureNote,
            "Identity" => CredentialType::Identity,
            "SoftwareLicense" => CredentialType::SoftwareLicense,
            custom => CredentialType::Custom(custom.to_string()),
        })
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

impl std::str::FromStr for SecurityLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Critical" => Ok(SecurityLevel::Critical),
            "High" => Ok(SecurityLevel::High),
            "Medium" => Ok(SecurityLevel::Medium),
            "Low" => Ok(SecurityLevel::Low),
            other => Err(format!("Unknown security level: {other}")),
        }
    }
}
