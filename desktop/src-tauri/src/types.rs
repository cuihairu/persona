use persona_core::*;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio::sync::Mutex;

/// Application state that holds the Persona service
pub struct AppState {
    pub service: Mutex<Option<PersonaService>>,
    pub db_path: Mutex<Option<String>>,
    pub agent_handle: Mutex<Option<JoinHandle<()>>>,
}

/// Response structure for API calls
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

/// Initialization request
#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub master_password: String,
    pub db_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StartAgentRequest {
    pub master_password: Option<String>,
}

/// Identity creation request
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    pub name: String,
    pub identity_type: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

/// Identity update request
#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    pub id: String,
    pub name: String,
    pub identity_type: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Credential creation request
#[derive(Debug, Deserialize)]
pub struct CreateCredentialRequest {
    pub identity_id: String,
    pub name: String,
    pub credential_type: String,
    pub security_level: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub credential_data: CredentialDataRequest,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum CredentialDataRequest {
    Password {
        password: String,
        email: Option<String>,
        security_questions: Vec<SecurityQuestionRequest>,
    },
    CryptoWallet {
        wallet_type: String,
        mnemonic_phrase: Option<String>,
        private_key: Option<String>,
        public_key: String,
        address: String,
        network: String,
    },
    SshKey {
        private_key: String,
        public_key: String,
        key_type: String,
        passphrase: Option<String>,
    },
    ApiKey {
        api_key: String,
        api_secret: Option<String>,
        token: Option<String>,
        permissions: Vec<String>,
        expires_at: Option<String>,
    },
    TwoFactor {
        secret_key: String,
        issuer: String,
        account_name: String,
        algorithm: String,
        digits: u8,
        period: u32,
    },
    Raw {
        data: Vec<u8>,
    },
}

#[derive(Debug, Deserialize)]
pub struct SecurityQuestionRequest {
    pub question: String,
    pub answer: String,
}

/// Serializable versions of core types for frontend
#[derive(Debug, Serialize)]
pub struct SerializableIdentity {
    pub id: String,
    pub name: String,
    pub identity_type: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssh_key: Option<String>,
    pub gpg_key: Option<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub is_active: bool,
}

#[derive(Debug, Serialize)]
pub struct SerializableCredential {
    pub id: String,
    pub identity_id: String,
    pub name: String,
    pub credential_type: String,
    pub security_level: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_accessed: Option<String>,
    pub is_active: bool,
    pub is_favorite: bool,
}

#[derive(Debug, Serialize)]
pub struct SerializableCredentialData {
    pub credential_type: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct SshAgentStatus {
    pub running: bool,
    pub socket_path: Option<String>,
    pub pid: Option<u32>,
    pub key_count: Option<usize>,
    pub state_dir: String,
}

#[derive(Debug, Serialize)]
pub struct SshKeySummary {
    pub id: String,
    pub identity_id: String,
    pub identity_name: String,
    pub name: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Identity> for SerializableIdentity {
    fn from(identity: Identity) -> Self {
        Self {
            id: identity.id.to_string(),
            name: identity.name,
            identity_type: identity.identity_type.to_string(),
            description: identity.description,
            email: identity.email,
            phone: identity.phone,
            ssh_key: identity.ssh_key,
            gpg_key: identity.gpg_key,
            tags: identity.tags,
            created_at: identity.created_at.to_rfc3339(),
            updated_at: identity.updated_at.to_rfc3339(),
            is_active: identity.is_active,
        }
    }
}

impl From<Credential> for SerializableCredential {
    fn from(credential: Credential) -> Self {
        Self {
            id: credential.id.to_string(),
            identity_id: credential.identity_id.to_string(),
            name: credential.name,
            credential_type: credential.credential_type.to_string(),
            security_level: credential.security_level.to_string(),
            url: credential.url,
            username: credential.username,
            notes: credential.notes,
            tags: credential.tags,
            created_at: credential.created_at.to_rfc3339(),
            updated_at: credential.updated_at.to_rfc3339(),
            last_accessed: credential.last_accessed.map(|dt| dt.to_rfc3339()),
            is_active: credential.is_active,
            is_favorite: credential.is_favorite,
        }
    }
}

/// Helper function to convert credential data for serialization
pub fn credential_data_to_json(data: &CredentialData) -> serde_json::Value {
    match data {
        CredentialData::Password(pwd_data) => serde_json::json!({
            "type": "Password",
            "password": pwd_data.password,
            "email": pwd_data.email,
            "security_questions": pwd_data.security_questions
        }),
        CredentialData::CryptoWallet(wallet_data) => serde_json::json!({
            "type": "CryptoWallet",
            "wallet_type": wallet_data.wallet_type,
            "public_key": wallet_data.public_key,
            "address": wallet_data.address,
            "network": wallet_data.network
        }),
        CredentialData::SshKey(ssh_data) => serde_json::json!({
            "type": "SshKey",
            "public_key": ssh_data.public_key,
            "key_type": ssh_data.key_type
        }),
        CredentialData::ApiKey(api_data) => serde_json::json!({
            "type": "ApiKey",
            "permissions": api_data.permissions,
            "expires_at": api_data.expires_at
        }),
        CredentialData::BankCard(card_data) => serde_json::json!({
            "type": "BankCard",
            "cardholder_name": card_data.cardholder_name,
            "expiry_date": card_data.expiry_date,
            "bank_name": card_data.bank_name,
            "card_type": card_data.card_type,
            "last4": card_data.card_number.chars().filter(|c| c.is_ascii_digit()).collect::<String>().chars().rev().take(4).collect::<String>().chars().rev().collect::<String>(),
        }),
        CredentialData::ServerConfig(server_data) => serde_json::json!({
            "type": "ServerConfig",
            "hostname": server_data.hostname,
            "ip_address": server_data.ip_address,
            "port": server_data.port,
            "protocol": server_data.protocol,
            "username": server_data.username,
            "ssh_key_id": server_data.ssh_key_id,
            "additional_config": server_data.additional_config
        }),
        CredentialData::TwoFactor(tf_data) => serde_json::json!({
            "type": "TwoFactor",
            "issuer": tf_data.issuer,
            "account_name": tf_data.account_name,
            "algorithm": tf_data.algorithm,
            "digits": tf_data.digits,
            "period": tf_data.period
        }),
        CredentialData::Raw(_) => serde_json::json!({
            "type": "Raw",
            "message": "Binary data"
        }),
    }
}

#[derive(Debug, Serialize)]
pub struct TotpCodeResponse {
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
    pub digits: u8,
    pub algorithm: String,
    pub issuer: String,
    pub account_name: String,
}

// Wallet types for Tauri commands

/// Wallet summary for listing
#[derive(Debug, Serialize)]
pub struct SerializableWallet {
    pub id: String,
    pub name: String,
    pub network: String,
    pub wallet_type: String,
    pub balance: String,
    pub address_count: usize,
    pub watch_only: bool,
    pub security_level: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Wallet address for display
#[derive(Debug, Serialize)]
pub struct SerializableWalletAddress {
    pub address: String,
    pub address_type: String,
    pub index: u32,
    pub used: bool,
    pub balance: String,
    pub derivation_path: Option<String>,
}

/// Wallet list response
#[derive(Debug, Serialize)]
pub struct WalletListResponse {
    pub wallets: Vec<SerializableWallet>,
}

/// Wallet addresses response
#[derive(Debug, Serialize)]
pub struct WalletAddressesResponse {
    pub addresses: Vec<SerializableWalletAddress>,
}

/// Wallet generation request
#[derive(Debug, Deserialize)]
pub struct WalletGenerateRequest {
    pub name: String,
    pub network: String,
    pub wallet_type: String,
    pub password: String,
    pub address_count: Option<usize>,
}

/// Wallet generation response (includes mnemonic)
#[derive(Debug, Serialize)]
pub struct WalletGenerateResponse {
    pub wallet_id: String,
    pub name: String,
    pub network: String,
    pub mnemonic: String,
    pub first_address: String,
}

/// Wallet import request
#[derive(Debug, Deserialize)]
pub struct WalletImportRequest {
    pub name: String,
    pub network: String,
    pub import_type: String, // "mnemonic" or "private_key"
    pub data: String,
    pub password: String,
    pub address_count: Option<usize>,
}

/// Wallet export request
#[derive(Debug, Deserialize)]
pub struct WalletExportRequest {
    pub wallet_id: String,
    pub format: String, // "json", "mnemonic", "xpub"
    pub include_private: bool,
    pub password: Option<String>,
}

impl CredentialDataRequest {
    pub fn to_credential_data(&self) -> CredentialData {
        match self {
            CredentialDataRequest::Password { password, email, security_questions } => {
                CredentialData::Password(PasswordCredentialData {
                    password: password.clone(),
                    email: email.clone(),
                    security_questions: security_questions.iter().map(|q| SecurityQuestion {
                        question: q.question.clone(),
                        answer: q.answer.clone(),
                    }).collect(),
                })
            }
            CredentialDataRequest::CryptoWallet {
                wallet_type, mnemonic_phrase, private_key, public_key, address, network
            } => {
                CredentialData::CryptoWallet(CryptoWalletData {
                    wallet_type: wallet_type.clone(),
                    mnemonic_phrase: mnemonic_phrase.clone(),
                    private_key: private_key.clone(),
                    public_key: public_key.clone(),
                    address: address.clone(),
                    network: network.clone(),
                })
            }
            CredentialDataRequest::SshKey { private_key, public_key, key_type, passphrase } => {
                CredentialData::SshKey(SshKeyData {
                    private_key: private_key.clone(),
                    public_key: public_key.clone(),
                    key_type: key_type.clone(),
                    passphrase: passphrase.clone(),
                })
            }
            CredentialDataRequest::ApiKey { api_key, api_secret, token, permissions, expires_at } => {
                CredentialData::ApiKey(ApiKeyData {
                    api_key: api_key.clone(),
                    api_secret: api_secret.clone(),
                    token: token.clone(),
                    permissions: permissions.clone(),
                    expires_at: expires_at.as_ref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                })
            }
            CredentialDataRequest::TwoFactor {
                secret_key,
                issuer,
                account_name,
                algorithm,
                digits,
                period,
            } => CredentialData::TwoFactor(TwoFactorData {
                secret_key: secret_key.clone(),
                issuer: issuer.clone(),
                account_name: account_name.clone(),
                algorithm: algorithm.clone(),
                digits: *digits,
                period: *period,
            }),
            CredentialDataRequest::Raw { data } => {
                CredentialData::Raw(data.clone())
            }
        }
    }
}
