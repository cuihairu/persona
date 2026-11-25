//! `Serializable*` wire types and the persona_core -> wire `From` conversion domain.

use persona_core::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    /// Travel-mode marker: removed from this device on enter (the edit form's
    /// toggle reads/writes it directly).
    pub travel_marked: bool,
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

/// Structured custom field (1Password parity). `value` is a secret for
/// `Concealed` fields, so reads require an unlocked vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableCustomField {
    pub id: String,
    pub label: String,
    pub value: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub section: Option<String>,
}

impl From<CustomField> for SerializableCustomField {
    fn from(f: CustomField) -> Self {
        Self {
            id: f.id,
            label: f.label,
            value: f.value,
            field_type: serde_json::to_value(f.field_type)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "text".to_string()),
            section: f.section,
        }
    }
}

impl TryFrom<SerializableCustomField> for CustomField {
    type Error = PersonaError;

    fn try_from(f: SerializableCustomField) -> std::result::Result<Self, Self::Error> {
        let field_type = match f.field_type.as_str() {
            "text" => CustomFieldType::Text,
            "concealed" => CustomFieldType::Concealed,
            "date" => CustomFieldType::Date,
            other => {
                return Err(PersonaError::InvalidInput(format!(
                    "unknown custom field type: {other}"
                )))
            }
        };
        Ok(CustomField {
            id: f.id,
            label: f.label,
            value: f.value,
            field_type,
            section: f.section,
        })
    }
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
            travel_marked: identity.travel_marked,
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
        // secret_key is not sent back to the frontend (same reason TwoFactor does
        // not return secret_key)
        CredentialData::GameToken(gt_data) => serde_json::json!({
            "type": "GameToken",
            "provider": gt_data.provider,
            "issuer": gt_data.issuer,
            "account_name": gt_data.account_name,
            "url": gt_data.url
        }),
        // Note body is sent back (needed for the detail panel display;
        // get_credential_data goes through the sensitive-op gate, same
        // reason Password returns password)
        CredentialData::SecureNote(note_data) => serde_json::json!({
            "type": "SecureNote",
            "note": note_data.note
        }),
        // ID number / license_key and other sensitive fields, same as above:
        // needed for detail panel display; reads go through the
        // sensitive-op gate (consistent with Password/SecureNote)
        CredentialData::Identity(id_data) => serde_json::json!({
            "type": "Identity",
            "first_name": id_data.first_name,
            "last_name": id_data.last_name,
            "username": id_data.username,
            "email": id_data.email,
            "phone": id_data.phone,
            "birthday": id_data.birthday,
            "address": id_data.address,
            "id_number": id_data.id_number,
            "passport_number": id_data.passport_number,
            "driver_license": id_data.driver_license,
            "tax_id": id_data.tax_id,
            "organization": id_data.organization,
            "job_title": id_data.job_title
        }),
        CredentialData::SoftwareLicense(lic_data) => serde_json::json!({
            "type": "SoftwareLicense",
            "license_key": lic_data.license_key,
            "version": lic_data.version,
            "publisher": lic_data.publisher,
            "purchase_date": lic_data.purchase_date,
            "order_number": lic_data.order_number,
            "support_email": lic_data.support_email,
            "download_url": lic_data.download_url,
            "seats": lic_data.seats,
            "valid_until": lic_data.valid_until
        }),
    }
}

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

/// Serializable audit log (no sensitive payload)
#[derive(Debug, Serialize)]
pub struct SerializableAuditLog {
    pub id: String,
    pub user_id: Option<String>,
    pub identity_id: Option<String>,
    pub credential_id: Option<String>,
    pub session_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: HashMap<String, String>,
    pub timestamp: String,
}

impl From<AuditLog> for SerializableAuditLog {
    fn from(log: AuditLog) -> Self {
        Self {
            id: log.id.to_string(),
            user_id: log.user_id,
            identity_id: log.identity_id.map(|id| id.to_string()),
            credential_id: log.credential_id.map(|id| id.to_string()),
            session_id: log.session_id,
            action: log.action.to_string(),
            resource_type: log.resource_type.to_string(),
            resource_id: log.resource_id,
            success: log.success,
            error_message: log.error_message,
            metadata: log.metadata,
            timestamp: log.timestamp.to_rfc3339(),
        }
    }
}

/// Audit query request (None fields = no filter)
#[derive(Debug, Deserialize)]
pub struct AuditQueryRequest {
    pub user_id: Option<String>,
    pub identity_id: Option<String>,
    /// Action name (e.g. "identity_created"); an illegal name returns an error
    pub action: Option<String>,
    pub failures_only: Option<bool>,
    pub security_sensitive_only: Option<bool>,
    /// RFC 3339 times, (start, end)
    pub time_range: Option<(String, String)>,
    pub limit: Option<usize>,
}

/// Watchtower health scan request (None fields = use the core defaults)
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HealthScanRequest {
    /// zxcvbn score threshold (0-4): passwords below it count as weak
    pub min_password_score: Option<u8>,
    /// Expiry warning window (days)
    pub expiry_warning_days: Option<i64>,
    /// Credentials not updated within this many days count as stale
    pub stale_after_days: Option<i64>,
    /// Also query the HIBP breach database (k-anonymity: only the first 5
    /// characters of the hash are sent); a network failure degrades to a
    /// warning and does not affect the offline rules
    pub check_breaches: Option<bool>,
}

/// Audit statistics
#[derive(Debug, Serialize)]
pub struct SerializableAuditStatistics {
    pub total_logs: u64,
    pub failed_operations: u64,
    pub recent_login_attempts: u64,
    pub active_users_last_week: u64,
}

// ---------------------------------------------------------------------------
// Passkey management (command-layer seam for the P3 desktop GUI)
// ---------------------------------------------------------------------------

/// Serializable passkey (never carries private-key fields)
#[derive(Debug, Serialize)]
pub struct SerializablePasskey {
    pub id: String,
    pub identity_id: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_handle_b64: String,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub credential_id_b64: String,
    pub uv_initialized: bool,
    pub export_allowed: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePasskeyRequest {
    pub identity_id: String,
    pub rp_id: String,
    pub origin: String,
    /// base64(UTF-8 JSON) clientDataJSON
    pub client_data_json_b64: String,
    pub user_handle_b64: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub user_verification: bool,
}

#[derive(Debug, Serialize)]
pub struct PasskeyCreationResponse {
    pub passkey: SerializablePasskey,
    /// base64 `none`-format attestation object
    pub attestation_object_b64: String,
}

impl From<PasskeyItem> for SerializablePasskey {
    fn from(item: PasskeyItem) -> Self {
        use base64::Engine;

        let engine = base64::engine::general_purpose::STANDARD;
        Self {
            id: item.id.to_string(),
            identity_id: item.identity_id.to_string(),
            rp_id: item.rp_id,
            rp_name: item.rp_name,
            user_handle_b64: engine.encode(item.user_handle),
            user_name: item.user_name,
            user_display_name: item.user_display_name,
            credential_id_b64: engine.encode(item.credential_id),
            uv_initialized: item.uv_initialized,
            export_allowed: item.export_allowed,
            created_at: item.created_at.to_rfc3339(),
            last_used_at: item.last_used_at.map(|dt| dt.to_rfc3339()),
        }
    }
}

// ---------------------------------------------------------------------------
// Auto-lock
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AutoLockConfigRequest {
    pub inactivity_timeout_secs: u64,
    pub absolute_timeout_secs: Option<u64>,
    pub require_reauth_sensitive: Option<bool>,
    /// Re-authentication window for sensitive operations (seconds); core default
    /// (300) when absent.
    pub sensitive_operation_timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AutoLockStatusResponse {
    pub is_unlocked: bool,
    pub session_locked: bool,
    pub needs_reauth: bool,
    pub inactivity_timeout_secs: u64,
}

/// Auto-lock event carried across emit (variants discriminated by serde tag)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SerializableAutoLockEvent {
    LockPending {
        session_id: String,
        seconds_remaining: u64,
    },
    Locked {
        session_id: String,
        reason: String,
    },
    Unlocked {
        session_id: String,
    },
    Activity {
        session_id: String,
    },
}

impl From<AutoLockEvent> for SerializableAutoLockEvent {
    fn from(event: AutoLockEvent) -> Self {
        match event {
            AutoLockEvent::LockPending {
                session_id,
                seconds_remaining,
            } => Self::LockPending {
                session_id,
                seconds_remaining,
            },
            AutoLockEvent::Locked { session_id, reason } => Self::Locked {
                session_id,
                reason: format!("{:?}", reason),
            },
            AutoLockEvent::Unlocked { session_id } => Self::Unlocked { session_id },
            AutoLockEvent::Activity { session_id } => Self::Activity { session_id },
        }
    }
}

// ---------------------------------------------------------------------------
// Sensitive field reveal / re-authentication
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SerializableIdentityExport {
    pub exported_at: String,
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// favicon cache
// ---------------------------------------------------------------------------

/// Frontend favicon DTO; icon bytes base64-encoded, the frontend composes a
/// `data:` URL to render.
#[derive(Debug, Clone, Serialize)]
pub struct SerializableFavicon {
    pub host: String,
    pub mime_type: String,
    /// base64-encoded image bytes (≤ 512 KiB)
    pub data: String,
}

impl From<persona_core::models::FaviconCacheEntry> for SerializableFavicon {
    fn from(entry: persona_core::models::FaviconCacheEntry) -> Self {
        use base64::Engine;
        Self {
            host: entry.host,
            mime_type: entry.mime_type,
            data: base64::engine::general_purpose::STANDARD.encode(entry.data),
        }
    }
}

// ---------------------------------------------------------------------------
// Item history (1Password-aligned)
// ---------------------------------------------------------------------------

/// Field-level diff (the snapshot JSON is not sent to the frontend; the diff
/// is enough for the UI)
#[derive(Debug, Serialize)]
pub struct SerializableFieldChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Serializable history row. The full previous_state/new_state JSON is not
/// sent — the field-level diff is the minimum information the display needs.
/// `restorable` only exposes the single "is it recoverable" bit (a deleted
/// row has no new_state and is not recoverable); the snapshot itself still
/// never enters IPC.
#[derive(Debug, Serialize)]
pub struct SerializableChangeHistory {
    pub id: String,
    pub entity_id: String,
    pub change_type: String,
    pub version: u32,
    pub timestamp: String,
    pub changes: Vec<SerializableFieldChange>,
    pub restorable: bool,
}

impl From<persona_core::models::ChangeHistory> for SerializableChangeHistory {
    fn from(entry: persona_core::models::ChangeHistory) -> Self {
        Self {
            id: entry.id.to_string(),
            entity_id: entry.entity_id.to_string(),
            change_type: entry.change_type.to_string(),
            version: entry.version,
            timestamp: entry.timestamp.to_rfc3339(),
            changes: entry
                .changes_summary
                .into_iter()
                .map(|(field, change)| SerializableFieldChange {
                    field,
                    old_value: change.old_value,
                    new_value: change.new_value,
                })
                .collect(),
            restorable: entry.new_state.is_some(),
        }
    }
}

// ---------------------------------------------------------------------------
// Attachments (1Password-aligned): metadata alone is what gets displayed;
// encryption_key_id is only a key fingerprint (first 16 bytes hex), not key
// material
// ---------------------------------------------------------------------------

/// Serializable attachment metadata
#[derive(Debug, Serialize)]
pub struct SerializableAttachment {
    pub id: String,
    pub credential_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub is_encrypted: bool,
    pub content_hash: String,
    pub created_at: String,
}

impl From<persona_core::models::Attachment> for SerializableAttachment {
    fn from(attachment: persona_core::models::Attachment) -> Self {
        Self {
            id: attachment.id.to_string(),
            credential_id: attachment.credential_id.to_string(),
            filename: attachment.filename,
            mime_type: attachment.mime_type,
            size: attachment.size,
            is_encrypted: attachment.is_encrypted,
            content_hash: attachment.content_hash,
            created_at: attachment.created_at.to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// Sync-group pairing (S1 desktop wiring)
// ---------------------------------------------------------------------------
