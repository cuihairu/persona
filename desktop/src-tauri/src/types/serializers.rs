//! `Serializable*` wire 类型与 persona_core → wire 的 `From` 转换域。

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
    /// 旅行模式标记：enter 时随之移出本设备（编辑表单的开关直读写）。
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
        // secret_key 不回传前端（与 TwoFactor 不回传 secret_key 同理）
        CredentialData::GameToken(gt_data) => serde_json::json!({
            "type": "GameToken",
            "provider": gt_data.provider,
            "issuer": gt_data.issuer,
            "account_name": gt_data.account_name,
            "url": gt_data.url
        }),
        // 笔记正文回传（详情面板展示需要；get_credential_data 走敏感操作
        // 门禁，与 Password 回传 password 同理）
        CredentialData::SecureNote(note_data) => serde_json::json!({
            "type": "SecureNote",
            "note": note_data.note
        }),
        // 证件号 / license_key 等敏感字段同上：详情面板展示需要，
        // 读取走敏感操作门禁（与 Password/SecureNote 一致）
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

/// 可序列化的审计日志（不含敏感负载）
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

/// 审计查询请求（None 字段 = 不过滤）
#[derive(Debug, Deserialize)]
pub struct AuditQueryRequest {
    pub user_id: Option<String>,
    pub identity_id: Option<String>,
    /// 动作名（如 "identity_created"），非法名称返回错误
    pub action: Option<String>,
    pub failures_only: Option<bool>,
    pub security_sensitive_only: Option<bool>,
    /// RFC 3339 时间，(start, end)
    pub time_range: Option<(String, String)>,
    pub limit: Option<usize>,
}

/// Watchtower 健康扫描请求（None 字段 = 使用 core 默认值）
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HealthScanRequest {
    /// zxcvbn 分数阈值（0-4）：低于该值的密码判弱
    pub min_password_score: Option<u8>,
    /// 过期警告窗口（天）
    pub expiry_warning_days: Option<i64>,
    /// 超过该天数未更新的凭据判陈旧
    pub stale_after_days: Option<i64>,
    /// 同时查询 HIBP 泄露库（k-anonymity：仅发送哈希前 5 字符）；
    /// 网络失败降级为告警，不影响离线规则
    pub check_breaches: Option<bool>,
}

/// 审计统计
#[derive(Debug, Serialize)]
pub struct SerializableAuditStatistics {
    pub total_logs: u64,
    pub failed_operations: u64,
    pub recent_login_attempts: u64,
    pub active_users_last_week: u64,
}

// ---------------------------------------------------------------------------
// Passkey 管理（P3 桌面 GUI 的命令层接缝）
// ---------------------------------------------------------------------------

/// 可序列化的 passkey（永不包含私钥字段）
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
    /// base64(UTF-8 JSON) 的 clientDataJSON
    pub client_data_json_b64: String,
    pub user_handle_b64: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub user_verification: bool,
}

#[derive(Debug, Serialize)]
pub struct PasskeyCreationResponse {
    pub passkey: SerializablePasskey,
    /// base64 的 `none` 格式 attestation object
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
    /// 敏感操作再认证的窗口（秒）；不传用 core 默认（300）。
    pub sensitive_operation_timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AutoLockStatusResponse {
    pub is_unlocked: bool,
    pub session_locked: bool,
    pub needs_reauth: bool,
    pub inactivity_timeout_secs: u64,
}

/// 跨 emit 传递的 auto-lock 事件（serde tag 区分变体）
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
// 敏感字段 reveal / 重新认证
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SerializableIdentityExport {
    pub exported_at: String,
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// favicon 缓存
// ---------------------------------------------------------------------------

/// 前端 favicon DTO；图标字节 base64 编码，前端拼 `data:` URL 渲染。
#[derive(Debug, Clone, Serialize)]
pub struct SerializableFavicon {
    pub host: String,
    pub mime_type: String,
    /// base64 编码的图像字节（≤ 512 KiB）
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
// Item history（1Password 对齐）
// ---------------------------------------------------------------------------

/// 字段级 diff（快照 JSON 不回传前端，diff 足够 UI 展示）
#[derive(Debug, Serialize)]
pub struct SerializableFieldChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// 可序列化的历史行。previous_state/new_state 整份 JSON 不回传——
/// 字段级 diff 是展示所需的最小信息。`restorable` 只暴露「是否可恢复」
/// 一位（删除行无 new_state 不可恢复），快照本身仍不进 IPC。
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
// Attachments（1Password 对齐）：元数据即可展示信息；
// encryption_key_id 只是密钥指纹（前 16 字节 hex），不含密钥材料
// ---------------------------------------------------------------------------

/// 可序列化的附件元数据
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
// 同步组配对（S1 桌面接线）
// ---------------------------------------------------------------------------
