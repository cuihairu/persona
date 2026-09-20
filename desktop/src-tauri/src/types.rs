use persona_core::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// agent 任务挂在 tauri 管理的全局运行时上（而非任意调用方的 tokio
// 上下文）：命令处理器之外的环境（含测试）不一定有可用 reactor。
use tauri::async_runtime::JoinHandle;

/// Application state that holds the Persona service
///
/// `service` 用 `Arc` 包裹：auto-lock 回调在独立任务里触发落锁，
/// 需要在不经过 Tauri `State` 的情况下持有同一份引用。
pub struct AppState {
    pub service: Arc<Mutex<Option<PersonaService>>>,
    pub db_path: Mutex<Option<String>>,
    pub agent_handle: Mutex<Option<JoinHandle<()>>>,
    /// auto-lock 回调只注册一次（多次 init_service 时防重复）
    pub auto_lock_registered: std::sync::atomic::AtomicBool,
    /// passkey 审批服务端本会话已启动（workspace 开关门禁的幂等标记）
    pub passkey_server_started: std::sync::atomic::AtomicBool,
    /// passkey 审批服务端的关停通道（maybe_start 填充、关 flag 时消费发送；
    /// None = 本会话未启动或已关停）
    pub passkey_server_shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// 待应答的 SSH 签名审批（request_id → oneshot），由
    /// DesktopApprovalHandler 写入、ssh_approval_respond 命令取出
    pub ssh_approvals: Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
    /// 待应答的 bridge passkey 审批（request_id → oneshot），由
    /// passkey_bridge 服务端写入、passkey_approval_respond 命令取出
    pub passkey_approvals:
        Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
    /// 审计事件同步上报器（settings.sync 配置驱动；None = 未启用）。
    /// 槽位即真相源：重挂时先 stop 旧的再换新，防止双任务。注意这里
    /// 用全路径——`tauri::Emitter`（事件 emit trait）占用了 `Emitter` 名。
    pub sync_emitter: Mutex<Option<persona_core::events::Emitter>>,
    /// sync token 的字段级加密存储（生产 = OS keyring，测试 = 内存
    /// fake）。vault settings JSON 里的 `server_token` 恒为空串占位，
    /// 真值只存在这里。
    pub token_store: Arc<dyn crate::token_store::TokenStore>,
}

/// `persona://ssh-approval` 事件负载：一条待审批的 SSH 签名请求
#[derive(Debug, Clone, Serialize)]
pub struct SshApprovalRequest {
    pub request_id: String,
    /// 凭据 UUID（非敏感）
    pub key_id: String,
    /// 公钥指纹（SHA256 前 8 字节，用于人工核对）
    pub fingerprint: String,
    /// 操作名（当前恒为 "sign"）
    pub operation: String,
    /// 目标主机（未知时为 null）
    pub peer: Option<String>,
    /// 触发原因（策略说明）
    pub reason: String,
}

/// `persona://passkey-approval` 事件负载：一条待审批的 bridge passkey 请求。
/// 只含 origin/rp/账号等元数据 —— clientDataJSON 永不出 bridge 进程。
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyApprovalRequest {
    pub request_id: String,
    /// 沿用 bridge wire 的操作名："passkey_create" | "passkey_assert"
    pub operation: String,
    /// 人工核对的 relying party（assert 时为 None：rp 存在 vault item 上）
    pub rp_id: Option<String>,
    /// 发起请求的完整页面 origin
    pub origin: String,
    /// create 时的账号名（assert 时在存储 item 上，桌面无从得知）
    pub user_name: Option<String>,
    /// assert 时对应 vault item 的 UUID
    pub item_id: Option<String>,
}

/// Response structure for API calls
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    /// 机器可读错误码（"REAUTH_REQUIRED" / "SERVICE_LOCKED"），供前端分流
    pub error_code: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            error_code: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            error_code: None,
        }
    }

    pub fn error_with_code(error_code: String, message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            error_code: Some(error_code),
        }
    }
}

/// Initialization request
#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub master_password: String,
    pub db_path: Option<String>,
}

/// Change-master-password request（改密命令参数；旧密码仅存在于本请求，
/// 不落盘不进日志）
#[derive(Debug, Deserialize)]
pub struct ChangeMasterPasswordRequest {
    pub old_password: String,
    pub new_password: String,
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

/// Credential metadata edit request（1Password 对齐：编辑不改条目类型，
/// payload 单独走 update_credential_data）
#[derive(Debug, Deserialize)]
pub struct UpdateCredentialRequest {
    pub id: String,
    pub name: String,
    pub security_level: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Credential payload edit request（敏感：复用原 item key 重封 + 敏感门禁）
#[derive(Debug, Deserialize)]
pub struct UpdateCredentialDataRequest {
    pub credential_id: String,
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
    GameToken {
        provider: String,
        secret_key: String,
        issuer: String,
        account_name: String,
        url: Option<String>,
    },
    SecureNote {
        note: String,
    },
    Identity {
        first_name: String,
        last_name: String,
        username: Option<String>,
        email: Option<String>,
        phone: Option<String>,
        birthday: Option<String>,
        address: Option<String>,
        id_number: Option<String>,
        passport_number: Option<String>,
        driver_license: Option<String>,
        tax_id: Option<String>,
        organization: Option<String>,
        job_title: Option<String>,
    },
    SoftwareLicense {
        license_key: String,
        version: Option<String>,
        publisher: Option<String>,
        purchase_date: Option<String>,
        order_number: Option<String>,
        support_email: Option<String>,
        download_url: Option<String>,
        seats: Option<u32>,
        valid_until: Option<String>,
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
            CredentialDataRequest::Password {
                password,
                email,
                security_questions,
            } => CredentialData::Password(PasswordCredentialData {
                password: password.clone(),
                email: email.clone(),
                security_questions: security_questions
                    .iter()
                    .map(|q| SecurityQuestion {
                        question: q.question.clone(),
                        answer: q.answer.clone(),
                    })
                    .collect(),
            }),
            CredentialDataRequest::CryptoWallet {
                wallet_type,
                mnemonic_phrase,
                private_key,
                public_key,
                address,
                network,
            } => CredentialData::CryptoWallet(CryptoWalletData {
                wallet_type: wallet_type.clone(),
                mnemonic_phrase: mnemonic_phrase.clone(),
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                address: address.clone(),
                network: network.clone(),
            }),
            CredentialDataRequest::SshKey {
                private_key,
                public_key,
                key_type,
                passphrase,
            } => CredentialData::SshKey(SshKeyData {
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                key_type: key_type.clone(),
                passphrase: passphrase.clone(),
            }),
            CredentialDataRequest::ApiKey {
                api_key,
                api_secret,
                token,
                permissions,
                expires_at,
            } => CredentialData::ApiKey(ApiKeyData {
                api_key: api_key.clone(),
                api_secret: api_secret.clone(),
                token: token.clone(),
                permissions: permissions.clone(),
                expires_at: expires_at
                    .as_ref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc)),
            }),
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
            CredentialDataRequest::GameToken {
                provider,
                secret_key,
                issuer,
                account_name,
                url,
            } => CredentialData::GameToken(GameTokenData {
                provider: provider.clone(),
                secret_key: secret_key.clone(),
                issuer: issuer.clone(),
                account_name: account_name.clone(),
                url: url.clone(),
            }),
            CredentialDataRequest::SecureNote { note } => {
                CredentialData::SecureNote(SecureNoteData { note: note.clone() })
            }
            CredentialDataRequest::Identity {
                first_name,
                last_name,
                username,
                email,
                phone,
                birthday,
                address,
                id_number,
                passport_number,
                driver_license,
                tax_id,
                organization,
                job_title,
            } => CredentialData::Identity(IdentityData {
                first_name: first_name.clone(),
                last_name: last_name.clone(),
                username: username.clone(),
                email: email.clone(),
                phone: phone.clone(),
                birthday: birthday.clone(),
                address: address.clone(),
                id_number: id_number.clone(),
                passport_number: passport_number.clone(),
                driver_license: driver_license.clone(),
                tax_id: tax_id.clone(),
                organization: organization.clone(),
                job_title: job_title.clone(),
            }),
            CredentialDataRequest::SoftwareLicense {
                license_key,
                version,
                publisher,
                purchase_date,
                order_number,
                support_email,
                download_url,
                seats,
                valid_until,
            } => CredentialData::SoftwareLicense(SoftwareLicenseData {
                license_key: license_key.clone(),
                version: version.clone(),
                publisher: publisher.clone(),
                purchase_date: purchase_date.clone(),
                order_number: order_number.clone(),
                support_email: support_email.clone(),
                download_url: download_url.clone(),
                seats: *seats,
                valid_until: valid_until.clone(),
            }),
            CredentialDataRequest::Raw { data } => CredentialData::Raw(data.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// 审计查询
// ---------------------------------------------------------------------------

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

#[derive(Debug, Deserialize)]
pub struct RevealSecretRequest {
    pub credential_id: String,
    /// "password" | "security_questions" | "ssh_private_key" | "ssh_passphrase" |
    /// "api_key" | "api_secret" | "token" | "wallet_private_key" |
    /// "wallet_mnemonic" | "raw_data"
    pub field: String,
}

#[derive(Debug, Serialize)]
pub struct SecretRevealResponse {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ReauthRequest {
    pub master_password: String,
}

// ---------------------------------------------------------------------------
// 身份导出
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
/// 字段级 diff 是展示所需的最小信息。
#[derive(Debug, Serialize)]
pub struct SerializableChangeHistory {
    pub id: String,
    pub entity_id: String,
    pub change_type: String,
    pub version: u32,
    pub timestamp: String,
    pub changes: Vec<SerializableFieldChange>,
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
