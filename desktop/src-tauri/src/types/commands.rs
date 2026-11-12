//! 命令 wire 请求、`ApiResponse<T>` 与 `CredentialDataRequest` 域。

use persona_core::*;
use serde::{Deserialize, Serialize};

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

    /// code 为 None 时等价 [`Self::error`]，有码时等价 [`Self::error_with_code`]。
    /// 供边界收敛点使用：错误有时可映射错误码、有时只能透传消息。
    pub fn error_maybe_coded(error_code: Option<String>, message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            error_code,
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

/// `generate_password_advanced` 的结果：候选口令 + 供 UI 展示的熵值估计
/// 与字符池大小（显示参考而非安全承诺；字符集与 core 生成器同源）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPasswords {
    pub passwords: Vec<String>,
    pub entropy_bits: f64,
    pub pool_size: usize,
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
        bip39_passphrase: Option<String>,
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
        /// HOTP（RFC 4226）计数器型条目；缺省（旧前端）= 时间型 TOTP。
        #[serde(default)]
        hotp: Option<bool>,
        #[serde(default)]
        initial_counter: Option<u64>,
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
    /// 展示用：线格式算法（`ssh-ed25519` 等）；数据取不到时为 null
    pub ssh_algorithm: Option<String>,
    /// 展示用：SHA256 指纹（`SHA256:…`），与导入/生成确认处同口径
    pub fingerprint: Option<String>,
    /// 展示用：位数/曲线标签（Ed25519→`256`、RSA→`4096`、ECDSA→`P-256`）；
    /// 证书等不适用的容器为 null
    pub key_size: Option<String>,
    /// 完整公钥行，供一键复制到 authorized_keys / GitHub
    pub public_key: Option<String>,
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
                bip39_passphrase,
            } => CredentialData::CryptoWallet(CryptoWalletData {
                wallet_type: wallet_type.clone(),
                mnemonic_phrase: mnemonic_phrase.clone(),
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                address: address.clone(),
                network: network.clone(),
                bip39_passphrase: bip39_passphrase.clone(),
                // 条目级独立密码走 wallet_set_item_password 独立命令设置
                // （创建后二次加固），创建请求不承载
                item_password_hash: None,
                item_password_hint: None,
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
                hotp,
                initial_counter,
                period,
            } => CredentialData::TwoFactor(TwoFactorData {
                secret_key: secret_key.clone(),
                issuer: issuer.clone(),
                account_name: account_name.clone(),
                algorithm: algorithm.clone(),
                digits: *digits,
                period: *period,
                hotp: *hotp,
                initial_counter: *initial_counter,
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
                identity_secret: None,
                device_id: None,
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

#[derive(Debug, Deserialize)]
pub struct RevealSecretRequest {
    pub credential_id: String,
    /// "password" | "security_questions" | "ssh_private_key" | "ssh_passphrase" |
    /// "api_key" | "api_secret" | "token" | "wallet_private_key" |
    /// "wallet_mnemonic" | "raw_data"
    pub field: String,
    /// 钱包条目级独立密码（可选）：条目设置了 item_password_hash 的种子
    /// 材料 reveal 必须携带，后端 Argon2id 比对通过才返回明文
    #[serde(default)]
    pub item_password: Option<String>,
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

/// Quick Access 浮窗"在 Persona 中打开"：跨窗跳转的两个 id（UUID 形态，
/// 后端会再校验一次——前端校验只是提前反馈）
#[derive(Debug, Deserialize)]
pub struct QuickAccessOpenCredentialRequest {
    pub identity_id: String,
    pub credential_id: String,
}

// ---------------------------------------------------------------------------
// 身份导出
// ---------------------------------------------------------------------------
