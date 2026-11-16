//! 多类型凭据 payload：各类型的明文数据结构、AUDIT-021 手写脱敏 Debug、
//! `CredentialData` 外部标签枚举与 bincode 编解码（含 legacy 容忍读）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Specific credential data structures for different types
#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordCredentialData {
    pub password: String,
    pub email: Option<String>,
    pub security_questions: Vec<SecurityQuestion>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityQuestion {
    pub question: String,
    pub answer: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CryptoWalletData {
    pub wallet_type: String,
    pub mnemonic_phrase: Option<String>,
    pub private_key: Option<String>,
    pub public_key: String,
    pub address: String,
    pub network: String,
    /// BIP-39 第 25 个词（可选）；与助记词分离存储，同为高敏字段
    #[serde(default)]
    pub bip39_passphrase: Option<String>,
    /// 条目级独立密码的 Argon2id PHC hash（可选）：揭示种子材料
    /// （助记词/私钥/第 25 词）时需额外比对——防解锁态顺手窥探的
    /// 第二因子。hash 随条目密文存储，不改变加密封套与同步格式。
    #[serde(default)]
    pub item_password_hash: Option<String>,
    /// 条目密码提示（明文，低敏——帮助回忆，不承载安全强度）
    #[serde(default)]
    pub item_password_hint: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SshKeyData {
    pub private_key: String,
    pub public_key: String,
    pub key_type: String, // rsa, ed25519, etc.
    pub passphrase: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKeyData {
    pub api_key: String,
    pub api_secret: Option<String>,
    pub token: Option<String>,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BankCardData {
    pub card_number: String,
    pub cardholder_name: String,
    pub expiry_date: String,
    pub cvv: String,
    pub bank_name: String,
    pub card_type: String, // visa, mastercard, etc.
}

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct TwoFactorData {
    pub secret_key: String,
    pub issuer: String,
    pub account_name: String,
    pub algorithm: String, // SHA1, SHA256, etc.
    pub digits: u8,
    pub period: u32,
    /// HOTP（RFC 4226）开关：None/false = 时间型 TOTP（RFC 6238），
    /// Some(true) = 计数器型 HOTP。字段追加规则见 GameTokenData 上方
    /// 注释——只能以 `#[serde(default)] Option` 追加在末尾，旧六字段
    /// 密文经 `CredentialData::from_bytes` 的 legacy 容忍读回迁。
    #[serde(default)]
    pub hotp: Option<bool>,
    /// HOTP 起始计数器（otpauth://hotp/ URI 的 `counter` 参数）。出码时由
    /// 调用方按服务侧当前窗口传显式计数器（CLI：`--counter`），本字段只
    /// 作缺省起点；计数器递增不落库。
    #[serde(default)]
    pub initial_counter: Option<u64>,
}

/// Game token data for vendor algorithms outside RFC 4226/6238
/// (e.g. Steam Guard; providers are dispatched in `core::crypto::game_token`)
///
/// 字段追加规则与枚举变体同理：新字段只能以 `#[serde(default)] Option`
/// 追加在末尾，旧负载经 `CredentialData::from_bytes` 的 legacy 容忍读回迁。
#[derive(Clone, Serialize, Deserialize)]
pub struct GameTokenData {
    /// Vendor identifier (`core::crypto::game_token::PROVIDER_*`, e.g. "steam_guard")
    pub provider: String,
    /// Vendor token secret (Steam: base64 `shared_secret`)
    pub secret_key: String,
    pub issuer: String,
    pub account_name: String,
    /// Associated service origin (optional)
    pub url: Option<String>,
    /// Steam trade-confirmation HMAC key（SDA maFile 的 `identity_secret`，
    /// 标准 base64）。登录出码不需要它；移动端交易确认才用。非 Steam
    /// provider 恒为 None。
    #[serde(default)]
    pub identity_secret: Option<String>,
    /// SDA 设备标识（maFile 的 `device_id`，形如 "mobile1234567"）
    #[serde(default)]
    pub device_id: Option<String>,
}

/// 追加 `identity_secret`/`device_id` 之前的 GameTokenData 形状（五字段）。
///
/// 私有镜像结构，仅供 `CredentialData::from_bytes` 的 legacy 容忍读使用：
/// bincode 不支持缺省字段，旧密文反序列化新结构会在尾部 EOF 失败，需要按
/// 旧形状手动解析后再映射（见 `from_bytes`）。
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LegacyGameTokenData {
    pub(super) provider: String,
    pub(super) secret_key: String,
    pub(super) issuer: String,
    pub(super) account_name: String,
    pub(super) url: Option<String>,
}

/// TwoFactorData 追加 hotp/initial_counter 之前的旧六字段形状。私有镜像
/// 结构，仅供 legacy 容忍读使用（口径同 LegacyGameTokenData）。
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LegacyTwoFactorData {
    pub(super) secret_key: String,
    pub(super) issuer: String,
    pub(super) account_name: String,
    pub(super) algorithm: String,
    pub(super) digits: u8,
    pub(super) period: u32,
}

// AUDIT-021：以下含密 data 结构一律**手写 Debug 并脱敏**——不派生 Debug，
// 防止任何 `{:?}`/dbg!/错误链把主密码、SSH 私钥、TOTP/HOTP seed、API key、
// 卡号/CVV、钱包助记词/私钥/xprv、同步/Bearer token 等秘密打进日志、toast、
// 崩溃报告或测试快照。非密字段保留以便诊断。顶层 Credential 只存
// `encrypted_data: Vec<u8>`（不落明文），此处保护的是「解密后在内存里被
// 格式化」的瞬间。合成 canary 回归测试见 core/tests/secret_canary.rs。

impl std::fmt::Debug for PasswordCredentialData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordCredentialData")
            .field("password", &"[redacted]")
            .field("email", &self.email)
            .field("security_questions", &self.security_questions)
            .finish()
    }
}

impl std::fmt::Debug for SecurityQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityQuestion")
            .field("question", &self.question)
            .field("answer", &"[redacted]")
            .finish()
    }
}

impl std::fmt::Debug for CryptoWalletData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoWalletData")
            .field("wallet_type", &self.wallet_type)
            .field("mnemonic_phrase", &"[redacted]")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("address", &self.address)
            .field("network", &self.network)
            .field("bip39_passphrase", &"[redacted]")
            .field(
                "item_password_hash",
                &self.item_password_hash.as_ref().map(|_| "[set]"),
            )
            .field("item_password_hint", &self.item_password_hint)
            .finish()
    }
}

impl std::fmt::Debug for SshKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKeyData")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("key_type", &self.key_type)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl std::fmt::Debug for ApiKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyData")
            .field("api_key", &"[redacted]")
            .field(
                "api_secret",
                &self.api_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("permissions", &self.permissions)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl std::fmt::Debug for BankCardData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BankCardData")
            .field("card_number", &"[redacted]")
            .field("cardholder_name", &self.cardholder_name)
            .field("expiry_date", &self.expiry_date)
            .field("cvv", &"[redacted]")
            .field("bank_name", &self.bank_name)
            .field("card_type", &self.card_type)
            .finish()
    }
}

impl std::fmt::Debug for ServerConfigData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfigData")
            .field("hostname", &self.hostname)
            .field("ip_address", &self.ip_address)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("ssh_key_id", &self.ssh_key_id)
            .field("additional_config", &self.additional_config)
            .finish()
    }
}

impl std::fmt::Debug for TwoFactorData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorData")
            .field("secret_key", &"[redacted]")
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("hotp", &self.hotp)
            .field("initial_counter", &self.initial_counter)
            .finish()
    }
}

impl std::fmt::Debug for LegacyTwoFactorData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyTwoFactorData")
            .field("secret_key", &"[redacted]")
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl std::fmt::Debug for GameTokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GameTokenData")
            .field("provider", &self.provider)
            .field("secret_key", &"[redacted]")
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("url", &self.url)
            .field(
                "identity_secret",
                &self.identity_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl std::fmt::Debug for LegacyGameTokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyGameTokenData")
            .field("provider", &self.provider)
            .field("secret_key", &"[redacted]")
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("url", &self.url)
            .finish()
    }
}

/// 1Password「Secure Note」对齐：全文加密的笔记条目。
///
/// 与 `Credential.notes` 字段（credentials 表**明文列**，001 迁移）不同，
/// 本类型的内容随 `encrypted_data` 走 per-item key 加密，静态存储不可读。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNoteData {
    /// 笔记正文（纯文本，MVP 不做富文本分节）
    pub note: String,
}

/// 1Password「Identity」对齐：个人身份信息条目。
///
/// 证件号等敏感字段随 `encrypted_data` 走 per-item key 加密；
/// 日期类字段沿用自由格式文本（与 1Password 的文本字段一致，不做解析）。
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityData {
    pub first_name: String,
    pub last_name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// 生日（自由格式，如 1990-01-31）
    pub birthday: Option<String>,
    /// 多行邮寄地址
    pub address: Option<String>,
    /// 证件号（身份证 / SSN 等）
    pub id_number: Option<String>,
    pub passport_number: Option<String>,
    pub driver_license: Option<String>,
    pub tax_id: Option<String>,
    pub organization: Option<String>,
    pub job_title: Option<String>,
}

/// 1Password「Software License」对齐：软件许可证条目。
///
/// `license_key` 是核心敏感字段，随 `encrypted_data` 走 per-item key 加密。
#[derive(Clone, Serialize, Deserialize)]
pub struct SoftwareLicenseData {
    pub license_key: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    /// 购买日期（自由格式）
    pub purchase_date: Option<String>,
    pub order_number: Option<String>,
    pub support_email: Option<String>,
    pub download_url: Option<String>,
    /// 授权席位数
    pub seats: Option<u32>,
    /// 许可有效期（自由格式）
    pub valid_until: Option<String>,
}

impl std::fmt::Debug for IdentityData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityData")
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("phone", &self.phone)
            .field("birthday", &self.birthday)
            .field("address", &self.address)
            .field("id_number", &self.id_number.as_ref().map(|_| "[redacted]"))
            .field(
                "passport_number",
                &self.passport_number.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "driver_license",
                &self.driver_license.as_ref().map(|_| "[redacted]"),
            )
            .field("tax_id", &self.tax_id.as_ref().map(|_| "[redacted]"))
            .field("organization", &self.organization)
            .field("job_title", &self.job_title)
            .finish()
    }
}

impl std::fmt::Debug for SoftwareLicenseData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareLicenseData")
            .field("license_key", &"[redacted]")
            .field("version", &self.version)
            .field("publisher", &self.publisher)
            .field("purchase_date", &self.purchase_date)
            .field("order_number", &self.order_number)
            .field("support_email", &self.support_email)
            .field("download_url", &self.download_url)
            .field("seats", &self.seats)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

/// Helper enum for strongly-typed credential data
///
/// bincode 外部标签枚举：新变体只能追加在末尾，既有变体索引不可变，
/// 否则旧密文将无法反序列化。
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
    GameToken(GameTokenData),
    SecureNote(SecureNoteData),
    Identity(IdentityData),
    SoftwareLicense(SoftwareLicenseData),
}

impl CredentialData {
    /// Serialize credential data to bytes for encryption
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize credential data from bytes after decryption.
    ///
    /// 当前形状反序列化失败时，回退到 legacy 容忍读（见
    /// [`Self::from_bytes_legacy_game_token`] 与
    /// [`Self::from_bytes_legacy_two_factor`]）；两条 legacy 路都失败
    /// 则返回原错误，保证损坏负载不会被静默"修复"。
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        match bincode::deserialize(data) {
            Ok(parsed) => Ok(parsed),
            Err(e) => Self::from_bytes_legacy_game_token(data)
                .or_else(|| Self::from_bytes_legacy_two_factor(data))
                .ok_or(e),
        }
    }

    /// GameTokenData 追加 `identity_secret`/`device_id` 之前的旧密文容忍读。
    ///
    /// bincode 外部标签枚举里 GameToken 的变体索引是 8（u32 LE 前缀）；
    /// 旧负载 = 4 字节 tag + 五字段 `LegacyGameTokenData`。识别后先按旧
    /// 形状解析，再把解析结果**重序列化并与原字节逐位比对**——只有整个
    /// 负载恰好是旧形状时才接受，避免把碰巧以 0x08000000 开头的损坏数据
    /// 误判成令牌。映射时新增字段置 None（导入 Steam maFile 后才有值）。
    fn from_bytes_legacy_game_token(data: &[u8]) -> Option<Self> {
        const GAME_TOKEN_VARIANT: u32 = 8;
        if data.len() < 4 || u32::from_le_bytes(data[..4].try_into().ok()?) != GAME_TOKEN_VARIANT {
            return None;
        }
        let legacy: LegacyGameTokenData = bincode::deserialize(&data[4..]).ok()?;
        if bincode::serialize(&legacy).ok()?.as_slice() != &data[4..] {
            return None;
        }
        Some(CredentialData::GameToken(GameTokenData {
            provider: legacy.provider,
            secret_key: legacy.secret_key,
            issuer: legacy.issuer,
            account_name: legacy.account_name,
            url: legacy.url,
            identity_secret: None,
            device_id: None,
        }))
    }

    /// TwoFactorData 追加 `hotp`/`initial_counter` 之前的旧密文容忍读。
    ///
    /// bincode 外部标签枚举里 TwoFactor 的变体索引是 6（u32 LE 前缀）；
    /// 旧负载 = 4 字节 tag + 六字段 `LegacyTwoFactorData`。与 GameToken
    /// 同一口径：先按旧形状解析，再重序列化并逐位比对——只有整个负载
    /// 恰好是旧形状时才接受，避免把碰巧以 0x06000000 开头的损坏数据
    /// 误判成 TOTP。映射时新增字段置 None（即旧条目仍是时间型 TOTP）。
    fn from_bytes_legacy_two_factor(data: &[u8]) -> Option<Self> {
        const TWO_FACTOR_VARIANT: u32 = 6;
        if data.len() < 4 || u32::from_le_bytes(data[..4].try_into().ok()?) != TWO_FACTOR_VARIANT {
            return None;
        }
        let legacy: LegacyTwoFactorData = bincode::deserialize(&data[4..]).ok()?;
        if bincode::serialize(&legacy).ok()?.as_slice() != &data[4..] {
            return None;
        }
        Some(CredentialData::TwoFactor(TwoFactorData {
            secret_key: legacy.secret_key,
            issuer: legacy.issuer,
            account_name: legacy.account_name,
            algorithm: legacy.algorithm,
            digits: legacy.digits,
            period: legacy.period,
            hotp: None,
            initial_counter: None,
        }))
    }
}
