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

    /// 与 [`Display`](std::fmt::Display) / 存储层字符串往返对齐：未知字符串
    /// 归入 `Custom`（与 `row_to_credential` 同一策略）。
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

/// Game token data for vendor algorithms outside RFC 4226/6238
/// (e.g. Steam Guard; providers are dispatched in `core::crypto::game_token`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameTokenData {
    /// Vendor identifier (`core::crypto::game_token::PROVIDER_*`, e.g. "steam_guard")
    pub provider: String,
    /// Vendor token secret (Steam: base64 `shared_secret`)
    pub secret_key: String,
    pub issuer: String,
    pub account_name: String,
    /// Associated service origin (optional)
    pub url: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Deserialize credential data from bytes after decryption
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_type_display_values() {
        assert_eq!(CredentialType::Password.to_string(), "Password");
        assert_eq!(CredentialType::CryptoWallet.to_string(), "CryptoWallet");
        assert_eq!(CredentialType::SshKey.to_string(), "SshKey");
        assert_eq!(CredentialType::TwoFactor.to_string(), "TwoFactor");
        assert_eq!(
            CredentialType::Custom("X".to_string()).to_string(),
            "X".to_string()
        );
    }

    #[test]
    fn security_level_display_values() {
        assert_eq!(SecurityLevel::Critical.to_string(), "Critical");
        assert_eq!(SecurityLevel::High.to_string(), "High");
        assert_eq!(SecurityLevel::Medium.to_string(), "Medium");
        assert_eq!(SecurityLevel::Low.to_string(), "Low");
    }

    #[test]
    fn credential_new_sets_required_fields() {
        let identity_id = Uuid::new_v4();
        let cred = Credential::new(
            identity_id,
            "GitHub".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1, 2, 3],
            None,
        );

        assert_eq!(cred.identity_id, identity_id);
        assert_eq!(cred.name, "GitHub");
        assert_eq!(cred.credential_type, CredentialType::Password);
        assert_eq!(cred.security_level, SecurityLevel::High);
        assert_eq!(cred.encrypted_data, vec![1, 2, 3]);
        assert!(cred.is_active);
        assert!(!cred.is_favorite);
        assert!(cred.tags.is_empty());
        assert!(cred.metadata.is_empty());
    }

    #[test]
    fn credential_tag_operations_are_idempotent() {
        let identity_id = Uuid::new_v4();
        let mut cred = Credential::new(
            identity_id,
            "GitHub".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1],
            None,
        );
        cred.tags.clear();

        cred.add_tag("work".to_string());
        cred.add_tag("work".to_string());
        assert_eq!(cred.tags, vec!["work".to_string()]);

        cred.remove_tag("work");
        assert!(cred.tags.is_empty());
    }

    #[test]
    fn credential_metadata_roundtrip() {
        let identity_id = Uuid::new_v4();
        let mut cred = Credential::new(
            identity_id,
            "GitHub".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1],
            None,
        );
        cred.metadata.clear();

        cred.set_metadata("env".to_string(), "prod".to_string());
        assert_eq!(cred.get_metadata("env").map(|s| s.as_str()), Some("prod"));

        cred.remove_metadata("env");
        assert!(cred.get_metadata("env").is_none());
    }

    #[test]
    fn credential_mark_accessed_sets_timestamp() {
        let identity_id = Uuid::new_v4();
        let mut cred = Credential::new(
            identity_id,
            "GitHub".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1],
            None,
        );

        assert!(cred.last_accessed.is_none());
        cred.mark_accessed();
        assert!(cred.last_accessed.is_some());
    }

    #[test]
    fn credential_data_bincode_roundtrip() {
        let data = CredentialData::Password(PasswordCredentialData {
            password: "p@ss".to_string(),
            email: Some("alice@example.com".to_string()),
            security_questions: vec![SecurityQuestion {
                question: "q".to_string(),
                answer: "a".to_string(),
            }],
        });

        let bytes = data.to_bytes().unwrap();
        let decoded = CredentialData::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, CredentialData::Password(_)));
    }

    #[test]
    fn credential_type_display_remaining_values() {
        assert_eq!(CredentialType::ApiKey.to_string(), "ApiKey");
        assert_eq!(CredentialType::BankCard.to_string(), "BankCard");
        assert_eq!(CredentialType::GameAccount.to_string(), "GameAccount");
        assert_eq!(CredentialType::ServerConfig.to_string(), "ServerConfig");
        assert_eq!(CredentialType::Certificate.to_string(), "Certificate");
        assert_eq!(CredentialType::SecureNote.to_string(), "SecureNote");
        assert_eq!(CredentialType::Identity.to_string(), "Identity");
        assert_eq!(
            CredentialType::SoftwareLicense.to_string(),
            "SoftwareLicense"
        );
    }

    #[test]
    fn credential_data_bincode_roundtrip_all_variants() {
        let variants = vec![
            CredentialData::CryptoWallet(CryptoWalletData {
                wallet_type: "hd".to_string(),
                mnemonic_phrase: Some("word word word".to_string()),
                private_key: Some("hex".to_string()),
                public_key: "pub".to_string(),
                address: "0xabc".to_string(),
                network: "ethereum".to_string(),
            }),
            CredentialData::SshKey(SshKeyData {
                private_key: "priv".to_string(),
                public_key: "pub".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: Some("phrase".to_string()),
            }),
            CredentialData::ApiKey(ApiKeyData {
                api_key: "key".to_string(),
                api_secret: Some("secret".to_string()),
                token: Some("token".to_string()),
                permissions: vec!["read".to_string(), "write".to_string()],
                expires_at: Some(chrono::Utc::now()),
            }),
            CredentialData::BankCard(BankCardData {
                card_number: "4242".to_string(),
                cardholder_name: "Alice".to_string(),
                expiry_date: "12/30".to_string(),
                cvv: "123".to_string(),
                bank_name: "Example Bank".to_string(),
                card_type: "visa".to_string(),
            }),
            CredentialData::ServerConfig(ServerConfigData {
                hostname: "server.example.com".to_string(),
                ip_address: Some("10.0.0.2".to_string()),
                port: 22,
                protocol: "ssh".to_string(),
                username: "deploy".to_string(),
                password: None,
                ssh_key_id: Some(Uuid::new_v4()),
                additional_config: HashMap::new(),
            }),
            CredentialData::TwoFactor(TwoFactorData {
                secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                issuer: "Example".to_string(),
                account_name: "alice@example.com".to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                period: 30,
            }),
            CredentialData::Raw(vec![1, 2, 3]),
            CredentialData::GameToken(GameTokenData {
                provider: "steam_guard".to_string(),
                secret_key: "abcdefghijklmnopqrst".to_string(),
                issuer: "Steam".to_string(),
                account_name: "alice".to_string(),
                url: Some("https://steamcommunity.com".to_string()),
            }),
            CredentialData::SecureNote(SecureNoteData {
                note: "recovery codes:\n1111-2222\n3333-4444".to_string(),
            }),
            CredentialData::Identity(IdentityData {
                first_name: "Alice".to_string(),
                last_name: "Zhang".to_string(),
                username: Some("alicez".to_string()),
                email: Some("alice@example.com".to_string()),
                phone: Some("+86 13800000000".to_string()),
                birthday: Some("1990-01-31".to_string()),
                address: Some("1 Main St\nBeijing".to_string()),
                id_number: Some("110101199001310011".to_string()),
                passport_number: Some("E12345678".to_string()),
                driver_license: None,
                tax_id: None,
                organization: Some("Example Inc".to_string()),
                job_title: Some("Engineer".to_string()),
            }),
            CredentialData::SoftwareLicense(SoftwareLicenseData {
                license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
                version: Some("2.1.0".to_string()),
                publisher: Some("Example Soft".to_string()),
                purchase_date: Some("2024-05-01".to_string()),
                order_number: Some("ORD-42".to_string()),
                support_email: Some("support@example.com".to_string()),
                download_url: Some("https://example.com/dl".to_string()),
                seats: Some(3),
                valid_until: Some("2027-05-01".to_string()),
            }),
        ];

        for data in variants {
            let bytes = data.to_bytes().unwrap();
            let decoded = CredentialData::from_bytes(&bytes).unwrap();
            assert_eq!(
                std::mem::discriminant(&decoded),
                std::mem::discriminant(&data)
            );
        }
    }

    #[test]
    fn credential_data_from_bytes_rejects_garbage() {
        assert!(CredentialData::from_bytes(b"not bincode").is_err());
    }

    /// 既有变体的 bincode 编码必须逐字节稳定（变体索引 = 枚举序号），
    /// 新变体只能追加在末尾——否则旧密文全部变砖。
    #[test]
    fn credential_data_bincode_variant_indices_are_stable() {
        // Raw 是追加 GameToken 之前的最后一个变体（索引 7；Vec 带 u64 长度前缀）
        assert_eq!(
            CredentialData::Raw(vec![1, 2, 3]).to_bytes().unwrap(),
            vec![7, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3]
        );
        // GameToken 追加在末尾，索引 8
        let game = CredentialData::GameToken(GameTokenData {
            provider: "steam_guard".to_string(),
            secret_key: "s".to_string(),
            issuer: "i".to_string(),
            account_name: "a".to_string(),
            url: None,
        })
        .to_bytes()
        .unwrap();
        assert_eq!(&game[..4], &[8, 0, 0, 0]);
        let decoded = CredentialData::from_bytes(&game).unwrap();
        assert!(matches!(decoded, CredentialData::GameToken(_)));
        // SecureNote 追加在末尾，索引 9（String 带 u64 长度前缀）
        let note = CredentialData::SecureNote(SecureNoteData {
            note: "abc".to_string(),
        })
        .to_bytes()
        .unwrap();
        assert_eq!(&note[..4], &[9, 0, 0, 0]);
        let decoded = CredentialData::from_bytes(&note).unwrap();
        assert!(matches!(decoded, CredentialData::SecureNote(_)));
        // Identity 追加在末尾，索引 10
        let identity = CredentialData::Identity(IdentityData {
            first_name: "a".to_string(),
            last_name: "b".to_string(),
            username: None,
            email: None,
            phone: None,
            birthday: None,
            address: None,
            id_number: None,
            passport_number: None,
            driver_license: None,
            tax_id: None,
            organization: None,
            job_title: None,
        })
        .to_bytes()
        .unwrap();
        assert_eq!(&identity[..4], &[10, 0, 0, 0]);
        let decoded = CredentialData::from_bytes(&identity).unwrap();
        assert!(matches!(decoded, CredentialData::Identity(_)));
        // SoftwareLicense 追加在末尾，索引 11
        let license = CredentialData::SoftwareLicense(SoftwareLicenseData {
            license_key: "k".to_string(),
            version: None,
            publisher: None,
            purchase_date: None,
            order_number: None,
            support_email: None,
            download_url: None,
            seats: None,
            valid_until: None,
        })
        .to_bytes()
        .unwrap();
        assert_eq!(&license[..4], &[11, 0, 0, 0]);
        let decoded = CredentialData::from_bytes(&license).unwrap();
        assert!(matches!(decoded, CredentialData::SoftwareLicense(_)));
    }

    #[test]
    fn credential_serde_roundtrip() {
        let mut cred = Credential::new(
            Uuid::new_v4(),
            "Example".to_string(),
            CredentialType::ApiKey,
            SecurityLevel::Critical,
            vec![1, 2, 3],
            Some(vec![9, 9]),
        );
        cred.url = Some("https://example.com".to_string());
        cred.username = Some("alice".to_string());
        cred.notes = Some("rotates quarterly".to_string());
        cred.tags = vec!["work".to_string()];
        cred.mark_accessed();

        let json = serde_json::to_string(&cred).unwrap();
        let decoded: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, cred.id);
        assert_eq!(decoded.wrapped_item_key, Some(vec![9, 9]));
        assert_eq!(decoded.last_accessed, cred.last_accessed);
        assert_eq!(decoded.credential_type, CredentialType::ApiKey);
    }

    #[test]
    fn credential_remove_missing_tag_and_metadata_are_noop() {
        let mut cred = Credential::new(
            Uuid::new_v4(),
            "Example".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1],
            None,
        );
        cred.tags.clear();
        cred.metadata.clear();

        let before = cred.updated_at;
        cred.remove_tag("missing");
        cred.remove_metadata("missing");
        assert!(cred.tags.is_empty());
        assert!(cred.get_metadata("missing").is_none());
        assert_eq!(cred.updated_at, before);
    }

    #[test]
    fn credential_touch_refreshes_updated_at() {
        let mut cred = Credential::new(
            Uuid::new_v4(),
            "Example".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1],
            None,
        );

        let before = cred.updated_at;
        cred.touch();
        assert!(cred.updated_at >= before);
    }

    // FromStr 与 Display/存储层字符串对齐：已知串逐一归位，未知串归入
    // Custom（与 row_to_credential 同一策略）。
    #[test]
    fn credential_type_from_str_roundtrips_all_known_variants() {
        for name in [
            "Password",
            "CryptoWallet",
            "SshKey",
            "ApiKey",
            "BankCard",
            "GameAccount",
            "ServerConfig",
            "Certificate",
            "TwoFactor",
            "SecureNote",
            "Identity",
            "SoftwareLicense",
        ] {
            let parsed: CredentialType = name.parse().unwrap();
            assert_eq!(parsed.to_string(), name, "roundtrip must hold for {name}");
        }

        // 未知串不报错，归入 Custom 并保留原文
        let custom: CredentialType = "LoyaltyCard".parse().unwrap();
        assert_eq!(custom, CredentialType::Custom("LoyaltyCard".to_string()));
        assert_eq!(custom.to_string(), "LoyaltyCard");
    }

    #[test]
    fn security_level_from_str_rejects_unknown() {
        let low: SecurityLevel = "Low".parse().unwrap();
        assert_eq!(low, SecurityLevel::Low);
        assert_eq!(
            "Critical".parse::<SecurityLevel>().unwrap(),
            SecurityLevel::Critical
        );
        assert_eq!(
            "High".parse::<SecurityLevel>().unwrap(),
            SecurityLevel::High
        );
        assert_eq!(
            "Medium".parse::<SecurityLevel>().unwrap(),
            SecurityLevel::Medium
        );

        let err = "extreme".parse::<SecurityLevel>().unwrap_err();
        assert_eq!(err, "Unknown security level: extreme");
    }

    // serde 派生覆盖全部字段：is_active/is_favorite/metadata 也要在
    // roundtrip 里断言（序列化/反序列化的字段赋值行才全部落地）。
    #[test]
    fn credential_serde_roundtrip_preserves_every_field() {
        let mut cred = Credential::new(
            Uuid::new_v4(),
            "Full field row".to_string(),
            CredentialType::SoftwareLicense,
            SecurityLevel::Low,
            vec![7, 8, 9],
            Some(vec![1, 1]),
        );
        cred.url = Some("https://example.com".to_string());
        cred.username = Some("alice".to_string());
        cred.notes = Some("perpetual license".to_string());
        cred.tags = vec!["office".to_string(), "license".to_string()];
        cred.set_metadata("vendor".to_string(), "acme".to_string());
        cred.mark_accessed();
        cred.is_active = false;
        cred.is_favorite = true;

        let json = serde_json::to_string(&cred).unwrap();
        let decoded: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, cred.id);
        assert_eq!(decoded.identity_id, cred.identity_id);
        assert_eq!(decoded.name, cred.name);
        assert_eq!(decoded.credential_type, CredentialType::SoftwareLicense);
        assert_eq!(decoded.security_level, SecurityLevel::Low);
        assert_eq!(decoded.url, cred.url);
        assert_eq!(decoded.username, cred.username);
        assert_eq!(decoded.encrypted_data, cred.encrypted_data);
        assert_eq!(decoded.wrapped_item_key, Some(vec![1, 1]));
        assert_eq!(decoded.notes, cred.notes);
        assert_eq!(decoded.tags, cred.tags);
        assert_eq!(decoded.metadata, cred.metadata);
        assert_eq!(decoded.created_at, cred.created_at);
        assert_eq!(decoded.updated_at, cred.updated_at);
        assert_eq!(decoded.last_accessed, cred.last_accessed);
        assert!(!decoded.is_active);
        assert!(decoded.is_favorite);
    }

    #[test]
    fn bank_card_data_serde_roundtrip() {
        let card = BankCardData {
            card_number: "4111 1111 1111 1111".to_string(),
            cardholder_name: "Alice".to_string(),
            expiry_date: "09/28".to_string(),
            cvv: "123".to_string(),
            bank_name: "Test Bank".to_string(),
            card_type: "visa".to_string(),
        };

        let json = serde_json::to_string(&card).unwrap();
        let decoded: BankCardData = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.card_number, card.card_number);
        assert_eq!(decoded.cardholder_name, card.cardholder_name);
        assert_eq!(decoded.expiry_date, card.expiry_date);
        assert_eq!(decoded.cvv, card.cvv);
        assert_eq!(decoded.bank_name, card.bank_name);
        assert_eq!(decoded.card_type, card.card_type);
    }
}
