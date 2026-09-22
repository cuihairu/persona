//! Connect token 形态、scope 三维与判定纯函数（DR-2）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::CredentialType;

/// token 明文前缀；无此前缀的呈现值直接判无效（不进哈希查表）。
pub const TOKEN_PREFIX: &str = "pconn_";

/// scope 可授权的条目类型。**敏感类型恒不在枚举里**：SSH key、crypto
/// wallet、custom 由排除法不可授权（passkey 不走 token 端点，见 DR-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectItemType {
    Password,
    ApiKey,
    /// TwoFactor 凭据（TOTP）。
    Totp,
    /// SecureNote 凭据。
    Note,
    BankCard,
    ServerConfig,
    Certificate,
    GameAccount,
    Identity,
    SoftwareLicense,
}

impl ConnectItemType {
    /// 从库内 [`CredentialType`] 折算到 scope 枚举；不在合法集的返回
    /// `None`（custom / ssh key / crypto wallet → 永不在 scope 内）。
    pub fn from_credential_type(t: &CredentialType) -> Option<Self> {
        let kind = match t {
            CredentialType::Password => Self::Password,
            CredentialType::ApiKey => Self::ApiKey,
            CredentialType::TwoFactor => Self::Totp,
            CredentialType::SecureNote => Self::Note,
            CredentialType::BankCard => Self::BankCard,
            CredentialType::ServerConfig => Self::ServerConfig,
            CredentialType::Certificate => Self::Certificate,
            CredentialType::GameAccount => Self::GameAccount,
            CredentialType::Identity => Self::Identity,
            CredentialType::SoftwareLicense => Self::SoftwareLicense,
            CredentialType::CryptoWallet | CredentialType::SshKey | CredentialType::Custom(_) => {
                return None
            }
        };
        Some(kind)
    }
}

/// 授权动作；起步唯一合法值 `read`（写路径未拍板，见设计稿 §9-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectVerb {
    Read,
}

/// 三维 scope。`identities` / `item_types` 为空 = 全部（显式选择，创建方
/// UI 需二次确认「可读取所有身份/类型」——语义与 1P 的 vault 授权一致，
/// 授权粒度是身份）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectTokenScope {
    #[serde(default)]
    pub identities: Vec<Uuid>,
    #[serde(default)]
    pub item_types: Vec<ConnectItemType>,
    #[serde(default)]
    pub verbs: Vec<ConnectVerb>,
}

impl ConnectTokenScope {
    /// 创建期校验：verbs 必须恰为 `[Read]`。数据面判定只认这个形态，
    /// 其他形态（空 verbs / 含未来枚举）在入库前就拒绝（fail-closed）。
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.verbs != vec![ConnectVerb::Read] {
            return Err("verbs must be exactly [read]");
        }
        Ok(())
    }

    pub fn allows_verb(&self, verb: ConnectVerb) -> bool {
        self.verbs.contains(&verb)
    }

    /// 身份授权：空列表 = 全部身份。
    pub fn allows_identity(&self, identity_id: &Uuid) -> bool {
        self.identities.is_empty() || self.identities.contains(identity_id)
    }

    /// 类型授权：空列表 = 全部**合法**类型；不在合法集的类型（custom/
    /// ssh/wallet）无论何时都不可见。
    pub fn allows_credential_type(&self, t: &CredentialType) -> bool {
        let Some(kind) = ConnectItemType::from_credential_type(t) else {
            return false;
        };
        self.item_types.is_empty() || self.item_types.contains(&kind)
    }
}

/// `connect_tokens` 库行（scope JSON 已解出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTokenRow {
    pub id: Uuid,
    pub label: String,
    /// SHA-256 hex；唯一，查表校验键。
    pub hash: String,
    /// 哈希前 8 字节 hex（16 字符）——列表识别/审计用，不泄露 token。
    pub fingerprint: String,
    pub scope: ConnectTokenScope,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ConnectTokenRow {
    pub fn revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// 生成一次 presented token：`pconn_` + 32 随机字节 base64url（无 padding）。
pub fn generate_token() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG unavailable");
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// 呈现值 → SHA-256 hex；无 `pconn_` 前缀的输入返回 `None`
/// （不浪费查表，也让「格式即无效」与「查无此 token」同形）。
pub fn hash_token(presented: &str) -> Option<String> {
    if !presented.starts_with(TOKEN_PREFIX) {
        return None;
    }
    let digest = Sha256::digest(presented.as_bytes());
    Some(hex::encode(digest))
}

/// 哈希前 8 字节的 hex 指纹。
pub fn fingerprint_from_hash(hash: &str) -> String {
    hash.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_have_prefix_and_entropy() {
        let a = generate_token();
        let b = generate_token();
        assert!(a.starts_with(TOKEN_PREFIX));
        assert_ne!(a, b, "OS RNG must not repeat within a test lifetime");
        // 32 字节 base64url 无 padding = 43 字符。
        assert_eq!(a[TOKEN_PREFIX.len()..].len(), 43);
    }

    #[test]
    fn hash_round_trips_and_rejects_missing_prefix() {
        let token = generate_token();
        let hash = hash_token(&token).unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_token(&token).unwrap(), "hash is deterministic");
        assert!(hash_token("no-prefix").is_none());
        assert!(hash_token("").is_none());
    }

    #[test]
    fn fingerprint_is_stable_prefix_of_hash() {
        let hash = hash_token(&generate_token()).unwrap();
        let fp = fingerprint_from_hash(&hash);
        assert_eq!(fp.len(), 16);
        assert!(hash.starts_with(&fp));
    }

    #[test]
    fn scope_allows_identity_is_empty_means_all() {
        let id = Uuid::new_v4();
        let mut scope = ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read],
        };
        assert!(scope.allows_identity(&id));
        scope.identities = vec![Uuid::new_v4()];
        assert!(!scope.allows_identity(&id), "unlisted identity is denied");
        scope.identities.push(id);
        assert!(scope.allows_identity(&id));
    }

    #[test]
    fn scope_never_allows_sensitive_types_even_when_empty() {
        // 空 item_types = 全部合法类型；ssh/wallet/custom 仍不可见。
        let scope = ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read],
        };
        assert!(scope.allows_credential_type(&CredentialType::Password));
        assert!(!scope.allows_credential_type(&CredentialType::SshKey));
        assert!(!scope.allows_credential_type(&CredentialType::CryptoWallet));
        assert!(!scope.allows_credential_type(&CredentialType::Custom("x".into())));
    }

    #[test]
    fn scope_json_round_trip_uses_wire_names() {
        let scope = ConnectTokenScope {
            identities: vec![Uuid::nil()],
            item_types: vec![ConnectItemType::Password, ConnectItemType::Totp],
            verbs: vec![ConnectVerb::Read],
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("\"totp\""), "wire name is snake_case: {json}");
        assert!(json.contains("\"read\""));
        let back: ConnectTokenScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, scope);
    }

    #[test]
    fn validate_requires_exactly_read_verb() {
        let ok = ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read],
        };
        assert!(ok.validate().is_ok());

        let no_verbs = ConnectTokenScope {
            verbs: vec![],
            ..ok.clone()
        };
        assert!(no_verbs.validate().is_err());
    }
}
