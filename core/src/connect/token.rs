//! Connect token shape, the three scope dimensions, and the pure decision
//! functions (DR-2).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::CredentialType;

/// Plaintext prefix of a token; a presented value without it is judged
/// invalid outright (it never reaches the hash lookup).
pub const TOKEN_PREFIX: &str = "pconn_";

/// Item types that a scope may authorize. **Sensitive types never appear
/// in the enum**: SSH key, crypto wallet, and custom are excluded by
/// construction (passkey does not go through the token endpoint, see DR-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectItemType {
    Password,
    ApiKey,
    /// TwoFactor credential (TOTP).
    Totp,
    /// SecureNote credential.
    Note,
    BankCard,
    ServerConfig,
    Certificate,
    GameAccount,
    Identity,
    SoftwareLicense,
}

impl ConnectItemType {
    /// Map an in-database [`CredentialType`] onto the scope enum; types
    /// outside the valid set return `None` (custom / ssh key / crypto
    /// wallet → never in a scope).
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

/// Authorized actions; `read` reads the data plane, `use` consumes a
/// credential inside the database (signing / OTP-generation style
/// operations, not export — export is not a Connect verb). Write paths
/// are undecided and absent from the enum (design draft §9-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectVerb {
    Read,
    Use,
}

/// Three-dimensional scope. Empty `identities` / `item_types` = all (an
/// explicit choice, so the creating UI needs a second confirmation for
/// "may read all identities/types" — the semantics match the 1P vault
/// grant, whose unit of authorization is the identity).
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
    /// Creation-time validation: verbs must be non-empty and a subset of
    /// `{read, use}`. Data-plane decisions only accept this shape, and any
    /// other shape (empty verbs / containing future enum variants) is
    /// rejected before insertion (fail-closed). Export/signing cannot be
    /// granted via Connect (they are not Connect verbs).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.verbs.is_empty() {
            return Err("verbs must not be empty");
        }
        if self
            .verbs
            .iter()
            .any(|v| !matches!(v, ConnectVerb::Read | ConnectVerb::Use))
        {
            return Err("verbs must be a subset of [read, use]");
        }
        Ok(())
    }

    pub fn allows_verb(&self, verb: ConnectVerb) -> bool {
        self.verbs.contains(&verb)
    }

    /// Identity authorization: an empty list = all identities.
    pub fn allows_identity(&self, identity_id: &Uuid) -> bool {
        self.identities.is_empty() || self.identities.contains(identity_id)
    }

    /// Type authorization: an empty list = all **valid** types; types
    /// outside the valid set (custom / ssh / wallet) are never visible.
    pub fn allows_credential_type(&self, t: &CredentialType) -> bool {
        let Some(kind) = ConnectItemType::from_credential_type(t) else {
            return false;
        };
        self.item_types.is_empty() || self.item_types.contains(&kind)
    }
}

/// `connect_tokens` database row (scope JSON already decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTokenRow {
    pub id: Uuid,
    pub label: String,
    /// SHA-256 hex; unique, the lookup/verification key.
    pub hash: String,
    /// Hex of the hash's first 8 bytes (16 chars) — used for list
    /// identification/auditing, does not reveal the token.
    pub fingerprint: String,
    pub scope: ConnectTokenScope,
    /// Identity of the bound caller (migration 019); `None` = legacy data
    /// with no binding.
    pub principal: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// Expiration time (migration 019); `None` = never expires (legacy
    /// data keeps its semantics).
    pub expires_at: Option<DateTime<Utc>>,
}

impl ConnectTokenRow {
    pub fn revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Expiration check: once the expiration time has passed the token is
    /// invalid (rejected in the same shape as revocation at auth time).
    pub fn expired(&self) -> bool {
        self.expires_at.is_some_and(|t| t <= chrono::Utc::now())
    }
}

/// Generate a presented token: `pconn_` + 32 random bytes as base64url
/// (no padding).
pub fn generate_token() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG unavailable");
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Presented value → SHA-256 hex; an input without the `pconn_` prefix
/// returns `None` (saves the lookup and makes "invalid format" and "no
/// such token" indistinguishable).
pub fn hash_token(presented: &str) -> Option<String> {
    if !presented.starts_with(TOKEN_PREFIX) {
        return None;
    }
    let digest = Sha256::digest(presented.as_bytes());
    Some(hex::encode(digest))
}

/// Hex fingerprint of the hash's first 8 bytes.
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
        // 32 bytes base64url without padding = 43 chars.
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
        // Empty item_types = all valid types; ssh/wallet/custom remain invisible.
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
    fn validate_requires_nonempty_subset_of_read_use() {
        let ok = ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read],
        };
        assert!(ok.validate().is_ok());

        // Both read+use and use-only are valid (use is for future signing-style
        // endpoints; export cannot be granted).
        let read_use = ConnectTokenScope {
            verbs: vec![ConnectVerb::Read, ConnectVerb::Use],
            ..ok.clone()
        };
        assert!(read_use.validate().is_ok());
        let use_only = ConnectTokenScope {
            verbs: vec![ConnectVerb::Use],
            ..ok.clone()
        };
        assert!(use_only.validate().is_ok());

        let no_verbs = ConnectTokenScope {
            verbs: vec![],
            ..ok.clone()
        };
        assert!(no_verbs.validate().is_err());
    }

    #[test]
    fn expired_depends_on_expires_at_only() {
        let row = ConnectTokenRow {
            id: Uuid::new_v4(),
            label: "t".to_string(),
            hash: "h".to_string(),
            fingerprint: "f".to_string(),
            scope: ConnectTokenScope {
                identities: vec![],
                item_types: vec![],
                verbs: vec![ConnectVerb::Read],
            },
            principal: None,
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
            expires_at: None,
        };
        assert!(!row.expired(), "no expiry means never expires");

        let future = ConnectTokenRow {
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            ..row.clone()
        };
        assert!(!future.expired());

        let past = ConnectTokenRow {
            expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
            ..row.clone()
        };
        assert!(past.expired());
    }
}
