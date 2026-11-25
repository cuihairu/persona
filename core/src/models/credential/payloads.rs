//! Multi-type credential payloads: the plaintext data structures for each
//! type, the AUDIT-021 handwritten redacted Debug impls, the `CredentialData`
//! externally-tagged enum and its bincode codec (with legacy-tolerant reads).

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
    /// BIP-39 25th word (optional); stored separately from the mnemonic, and
    /// equally high-sensitivity
    #[serde(default)]
    pub bip39_passphrase: Option<String>,
    /// Argon2id PHC hash of an item-level independent password (optional):
    /// revealing seed material (mnemonic/private key/25th word) requires an
    /// extra comparison — a second factor against prying while unlocked. The
    /// hash is stored with the item ciphertext and does not change the
    /// encryption envelope or the sync format.
    #[serde(default)]
    pub item_password_hash: Option<String>,
    /// Item password hint (plaintext, low sensitivity — a recall aid, carries
    /// no security strength)
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
    /// HOTP (RFC 4226) switch: None/false = time-based TOTP (RFC 6238),
    /// Some(true) = counter-based HOTP. For the field-addition rule see the
    /// comment above GameTokenData — new fields may only be appended at the
    /// end as `#[serde(default)] Option`; legacy six-field ciphertexts are
    /// migrated back via `CredentialData::from_bytes`'s legacy-tolerant read.
    #[serde(default)]
    pub hotp: Option<bool>,
    /// HOTP initial counter (the `counter` parameter of the otpauth://hotp/
    /// URI). When generating codes the caller passes an explicit counter for
    /// the server's current window (CLI: `--counter`); this field is only the
    /// default starting point, and counter increments are not persisted.
    #[serde(default)]
    pub initial_counter: Option<u64>,
}

/// Game token data for vendor algorithms outside RFC 4226/6238
/// (e.g. Steam Guard; providers are dispatched in `core::crypto::game_token`)
///
/// The field-addition rule mirrors the enum variants: new fields may only be
/// appended at the end as `#[serde(default)] Option`, and legacy payloads are
/// migrated back via `CredentialData::from_bytes`'s legacy-tolerant read.
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
    /// Steam trade-confirmation HMAC key (SDA maFile `identity_secret`,
    /// standard base64). Not needed for login code generation; only mobile
    /// trade confirmations use it. Always None for non-Steam providers.
    #[serde(default)]
    pub identity_secret: Option<String>,
    /// SDA device identifier (maFile `device_id`, e.g. "mobile1234567")
    #[serde(default)]
    pub device_id: Option<String>,
}

/// The GameTokenData shape (five fields) from before `identity_secret` and
/// `device_id` were appended.
///
/// Private mirror struct used only by `CredentialData::from_bytes`'s
/// legacy-tolerant read: bincode has no default fields, so deserializing old
/// ciphertext into the new struct fails with an EOF at the tail — it must be
/// parsed against the old shape and then mapped (see `from_bytes`).
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LegacyGameTokenData {
    pub(super) provider: String,
    pub(super) secret_key: String,
    pub(super) issuer: String,
    pub(super) account_name: String,
    pub(super) url: Option<String>,
}

/// The old six-field TwoFactorData shape from before hotp/initial_counter were
/// appended. Private mirror struct used only by the legacy-tolerant read (same
/// standard as LegacyGameTokenData).
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LegacyTwoFactorData {
    pub(super) secret_key: String,
    pub(super) issuer: String,
    pub(super) account_name: String,
    pub(super) algorithm: String,
    pub(super) digits: u8,
    pub(super) period: u32,
}

// AUDIT-021: every secret-bearing data struct below gets a **handwritten,
// redacted Debug** — Debug must not be derived, so that no `{:?}`/dbg!/error
// chain can leak master passwords, SSH private keys, TOTP/HOTP seeds, API
// keys, card numbers/CVV, wallet mnemonics/private keys/xprv, sync/Bearer
// tokens or other secrets into logs, toasts, crash reports or test snapshots.
// Non-secret fields stay visible for diagnostics. The top-level Credential
// only stores `encrypted_data: Vec<u8>` (no plaintext), so what is protected
// here is the instant "after decryption, while formatted in memory". The
// synthetic canary regression test lives in core/tests/secret_canary.rs.

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

/// Aligned with 1Password's "Secure Note": a note entry encrypted as a whole.
///
/// Unlike the `Credential.notes` field (a **plaintext column** in the
/// credentials table, migration 001), this type's content is encrypted with a
/// per-item key via `encrypted_data`, unreadable at rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNoteData {
    /// Note body (plain text; no rich-text sections in the MVP)
    pub note: String,
}

/// Aligned with 1Password's "Identity": a personal identity information entry.
///
/// Sensitive fields such as ID numbers are encrypted with a per-item key via
/// `encrypted_data`; date-like fields stay free-form text (matching
/// 1Password's text fields, no parsing).
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityData {
    pub first_name: String,
    pub last_name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// Birthday (free-form, e.g. 1990-01-31)
    pub birthday: Option<String>,
    /// Multi-line mailing address
    pub address: Option<String>,
    /// ID number (national ID / SSN etc.)
    pub id_number: Option<String>,
    pub passport_number: Option<String>,
    pub driver_license: Option<String>,
    pub tax_id: Option<String>,
    pub organization: Option<String>,
    pub job_title: Option<String>,
}

/// Aligned with 1Password's "Software License": a software license entry.
///
/// `license_key` is the core sensitive field, encrypted with a per-item key
/// via `encrypted_data`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SoftwareLicenseData {
    pub license_key: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    /// Purchase date (free-form)
    pub purchase_date: Option<String>,
    pub order_number: Option<String>,
    pub support_email: Option<String>,
    pub download_url: Option<String>,
    /// Number of licensed seats
    pub seats: Option<u32>,
    /// License validity period (free-form)
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
/// bincode externally-tagged enum: new variants may only be appended at the
/// end, and existing variant indices are immutable — otherwise old ciphertexts
/// could no longer be deserialized.
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
    /// When deserialization against the current shape fails, it falls back to
    /// the legacy-tolerant reads (see
    /// [`Self::from_bytes_legacy_game_token`] and
    /// [`Self::from_bytes_legacy_two_factor`]); if both legacy paths fail the
    /// original error is returned, so a corrupted payload is never silently
    /// "repaired".
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        match bincode::deserialize(data) {
            Ok(parsed) => Ok(parsed),
            Err(e) => Self::from_bytes_legacy_game_token(data)
                .or_else(|| Self::from_bytes_legacy_two_factor(data))
                .ok_or(e),
        }
    }

    /// Legacy-tolerant read for ciphertext written before GameTokenData gained
    /// `identity_secret`/`device_id`.
    ///
    /// In the bincode externally-tagged enum, GameToken's variant index is 8
    /// (a u32 LE prefix); an old payload = 4 tag bytes + a five-field
    /// `LegacyGameTokenData`. Once recognized, it is first parsed against the
    /// old shape, and the parsed result is then **re-serialized and compared
    /// bit-for-bit with the original bytes** — accepted only when the whole
    /// payload is exactly the old shape, so corrupted data that merely begins
    /// with 0x08000000 is not mistaken for a token. When mapping, the new
    /// fields are set to None (they only get values after a Steam maFile import).
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

    /// Legacy-tolerant read for ciphertext written before TwoFactorData gained
    /// `hotp`/`initial_counter`.
    ///
    /// In the bincode externally-tagged enum, TwoFactor's variant index is 6
    /// (a u32 LE prefix); an old payload = 4 tag bytes + a six-field
    /// `LegacyTwoFactorData`. Same standard as GameToken: parse against the old
    /// shape first, then re-serialize and compare bit-for-bit — accepted only
    /// when the whole payload is exactly the old shape, so corrupted data that
    /// merely begins with 0x06000000 is not mistaken for TOTP. When mapping,
    /// the new fields are set to None (i.e. old entries are still time-based TOTP).
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
