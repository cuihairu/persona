use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256).
/// The only algorithm Persona's software authenticator supports in v1,
/// per the WebAuthn Level 2 requirements on RPs.
pub const ES256_ALG: i64 = -7;

/// A WebAuthn passkey stored as identity-scoped identity material.
///
/// The private key is encrypted with a per-item key wrapped by the master
/// key (`encrypted_private_key` + `wrapped_item_key`), matching the vault's
/// key hierarchy. Everything else is non-secret metadata kept searchable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasskeyItem {
    /// Unique identifier
    pub id: Uuid,

    /// Identity this passkey belongs to
    pub identity_id: Uuid,

    /// Relying party ID (effective domain, e.g. "github.com")
    pub rp_id: String,

    /// Human-readable relying party name (from creation options)
    pub rp_name: Option<String>,

    /// RP-generated user handle, stored verbatim
    pub user_handle: Vec<u8>,

    /// Login name (display/search only)
    pub user_name: Option<String>,

    /// Display name (display/search only)
    pub user_display_name: Option<String>,

    /// WebAuthn credential ID (32 random bytes for Persona's software authenticator)
    pub credential_id: Vec<u8>,

    /// Encrypted ECDSA P-256 private scalar
    pub encrypted_private_key: Vec<u8>,

    /// Item key wrapped by the master key (unwraps `encrypted_private_key`)
    pub wrapped_item_key: Vec<u8>,

    /// Public key in COSE_Key form (attested credential data at registration)
    pub public_key_cose: Vec<u8>,

    /// COSE algorithm identifier (ES256 = -7)
    pub alg: i64,

    /// Signature counter. Persona is a software authenticator and keeps it at 0
    /// (same as other software passkey providers); no clone detection.
    pub sign_count: u32,

    /// Whether user verification was performed when the credential was created
    pub uv_initialized: bool,

    /// Whether this passkey may leave the vault via export/backup
    pub export_allowed: bool,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last assertion timestamp
    pub last_used_at: Option<DateTime<Utc>>,

    /// User tags for organization
    pub tags: Vec<String>,
}

impl PasskeyItem {
    /// The AAGUID is a fixed Persona-specific identifier so relying parties
    /// can recognize the software authenticator. No attestation is produced.
    pub fn aaguid() -> [u8; 16] {
        [
            0x50, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x50, 0x61, 0x73, 0x73, 0x6b, 0x65, 0x79,
            0x30, 0x31,
        ]
    }

    pub fn new(
        identity_id: Uuid,
        rp_id: String,
        user_handle: Vec<u8>,
        credential_id: Vec<u8>,
        encrypted_private_key: Vec<u8>,
        wrapped_item_key: Vec<u8>,
        public_key_cose: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            identity_id,
            rp_id,
            rp_name: None,
            user_handle,
            user_name: None,
            user_display_name: None,
            credential_id,
            encrypted_private_key,
            wrapped_item_key,
            public_key_cose,
            alg: ES256_ALG,
            sign_count: 0,
            uv_initialized: false,
            export_allowed: true,
            created_at: Utc::now(),
            last_used_at: None,
            tags: Vec::new(),
        }
    }
}
