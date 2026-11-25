//! Persona Core Library
//!
//! This crate provides the core functionality for the Persona digital identity management system,
//! including cryptographic operations, secure storage, and identity management.

#[cfg(feature = "accounts")]
pub mod accounts;
pub mod auth;
pub mod authz;
#[cfg(feature = "backup")]
pub mod backup;
pub mod breach;
pub mod connect;
pub mod context;
pub mod crypto;
pub mod custom_fields;
pub mod events;
#[cfg(feature = "favicon")]
pub mod favicon;
pub mod health;
pub mod import_1pux;
pub mod import_generic;
pub mod import_mafile;
pub mod logging;
pub mod models;
pub mod password;
pub mod service;
#[cfg(unix)]
pub mod socket;
pub mod storage;
pub mod sync;
#[cfg(feature = "backup")]
pub mod travel;

// Re-export commonly used types
// Explicit single items instead of `accounts::*`: `auth::*` already re-exports a same-named
// module `remote`, which would cause a glob collision (ambiguous_glob_reexports). Wire types
// go through the full path `persona_core::accounts::remote::*`.
#[cfg(feature = "accounts")]
pub use accounts::remote::AccountsApi;
pub use auth::*;
pub use breach::*;
pub use crypto::*;
pub use events::*;
pub use health::*;
pub use import_1pux::*;
pub use import_generic::*;
pub use import_mafile::*;
pub use logging::*;

// Selective re-exports from models to avoid conflicts
pub use models::audit_log::*;
pub use models::auto_lock_policy::*;
pub use models::change_history::*;
pub use models::credential::*;
pub use models::identity::*;
pub use models::passkey::*;
pub use models::workspace::*;

// Selective re-exports from storage to avoid conflicts
pub use storage::blob::*;
pub use storage::database::*;
pub use storage::filesystem::*;
pub use storage::repository::*;
pub use storage::user_auth::*;

pub use password::*;
pub use service::*;
#[cfg(feature = "backup")]
pub use travel::{TravelCounts, TravelStatus};

/// Core result type used throughout the library
pub type Result<T> = anyhow::Result<T>;

/// Persona-specific result type for better error handling
pub type PersonaResult<T> = std::result::Result<T, PersonaError>;

/// Core error type for the Persona system
#[derive(Debug, thiserror::Error)]
pub enum PersonaError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Re-authentication required: {0}")]
    ReauthRequired(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),

    #[error("Storage operation failed: {0}")]
    StorageError(String),

    #[error("Database operation failed: {0}")]
    Database(String),

    #[error("IO operation failed: {0}")]
    Io(String),

    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    /// Travel mode is active (operations incompatible with the wrapped key in the sidecar,
    /// such as password changes, are rejected; clients should prompt the user to exit travel mode first)
    #[error("Travel mode is active: {0}")]
    TravelModeActive(String),

    /// The vault is locked; the Connect automation data plane returns 503 on this
    /// (CONNECT_AUTOMATION_DESIGN DR-4: unlocking restores service, no token quota deducted).
    #[error("Vault is locked: {0}")]
    VaultLocked(String),

    /// Concurrent exclusive-operation conflict: the epoch optimistic lock on group key rotation
    /// missed (another device rotated first). Clients should re-read state and retry
    /// (E2EE_SYNC_DESIGN §11-2).
    #[error("Concurrent operation conflict: {0}")]
    ConcurrentConflict(String),

    /// Authorization denied: the unified authorization entry point (core/src/authz.rs) returned Denied.
    /// Distinct from authentication failure (AuthenticationFailed, identity did not pass) —
    /// here the identity passed but the action is not permitted.
    #[error("Operation not allowed: {0}")]
    Forbidden(String),
}

// Implement From conversions for common error types
impl From<sqlx::Error> for PersonaError {
    fn from(err: sqlx::Error) -> Self {
        PersonaError::Database(err.to_string())
    }
}

impl From<serde_json::Error> for PersonaError {
    fn from(err: serde_json::Error) -> Self {
        PersonaError::InvalidInput(err.to_string())
    }
}

impl From<std::io::Error> for PersonaError {
    fn from(err: std::io::Error) -> Self {
        PersonaError::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The crypto error triplets (CryptographicError/Crypto/Cryptography, with identical
    // Display text) have been merged into a single CryptographicError — construction sites
    // were mechanically renamed with the merge; this pins the post-merge contract: a unique
    // variant + Display prefix + pass-through thiserror Source semantics
    // (no inner source; the top of the chain is the variant itself).
    #[test]
    fn crypto_error_is_a_single_variant_with_stable_display() {
        let err = PersonaError::CryptographicError("gcm seal failed".to_string());
        assert_eq!(
            err.to_string(),
            "Cryptographic operation failed: gcm seal failed"
        );
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn persona_error_display_matches_variants() {
        let cases = [
            (
                PersonaError::AuthenticationFailed("locked".into()),
                "Authentication failed: locked",
            ),
            (
                PersonaError::CryptographicError("aes".into()),
                "Cryptographic operation failed: aes",
            ),
            (
                PersonaError::StorageError("blob".into()),
                "Storage operation failed: blob",
            ),
            (
                PersonaError::Database("sql".into()),
                "Database operation failed: sql",
            ),
            (PersonaError::Io("disk".into()), "IO operation failed: disk"),
            (
                PersonaError::IdentityNotFound("id-1".into()),
                "Identity not found: id-1",
            ),
            (
                PersonaError::InvalidInput("bad".into()),
                "Invalid input: bad",
            ),
            (
                PersonaError::ConfigurationError("cfg".into()),
                "Configuration error: cfg",
            ),
            (
                PersonaError::NotFound("gone".into()),
                "Resource not found: gone",
            ),
            (PersonaError::Validation("v".into()), "Validation error: v"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn persona_error_from_conversions() {
        let db: PersonaError = sqlx::Error::RowNotFound.into();
        assert!(matches!(db, PersonaError::Database(_)));

        let json: PersonaError = serde_json::from_str::<Vec<u8>>("{").unwrap_err().into();
        assert!(matches!(json, PersonaError::InvalidInput(_)));

        let io: PersonaError = std::io::Error::other("boom").into();
        assert!(matches!(io, PersonaError::Io(_)));
    }

    #[test]
    #[allow(clippy::unnecessary_literal_unwrap)] // unwrapping a literal is the point of this test
    fn result_type_aliases_are_compatible() {
        // Result<T> is anyhow-based; PersonaResult<T> carries PersonaError.
        let ok: Result<u8> = Ok(1);
        assert_eq!(ok.unwrap(), 1);

        let err: PersonaResult<u8> = Err(PersonaError::NotFound("x".into()));
        assert!(err.is_err());
    }
}
