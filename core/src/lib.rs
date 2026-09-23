//! Persona Core Library
//!
//! This crate provides the core functionality for the Persona digital identity management system,
//! including cryptographic operations, secure storage, and identity management.

pub mod auth;
#[cfg(feature = "backup")]
pub mod backup;
pub mod breach;
pub mod connect;
pub mod crypto;
pub mod events;
#[cfg(feature = "favicon")]
pub mod favicon;
pub mod health;
pub mod import_1pux;
pub mod logging;
pub mod models;
pub mod password;
pub mod service;
pub mod storage;
pub mod sync;
#[cfg(feature = "backup")]
pub mod travel;

// Re-export commonly used types
pub use auth::*;
pub use breach::*;
pub use crypto::*;
pub use events::*;
pub use health::*;
pub use import_1pux::*;
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

    /// 旅行模式进行中（改密等与 sidecar 中 wrapped key 不兼容的操作被拒；
    /// 客户端应提示先退出旅行模式）
    #[error("Travel mode is active: {0}")]
    TravelModeActive(String),

    /// 保险库处于锁定态，Connect 自动化数据面据此返回 503
    /// （CONNECT_AUTOMATION_DESIGN DR-4：解锁即恢复，token 不扣限额）。
    #[error("Vault is locked: {0}")]
    VaultLocked(String),
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

    // 加密错误三胞胎（CryptographicError/Crypto/Cryptography，Display 完全
    // 相同）已合并为单一 CryptographicError——构造点随合并机械重命名，这里
    // 钉住合并后的契约：唯一变体 + Display 前缀 + 透传 thiserror Source 语义
    // （无内层 source，链顶就是它自身）。
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
