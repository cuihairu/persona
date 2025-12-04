//! Persona Core Library
//!
//! This crate provides the core functionality for the Persona digital identity management system,
//! including cryptographic operations, secure storage, and identity management.

pub mod auth;
pub mod crypto;
pub mod logging;
pub mod models;
pub mod password;
pub mod service;
pub mod storage;

// Re-export commonly used types
pub use auth::*;
pub use crypto::*;
pub use logging::*;

// Selective re-exports from models to avoid conflicts
pub use models::identity::*;
pub use models::credential::*;
pub use models::workspace::*;
pub use models::audit_log::*;
pub use models::auto_lock_policy::*;
pub use models::change_history::*;

// Selective re-exports from storage to avoid conflicts
pub use storage::database::*;
pub use storage::user_auth::*;
pub use storage::blob::*;
pub use storage::repository::*;
pub use storage::filesystem::*;

pub use password::*;
pub use service::*;

/// Core result type used throughout the library
pub type Result<T> = anyhow::Result<T>;

/// Persona-specific result type for better error handling
pub type PersonaResult<T> = std::result::Result<T, PersonaError>;

/// Core error type for the Persona system
#[derive(Debug, thiserror::Error)]
pub enum PersonaError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),

    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("Cryptographic operation failed: {0}")]
    Cryptography(String),

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

