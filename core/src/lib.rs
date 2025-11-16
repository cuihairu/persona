//! Persona Core Library
//!
//! This crate provides the core functionality for the Persona digital identity management system,
//! including cryptographic operations, secure storage, and identity management.

pub mod auth;
pub mod crypto;
pub mod models;
pub mod storage;
pub mod service;

// Re-export commonly used types
pub use models::*;
pub use auth::*;
pub use crypto::*;
pub use storage::*;
pub use service::*;

/// Core result type used throughout the library
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Core error type for the Persona system
#[derive(Debug, thiserror::Error)]
pub enum PersonaError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

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
}