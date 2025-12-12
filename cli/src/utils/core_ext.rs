use anyhow::{anyhow, Result};

/// Helper trait to convert core `Result` types into `anyhow::Result`.
pub trait CoreResultExt<T> {
    fn into_anyhow(self) -> Result<T>;
}

// For already anyhow::Result - just pass through
impl<T> CoreResultExt<T> for Result<T> {
    fn into_anyhow(self) -> Result<T> {
        self
    }
}

// For Box<dyn std::error::Error>
impl<T> CoreResultExt<T> for std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>> {
    fn into_anyhow(self) -> Result<T> {
        self.map_err(|e| anyhow!(e.to_string()))
    }
}

// For PersonaError (assuming it exists)
impl<T> CoreResultExt<T> for std::result::Result<T, persona_core::PersonaError> {
    fn into_anyhow(self) -> Result<T> {
        self.map_err(|e| anyhow!(e.to_string()))
    }
}
