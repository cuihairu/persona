use anyhow::{anyhow, Result};

/// Helper trait to convert core `Result` types into `anyhow::Result`.
pub trait CoreResultExt<T> {
    fn into_anyhow(self) -> Result<T>;
}

impl<T> CoreResultExt<T> for Result<T, Box<dyn std::error::Error + Send + Sync + 'static>> {
    fn into_anyhow(self) -> Result<T> {
        self.map_err(|e| anyhow!(e.to_string()))
    }
}
