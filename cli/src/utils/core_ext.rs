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
impl<T> CoreResultExt<T>
    for std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>
{
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

#[cfg(test)]
mod tests {
    use super::*;
    use persona_core::PersonaError;
    use std::error::Error as StdError;

    #[test]
    fn anyhow_result_passes_through_ok_and_err() {
        let ok: Result<i32> = Ok(7);
        assert_eq!(ok.into_anyhow().unwrap(), 7);

        let err: Result<i32> = Err(anyhow!("plain failure"));
        let message = err.into_anyhow().unwrap_err().to_string();
        assert_eq!(message, "plain failure");
    }

    #[test]
    fn boxed_error_result_maps_into_anyhow() {
        let boxed_err: Box<dyn StdError + Send + Sync> =
            Box::new(std::io::Error::other("io went wrong"));

        let ok: std::result::Result<i32, Box<dyn StdError + Send + Sync>> = Ok(3);
        assert_eq!(ok.into_anyhow().unwrap(), 3);

        let err: std::result::Result<i32, Box<dyn StdError + Send + Sync>> = Err(boxed_err);
        let message = err.into_anyhow().unwrap_err().to_string();
        assert_eq!(message, "io went wrong");
    }

    #[test]
    fn persona_error_result_maps_into_anyhow() {
        let ok: std::result::Result<i32, PersonaError> = Ok(5);
        assert_eq!(ok.into_anyhow().unwrap(), 5);

        let err: std::result::Result<i32, PersonaError> =
            Err(PersonaError::InvalidInput("bad input".to_string()));
        let message = err.into_anyhow().unwrap_err().to_string();
        assert_eq!(message, "Invalid input: bad input");
    }
}
