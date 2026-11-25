use anyhow::Result;

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

// For Box<dyn std::error::Error>. Use from_boxed to keep the concrete error type:
// `anyhow!(e.to_string())` would squash the error into a bare string, and every
// `downcast_ref::<E>()` further down the chain would come back empty.
impl<T> CoreResultExt<T>
    for std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>
{
    fn into_anyhow(self) -> Result<T> {
        self.map_err(anyhow::Error::from_boxed)
    }
}

// For PersonaError. The type must be preserved here too: on the CLI side (e.g. the
// bridge's passkey assertions) the code relies on downcast_ref::<PersonaError>() to
// recognize semantic variants.
impl<T> CoreResultExt<T> for std::result::Result<T, persona_core::PersonaError> {
    fn into_anyhow(self) -> Result<T> {
        self.map_err(anyhow::Error::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
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

    // The conversion must preserve the concrete error type: callers use
    // downcast_ref::<PersonaError>() along the chain to recognize semantic variants
    // (e.g. the bridge's passkey NotFound branch). If the implementation degenerated
    // into anyhow!(e.to_string()), this downcast would land on None — this test is
    // the tripwire for that.
    #[test]
    fn persona_error_survives_into_anyhow_for_downcast() {
        let err: std::result::Result<i32, PersonaError> =
            Err(PersonaError::NotFound("Passkey".to_string()));
        let anyhow_err = err.into_anyhow().unwrap_err();
        let pe = anyhow_err
            .downcast_ref::<PersonaError>()
            .expect("PersonaError must stay downcastable through into_anyhow");
        assert!(matches!(pe, PersonaError::NotFound(_)));
    }

    #[test]
    fn boxed_error_survives_into_anyhow_for_downcast() {
        use std::io;
        let boxed: Box<dyn StdError + Send + Sync> = Box::new(io::Error::other("disk full"));
        let err: std::result::Result<i32, Box<dyn StdError + Send + Sync>> = Err(boxed);
        let anyhow_err = err.into_anyhow().unwrap_err();
        // The type-preservation ceiling for the boxed path: anyhow::from_boxed keeps
        // the whole erased box (it does not degenerate into a string), and once the
        // Box is recovered std's downcast chain stays available inside it.
        let inner = anyhow_err
            .downcast_ref::<Box<dyn StdError + Send + Sync>>()
            .expect("boxed error must stay downcastable through into_anyhow");
        let io_err = (**inner)
            .downcast_ref::<io::Error>()
            .expect("std downcast chain stays intact inside the box");
        assert_eq!(io_err.to_string(), "disk full");
    }
}
