use crate::{PersonaError, PersonaResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::seed::random_bytes32;
use super::CLIENT_DATA_TYPE_GET;

/// Parsed fields of a clientDataJSON blob.
pub struct ParsedClientData {
    /// `origin` as claimed by the client
    pub origin: String,
    /// `challenge` verbatim (base64url string as serialized)
    pub challenge: String,
}

/// Build a clientDataJSON with a locally generated challenge. CLI-created
/// credentials have no live RP; the challenge only needs to be unpredictable.
pub fn local_client_data(ceremony: &str, origin: &str) -> PersonaResult<Vec<u8>> {
    let challenge = URL_SAFE_NO_PAD.encode(random_bytes32());
    Ok(
        format!(r#"{{"type":"{ceremony}","challenge":"{challenge}","origin":"{origin}"}}"#)
            .into_bytes(),
    )
}

/// Build a clientDataJSON for a self-test assertion ceremony (the challenge
/// is generated here; the RP normally provides it).
pub fn self_test_client_data(origin: &str) -> PersonaResult<Vec<u8>> {
    local_client_data(CLIENT_DATA_TYPE_GET, origin)
}

/// Parse and sanity-check a clientDataJSON blob: the `type` must match the
/// expected ceremony, `challenge` must be base64url, and the claimed `origin`
/// must equal the transport-verified origin. Returns the parsed fields; the
/// raw bytes stay the source of truth for hashing.
pub fn parse_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    origin: &str,
) -> PersonaResult<ParsedClientData> {
    let value: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid clientDataJSON: {e}")))?;

    let data_type = value
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PersonaError::InvalidInput("clientDataJSON missing type".to_string()))?;
    if data_type != expected_type {
        return Err(PersonaError::InvalidInput(format!(
            "clientDataJSON type mismatch: expected {expected_type}, got {data_type}"
        )));
    }

    let challenge = value
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PersonaError::InvalidInput("clientDataJSON missing challenge".to_string())
        })?;
    URL_SAFE_NO_PAD
        .decode(challenge)
        .map_err(|_| PersonaError::InvalidInput("challenge is not base64url".to_string()))?;

    let data_origin = value
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PersonaError::InvalidInput("clientDataJSON missing origin".to_string()))?;
    if !data_origin.eq_ignore_ascii_case(origin) {
        return Err(PersonaError::InvalidInput(format!(
            "clientDataJSON origin {data_origin} does not match request origin {origin}"
        )));
    }

    Ok(ParsedClientData {
        origin: data_origin.to_string(),
        challenge: challenge.to_string(),
    })
}
