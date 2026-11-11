use crate::{PersonaError, PersonaResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::rp::origin_host;

/// The subset of `PublicKeyCredentialCreationOptions` the authenticator acts on.
#[derive(Debug, Clone)]
pub struct ParsedCreationOptions {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
}

/// Parse the JSON form of `PublicKeyCredentialCreationOptions` as forwarded by
/// the browser extension (bridge protocol v2 `passkey_create`).
///
/// Only ES256 is accepted — a request whose `pubKeyCredParams` lacks
/// `alg: -7` is rejected. When the RP omits `rp.id`, the origin's effective
/// host is used (WebAuthn §5.4). `user.id` must be a base64url string (the
/// extension serializes BufferSource bytes before forwarding).
pub fn parse_creation_options(
    options: &serde_json::Value,
    origin: &str,
) -> PersonaResult<ParsedCreationOptions> {
    let params = options.get("pubKeyCredParams").and_then(|v| v.as_array());
    let es256 = params.is_some_and(|params| {
        params.iter().any(|p| {
            p.get("type").and_then(|v| v.as_str()) == Some("public-key")
                && p.get("alg").and_then(|v| v.as_i64()) == Some(crate::models::passkey::ES256_ALG)
        })
    });
    if !es256 {
        return Err(PersonaError::InvalidInput(
            "passkey_alg_unsupported: pubKeyCredParams must include ES256 (alg -7)".to_string(),
        ));
    }

    let user = options
        .get("user")
        .ok_or_else(|| PersonaError::InvalidInput("invalid_request: missing user".to_string()))?;
    let user_id_b64 = user.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        PersonaError::InvalidInput(
            "invalid_request: user.id must be a base64url string".to_string(),
        )
    })?;
    let user_handle = decode_b64url(user_id_b64)?;
    if user_handle.is_empty() || user_handle.len() > 64 {
        return Err(PersonaError::InvalidInput(
            "invalid_request: user.id must be 1..=64 bytes (WebAuthn §5.4.2)".to_string(),
        ));
    }

    let rp_id = match options
        .get("rp")
        .and_then(|rp| rp.get("id"))
        .and_then(|v| v.as_str())
    {
        Some(id) => id.to_string(),
        None => origin_host(origin)?,
    };

    Ok(ParsedCreationOptions {
        rp_id,
        rp_name: options
            .get("rp")
            .and_then(|rp| rp.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        user_handle,
        user_name: user
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        user_display_name: user
            .get("displayName")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// Decode base64url with or without padding.
pub(super) fn decode_b64url(s: &str) -> PersonaResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .map_err(|e| PersonaError::InvalidInput(format!("invalid base64url encoding: {e}")))
}
