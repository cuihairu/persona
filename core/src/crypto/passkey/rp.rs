use crate::{PersonaError, PersonaResult};

/// Extract and lowercase the host component of a WebAuthn origin.
pub(super) fn origin_host(origin: &str) -> PersonaResult<String> {
    let after_scheme = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| PersonaError::InvalidInput(format!("Invalid origin: {origin}")))?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return Err(PersonaError::InvalidInput(format!(
            "Origin has no host: {origin}"
        )));
    }
    Ok(host.to_ascii_lowercase())
}

/// Validate an rp_id: a registrable-domain-looking hostname or localhost.
pub(super) fn validate_rp_id(rp_id: &str) -> PersonaResult<String> {
    let rp_id = rp_id.trim().to_ascii_lowercase();
    if rp_id.is_empty() || rp_id.starts_with('.') || rp_id.ends_with('.') {
        return Err(PersonaError::InvalidInput(format!(
            "Invalid rp_id: {rp_id}"
        )));
    }
    if rp_id.contains("://") || rp_id.contains('/') || rp_id.contains(':') {
        return Err(PersonaError::InvalidInput(format!(
            "rp_id must be a bare hostname, got: {rp_id}"
        )));
    }
    // A public-suffix-only rp_id (e.g. "com") would let any registrant of a
    // subdomain match; browsers refuse such rp_ids, so do we.
    if !rp_id.contains('.') && rp_id != "localhost" {
        return Err(PersonaError::InvalidInput(format!(
            "rp_id must be a registrable domain or localhost, got: {rp_id}"
        )));
    }
    Ok(rp_id)
}

/// Validate the WebAuthn origin ↔ rp_id relationship: the origin's effective
/// domain must equal the rp_id or be a subdomain of it (WebAuthn §5.4).
/// Note: without a full Public Suffix List this is the registrable-suffix
/// approximation; rp_ids on public suffixes are rejected outright above.
pub fn validate_origin_matches_rp_id(origin: &str, rp_id: &str) -> PersonaResult<()> {
    let rp_id = validate_rp_id(rp_id)?;
    let host = origin_host(origin)?;
    if host == rp_id || host.ends_with(&format!(".{rp_id}")) {
        Ok(())
    } else {
        Err(PersonaError::InvalidInput(format!(
            "Origin {origin} does not match rp_id {rp_id}"
        )))
    }
}
