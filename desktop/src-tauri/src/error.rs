//! Maps persona-core errors onto machine-readable error codes for the frontend to dispatch on.

use persona_core::PersonaError;

/// Error code: a sensitive operation requires re-authentication (frontend should show ReauthModal)
pub const CODE_REAUTH_REQUIRED: &str = "REAUTH_REQUIRED";
/// Error code: the service is locked (frontend should return to the unlock screen)
pub const CODE_SERVICE_LOCKED: &str = "SERVICE_LOCKED";
/// Error code: the master password must be rotated per policy (frontend should
/// guide the password-change flow)
pub const CODE_PASSWORD_CHANGE_REQUIRED: &str = "PASSWORD_CHANGE_REQUIRED";
/// Error code: the biometric-escrowed entry has been invalidated and deleted
/// (not configured / stale self-delete; frontend should refresh status to hide
/// the fingerprint button and suggest signing in with the master password)
pub const CODE_BIOMETRIC_RESET: &str = "BIOMETRIC_RESET";
/// Error code: the user cancelled in the biometric dialog (the wrapper was not
/// deleted; the frontend should silently return to the unlock screen and keep
/// the fingerprint button — not a failure, no error toast; design doc §3.4)
pub const CODE_BIOMETRIC_CANCELLED: &str = "BIOMETRIC_CANCELLED";
/// Error code: travel mode is active (operations such as password change that
/// are incompatible with the sidecar's wrapped key are rejected; frontend
/// should prompt to exit travel mode first)
pub const CODE_TRAVEL_MODE_ACTIVE: &str = "TRAVEL_MODE_ACTIVE";
/// Error code: conflicting concurrent exclusive operation (the group key
/// rotation's epoch optimistic lock missed — another device already rotated
/// first; frontend should note that sync state was updated and retry rotation later)
pub const CODE_CONCURRENT_CONFLICT: &str = "CONCURRENT_CONFLICT";
/// Error code: the wallet entry has its own password; revealing seed material
/// requires item_password (frontend should expand the entry password input)
pub const CODE_ITEM_PASSWORD_REQUIRED: &str = "ITEM_PASSWORD_REQUIRED";
/// Error code: the entry password does not match (frontend should show the
/// error and keep the input box)
pub const CODE_ITEM_PASSWORD_WRONG: &str = "ITEM_PASSWORD_WRONG";

/// Maps any service error to `(error_code, message)`.
///
/// `error_code` being None means there is no dedicated code; the frontend can
/// show a generic error.
pub fn map_persona_error(err: &anyhow::Error) -> (Option<String>, String) {
    // Prefer an exact match on the PersonaError variant
    for cause in err.chain() {
        if let Some(pe) = cause.downcast_ref::<PersonaError>() {
            match pe {
                PersonaError::ReauthRequired(_) => {
                    return (Some(CODE_REAUTH_REQUIRED.to_string()), pe.to_string());
                }
                PersonaError::TravelModeActive(_) => {
                    return (Some(CODE_TRAVEL_MODE_ACTIVE.to_string()), pe.to_string());
                }
                PersonaError::ConcurrentConflict(_) => {
                    return (Some(CODE_CONCURRENT_CONFLICT.to_string()), pe.to_string());
                }
                PersonaError::AuthenticationFailed(msg)
                    if msg.contains("locked") || msg.contains("Service is locked") =>
                {
                    return (Some(CODE_SERVICE_LOCKED.to_string()), pe.to_string());
                }
                // Lock semantics of the Connect automation data plane (the core 503
                // convention) — map straight from the variant, without relying on the
                // "Vault is locked" text.
                PersonaError::VaultLocked(_) => {
                    return (Some(CODE_SERVICE_LOCKED.to_string()), pe.to_string());
                }
                _ => {}
            }
        }
    }

    // Fallback: recognize by message text (covers errors not wrapped in PersonaError)
    let msg = err.to_string();
    if msg.contains("Re-authentication required") {
        return (Some(CODE_REAUTH_REQUIRED.to_string()), msg);
    }
    if msg.contains("Service is locked") || msg.contains("Session is auto-locked") {
        return (Some(CODE_SERVICE_LOCKED.to_string()), msg);
    }

    (None, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reauth_required_variant_maps_to_code() {
        let err: anyhow::Error = PersonaError::ReauthRequired("sensitive op".to_string()).into();
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_REAUTH_REQUIRED));
        assert!(msg.contains("Re-authentication required"));
    }

    #[test]
    fn locked_messages_map_to_service_locked() {
        let err: anyhow::Error =
            PersonaError::AuthenticationFailed("Service is locked".into()).into();
        let (code, _) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_SERVICE_LOCKED));
    }

    #[test]
    fn vault_locked_variant_maps_to_service_locked_by_type() {
        // "Vault is locked" does not fall into any text fallback — the direct
        // variant mapping must take effect, and it must surface along the chain
        // even across a context layer.
        let err = anyhow::Error::from(PersonaError::VaultLocked("data plane".into()))
            .context("connect request failed");
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_SERVICE_LOCKED));
        assert!(msg.contains("Vault is locked"));
    }

    #[test]
    fn reauth_message_without_variant_still_detected() {
        let err = anyhow::anyhow!("Re-authentication required for sensitive operation");
        let (code, _) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_REAUTH_REQUIRED));
    }

    #[test]
    fn generic_error_has_no_code() {
        let err = anyhow::anyhow!("boom");
        let (code, msg) = map_persona_error(&err);
        assert!(code.is_none());
        assert_eq!(msg, "boom");
    }

    #[test]
    fn travel_mode_active_maps_to_code_even_wrapped() {
        // The password-change block enters anyhow inside core through the
        // thiserror From chain; a TravelModeActive appearing mid-chain must
        // still resolve to the matching code
        let err = anyhow::Error::from(PersonaError::TravelModeActive(
            "exit travel mode first".to_string(),
        ))
        .context("change_master_password failed");
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_TRAVEL_MODE_ACTIVE));
        assert!(msg.contains("Travel mode is active"));
    }

    #[test]
    fn concurrent_conflict_maps_to_code_even_wrapped() {
        // Concurrent-rotation mutual exclusion: rotate_group_key enters
        // anyhow via begin_group_rotation's 409 mapping; a context layer in
        // between must still resolve to CONCURRENT_CONFLICT
        let err = anyhow::Error::from(PersonaError::ConcurrentConflict(
            "concurrent group key rotation detected".to_string(),
        ))
        .context("sync_rotate failed");
        let (code, msg) = map_persona_error(&err);
        assert_eq!(code.as_deref(), Some(CODE_CONCURRENT_CONFLICT));
        assert!(msg.contains("Concurrent operation conflict"));
    }
}
