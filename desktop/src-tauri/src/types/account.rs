//! Account-domain wire types: registration, passkey, SRP, device list and
//! biometrics.

use serde::{Deserialize, Serialize};

/// account_register request (public registration, no authentication
/// required).
#[derive(Debug, Deserialize)]
pub struct AccountRegisterRequest {
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountRegistrationResponse {
    pub account_id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// account_passkey_create_options request. The response is the raw WebAuthn
/// creation options JSON (the server's untyped `json!` object); the command
/// layer passes `serde_json::Value` through unchanged (= the frontend's
/// AccountPasskeyCreationOptions).
#[derive(Debug, Deserialize)]
pub struct AccountPasskeyCreateOptionsRequest {
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: Option<String>,
    pub user_handle: String,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub user_display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccountPasskeyRegisterRequest {
    /// Authenticator attestation response ({credentialId, attestationObject},
    /// both base64url strings); the server accepts it as an opaque Value.
    pub attestation_response: serde_json::Value,
    pub client_data_json: String,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountPasskeyRegisterResponse {
    pub passkey_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountPasskeyLoginOptionsRequest {
    pub credential_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountPasskeyLoginOptionsResponse {
    pub challenge: String,
    pub rp_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountSrpRegisterRequest {
    pub device_name: String,
    pub salt: String,
    pub verifier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpRegisterResponse {
    pub device_name: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountSrpChallengeRequest {
    pub device_name: String,
    pub client_public: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpChallengeResponse {
    pub session_id: String,
    pub salt: String,
    pub server_public: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountSrpVerifyRequest {
    pub session_id: String,
    pub client_proof: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpVerifyResponse {
    pub server_proof: String,
    /// 15-minute account login token: besides passing it through, the
    /// command layer also writes it to `account_token_store` (the resolution
    /// source for bearer-gated commands).
    pub token: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountRecoveryCodes {
    pub codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccountVerifyRecoveryCodeRequest {
    pub code: String,
}

/// verify_recovery_code response (= the frontend's inline
/// `{ success: boolean }`; the core-side same-shape wire type is only
/// Deserialize and never sits in a command return position).
#[derive(Debug, Clone, Serialize)]
pub struct AccountVerifyRecoveryCodeResponse {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
pub struct AccountAuthorizeDeviceRequest {
    /// sync_devices.id
    pub device_id: String,
    /// base64, 32-byte X25519
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountAuthorizeDeviceResponse {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountDeviceInfo {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountDevicesList {
    pub devices: Vec<AccountDeviceInfo>,
}

/// Passkey assertion evidence for the sessions endpoint (all fields
/// base64url-encoded).
#[derive(Debug, Deserialize)]
pub struct AccountPasskeyAssertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub origin: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// Evidence for the sessions endpoint: an SRP 15-minute token or a passkey
/// assertion, exactly one (the server returns 422 for both / neither).
/// serde ignores unknown fields by default, so both shapes are accepted.
#[derive(Debug, Default, Deserialize)]
pub struct AccountSessionEvidence {
    #[serde(default)]
    pub srp_token: Option<String>,
    #[serde(default)]
    pub passkey_assertion: Option<AccountPasskeyAssertion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSessionInfo {
    pub session_token: String,
    pub expires_in_secs: u64,
}

/// Guided SRP credential registration (password in, no wire values out):
/// salt/verifier are derived by core; the frontend submits only the device
/// name and the password.
#[derive(Debug, Deserialize)]
pub struct AccountSrpRegisterWithPasswordRequest {
    pub device_name: String,
    pub password: String,
}

/// Guided SRP login request: the challenge/verify two hops are orchestrated
/// by core, and M2 verification is completed in core.
#[derive(Debug, Deserialize)]
pub struct AccountSrpLoginRequest {
    pub device_name: String,
    pub password: String,
}

/// `account_srp_login` response. **No token included**: the 15-minute token
/// is written directly by the command layer to `account_token_store` (the
/// bearer resolution source) and is not sent to the render layer with the
/// response; the fingerprint is for diagnostics / session-binding display.
#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpLoginResponse {
    pub expires_in_secs: u64,
    pub session_key_fingerprint: String,
}

/// `account_exchange_session` response. **No session token included**: the
/// command layer writes the 24h session straight to the keyring, replacing
/// the 15-minute short-lived token; the render layer only sees the validity
/// period.
#[derive(Debug, Clone, Serialize)]
pub struct AccountSessionExchangeResponse {
    pub expires_in_secs: u64,
}

/// `account_sign_out` response: the local token is always cleared (otherwise
/// an error is returned); server-side revocation is best-effort — sign-out
/// still counts as success when the token is expired / no longer exists
/// (`false` only means the server had nothing to revoke), and local state is
/// never blocked on a remote 4xx.
#[derive(Debug, Clone, Serialize)]
pub struct AccountSignOutResponse {
    pub revoked_on_server: bool,
}

/// Response for a biometric unlock status query. `available` = both the OS
/// authentication stack and the keyring are reachable (fail-closed: either
/// unavailable yields false, and the frontend hides the fingerprint entry);
/// `enabled` = the keyring custody entry for this vault exists — the single
/// source of truth; workspace settings stores no switch (after copying the
/// vault files to another machine the keyring has no entry, so the feature
/// naturally reverts to disabled).
#[derive(Debug, Clone, Serialize)]
pub struct BiometricStatusResponse {
    pub available: bool,
    pub enabled: bool,
    /// Platform name ("touch-id" / "windows-hello" / "linux-polkit" / "unsupported")
    pub platform: String,
    /// Wrap tier (the biometric_wrap module's three tiers, design doc §1):
    /// "hardware-bound" (this vault's wrapper blob exists and unwrapping
    /// goes through hardware) / "os-gate" (gate-layer password custody) /
    /// "unsupported" (the platform has no hardware-bound layer)
    pub wrap_tier: String,
}

/// Enable biometric unlock: the master password is put into custody after
/// being confirmed by the OS authentication prompt (the hardware-bound tier
/// uses the key-wrapping blob, the gate tier uses keyring password custody —
/// see biometric_enable for the split)
#[derive(Debug, Deserialize)]
pub struct BiometricEnableRequest {
    pub master_password: String,
}

/// Biometric unlock: db_path is passed when the frontend checks a custom
/// vault path (default None = this session's path or the default path)
#[derive(Debug, Deserialize)]
pub struct BiometricUnlockRequest {
    pub db_path: Option<String>,
}

/// Single-step output of the Secure Enclave spike probe (returned by the
/// `biometric_wrap_spike` command; design doc §5.2). After running it on
/// real hardware, paste the OSStatus from `detail` back into the design
/// doc.
#[derive(Debug, Clone, Serialize)]
pub struct BiometricSpikeStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}
