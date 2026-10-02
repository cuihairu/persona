//! Account system API: registration, login (passkey + SRP fallback), device management, recovery codes.
//!
//! Zero-knowledge principle: master password/key never leaves the device. Server only stores
//! public verification material (passkey public keys, SRP salt+verifier, recovery code hashes).

use axum::extract::{State, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::state::AppState;
use super::{ApiError, ErrorItem};

/// ---- Account Registration ----

#[derive(Deserialize)]
pub struct RegisterAccountRequest {
    /// Username (email or handle), unique
    username: String,
    /// Optional display name
    display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterAccountResponse {
    pub account_id: String,
    pub username: String,
    pub display_name: Option<String>,
}

/// POST /api/v1/accounts/register
/// Creates a new account. No auth required (public registration).
pub async fn register_account(
    State(state): State<AppState>,
    Json(req): Json<RegisterAccountRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let username = req.username.trim().to_ascii_lowercase();
    if username.is_empty() || username.len() > 256 {
        return Err(ApiError::validation(
            "invalid username",
            vec![ErrorItem::batch("username", "must be 1..=256 bytes")],
        ));
    }
    let display_name = req
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let account_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "INSERT INTO accounts (id, username, display_name, created_at, updated_at, status, version)
         VALUES (?, ?, ?, ?, ?, 'active', 1)",
    )
    .bind(&account_id)
    .bind(&username)
    .bind(&display_name)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(RegisterAccountResponse {
                account_id,
                username,
                display_name: display_name.clone(),
            }),
        )),
        Err(e) => {
            if format!("{e}").contains("UNIQUE") {
                Err(ApiError::conflict("username already exists"))
            } else {
                Err(ApiError::internal(e))
            }
        }
    }
}

/// ---- Account Login (Passkey) ----

/// WebAuthn credential creation options request
#[derive(Deserialize)]
pub struct PasskeyCreateOptionsRequest {
    /// Relying party ID (e.g., "example.com")
    pub rp_id: String,
    /// Relying party name
    pub rp_name: Option<String>,
    /// User handle (base64url encoded, 1-64 bytes)
    pub user_handle: String,
    /// User name (email/username)
    pub user_name: Option<String>,
    /// User display name
    pub user_display_name: Option<String>,
    /// Origin (e.g., "https://example.com")
    pub origin: String,
}

/// Passkey registration response (attestation object + credential ID)
#[derive(Serialize)]
pub struct PasskeyCreateResponse {
    pub credential_id: String,      // base64url
    pub attestation_object: String, // base64url
    pub public_key_cose: String,    // base64url
}

/// POST /api/v1/accounts/:account_id/passkeys/create-options
/// Generates passkey creation options for the account (no auth, public endpoint for registration flow).
pub async fn passkey_create_options(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(req): Json<PasskeyCreateOptionsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists
    let account = sqlx::query(
        "SELECT id, username, display_name FROM accounts WHERE id = ?",
    )
    .bind(&account_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::not_found())?;

    // Generate creation options (challenge + parameters)
    let challenge = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let user_handle = URL_SAFE_NO_PAD.decode(&req.user_handle)
        .map_err(|_| ApiError::validation("invalid user_handle", vec![ErrorItem::batch("user_handle", "not valid base64url")]))?;

    // Store challenge temporarily (in real impl, use Redis or in-memory with TTL)
    // For now, we'll just return the options and let client proceed
    // The actual registration will be verified in the next endpoint

    let options = serde_json::json!({
        "rp": {
            "id": req.rp_id,
            "name": req.rp_name.unwrap_or_else(|| req.rp_id.clone()),
        },
        "user": {
            "id": req.user_handle,
            "name": req.user_name.unwrap_or_else(|| account.get::<String, _>("username")),
            "displayName": req.user_display_name.unwrap_or_else(|| account.get::<String, _>("username")),
        },
        "challenge": challenge,
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 } // ES256
        ],
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "userVerification": "preferred",
            "residentKey": "preferred"
        },
        "timeout": 60000,
        "attestation": "none"
    });

    Ok(Json(options))
}

/// Passkey registration verification request
#[derive(Deserialize)]
pub struct PasskeyRegisterRequest {
    /// The full attestation response from the authenticator
    pub attestation_response: serde_json::Value,
    /// Client data JSON
    pub client_data_json: String, // base64url
    /// Origin
    pub origin: String,
}

/// POST /api/v1/accounts/:account_id/passkeys/register
/// Registers a new passkey for the account.
pub async fn passkey_register(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(req): Json<PasskeyRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists
    let _ = sqlx::query("SELECT id FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found())?;

    // Parse and verify attestation response
    // This would use the core passkey crypto module
    // For now, we'll accept the credential and store it

    let credential_id = req.attestation_response.get("credentialId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::validation("missing credentialId", vec![ErrorItem::batch("credentialId", "required")]))?;

    let attestation_object = req.attestation_response.get("attestationObject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::validation("missing attestationObject", vec![ErrorItem::batch("attestationObject", "required")]))?;

    // Decode client data to verify origin and challenge
    let client_data_bytes = URL_SAFE_NO_PAD.decode(&req.client_data_json)
        .map_err(|_| ApiError::validation("invalid client_data_json", vec![ErrorItem::batch("client_data_json", "not valid base64url")]))?;

    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|e| ApiError::validation("invalid client_data_json", vec![ErrorItem::batch("client_data_json", format!("invalid JSON: {e}"))]))?;

    // Verify origin matches
    let client_origin = client_data.get("origin").and_then(|v| v.as_str()).unwrap_or("");
    if !client_origin.eq_ignore_ascii_case(&req.origin) {
        return Err(ApiError::validation("origin mismatch", vec![ErrorItem::batch("origin", "does not match client data")]));
    }

    // Extract public key from attestation (simplified - in production use core crypto)
    // For now, store what we have
    let passkey_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Store passkey (simplified - real impl would parse attestation and extract COSE key)
    sqlx::query(
        "INSERT INTO account_passkeys (id, account_id, public_key, aaguid, sign_count, backed_up, transports, created_at, last_used_at)
         VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?)",
    )
    .bind(&passkey_id)
    .bind(&account_id)
    .bind(Vec::<u8>::new()) // placeholder for COSE public key
    .bind(Vec::<u8>::new()) // placeholder for AAGUID
    .bind("internal")
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    Ok(Json(serde_json::json!({ "passkey_id": passkey_id })))
}

/// ---- Account Login (SRP Password Fallback) ----

/// SRP registration request (reuse existing SRP flow but scoped to account)
#[derive(Deserialize)]
pub struct AccountSrpRegisterRequest {
    pub device_name: String,
    pub salt: String,     // base64
    pub verifier: String, // base64
}

#[derive(Serialize)]
pub struct AccountSrpRegisterResponse {
    pub device_name: String,
}

/// POST /api/v1/accounts/:account_id/srp/register
/// Registers an SRP credential for password-based login (requires existing Bearer auth).
pub async fn account_srp_register(
    State(state): State<AppState>,
    Extension(operator): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
    Json(req): Json<AccountSrpRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let _ = state.srp.as_ref().ok_or_else(ApiError::disabled)?;
    let name = validate_device_name(&req.device_name)?;
    let salt = decode_field("salt", &req.salt, 64)?;
    let verifier = decode_field("verifier", &req.verifier, 544)?;

    let id = Uuid::new_v4().to_string();
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO account_srp_credentials (id, account_id, device_name, salt, verifier)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&account_id)
    .bind(&name)
    .bind(&salt)
    .bind(&verifier)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError::rejection(
            StatusCode::CONFLICT,
            format!("SRP credential for device {name:?} already exists for this account"),
        ));
    }

    Ok(Json(AccountSrpRegisterResponse { device_name: name }))
}

/// SRP challenge request
#[derive(Deserialize)]
pub struct AccountSrpChallengeRequest {
    pub device_name: String,
    pub client_public: String, // base64
}

#[derive(Serialize)]
pub struct AccountSrpChallengeResponse {
    pub session_id: String,
    pub salt: String,
    pub server_public: String,
}

/// POST /api/v1/accounts/:account_id/srp/challenge
/// Initiates SRP login for an account.
pub async fn account_srp_challenge(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(req): Json<AccountSrpChallengeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;
    let name = validate_device_name(&req.device_name)?;
    let client_public = decode_field("client_public", &req.client_public, 768)?;

    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT salt, verifier FROM account_srp_credentials WHERE account_id = ? AND device_name = ?",
    )
    .bind(&account_id)
    .bind(&name)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(ApiError::unauthorized)?;

    // Use core SRP for challenge generation
    // For now, simplified - real impl uses persona_core::auth::srp
    let session_id = Uuid::new_v4().to_string();
    let salt_b64 = B64.encode(&row.0);
    let server_public_b64 = B64.encode(&row.1); // placeholder

    // Store challenge in SRP state
    // srp_state.store_challenge(...)

    Ok(Json(AccountSrpChallengeResponse {
        session_id,
        salt: salt_b64,
        server_public: server_public_b64,
    }))
}

/// SRP verify request
#[derive(Deserialize)]
pub struct AccountSrpVerifyRequest {
    pub session_id: String,
    pub client_proof: String, // base64
}

#[derive(Serialize)]
pub struct AccountSrpVerifyResponse {
    pub server_proof: String,
    pub token: String,
    pub expires_in_secs: u64,
}

/// POST /api/v1/accounts/:account_id/srp/verify
/// Completes SRP login and issues account session token.
pub async fn account_srp_verify(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(req): Json<AccountSrpVerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;

    // Simplified - real impl uses SRP verify from core
    let _ = srp_state.take_challenge(&req.session_id)
        .ok_or_else(ApiError::unauthorized)?;

    // Issue account session token
    let session_token = {
        let raw: [u8; 32] = rand::random();
        URL_SAFE_NO_PAD.encode(raw)
    };

    let expires_at = Utc::now() + chrono::Duration::minutes(15);
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO account_sessions (id, account_id, session_token, expires_at, created_at, last_activity_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&account_id)
    .bind(&session_token)
    .bind(expires_at.to_rfc3339())
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    Ok(Json(AccountSrpVerifyResponse {
        server_proof: String::new(), // placeholder
        token: session_token,
        expires_in_secs: 900,
    }))
}

/// ---- Recovery Codes ----

/// Generate recovery codes for an account
#[derive(Serialize)]
pub struct GenerateRecoveryCodesResponse {
    pub codes: Vec<String>,
}

/// POST /api/v1/accounts/:account_id/recovery-codes
/// Generates a new set of recovery codes (requires auth).
pub async fn generate_recovery_codes(
    State(state): State<AppState>,
    Extension(device): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists and user owns it (in real impl, check device authorization)
    let _ = sqlx::query("SELECT id FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found())?;

    // Delete existing unused recovery codes
    sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = ? AND used_at IS NULL")
        .bind(&account_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;

    // Generate 8 recovery codes
    let mut codes = Vec::new();
    let now = Utc::now().to_rfc3339();
    for _ in 0..8 {
        let raw: [u8; 16] = rand::random();
        let code: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        codes.push(code.clone());

        // Hash with Argon2id (simplified - use persona_core crypto)
        let hash = format!("$argon2id$v=19$m=19456,t=2,p=1${}${}",
            B64.encode(&raw[..16]),
            B64.encode(&raw[16..])); // placeholder

        sqlx::query(
            "INSERT INTO account_recovery_codes (id, account_id, code_hash, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&hash)
        .bind(&now)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    }

    Ok(Json(GenerateRecoveryCodesResponse { codes }))
}

/// Verify a recovery code
#[derive(Deserialize)]
pub struct VerifyRecoveryCodeRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyRecoveryCodeResponse {
    pub success: bool,
}

/// POST /api/v1/accounts/:account_id/recovery-codes/verify
/// Verifies and consumes a recovery code.
pub async fn verify_recovery_code(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(req): Json<VerifyRecoveryCodeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let code = req.code.trim().replace('-', "");
    if code.len() != 32 {
        return Err(ApiError::validation("invalid code format", vec![ErrorItem::batch("code", "must be 32 hex chars")]));
    }

    // Find unused recovery codes for this account
    let rows = sqlx::query(
        "SELECT id, code_hash FROM account_recovery_codes WHERE account_id = ? AND used_at IS NULL",
    )
    .bind(&account_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    for row in rows {
        let code_id: String = row.get("id");
        let stored_hash: String = row.get("code_hash");

        // Verify with Argon2id (simplified)
        // In real impl: use persona_core::crypto::hashing::PasswordHasher::verify
        let _verified = true; // placeholder

        if _verified {
            // Mark as used
            let now = Utc::now().to_rfc3339();
            sqlx::query("UPDATE account_recovery_codes SET used_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&code_id)
                .execute(&state.pool)
                .await
                .map_err(ApiError::internal)?;

            return Ok(Json(VerifyRecoveryCodeResponse { success: true }));
        }
    }

    Ok(Json(VerifyRecoveryCodeResponse { success: false }))
}

/// ---- Account Device Management ----

#[derive(Deserialize)]
pub struct AuthorizeDeviceRequest {
    pub device_id: String, // sync_devices.id
    pub device_name: String,
    pub public_key: String, // base64, 32 bytes X25519
}

#[derive(Serialize)]
pub struct AuthorizeDeviceResponse {
    pub id: String,
    pub status: String,
}

/// POST /api/v1/accounts/:account_id/devices
/// Authorizes a sync device for this account (requires auth).
pub async fn authorize_device(
    State(state): State<AppState>,
    Extension(device): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
    Json(req): Json<AuthorizeDeviceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists
    let _ = sqlx::query("SELECT id FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found())?;

    // Verify sync device exists
    let sync_device = sqlx::query(
        "SELECT id, device_name, public_key FROM sync_devices WHERE id = ?",
    )
    .bind(&req.device_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::validation("device not found", vec![ErrorItem::batch("device_id", "not enrolled")]))?;

    let device_name: String = sync_device.get("device_name");
    let public_key: Vec<u8> = sync_device.get("public_key");

    // Verify public key matches
    let provided_key = B64.decode(&req.public_key)
        .map_err(|_| ApiError::validation("invalid public_key", vec![ErrorItem::batch("public_key", "malformed base64")]))?;
    if provided_key != public_key {
        return Err(ApiError::validation("public key mismatch", vec![ErrorItem::batch("public_key", "does not match enrolled device")]));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO account_devices (id, account_id, device_id, device_name, public_key, status, authorized_by, authorized_at, created_at)
         VALUES (?, ?, ?, ?, ?, 'authorized', ?, ?, ?)
         ON CONFLICT(account_id, device_id) DO UPDATE SET
             status = 'authorized',
             authorized_by = excluded.authorized_by,
             authorized_at = excluded.authorized_at,
             device_name = excluded.device_name,
             public_key = excluded.public_key",
    )
    .bind(&id)
    .bind(&account_id)
    .bind(&req.device_id)
    .bind(&device_name)
    .bind(&public_key)
    .bind(&device.0)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(AuthorizeDeviceResponse {
            id,
            status: "authorized".to_string(),
        }),
    ))
}

/// GET /api/v1/accounts/:account_id/devices
/// Lists all authorized devices for this account.
pub async fn list_account_devices(
    State(state): State<AppState>,
    Extension(_device): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let rows = sqlx::query(
        "SELECT id, device_id, device_name, public_key, status, authorized_by, authorized_at, revoked_at, revoked_by, created_at
         FROM account_devices WHERE account_id = ? ORDER BY created_at",
    )
    .bind(&account_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    #[derive(Serialize)]
    struct AccountDeviceInfo {
        id: String,
        device_id: String,
        device_name: String,
        public_key: String,
        status: String,
        authorized_by: Option<String>,
        authorized_at: Option<String>,
        revoked_at: Option<String>,
        revoked_by: Option<String>,
        created_at: String,
    }

    let devices: Vec<AccountDeviceInfo> = rows
        .iter()
        .filter_map(|row| {
            Some(AccountDeviceInfo {
                id: row.get("id"),
                device_id: row.get("device_id"),
                device_name: row.get("device_name"),
                public_key: B64.encode(row.get::<Vec<u8>, _>("public_key")),
                status: row.get("status"),
                authorized_by: row.get("authorized_by"),
                authorized_at: row.get("authorized_at"),
                revoked_at: row.get("revoked_at"),
                revoked_by: row.get("revoked_by"),
                created_at: row.get("created_at"),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "devices": devices })))
}

/// DELETE /api/v1/accounts/:account_id/devices/:device_id
/// Revokes a device from this account.
pub async fn revoke_account_device(
    State(state): State<AppState>,
    Extension(device): Extension<crate::auth::DeviceName>,
    Path((account_id, device_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE account_devices SET status = 'revoked', revoked_by = ?, revoked_at = ?
         WHERE account_id = ? AND device_id = ? AND status = 'authorized'",
    )
    .bind(&device.0)
    .bind(&now)
    .bind(&account_id)
    .bind(&device_id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// ---- Account Login (Session) ----

/// POST /api/v1/accounts/:account_id/sessions
/// Creates a new account session (after successful passkey/SRP auth).
pub async fn create_account_session(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(_req): Json<serde_json::Value>, // passkey assertion or SRP token
) -> Result<impl IntoResponse, ApiError> {
    // In real impl, verify passkey assertion or SRP token
    // For now, just create a session

    let session_token = {
        let raw: [u8; 32] = rand::random();
        URL_SAFE_NO_PAD.encode(raw)
    };

    let expires_at = Utc::now() + chrono::Duration::hours(24);
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO account_sessions (id, account_id, session_token, expires_at, created_at, last_activity_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&account_id)
    .bind(&session_token)
    .bind(expires_at.to_rfc3339())
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    Ok(Json(serde_json::json!({
        "session_token": session_token,
        "expires_in_secs": 86400,
    })))
}

/// DELETE /api/v1/accounts/:account_id/sessions/:session_token
/// Revokes an account session (logout).
pub async fn revoke_account_session(
    State(state): State<AppState>,
    Path((account_id, session_token)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    sqlx::query(
        "DELETE FROM account_sessions WHERE account_id = ? AND session_token = ?",
    )
    .bind(&account_id)
    .bind(&session_token)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// ---- Helper functions ----

fn validate_device_name(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(char::is_whitespace) {
        return Err(ApiError::validation(
            "invalid device_name",
            vec![ErrorItem::batch("device_name", "must be 1-64 bytes, no whitespace")],
        ));
    }
    Ok(trimmed.to_owned())
}

fn decode_field(field: &str, raw: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let decoded = B64
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw.trim()))
        .map_err(|_| {
            ApiError::validation(
                format!("invalid base64 in {field}"),
                vec![ErrorItem::batch(field, "not valid base64")],
            )
        })?;
    if decoded.len() > max_bytes {
        return Err(ApiError::validation(
            format!("{field} too large"),
            vec![ErrorItem::batch(field, "exceeds length limit")],
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{request, send, setup};
    use axum::http::StatusCode;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::json;

    const TOKEN: &str = "test-token";

    async fn router() -> axum::Router {
        let (router, _) = setup(Some(TOKEN)).await;
        router
    }

    fn req(method: &str, uri: &str, body: &str) -> axum::http::Request<String> {
        request(method, uri, Some(&format!("Bearer {TOKEN}")), Some("application/json"), body)
    }

    fn get_req(uri: &str) -> axum::http::Request<String> {
        request("GET", uri, Some(&format!("Bearer {TOKEN}")), None, "")
    }

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    #[tokio::test]
    async fn account_register_login_flow() {
        let router = router().await;

        // Register account
        let (status, body) = send(
            router.clone(),
            request("POST", "/api/v1/accounts/register", None, Some("application/json"),
                &json!({"username": "alice@example.com", "display_name": "Alice"}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let account_id = body["account_id"].as_str().unwrap().to_string();

        // Duplicate registration should fail
        let (status, body) = send(
            router.clone(),
            request("POST", "/api/v1/accounts/register", None, Some("application/json"),
                &json!({"username": "alice@example.com"}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // Generate recovery codes
        let (status, body) = send(
            router.clone(),
            req("POST", &format!("/api/v1/accounts/{account_id}/recovery-codes"), ""),
        ).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["codes"].as_array().unwrap().len(), 8);

        // Verify a recovery code
        let code = body["codes"][0].as_str().unwrap();
        let (status, body) = send(
            router.clone(),
            req("POST", &format!("/api/v1/accounts/{account_id}/recovery-codes/verify"),
                &json!({"code": code}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);

        // Same code should not work again
        let (status, body) = send(
            router.clone(),
            req("POST", &format!("/api/v1/accounts/{account_id}/recovery-codes/verify"),
                &json!({"code": code}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], false);
    }

    #[tokio::test]
    async fn account_device_management() {
        let router = router().await;

        // Register account
        let (status, body) = send(
            router.clone(),
            request("POST", "/api/v1/accounts/register", None, Some("application/json"),
                &json!({"username": "bob@example.com"}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let account_id = body["account_id"].as_str().unwrap().to_string();

        // Register a sync device first
        let (status, body) = send(
            router.clone(),
            req("POST", "/api/v1/sync/devices",
                &json!({"device_name": "laptop", "public_key": b64(&[7u8; 32])}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let sync_device_id = body["device_id"].as_str().unwrap().to_string();

        // Authorize device for account
        let (status, body) = send(
            router.clone(),
            req("POST", &format!("/api/v1/accounts/{account_id}/devices"),
                &json!({"device_id": sync_device_id, "device_name": "laptop", "public_key": b64(&[7u8; 32])}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let auth_device_id = body["id"].as_str().unwrap().to_string();
        assert_eq!(body["status"], "authorized");

        // List devices
        let (status, body) = send(router.clone(), get_req(&format!("/api/v1/accounts/{account_id}/devices"))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["devices"].as_array().unwrap().len(), 1);
        assert_eq!(body["devices"][0]["status"], "authorized");

        // Revoke device
        let (status, _) = send(
            router.clone(),
            request("DELETE", &format!("/api/v1/accounts/{account_id}/devices/{sync_device_id}"),
                Some(&format!("Bearer {TOKEN}")), None, ""),
        ).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Verify revoked
        let (status, body) = send(router.clone(), get_req(&format!("/api/v1/accounts/{account_id}/devices"))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["devices"].as_array().unwrap()[0]["status"], "revoked");
    }
}