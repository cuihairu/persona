use super::*;

/// Passkey assertion evidence (login-options challenge + authenticator signature).
#[derive(Deserialize)]
pub struct PasskeyAssertionRequest {
    /// The passkey_id returned at registration (= base64url(credential_id))
    pub credential_id: String,
    /// base64url-encoded clientDataJSON
    pub client_data_json: String,
    /// The origin claimed by the client (must match clientDataJSON and the rp_id)
    pub origin: String,
    /// base64url-encoded authenticator data
    pub authenticator_data: String,
    /// base64url-encoded DER signature
    pub signature: String,
}

#[derive(Deserialize)]
pub struct CreateAccountSessionRequest {
    /// SRP fallback login evidence: the 15-minute token issued by srp/verify.
    pub srp_token: Option<String>,
    /// Passkey login evidence: an assertion over the login-options challenge.
    pub passkey_assertion: Option<PasskeyAssertionRequest>,
}

/// POST /api/v1/accounts/:account_id/sessions
/// Creates a 24h account session after verifying exactly one piece of
/// login evidence: a live SRP token, or a passkey assertion over a
/// server-issued login-options challenge.
pub async fn create_account_session(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    payload: Result<Json<CreateAccountSessionRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(req) = payload.map_err(|r| ApiError::rejection(r.status(), r.body_text()))?;

    // Exactly one piece of evidence: none = 422; both given = 422 (ambiguous semantics, don't guess).
    match (&req.srp_token, &req.passkey_assertion) {
        (Some(token), None) => verify_srp_evidence(&state, &account_id, token).await?,
        (None, Some(assertion)) => verify_passkey_evidence(&state, &account_id, assertion).await?,
        _ => {
            return Err(ApiError::validation(
                "exactly one evidence required",
                vec![ErrorItem::batch(
                    "srp_token",
                    "provide exactly one of srp_token / passkey_assertion",
                )],
            ))
        }
    }

    let session_token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
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

/// SRP evidence: the token must be an unexpired account_sessions row for this account.
async fn verify_srp_evidence(
    state: &AppState,
    account_id: &str,
    token: &str,
) -> Result<(), ApiError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError::unauthorized());
    }
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM account_sessions
         WHERE account_id = ? AND session_token = ? AND expires_at > ? LIMIT 1",
    )
    .bind(account_id)
    .bind(token)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    if found.is_none() {
        return Err(ApiError::unauthorized());
    }
    Ok(())
}

/// Passkey evidence: the login-options challenge (single use) + clientData challenge
/// comparison + signature verification + sign_count monotonicity; on success the counter
/// and last_used_at are updated.
async fn verify_passkey_evidence(
    state: &AppState,
    account_id: &str,
    assertion: &PasskeyAssertionRequest,
) -> Result<(), ApiError> {
    // The challenge must come from this account's login-options (single use); consumption
    // failure means 401, and the client re-runs login-options.
    let Some((challenge, rp_id)) = state
        .account_webauthn
        .take(account_id, WebauthnCeremony::Authenticate)
    else {
        return Err(ApiError::unauthorized());
    };

    let row = sqlx::query(
        "SELECT id, public_key, sign_count FROM account_passkeys WHERE id = ? AND account_id = ?",
    )
    .bind(assertion.credential_id.trim())
    .bind(account_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(ApiError::unauthorized)?;
    let public_key: Vec<u8> = row.get("public_key");
    let stored_count: i64 = row.get("sign_count");

    let client_data_bytes = decode_b64url_field(
        "client_data_json",
        &assertion.client_data_json,
        MAX_CLIENT_DATA_BYTES,
    )?;
    let authenticator_data = decode_b64url_field(
        "authenticator_data",
        &assertion.authenticator_data,
        MAX_AUTHENTICATOR_DATA_BYTES,
    )?;
    let signature = decode_b64url_field("signature", &assertion.signature, MAX_SIGNATURE_BYTES)?;

    // Challenge comparison: verify_assertion does not inspect clientDataJSON, so the
    // server-issued challenge is anchored here (guards against assertion replay and
    // client-chosen challenges).
    let parsed =
        passkey::parse_client_data(&client_data_bytes, CLIENT_DATA_TYPE_GET, &assertion.origin)
            .map_err(|e| {
                tracing::warn!(%e, account = %account_id, "passkey assertion client data rejected");
                ApiError::unauthorized()
            })?;
    if parsed.challenge != challenge {
        tracing::warn!(account = %account_id, "passkey assertion challenge mismatch");
        return Err(ApiError::unauthorized());
    }

    passkey::verify_assertion(
        &public_key,
        &rp_id,
        &client_data_bytes,
        &authenticator_data,
        &signature,
    )
    .map_err(|e| {
        tracing::warn!(%e, account = %account_id, "passkey assertion signature invalid");
        ApiError::unauthorized()
    })?;

    // sign_count monotonicity (clone detection): when the stored value is non-zero the new
    // one must be greater; both being 0 is a legitimate "counterless authenticator"
    // (software authenticators work this way), so it is allowed.
    // verify_assertion already guarantees authenticator_data is at least 37 bytes.
    let new_count = u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]);
    if stored_count != 0 && new_count as i64 <= stored_count {
        tracing::warn!(account = %account_id, stored = stored_count, observed = new_count,
            "passkey sign count regression — possible cloned credential");
        return Err(ApiError::unauthorized());
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE account_passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND account_id = ?")
        .bind(new_count as i64)
        .bind(&now)
        .bind(assertion.credential_id.trim())
        .bind(account_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// DELETE /api/v1/accounts/:account_id/sessions/:session_token
/// Revokes an account session (logout).
pub async fn revoke_account_session(
    State(state): State<AppState>,
    Path((account_id, session_token)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    sqlx::query("DELETE FROM account_sessions WHERE account_id = ? AND session_token = ?")
        .bind(&account_id)
        .bind(&session_token)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- Helper functions ----

pub(super) fn validate_device_name(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(char::is_whitespace) {
        return Err(ApiError::validation(
            "invalid device_name",
            vec![ErrorItem::batch(
                "device_name",
                "must be 1-64 bytes, no whitespace",
            )],
        ));
    }
    Ok(trimmed.to_owned())
}

pub(super) fn decode_field(field: &str, raw: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
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
