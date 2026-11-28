use super::*;

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
    Extension(_operator): Extension<crate::auth::DeviceName>,
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
/// Initiates SRP login for an account: real server_challenge (B from the
/// stored verifier) with the pending handshake cached for verify (120s TTL).
pub async fn account_srp_challenge(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    payload: Result<Json<AccountSrpChallengeRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(req) = payload.map_err(|r| ApiError::rejection(r.status(), r.body_text()))?;
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
    // A missing credential has the same shape as any other failure (401, no differential
    // information) — registration status is not leaked.
    .ok_or_else(ApiError::unauthorized)?;
    let (salt, verifier) = row;

    let hc = srp::server_challenge(&verifier).map_err(ApiError::internal)?;
    let session_id = Uuid::new_v4().to_string();
    // Reuses the device-domain SrpAuthState pending-handshake cache; the lockout key is
    // prefixed with the account so its failure accounting does not interfere with the
    // device domain (auth_devices), and ownership is checked at verify time.
    srp_state.store_challenge(
        session_id.clone(),
        SrpChallengeEntry {
            device_name: account_lock_key(&account_id, &name),
            verifier,
            b_priv: hc.b_priv,
            client_public,
            expires_at: Instant::now() + SRP_CHALLENGE_TTL,
        },
    );

    Ok(Json(AccountSrpChallengeResponse {
        session_id,
        salt: B64.encode(salt),
        server_public: B64.encode(hc.b_pub),
    }))
}

/// Account-domain lockout key: SrpAuthState's failure accounting is keyed by "device name",
/// so the account domain uses `account:{account_id}:{device_name}` to stay isolated from the
/// device domain (the prefix is checked at verify time to prevent cross-account
/// session_id reuse).
fn account_lock_key(account_id: &str, device_name: &str) -> String {
    format!("account:{account_id}:{device_name}")
}

/// SRP verify request
#[derive(Deserialize)]
pub struct AccountSrpVerifyRequest {
    pub session_id: String,
    /// The base64-encoded client proof M1.
    pub client_proof: String,
}

#[derive(Serialize)]
pub struct AccountSrpVerifyResponse {
    pub server_proof: String,
    pub token: String,
    pub expires_in_secs: u64,
}

/// POST /api/v1/accounts/:account_id/srp/verify
/// Completes SRP login: verifies the client proof against the stored
/// handshake (lockout precheck + failure accounting included) and issues
/// a 15-minute account session token.
pub async fn account_srp_verify(
    State(state): State<AppState>,
    axum::Extension(peer): axum::Extension<crate::api::PeerIp>,
    Path(account_id): Path<String>,
    payload: Result<Json<AccountSrpVerifyRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(req) = payload.map_err(|r| ApiError::rejection(r.status(), r.body_text()))?;
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;

    // Take the pending handshake first (one handshake per challenge; outside the TTL it is as if it never existed)
    let entry = srp_state
        .take_challenge(&req.session_id)
        .ok_or_else(ApiError::unauthorized)?;

    // The challenge must belong to the account in the path: the lock key is
    // account:{id}:{name}, and a prefix mismatch means someone is borrowing
    // another account's session_id.
    if !entry
        .device_name
        .starts_with(&format!("account:{account_id}:"))
    {
        return Err(ApiError::unauthorized());
    }

    if srp_state.is_locked(&entry.device_name) {
        return Err(ApiError::rejection(
            StatusCode::LOCKED,
            "account locked after repeated failures; retry later",
        ));
    }

    let client_proof = decode_field("client_proof", &req.client_proof, 768)?;
    match srp::server_verify(
        &entry.b_priv,
        &entry.verifier,
        &entry.client_public,
        &client_proof,
    ) {
        Ok(outcome) => {
            srp_state.clear_failures(&entry.device_name);

            let session_token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
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

            tracing::info!(account = %account_id, "account SRP login OK");
            // Ledger key carries the account prefix so the login-awareness
            // registry keeps account and device domains separate.
            state
                .login_watch
                .record_login(&entry.device_name, true, &peer.0);
            Ok(Json(AccountSrpVerifyResponse {
                server_proof: B64.encode(outcome.server_proof),
                token: session_token,
                expires_in_secs: 900,
            }))
        }
        Err(_) => {
            srp_state.register_failure(&entry.device_name);
            state
                .login_watch
                .record_login(&entry.device_name, false, &peer.0);
            Err(ApiError::unauthorized())
        }
    }
}

// ---- Recovery Codes ----
