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
    // 凭据不存在与任何其他失败同形（401 无差异信息）——不泄露注册状态
    .ok_or_else(ApiError::unauthorized)?;
    let (salt, verifier) = row;

    let hc = srp::server_challenge(&verifier).map_err(ApiError::internal)?;
    let session_id = Uuid::new_v4().to_string();
    // 复用设备域 SrpAuthState 的未决握手缓存；锁户键带账号前缀，与
    // 设备域（auth_devices）的失败记账互不干扰，verify 时校验归属。
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

/// 账号域锁户键：SrpAuthState 的失败记账以"设备名"为键，账号域用
/// `account:{account_id}:{device_name}` 与设备域隔离（verify 时校验
/// 前缀防跨账号串用 session_id）。
fn account_lock_key(account_id: &str, device_name: &str) -> String {
    format!("account:{account_id}:{device_name}")
}

/// SRP verify request
#[derive(Deserialize)]
pub struct AccountSrpVerifyRequest {
    pub session_id: String,
    /// base64 编码的客户端证明 M1。
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
    Path(account_id): Path<String>,
    payload: Result<Json<AccountSrpVerifyRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(req) = payload.map_err(|r| ApiError::rejection(r.status(), r.body_text()))?;
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;

    // 未决握手先取走（一次握手一条；TTL 外即不存在）
    let entry = srp_state
        .take_challenge(&req.session_id)
        .ok_or_else(ApiError::unauthorized)?;

    // 挑战必须属于路径里的账号：锁键是 account:{id}:{name}，前缀不匹配
    // = 拿别账号的 session_id 串门。
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
            Ok(Json(AccountSrpVerifyResponse {
                server_proof: B64.encode(outcome.server_proof),
                token: session_token,
                expires_in_secs: 900,
            }))
        }
        Err(_) => {
            srp_state.register_failure(&entry.device_name);
            Err(ApiError::unauthorized())
        }
    }
}

// ---- Recovery Codes ----
