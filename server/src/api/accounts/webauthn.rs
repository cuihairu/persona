use super::*;

/// 账号 WebAuthn 未决挑战缓存（内存态，TTL 120s，一次性）。
///
/// 与设备域 SRP 挑战（[`crate::auth::SrpAuthState`]）同一设计纪律：
/// 挑战不落盘——服务器重启 = 在途仪式作废，客户端重走 options。按
/// account_id 键控（一个账号同时至多一条未决挑战，新挑战覆盖旧挑战），
/// register 与 authenticate 两种仪式各自配对消费，错配即弃（防拿注册
/// 挑战去断言、拿断言挑战去注册）。
pub struct AccountWebauthnState {
    entries: std::sync::Mutex<HashMap<String, WebauthnChallengeEntry>>,
}

/// 挑战所属的仪式类型；消费时必须与签发时一致。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WebauthnCeremony {
    /// credential creation（passkey_register 消费）
    Register,
    /// credential get（login-options → sessions 断言验证消费）
    Authenticate,
}

struct WebauthnChallengeEntry {
    challenge: String,
    rp_id: String,
    ceremony: WebauthnCeremony,
    expires_at: Instant,
}

/// 账号 WebAuthn 挑战存活期（对齐设备域 `SRP_CHALLENGE_TTL`）。
const ACCOUNT_WEBAUTHN_CHALLENGE_TTL: Duration = Duration::from_secs(120);

impl AccountWebauthnState {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 签发挑战（同账号覆盖式——新仪式开始即废弃上一条）。
    pub(super) fn store(
        &self,
        account_id: &str,
        challenge: String,
        rp_id: String,
        ceremony: WebauthnCeremony,
    ) {
        let mut map = self.entries.lock().expect("webauthn challenge lock");
        Self::prune(&mut map);
        map.insert(
            account_id.to_owned(),
            WebauthnChallengeEntry {
                challenge,
                rp_id,
                ceremony,
                expires_at: Instant::now() + ACCOUNT_WEBAUTHN_CHALLENGE_TTL,
            },
        );
    }

    /// 取走未过期且仪式匹配的挑战（一次性；仪式不匹配不消费——留给
    /// 真正的消费者，避免用 register 请求恶意烧掉待用 login 挑战）。
    pub(super) fn take(
        &self,
        account_id: &str,
        ceremony: WebauthnCeremony,
    ) -> Option<(String, String)> {
        let mut map = self.entries.lock().expect("webauthn challenge lock");
        Self::prune(&mut map);
        match map.get(account_id) {
            Some(entry) if entry.ceremony == ceremony && entry.expires_at > Instant::now() => {
                let entry = map.remove(account_id).expect("entry checked above");
                Some((entry.challenge, entry.rp_id))
            }
            _ => None,
        }
    }

    /// 惰性清理：每次触碰时顺带丢弃过期项（无定时任务）。
    fn prune(map: &mut HashMap<String, WebauthnChallengeEntry>) {
        let now = Instant::now();
        map.retain(|_, e| e.expires_at > now);
    }
}

impl Default for AccountWebauthnState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod webauthn_state_tests {
    use super::{AccountWebauthnState, WebauthnCeremony};

    #[test]
    fn challenge_is_single_use_and_ceremony_scoped() {
        let state = AccountWebauthnState::new();
        state.store(
            "acct",
            "challenge-1".to_string(),
            "example.com".to_string(),
            WebauthnCeremony::Register,
        );

        // 仪式不匹配：不消费，留给真正的 register 消费者。
        assert_eq!(state.take("acct", WebauthnCeremony::Authenticate), None);
        let (challenge, rp_id) = state
            .take("acct", WebauthnCeremony::Register)
            .expect("matching ceremony must consume");
        assert_eq!(challenge, "challenge-1");
        assert_eq!(rp_id, "example.com");

        // 一次性：取走即失效。
        assert_eq!(state.take("acct", WebauthnCeremony::Register), None);
    }

    #[test]
    fn expired_or_foreign_account_entries_are_never_served() {
        let state = AccountWebauthnState::new();
        state.store(
            "acct",
            "challenge-1".to_string(),
            "example.com".to_string(),
            WebauthnCeremony::Register,
        );
        // 别的账号取不到。
        assert_eq!(state.take("other", WebauthnCeremony::Register), None);
        // 过期即不存在。
        let mut map = state.entries.lock().unwrap();
        for entry in map.values_mut() {
            entry.expires_at = std::time::Instant::now() - std::time::Duration::from_secs(1);
        }
        drop(map);
        assert_eq!(state.take("acct", WebauthnCeremony::Register), None);
    }

    #[test]
    fn new_store_overrides_pending_challenge_for_same_account() {
        let state = AccountWebauthnState::new();
        state.store(
            "acct",
            "old".to_string(),
            "a.example".to_string(),
            WebauthnCeremony::Register,
        );
        state.store(
            "acct",
            "new".to_string(),
            "b.example".to_string(),
            WebauthnCeremony::Register,
        );
        let (challenge, rp_id) = state.take("acct", WebauthnCeremony::Register).unwrap();
        assert_eq!(challenge, "new");
        assert_eq!(rp_id, "b.example");
    }
}

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
}

/// POST /api/v1/accounts/:account_id/passkeys/create-options
/// Generates passkey creation options for the account (no auth, public endpoint for registration flow).
pub async fn passkey_create_options(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(req): Json<PasskeyCreateOptionsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists
    let account = sqlx::query("SELECT id, username, display_name FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;

    // Generate creation options (challenge + parameters)
    let challenge = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let _user_handle = URL_SAFE_NO_PAD.decode(&req.user_handle).map_err(|_| {
        ApiError::validation(
            "invalid user_handle",
            vec![ErrorItem::batch("user_handle", "not valid base64url")],
        )
    })?;

    // 挑战落内存缓存（120s TTL、一次性）：register 端点消费时与
    // clientDataJSON.challenge 严格比对，杜绝客户端自选挑战（重放）。
    state.account_webauthn.store(
        &account_id,
        challenge.clone(),
        req.rp_id.clone(),
        WebauthnCeremony::Register,
    );

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
/// Registers a new passkey for the account: consumes the create-options
/// challenge and runs full RP-side attestation verification (core
/// `verify_attestation`), then persists the attested credential material.
pub async fn passkey_register(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    payload: Result<Json<PasskeyRegisterRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(req) = payload.map_err(|r| ApiError::rejection(r.status(), r.body_text()))?;

    // Verify account exists
    let _ = sqlx::query("SELECT id FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;

    // 挑战必须来自本账号的 create-options（一次性）：没有在途仪式 = 401
    //（统一无差异信息，不区分"没发起过/已过期/已用过"）。
    let Some((challenge, rp_id)) = state
        .account_webauthn
        .take(&account_id, WebauthnCeremony::Register)
    else {
        return Err(ApiError::unauthorized());
    };

    let credential_id_claim = req
        .attestation_response
        .get("credentialId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::validation(
                "missing credentialId",
                vec![ErrorItem::batch("credentialId", "required")],
            )
        })?;
    let attestation_object_claim = req
        .attestation_response
        .get("attestationObject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::validation(
                "missing attestationObject",
                vec![ErrorItem::batch("attestationObject", "required")],
            )
        })?;

    // 传输层错误（base64/超限）422；密码学验证失败统一 401——不回显
    // 验证内部细节（挑战/origin/签名哪个环节失败只进日志）。
    let attestation_object = decode_b64url_field(
        "attestationObject",
        attestation_object_claim,
        MAX_ATTESTATION_BYTES,
    )?;
    let client_data_bytes = decode_b64url_field(
        "client_data_json",
        &req.client_data_json,
        MAX_CLIENT_DATA_BYTES,
    )?;
    let credential_id_claim =
        decode_b64url_field("credentialId", credential_id_claim, MAX_CREDENTIAL_ID_BYTES)?;

    let verified = passkey::verify_attestation(
        &attestation_object,
        &rp_id,
        &req.origin,
        &client_data_bytes,
        &challenge,
    )
    .map_err(|e| {
        tracing::warn!(%e, account = %account_id, "passkey registration verification failed");
        ApiError::unauthorized()
    })?;

    // 客户端声称的 credentialId 必须与 attested credential data 一致
    //（防止张冠李戴：拿 A 凭据的 id 注册 B 凭据的公钥）。
    if credential_id_claim != verified.credential_id {
        tracing::warn!(account = %account_id, "claimed credentialId does not match attestation");
        return Err(ApiError::unauthorized());
    }

    // 表设计（0007）：id 列即 credential_id 的 base64url 串。
    let passkey_id = URL_SAFE_NO_PAD.encode(&verified.credential_id);
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO account_passkeys (id, account_id, public_key, aaguid, sign_count, backed_up, transports, rp_id, created_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, 'internal', ?, ?, ?)",
    )
    .bind(&passkey_id)
    .bind(&account_id)
    .bind(&verified.public_key_cose)
    .bind(verified.aaguid.to_vec())
    .bind(verified.sign_count as i64)
    .bind(verified.backed_up)
    .bind(&rp_id)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if format!("{e}").contains("UNIQUE") {
            ApiError::conflict("credential already registered")
        } else {
            ApiError::internal(e)
        }
    })?;

    tracing::info!(account = %account_id, passkey = %passkey_id, "passkey registered");
    Ok(Json(serde_json::json!({ "passkey_id": passkey_id })))
}

/// WebAuthn 载荷字段上限（线上解码后字节）。
/// attestation object：CBOR 包 authData（37 + 2 + ≤1023 credId + COSE ≈ 200），
/// 8 KiB 留足余量；clientDataJSON 是小 JSON；断言侧 authData 37 字节头、
/// 签名 DER 70-72 字节。
const MAX_ATTESTATION_BYTES: usize = 8 * 1024;
pub(super) const MAX_CLIENT_DATA_BYTES: usize = 2 * 1024;
pub(super) const MAX_AUTHENTICATOR_DATA_BYTES: usize = 768;
pub(super) const MAX_SIGNATURE_BYTES: usize = 768;
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// base64url 解码（WebAuthn 惯例）+ 常见变体兜底（带 padding 的
/// base64url、标准 base64），超限拒绝。与 [`decode_field`] 的差别只在
/// 优先字符集：WebAuthn 字段一律 base64url，标准 base64 兜底容忍
/// 中间层做错变换的客户端。
pub(super) fn decode_b64url_field(
    field: &str,
    raw: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, ApiError> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE};
    let raw = raw.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| URL_SAFE.decode(raw))
        .or_else(|_| B64.decode(raw))
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .map_err(|_| {
            ApiError::validation(
                format!("invalid base64url in {field}"),
                vec![ErrorItem::batch(field, "not valid base64url")],
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

#[derive(Deserialize)]
pub struct PasskeyLoginOptionsRequest {
    /// 凭据 id（注册时返回的 passkey_id，即 base64url(credential_id)）
    pub credential_id: String,
}

#[derive(Serialize)]
pub struct PasskeyLoginOptionsResponse {
    pub challenge: String,
    pub rp_id: String,
}

/// POST /api/v1/accounts/:account_id/passkeys/login-options
/// Issues an authentication challenge for a registered passkey (public;
/// this is the login ceremony's first step). The challenge must come from
/// the server — assertions against client-chosen challenges are rejected
/// at session creation.
pub async fn passkey_login_options(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    payload: Result<Json<PasskeyLoginOptionsRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(req) = payload.map_err(|r| ApiError::rejection(r.status(), r.body_text()))?;

    let credential_id = req.credential_id.trim();
    if credential_id.is_empty() || credential_id.len() > 1024 {
        return Err(ApiError::validation(
            "invalid credential_id",
            vec![ErrorItem::batch("credential_id", "must be 1..=1024 bytes")],
        ));
    }

    // rp_id 以注册时存下的为准（挑战锚点），未知凭据/无 rp_id 的存根行
    // 一律 401 不泄露存在性。
    let row = sqlx::query("SELECT rp_id FROM account_passkeys WHERE id = ? AND account_id = ?")
        .bind(credential_id)
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::unauthorized)?;
    let rp_id: Option<String> = row.get("rp_id");
    let rp_id = rp_id
        .filter(|s| !s.is_empty())
        .ok_or_else(ApiError::unauthorized)?;

    let challenge = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    state.account_webauthn.store(
        &account_id,
        challenge.clone(),
        rp_id.clone(),
        WebauthnCeremony::Authenticate,
    );
    Ok(Json(PasskeyLoginOptionsResponse { challenge, rp_id }))
}

// ---- Account Login (SRP Password Fallback) ----
