//! Account system API: registration, login (passkey + SRP fallback), device management, recovery codes.
//!
//! Zero-knowledge principle: master password/key never leaves the device. Server only stores
//! public verification material (passkey public keys, SRP salt+verifier, recovery code hashes).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::Utc;
use persona_core::auth::srp;
use persona_core::crypto::hashing::PasswordHasher;
use persona_core::crypto::passkey::{self, CLIENT_DATA_TYPE_GET};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::{ApiError, ErrorItem};
use crate::auth::{SrpChallengeEntry, SRP_CHALLENGE_TTL};
use crate::state::AppState;

// ---- Account Registration ----

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

// ---- Account Login (Passkey) ----

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
enum WebauthnCeremony {
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
    fn store(
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
    fn take(&self, account_id: &str, ceremony: WebauthnCeremony) -> Option<(String, String)> {
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
const MAX_CLIENT_DATA_BYTES: usize = 2 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 768;
const MAX_SIGNATURE_BYTES: usize = 768;
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// base64url 解码（WebAuthn 惯例）+ 常见变体兜底（带 padding 的
/// base64url、标准 base64），超限拒绝。与 [`decode_field`] 的差别只在
/// 优先字符集：WebAuthn 字段一律 base64url，标准 base64 兜底容忍
/// 中间层做错变换的客户端。
fn decode_b64url_field(field: &str, raw: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
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

/// Generate recovery codes for an account
#[derive(Serialize)]
pub struct GenerateRecoveryCodesResponse {
    pub codes: Vec<String>,
}

/// POST /api/v1/accounts/:account_id/recovery-codes
/// Generates a new set of recovery codes (requires auth).
pub async fn generate_recovery_codes(
    State(state): State<AppState>,
    Extension(_device): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists and user owns it (in real impl, check device authorization)
    let _ = sqlx::query("SELECT id FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;

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

        // Hash with Argon2id using proper algorithm
        let hash = hash_recovery_code(&code)?;

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

/// Hash a recovery code using Argon2id
fn hash_recovery_code(code: &str) -> Result<String, ApiError> {
    let hasher = PasswordHasher::new();
    hasher
        .hash_password(code)
        .map_err(|e| ApiError::internal(format!("Hashing failed: {}", e)))
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
        return Err(ApiError::validation(
            "invalid code format",
            vec![ErrorItem::batch("code", "must be 32 hex chars")],
        ));
    }

    // Decode the hex code to bytes for verification
    let code_bytes = hex::decode(&code).map_err(|_| {
        ApiError::validation(
            "invalid code format",
            vec![ErrorItem::batch("code", "not valid hex")],
        )
    })?;

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

        // Verify the code against the stored hash
        // The hash format is: $argon2id$v=19$m=19456,t=2,p=1$salt$hash
        // We need to extract salt and hash, then verify
        let verified = verify_recovery_code_hash(&stored_hash, &code_bytes);

        if verified {
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

/// Verify a recovery code against an Argon2id hash
fn verify_recovery_code_hash(hash: &str, code_bytes: &[u8]) -> bool {
    let code_hex = hex::encode(code_bytes);
    let hasher = PasswordHasher::new();
    hasher.verify_password(&code_hex, hash).unwrap_or(false)
}

// ---- Account Device Management ----

#[derive(Deserialize)]
pub struct AuthorizeDeviceRequest {
    pub device_id: String,  // sync_devices.id
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
        .ok_or_else(ApiError::not_found)?;

    // Verify sync device exists
    let sync_device =
        sqlx::query("SELECT id, device_name, public_key FROM sync_devices WHERE id = ?")
            .bind(&req.device_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(|| {
                ApiError::validation(
                    "device not found",
                    vec![ErrorItem::batch("device_id", "not enrolled")],
                )
            })?;

    let device_name: String = sync_device.get("device_name");
    let public_key: Vec<u8> = sync_device.get("public_key");

    // Verify public key matches
    let provided_key = B64.decode(&req.public_key).map_err(|_| {
        ApiError::validation(
            "invalid public_key",
            vec![ErrorItem::batch("public_key", "malformed base64")],
        )
    })?;
    if provided_key != public_key {
        return Err(ApiError::validation(
            "public key mismatch",
            vec![ErrorItem::batch(
                "public_key",
                "does not match enrolled device",
            )],
        ));
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
        .map(|row| AccountDeviceInfo {
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

// ---- Account Login (Session) ----

/// passkey 断言证据（login-options 挑战 + authenticator 签名）。
#[derive(Deserialize)]
pub struct PasskeyAssertionRequest {
    /// 注册时返回的 passkey_id（= base64url(credential_id)）
    pub credential_id: String,
    /// base64url 编码的 clientDataJSON
    pub client_data_json: String,
    /// 客户端声明的 origin（须与 clientDataJSON 一致且匹配 rp_id）
    pub origin: String,
    /// base64url 编码的 authenticator data
    pub authenticator_data: String,
    /// base64url 编码的 DER 签名
    pub signature: String,
}

#[derive(Deserialize)]
pub struct CreateAccountSessionRequest {
    /// SRP 兜底登录证据：srp/verify 签发的 15 分钟令牌。
    pub srp_token: Option<String>,
    /// passkey 登录证据：对 login-options 挑战的断言。
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

    // 恰好一种证据：没有 = 422；两种同给 = 422（语义不明，不猜）。
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

/// SRP 证据：令牌必须是本账号未过期的 account_sessions 行。
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

/// passkey 证据：login-options 挑战（一次性）+ clientData 挑战比对 +
/// 签名验证 + sign_count 单调性；通过后更新计数器与 last_used_at。
async fn verify_passkey_evidence(
    state: &AppState,
    account_id: &str,
    assertion: &PasskeyAssertionRequest,
) -> Result<(), ApiError> {
    // 挑战必须来自本账号的 login-options（一次性）；消费失败即 401，
    // 客户端重走 login-options。
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

    // 挑战比对：verify_assertion 不看 clientDataJSON 内容，这里锚定
    // 服务器签发的挑战（防断言重放/客户端自选挑战）。
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

    // sign_count 单调性（克隆检测）：存量非 0 时新值必须更大；两端同为 0
    // 是合法的"无计数器 authenticator"（软件认证器即如此），放行。
    // verify_assertion 已保证 authenticator_data ≥ 37 字节。
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

fn validate_device_name(name: &str) -> Result<String, ApiError> {
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
        request(
            method,
            uri,
            Some(&format!("Bearer {TOKEN}")),
            Some("application/json"),
            body,
        )
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
            request(
                "POST",
                "/api/v1/accounts/register",
                None,
                Some("application/json"),
                &json!({"username": "alice@example.com", "display_name": "Alice"}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let account_id = body["account_id"].as_str().unwrap().to_string();

        // Duplicate registration should fail
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/accounts/register",
                None,
                Some("application/json"),
                &json!({"username": "alice@example.com"}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // Generate recovery codes
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/recovery-codes"),
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["codes"].as_array().unwrap().len(), 8);

        // Verify a recovery code
        let code = body["codes"][0].as_str().unwrap();
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/recovery-codes/verify"),
                &json!({"code": code}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);

        // Same code should not work again
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/recovery-codes/verify"),
                &json!({"code": code}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], false);
    }

    #[tokio::test]
    async fn account_device_management() {
        let router = router().await;

        // Register account
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/accounts/register",
                None,
                Some("application/json"),
                &json!({"username": "bob@example.com"}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let account_id = body["account_id"].as_str().unwrap().to_string();

        // Register a sync device first
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/devices",
                &json!({"device_name": "laptop", "public_key": b64(&[7u8; 32])}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let sync_device_id = body["device_id"].as_str().unwrap().to_string();

        // Authorize device for account
        let (status, body) = send(
            router.clone(),
            req("POST", &format!("/api/v1/accounts/{account_id}/devices"),
                &json!({"device_id": sync_device_id, "device_name": "laptop", "public_key": b64(&[7u8; 32])}).to_string()),
        ).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let _auth_device_id = body["id"].as_str().unwrap().to_string();
        assert_eq!(body["status"], "authorized");

        // List devices
        let (status, body) = send(
            router.clone(),
            get_req(&format!("/api/v1/accounts/{account_id}/devices")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["devices"].as_array().unwrap().len(), 1);
        assert_eq!(body["devices"][0]["status"], "authorized");

        // Revoke device
        let (status, _) = send(
            router.clone(),
            request(
                "DELETE",
                &format!("/api/v1/accounts/{account_id}/devices/{sync_device_id}"),
                Some(&format!("Bearer {TOKEN}")),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Verify revoked
        let (status, body) = send(
            router.clone(),
            get_req(&format!("/api/v1/accounts/{account_id}/devices")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["devices"].as_array().unwrap()[0]["status"], "revoked");
    }

    // ---- M2 验证链第一批：账号 SRP 真握手 / passkey 真 attestation / sessions 证据 ----

    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use persona_core::crypto::passkey;

    const SRP_DEVICE: &str = "primary";
    const SRP_PASSWORD: &str = "correct horse battery staple";
    const RP_ID: &str = "example.com";
    const ORIGIN: &str = "https://example.com";

    async fn setup_state() -> (axum::Router, crate::state::AppState) {
        crate::test_support::setup(Some(TOKEN)).await
    }

    async fn create_account(router: &axum::Router, username: &str) -> String {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/accounts/register",
                None,
                Some("application/json"),
                &json!({"username": username}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["account_id"].as_str().unwrap().to_string()
    }

    async fn register_account_srp(router: &axum::Router, account_id: &str) {
        let reg = srp::register_verifier(SRP_DEVICE, SRP_PASSWORD).unwrap();
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/srp/register"),
                &json!({
                    "device_name": SRP_DEVICE,
                    "salt": b64(&reg.salt),
                    "verifier": b64(&reg.verifier),
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// 发起账号 SRP challenge，返回 (session_id, salt, server_public)。
    async fn account_srp_challenge(
        router: &axum::Router,
        account_id: &str,
    ) -> (String, Vec<u8>, Vec<u8>) {
        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let (status, resp) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/srp/challenge"),
                None,
                Some("application/json"),
                &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        (
            resp["session_id"].as_str().unwrap().to_owned(),
            B64.decode(resp["salt"].as_str().unwrap()).unwrap(),
            B64.decode(resp["server_public"].as_str().unwrap()).unwrap(),
        )
    }

    /// 完整账号 SRP 握手一次；密码错时 verify 落 401（SRP 数学上客户端
    /// 总能算出 M1，拒绝发生在服务器侧的 server_verify）。
    async fn attempt_account_srp_login(
        router: &axum::Router,
        account_id: &str,
        password: &str,
    ) -> (StatusCode, serde_json::Value) {
        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let (status, resp) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/srp/challenge"),
                None,
                Some("application/json"),
                &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();

        let proof = login
            .process(SRP_DEVICE, password, &salt, &server_public)
            .unwrap();
        send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/srp/verify"),
                None,
                Some("application/json"),
                &json!({"session_id": session_id, "client_proof": b64(proof.client_proof())})
                    .to_string(),
            ),
        )
        .await
    }

    async fn account_session_count(state: &crate::state::AppState, account_id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM account_sessions WHERE account_id = ?")
            .bind(account_id)
            .fetch_one(&state.pool)
            .await
            .unwrap()
    }

    async fn account_passkey_count(state: &crate::state::AppState, account_id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM account_passkeys WHERE account_id = ?")
            .bind(account_id)
            .fetch_one(&state.pool)
            .await
            .unwrap()
    }

    // ---- 账号 SRP：challenge 出真 B、verify 验 client_proof ----

    #[tokio::test]
    async fn account_srp_challenge_returns_real_server_public() {
        let (router, _) = setup_state().await;
        let account_id = create_account(&router, "srp-real@example.com").await;
        register_account_srp(&router, &account_id).await;

        let (_, salt, server_public) = account_srp_challenge(&router, &account_id).await;
        // 4096-bit group：B 与 verifier 同为 512B 级（前导零时 511B），
        // 不再是 verifier 占位。
        assert!(
            (400..=512).contains(&server_public.len()),
            "server_public len = {}",
            server_public.len()
        );
        assert_eq!(salt.len(), 32);
    }

    #[tokio::test]
    async fn account_srp_login_round_trip_verifies_client_proof() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "srp-alice@example.com").await;
        register_account_srp(&router, &account_id).await;

        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let (status, resp) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/srp/challenge"),
                None,
                Some("application/json"),
                &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();

        let proof = login
            .process(SRP_DEVICE, SRP_PASSWORD, &salt, &server_public)
            .unwrap();
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/srp/verify"),
                None,
                Some("application/json"),
                &json!({"session_id": session_id, "client_proof": b64(proof.client_proof())})
                    .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["expires_in_secs"], 900);

        // 双向认证：server_proof（M2）必须过客户端核验
        let server_proof = B64.decode(body["server_proof"].as_str().unwrap()).unwrap();
        let session_key = proof.verify_server(&server_proof).unwrap();
        assert!((1..=512).contains(&session_key.len()));
        assert!(session_key.iter().any(|&b| b != 0));

        // DB：15min 会话行落库
        let token = body["token"].as_str().unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM account_sessions WHERE account_id = ? AND session_token = ?",
        )
        .bind(&account_id)
        .bind(token)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn account_srp_wrong_password_rejected_without_session() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "srp-wrong@example.com").await;
        register_account_srp(&router, &account_id).await;

        let (status, body) =
            attempt_account_srp_login(&router, &account_id, "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_session_count(&state, &account_id).await, 0);

        // 1 次失败不触发锁户：正确密码仍可登录
        let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn account_srp_verify_requires_client_proof_field() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "srp-fields@example.com").await;
        register_account_srp(&router, &account_id).await;
        let (session_id, _, _) = account_srp_challenge(&router, &account_id).await;

        // 缺 client_proof → 422（serde 反序列化 rejection）
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/srp/verify"),
                None,
                Some("application/json"),
                &json!({"session_id": session_id}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(account_session_count(&state, &account_id).await, 0);
    }

    #[tokio::test]
    async fn account_srp_verify_rejects_cross_account_session() {
        let (router, state) = setup_state().await;
        let a = create_account(&router, "cross-a@example.com").await;
        let b = create_account(&router, "cross-b@example.com").await;
        register_account_srp(&router, &b).await;
        // b 注册了 SRP 凭据，a 没有——拿 b 的 session 去 a 的 verify 路径
        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let (status, resp) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{b}/srp/challenge"),
                None,
                Some("application/json"),
                &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();
        let proof = login
            .process(SRP_DEVICE, SRP_PASSWORD, &salt, &server_public)
            .unwrap();

        // 正确的 M1，但打到 a 的路径：锁键前缀不匹配 → 401
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{a}/srp/verify"),
                None,
                Some("application/json"),
                &json!({"session_id": session_id, "client_proof": b64(proof.client_proof())})
                    .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_session_count(&state, &a).await, 0);
    }

    #[tokio::test]
    async fn account_srp_five_failures_lock_account() {
        let (router, _) = setup_state().await;
        let account_id = create_account(&router, "srp-locked@example.com").await;
        register_account_srp(&router, &account_id).await;

        for _ in 0..5 {
            let (status, _) =
                attempt_account_srp_login(&router, &account_id, "wrong-password").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // 锁定期内正确密码同样 423 Locked
        let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
        assert_eq!(status, StatusCode::LOCKED, "{body}");
    }

    // ---- passkey 注册：真 attestation 验证 ----

    /// 走 create-options（返回带服务器挑战的 options JSON）。
    async fn get_create_options(router: &axum::Router, account_id: &str) -> serde_json::Value {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/create-options"),
                None,
                Some("application/json"),
                &json!({
                    "rp_id": RP_ID,
                    "rp_name": "Example",
                    "user_handle": B64URL.encode(b"user-1"),
                    "user_name": "alice@example.com",
                    "user_display_name": "Alice",
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    fn create_client_data(challenge: &str) -> String {
        format!(r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{ORIGIN}"}}"#)
    }

    /// 以服务器签发的挑战完成软件认证器注册（返回注册产物）。
    async fn register_account_passkey(
        router: &axum::Router,
        account_id: &str,
    ) -> passkey::RegistrationOutput {
        let options = get_create_options(router, account_id).await;
        let challenge = options["challenge"].as_str().unwrap();
        let client_data = create_client_data(challenge);
        let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();

        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/register"),
                None,
                Some("application/json"),
                &json!({
                    "attestation_response": {
                        "credentialId": B64URL.encode(&reg.credential_id),
                        "attestationObject": B64URL.encode(&reg.attestation_object),
                    },
                    "client_data_json": B64URL.encode(client_data.as_bytes()),
                    "origin": ORIGIN,
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["passkey_id"].as_str().unwrap(),
            B64URL.encode(&reg.credential_id)
        );
        reg
    }

    #[tokio::test]
    async fn passkey_registration_stores_attested_material() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "passkey-alice@example.com").await;
        let reg = register_account_passkey(&router, &account_id).await;

        // DB：真 COSE 公钥 + rp_id 锚点 + 计数器（不再是无密钥存根行）
        let row = sqlx::query(
            "SELECT public_key, rp_id, sign_count, transports FROM account_passkeys WHERE id = ?",
        )
        .bind(B64URL.encode(&reg.credential_id))
        .fetch_one(&state.pool)
        .await
        .unwrap();
        let public_key: Vec<u8> = row.get("public_key");
        assert_eq!(public_key, reg.public_key_cose);
        assert_eq!(row.get::<String, _>("rp_id"), RP_ID);
        assert_eq!(row.get::<i64, _>("sign_count"), 0);
        assert_eq!(row.get::<String, _>("transports"), "internal");
    }

    #[tokio::test]
    async fn passkey_register_without_create_options_rejected() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "passkey-noch@example.com").await;

        // 没发起过 create-options：客户端自造挑战 → 401
        let client_data = create_client_data("client-made-up-challenge");
        let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/register"),
                None,
                Some("application/json"),
                &json!({
                    "attestation_response": {
                        "credentialId": B64URL.encode(&reg.credential_id),
                        "attestationObject": B64URL.encode(&reg.attestation_object),
                    },
                    "client_data_json": B64URL.encode(client_data.as_bytes()),
                    "origin": ORIGIN,
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_passkey_count(&state, &account_id).await, 0);
    }

    #[tokio::test]
    async fn passkey_register_with_stale_challenge_rejected() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "passkey-stale@example.com").await;

        // 拿了挑战 A，却用过期/别的挑战 B 造 clientData → 401
        let _options = get_create_options(&router, &account_id).await;
        let client_data = create_client_data("b3RoZXItY2hhbGxlbmdl");
        let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/register"),
                None,
                Some("application/json"),
                &json!({
                    "attestation_response": {
                        "credentialId": B64URL.encode(&reg.credential_id),
                        "attestationObject": B64URL.encode(&reg.attestation_object),
                    },
                    "client_data_json": B64URL.encode(client_data.as_bytes()),
                    "origin": ORIGIN,
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_passkey_count(&state, &account_id).await, 0);
    }

    #[tokio::test]
    async fn passkey_register_credential_id_mismatch_rejected() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "passkey-mism@example.com").await;

        let options = get_create_options(&router, &account_id).await;
        let client_data = create_client_data(options["challenge"].as_str().unwrap());
        let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();
        // 声称的 credentialId 与 attested 数据不一致（张冠李戴）→ 401
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/register"),
                None,
                Some("application/json"),
                &json!({
                    "attestation_response": {
                        "credentialId": B64URL.encode([9u8; 32]),
                        "attestationObject": B64URL.encode(&reg.attestation_object),
                    },
                    "client_data_json": B64URL.encode(client_data.as_bytes()),
                    "origin": ORIGIN,
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_passkey_count(&state, &account_id).await, 0);
    }

    // ---- passkey 登录：login-options 挑战 + sessions 断言验证 ----

    /// 走 login-options 并用返回的挑战完成一次断言。
    async fn login_options_and_assert(
        router: &axum::Router,
        account_id: &str,
        reg: &passkey::RegistrationOutput,
    ) -> (String, passkey::AssertionOutput) {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/login-options"),
                None,
                Some("application/json"),
                &json!({"credential_id": B64URL.encode(&reg.credential_id)}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rp_id"].as_str().unwrap(), RP_ID);
        let challenge = body["challenge"].as_str().unwrap().to_owned();

        let client_data =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}"}}"#);
        let out = passkey::assert_passkey(
            RP_ID,
            ORIGIN,
            client_data.as_bytes(),
            &reg.signing_key,
            false,
        )
        .unwrap();
        (client_data, out)
    }

    fn assertion_body(
        passkey_id: &str,
        client_data: &str,
        out: &passkey::AssertionOutput,
    ) -> String {
        json!({
            "passkey_assertion": {
                "credential_id": passkey_id,
                "client_data_json": B64URL.encode(client_data.as_bytes()),
                "origin": ORIGIN,
                "authenticator_data": B64URL.encode(&out.authenticator_data),
                "signature": B64URL.encode(&out.signature_der),
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn create_session_with_passkey_assertion_round_trip() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "pk-login@example.com").await;
        let reg = register_account_passkey(&router, &account_id).await;
        let passkey_id = B64URL.encode(&reg.credential_id);

        let (client_data, out) = login_options_and_assert(&router, &account_id, &reg).await;
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &assertion_body(&passkey_id, &client_data, &out),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["expires_in_secs"], 86400);

        // DB：24h 会话行 + last_used_at 触达
        let token = body["session_token"].as_str().unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM account_sessions WHERE account_id = ? AND session_token = ?",
        )
        .bind(&account_id)
        .bind(token)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
        let last_used: String =
            sqlx::query_scalar("SELECT last_used_at FROM account_passkeys WHERE id = ?")
                .bind(&passkey_id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert!(!last_used.is_empty());

        // 重放：重新 login-options（新挑战）后旧断言的挑战已不匹配 → 401
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/login-options"),
                None,
                Some("application/json"),
                &json!({"credential_id": passkey_id}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &assertion_body(&passkey_id, &client_data, &out),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    #[tokio::test]
    async fn create_session_rejects_tampered_signature() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "pk-tamper@example.com").await;
        let reg = register_account_passkey(&router, &account_id).await;
        let (client_data, mut out) = login_options_and_assert(&router, &account_id, &reg).await;

        // 翻转签名尾字节
        let last = out.signature_der.len() - 1;
        out.signature_der[last] ^= 0xFF;

        let passkey_id = B64URL.encode(&reg.credential_id);
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &assertion_body(&passkey_id, &client_data, &out),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_session_count(&state, &account_id).await, 0);
    }

    #[tokio::test]
    async fn create_session_rejects_sign_count_regression() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "pk-count@example.com").await;
        let reg = register_account_passkey(&router, &account_id).await;
        let passkey_id = B64URL.encode(&reg.credential_id);

        // 存量计数器抬到 5：软件认证器断言恒为 0 → 回退 → 401（克隆检测）
        sqlx::query("UPDATE account_passkeys SET sign_count = 5 WHERE id = ?")
            .bind(&passkey_id)
            .execute(&state.pool)
            .await
            .unwrap();

        let (client_data, out) = login_options_and_assert(&router, &account_id, &reg).await;
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &assertion_body(&passkey_id, &client_data, &out),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_session_count(&state, &account_id).await, 0);
    }

    #[tokio::test]
    async fn login_options_hides_unknown_credentials() {
        let (router, _) = setup_state().await;
        let account_id = create_account(&router, "pk-unknown@example.com").await;

        // 未知凭据 → 401（与"无挑战"同形，不泄露凭据存在性）
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/passkeys/login-options"),
                None,
                Some("application/json"),
                &json!({"credential_id": "unknown-credential-id"}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    // ---- sessions 证据分派：SRP token 臂 ----

    #[tokio::test]
    async fn create_session_with_srp_token_evidence() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "sess-srp@example.com").await;
        register_account_srp(&router, &account_id).await;
        let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let srp_token = body["token"].as_str().unwrap().to_owned();

        // 真 SRP token → 24h 会话
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &json!({"srp_token": srp_token}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["expires_in_secs"], 86400);

        // 假 token → 401
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &json!({"srp_token": "forged-token"}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

        // 跨账号：A 的 token 打到 B 的路径 → 401
        let other = create_account(&router, "sess-other@example.com").await;
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{other}/sessions"),
                &json!({"srp_token": srp_token}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(account_session_count(&state, &other).await, 0);
    }

    #[tokio::test]
    async fn create_session_rejects_missing_or_double_evidence() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "sess-none@example.com").await;

        // 无证据 → 422
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &json!({}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // 两种证据同给 → 422
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                &json!({
                    "srp_token": "some-token",
                    "passkey_assertion": {
                        "credential_id": "x", "client_data_json": "e30", "origin": ORIGIN,
                        "authenticator_data": "AQ", "signature": "AQ",
                    },
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(account_session_count(&state, &account_id).await, 0);
    }

    // ---- M2 收口：account_sessions 令牌消费方（require_account_bearer） ----

    /// 登录兑换链端到端：SRP 登录令牌（15min，account_sessions 行）本身
    /// 即可作账号路由 Bearer——兑换 24h 会话 → 会话令牌驱动账号管理路由
    /// （含活跃触达）→ 吊销自身（登出）→ 再用即 401。
    #[tokio::test]
    async fn account_session_tokens_drive_account_routes_end_to_end() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "consumer@example.com").await;
        register_account_srp(&router, &account_id).await;
        let (status, body) = attempt_account_srp_login(&router, &account_id, SRP_PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let srp_token = body["token"].as_str().unwrap().to_owned();

        // 15 分钟 SRP 令牌作 Bearer + 证据 → 24h 账号会话（此前该流程在
        // 没有静态令牌的客户端上拿不到 Bearer，兑换链断在第一步）
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                &format!("/api/v1/accounts/{account_id}/sessions"),
                Some(&format!("Bearer {srp_token}")),
                Some("application/json"),
                &json!({"srp_token": srp_token}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let session_token = body["session_token"].as_str().unwrap().to_owned();

        async fn session_activity(state: &crate::state::AppState, token: &str) -> String {
            sqlx::query_scalar(
                "SELECT last_activity_at FROM account_sessions WHERE session_token = ?",
            )
            .bind(token)
            .fetch_one(&state.pool)
            .await
            .unwrap()
        }
        let before = session_activity(&state, &session_token).await;

        // 24h 会话令牌驱动账号管理路由 + last_activity_at 被消费方触达
        let (status, body) = send(
            router.clone(),
            request(
                "GET",
                &format!("/api/v1/accounts/{account_id}/devices"),
                Some(&format!("Bearer {session_token}")),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["devices"].as_array().unwrap().len(), 0);
        let after = session_activity(&state, &session_token).await;
        assert!(
            after > before,
            "activity should be touched ({before} → {after})"
        );

        // 登出：会话令牌吊销自己 → 204；被吊销的令牌再用即 401
        let (status, _) = send(
            router.clone(),
            request(
                "DELETE",
                &format!("/api/v1/accounts/{account_id}/sessions/{session_token}"),
                Some(&format!("Bearer {session_token}")),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = send(
            router.clone(),
            request(
                "GET",
                &format!("/api/v1/accounts/{account_id}/devices"),
                Some(&format!("Bearer {session_token}")),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// 路径归属限定：账号 A 的会话令牌打 B 的账号路径 → 401。
    #[tokio::test]
    async fn account_session_token_rejected_on_foreign_account_paths() {
        let (router, _) = setup_state().await;
        let owner = create_account(&router, "owner@example.com").await;
        register_account_srp(&router, &owner).await;
        let (status, body) = attempt_account_srp_login(&router, &owner, SRP_PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["token"].as_str().unwrap().to_owned();

        let other = create_account(&router, "foreign@example.com").await;
        let (status, _) = send(
            router.clone(),
            request(
                "GET",
                &format!("/api/v1/accounts/{other}/devices"),
                Some(&format!("Bearer {token}")),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// 过期会话行不认（消费侧 TTL 与签发/证据核验同口径）。
    #[tokio::test]
    async fn expired_account_session_token_is_rejected() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "expired@example.com").await;
        sqlx::query(
            "INSERT INTO account_sessions (id, account_id, session_token, expires_at, created_at, last_activity_at)
             VALUES ('sid-expired', ?, 'expired-session-token', '2020-01-01T00:00:00+00:00',
                     '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00')",
        )
        .bind(&account_id)
        .execute(&state.pool)
        .await
        .unwrap();

        let (status, _) = send(
            router.clone(),
            request(
                "GET",
                &format!("/api/v1/accounts/{account_id}/devices"),
                Some("Bearer expired-session-token"),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// 迁移 0007 边界：账号会话不作 sync/events 的 Bearer——require_bearer
    /// 不查 account_sessions，账号路由之外的提权不存在。
    #[tokio::test]
    async fn account_session_token_is_not_accepted_outside_account_routes() {
        let (router, state) = setup_state().await;
        let account_id = create_account(&router, "isolation@example.com").await;
        let now = chrono::Utc::now().to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        sqlx::query(
            "INSERT INTO account_sessions (id, account_id, session_token, expires_at, created_at, last_activity_at)
             VALUES ('sid-live', ?, 'live-session-token', ?, ?, ?)",
        )
        .bind(&account_id)
        .bind(&future)
        .bind(&now)
        .bind(&now)
        .execute(&state.pool)
        .await
        .unwrap();

        // 未过期令牌对 sync/events 均无效（require_bearer 无此消费方）
        for uri in ["/api/v1/sync/devices", "/api/v1/events"] {
            let (status, _) = send(
                router.clone(),
                request("GET", uri, Some("Bearer live-session-token"), None, ""),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        }
        // 同一令牌在其归属账号路径上仍然有效（对照组，确认插入的行可用）
        let (status, _) = send(
            router.clone(),
            request(
                "GET",
                &format!("/api/v1/accounts/{account_id}/devices"),
                Some("Bearer live-session-token"),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}
