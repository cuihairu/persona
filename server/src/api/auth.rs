//! SRP 设备认证端点（`/api/v1/auth/*`，E2EE 同步轨道阶段 1）。
//!
//! 流程（设计稿 E2EE_SYNC_DESIGN DR-2；SRP 数学全部在 core
//! `auth::srp`，本文件只做 HTTP 编排与准入）：
//!
//! 1. `POST /auth/register`（**需既有 Bearer**——静态令牌或已登录的
//!    SRP 令牌构成引导链）：客户端本地生成 (salt, verifier) 上传，
//!    服务器存表——密码与 Argon2 派生值永不出机。
//! 2. `POST /auth/challenge`：客户端带设备名 + 公开值 A；服务器按
//!    verifier 生成 B，未决握手缓存 120s。
//! 3. `POST /auth/verify`：客户端带 session_id + 证明 M1；服务器核验
//!    并签发短期 Bearer 令牌（15 分钟，见 [`crate::auth`]）。
//!
//! fail-closed：认证体系未启用（`state.auth` 为 None）时三个端点整体
//! 503——静态令牌与 SRP 同开同关。锁户：连续 5 次失败锁 15 分钟。

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD};
use base64::Engine as _;
use persona_core::auth::srp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ApiError;
use crate::auth::{DeviceName, SrpChallengeEntry, SRP_CHALLENGE_TTL};
use crate::state::AppState;

/// SRP 盐字节上限（实际 32B，留余量拒绝异常大载荷）。
const MAX_SALT_BYTES: usize = 64;
/// verifier 字节上限（4096-bit group 的 N 为 512B，+余量）。
const MAX_VERIFIER_BYTES: usize = 544;
/// 公开值上限（客户端 a 为 64B、服务器 B 为 512B 级别，都远小于此）。
const MAX_PUBLIC_BYTES: usize = 768;

#[derive(Deserialize)]
pub struct RegisterRequest {
    device_name: String,
    /// base64（标准，含 padding）编码的 salt。
    salt: String,
    /// base64 编码的 SRP verifier。
    verifier: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub device_name: String,
}

/// POST /api/v1/auth/register —— 引导注册：要求既有 Bearer。
pub async fn register(
    State(state): State<AppState>,
    axum::Extension(operator): axum::Extension<DeviceName>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // fail-closed 检查:认证体系未启用时注册同样不可用(绑定名仅此用途)
    let _ = state.srp.as_ref().ok_or_else(ApiError::disabled)?;
    let name = validate_device_name(&req.device_name)?;
    let salt = decode_field("salt", &req.salt, MAX_SALT_BYTES)?;
    let verifier = decode_field("verifier", &req.verifier, MAX_VERIFIER_BYTES)?;

    let id = Uuid::new_v4().to_string();
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO auth_devices (id, device_name, salt, verifier) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&salt)
    .bind(&verifier)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::rejection(
            StatusCode::CONFLICT,
            format!("device {name:?} is already registered"),
        ));
    }
    tracing::info!(operator = %operator.0, device = %name, "SRP device registered");
    Ok(Json(RegisterResponse { device_name: name }))
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    device_name: String,
    /// base64 编码的客户端公开值 A。
    client_public: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub session_id: String,
    /// base64 编码的盐。
    pub salt: String,
    /// base64 编码的服务器公开值 B。
    pub server_public: String,
}

/// POST /api/v1/auth/challenge —— 免 Bearer（这本身就是登录的第一步）。
pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;
    let name = validate_device_name(&req.device_name)?;
    let client_public = decode_field("client_public", &req.client_public, MAX_PUBLIC_BYTES)?;

    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT salt, verifier FROM auth_devices WHERE device_name = ?",
    )
    .bind(&name)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?
    // 设备不存在与任何其他失败同形（401 无差异信息）——不暴露注册状态
    .ok_or_else(ApiError::unauthorized)?;

    let hc = srp::server_challenge(&row.1).map_err(ApiError::internal)?;
    let session_id = Uuid::new_v4().to_string();
    srp_state.store_challenge(
        session_id.clone(),
        SrpChallengeEntry {
            device_name: name,
            verifier: row.1,
            b_priv: hc.b_priv,
            client_public,
            expires_at: std::time::Instant::now() + SRP_CHALLENGE_TTL,
        },
    );
    Ok(Json(ChallengeResponse {
        session_id,
        salt: B64.encode(row.0),
        server_public: B64.encode(hc.b_pub),
    }))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    session_id: String,
    /// base64 编码的客户端证明 M1。
    client_proof: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    /// base64 编码的服务器证明 M2（客户端核验通过才算登录成功）。
    pub server_proof: String,
    /// 短期 Bearer 令牌（客户端在核验 M2 **之后**才应使用）。
    pub token: String,
    pub expires_in_secs: u64,
}

/// POST /api/v1/auth/verify —— 免 Bearer；锁户预检 + 失败记账都在这。
pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;

    // 未决握手先取走（一次握手一条；TTL 外即不存在）
    let entry = srp_state
        .take_challenge(&req.session_id)
        .ok_or_else(ApiError::unauthorized)?;

    if srp_state.is_locked(&entry.device_name) {
        // 423 Locked：明确告诉客户端等待，而非模糊 401（对齐本机锁户反馈）
        return Err(ApiError::rejection(
            StatusCode::LOCKED,
            "account locked after repeated failures; retry later",
        ));
    }

    let client_proof = decode_field("client_proof", &req.client_proof, MAX_PUBLIC_BYTES)?;
    match srp::server_verify(
        &entry.b_priv,
        &entry.verifier,
        &entry.client_public,
        &client_proof,
    ) {
        Ok(outcome) => {
            srp_state.clear_failures(&entry.device_name);
            let token = srp_state.issue_token(&entry.device_name);
            tracing::info!(device = %entry.device_name, "SRP login OK");
            Ok(Json(VerifyResponse {
                server_proof: B64.encode(outcome.server_proof),
                token,
                expires_in_secs: crate::auth::SRP_TOKEN_TTL.as_secs(),
            }))
        }
        Err(_) => {
            srp_state.register_failure(&entry.device_name);
            Err(ApiError::unauthorized())
        }
    }
}

/// 设备名规则与 `PERSONA_SERVER_TOKENS` 的名字约束对齐（非空、≤64 字节、
/// 无空白）。
fn validate_device_name(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(char::is_whitespace) {
        return Err(ApiError::validation(
            "invalid device_name",
            vec![super::ErrorItem::batch(
                "device_name",
                "must be 1-64 bytes, no whitespace",
            )],
        ));
    }
    Ok(trimmed.to_owned())
}

/// base64 字段解码 + 长度上限（无 padding 容忍——客户端可用任一变体）。
fn decode_field(field: &str, raw: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let decoded = B64
        .decode(raw.trim())
        .or_else(|_| STANDARD_NO_PAD.decode(raw.trim()))
        .map_err(|_| {
            ApiError::validation(
                format!("invalid base64 in {field}"),
                vec![super::ErrorItem::batch(field, "not valid base64")],
            )
        })?;
    if decoded.len() > max_bytes {
        return Err(ApiError::validation(
            format!("{field} too large"),
            vec![super::ErrorItem::batch(field, "exceeds length limit")],
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use crate::test_support::{event_json, get_events, post_events, request, send, setup};
    use axum::http::StatusCode;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use persona_core::auth::srp;

    /// 引导链用静态令牌(注册 /auth/register 需要它)。
    const BOOTSTRAP: &str = "bootstrap-token";
    const DEVICE: &str = "test-laptop";
    const PASSWORD: &str = "correct horse battery staple";

    fn register_body() -> String {
        let reg = srp::register_verifier(DEVICE, PASSWORD).unwrap();
        format!(
            r#"{{"device_name":"{DEVICE}","salt":"{}","verifier":"{}"}}"#,
            B64.encode(reg.salt),
            B64.encode(reg.verifier)
        )
    }

    async fn register_device(router: &axum::Router) {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/register",
                Some(&format!("Bearer {BOOTSTRAP}")),
                Some("application/json"),
                &register_body(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["device_name"], DEVICE);
    }

    /// 完整握手一次;`password` 错误时 verify 落 401(SRP 数学上客户端
    /// 总能算出 M1,拒绝发生在服务器侧)。
    async fn attempt_login(
        router: &axum::Router,
        password: &str,
    ) -> (StatusCode, serde_json::Value) {
        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let body = format!(
            r#"{{"device_name":"{DEVICE}","client_public":"{}"}}"#,
            B64.encode(&a_pub)
        );
        let (status, resp) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                &body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();

        let proof = login
            .process(DEVICE, password, &salt, &server_public)
            .unwrap();
        let body = format!(
            r#"{{"session_id":"{session_id}","client_proof":"{}"}}"#,
            B64.encode(proof.client_proof())
        );
        send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/verify",
                None,
                Some("application/json"),
                &body,
            ),
        )
        .await
    }

    #[tokio::test]
    async fn register_requires_bearer() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        let (status, body) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/register",
                None,
                Some("application/json"),
                &register_body(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn register_conflicting_device_name_returns_409() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;
        let (status, body) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/register",
                Some(&format!("Bearer {BOOTSTRAP}")),
                Some("application/json"),
                &register_body(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn register_rejects_non_base64_salt() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        let body =
            format!(r#"{{"device_name":"{DEVICE}","salt":"!!not-b64!!","verifier":"AAAA"}}"#);
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/register",
                Some(&format!("Bearer {BOOTSTRAP}")),
                Some("application/json"),
                &body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(resp["error"]["items"][0]["field"], "salt");
    }

    #[tokio::test]
    async fn challenge_hides_registration_state_for_unknown_device() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;
        let body = r#"{"device_name":"ghost-device","client_public":"AAAA"}"#;
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                body,
            ),
        )
        .await;
        // 未注册设备与无效公开值同形:401,不泄露「是否存在该设备」
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn full_login_issues_token_that_grants_api_access() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        let (status, resp) = attempt_login(&router, PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let token = resp["token"].as_str().unwrap();
        assert_eq!(resp["expires_in_secs"], 900);

        // SRP 签发的短期令牌与静态令牌同权访问受保护端点
        let events = format!(r#"{{"events":[{}]}}"#, event_json("e1", "login"));
        let (status, body) = send(router.clone(), post_events(&events, Some(token))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (status, _) = send(router, get_events("/api/v1/events", BOOTSTRAP)).await;
        assert!(status.is_success());
    }

    #[tokio::test]
    async fn server_proof_verifies_on_client_side() {
        // 双向认证的客户端半边:verify 响应里的 M2 必须通过
        // SrpClientProof::verify_server 核验,且两侧会话密钥一致
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let body = format!(
            r#"{{"device_name":"{DEVICE}","client_public":"{}"}}"#,
            B64.encode(&a_pub)
        );
        let (_, resp) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                &body,
            ),
        )
        .await;
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();
        let proof = login
            .process(DEVICE, PASSWORD, &salt, &server_public)
            .unwrap();

        let verify_body = format!(
            r#"{{"session_id":"{session_id}","client_proof":"{}"}}"#,
            B64.encode(proof.client_proof())
        );
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/verify",
                None,
                Some("application/json"),
                &verify_body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let server_proof = B64.decode(resp["server_proof"].as_str().unwrap()).unwrap();
        let session_key = proof.verify_server(&server_proof).unwrap();
        // premaster 原始字节 = 群模数字节长度(4096-bit group → 512B);
        // 用作密钥材料前由调用方再过 KDF(设计稿:信封加密另走 KDF 链)
        assert_eq!(session_key.len(), 512);
    }

    #[tokio::test]
    async fn wrong_password_returns_401_and_does_not_lock_after_one_failure() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        let (status, body) = attempt_login(&router, "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");

        // 1 次失败不触发锁户:正确密码仍可登录
        let (status, resp) = attempt_login(&router, PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
    }

    #[tokio::test]
    async fn five_consecutive_failures_lock_even_correct_password() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        for _ in 0..5 {
            let (status, _) = attempt_login(&router, "wrong-password").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // 锁定期内正确密码同样 423 Locked
        let (status, body) = attempt_login(&router, PASSWORD).await;
        assert_eq!(status, StatusCode::LOCKED, "{body}");
    }

    #[tokio::test]
    async fn auth_endpoints_fail_closed_without_tokens() {
        // TOKENS 未配 = 认证体系整体未启用:SRP 端点同样 503
        let (router, _) = setup(None).await;
        let body = r#"{"device_name":"x","client_public":"AAAA"}"#;
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp["error"]["code"], "api_disabled");
    }

    // ---- 跨端集成：core HttpRemoteAuthProvider ↔ 本 router（真 TCP）----
    // E2EE_SYNC_DESIGN 阶段 1 验收要点「跨端（CLI↔server）握手集成测试」：
    // 客户端 wire 编排（remote_http.rs）与服务器三端点在真实 HTTP 栈上
    // 互通，签发的 SRP token 能过 require_bearer（与静态 token 共存）。

    #[tokio::test(flavor = "multi_thread")]
    async fn http_provider_full_round_trip_over_real_tcp() {
        use persona_core::auth::remote_http::HttpRemoteAuthProvider;

        let (router, _) = setup(Some(BOOTSTRAP)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        let provider = HttpRemoteAuthProvider::new(format!("http://{addr}")).unwrap();
        provider
            .register_device(BOOTSTRAP, DEVICE, PASSWORD)
            .await
            .unwrap();

        let outcome = provider
            .begin_login(DEVICE)
            .await
            .unwrap()
            .finish(PASSWORD)
            .await
            .unwrap();
        assert!(!outcome.token.is_empty());
        assert_eq!(outcome.expires_in_secs, 900);
        // premaster 512B（4096-bit group）；指纹 = sha256 hex 64 字符
        assert_eq!(outcome.session_key.len(), 512);
        assert_eq!(outcome.session_key_fingerprint.len(), 64);

        // SRP 签发的 token 走 require_bearer：静态 TOKENS miss 后查 SRP 表
        // → 200（token 共存不打断既有链路）
        let probe = reqwest::Client::new()
            .get(format!("http://{addr}/api/v1/events?limit=1"))
            .bearer_auth(&outcome.token)
            .send()
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::OK, "{probe:?}");

        // 错密码 → 服务器 401（与未注册同形），客户端转 AuthenticationFailed
        let err = provider
            .begin_login(DEVICE)
            .await
            .unwrap()
            .finish("totally wrong")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("HTTP 401"), "{err}");

        task.abort();
    }
}
