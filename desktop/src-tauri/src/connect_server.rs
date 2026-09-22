//! Connect 本机自动化端点（CONNECT_AUTOMATION_DESIGN DR-1 A1 / DR-3 / DR-4）。
//!
//! axum listener 内嵌在宿主进程内，bind 硬编码 `127.0.0.1`（端口 0 =
//! OS 分配；地址无配置面，「拒绝非 loopback 配置」由硬编码天然满足）。
//! 默认关闭：不开启 = 不创建 listener。
//!
//! 请求管线（每请求）：
//! 1. Host 头白名单（`127.0.0.1`/`localhost`）→ 否则 421（DNS rebinding）
//! 2. `Origin` 头出现即 403（本机 API 无合法浏览器跨源消费者，CORS 全关）
//! 3. `/health` 免认证零信息；其余要求 `Authorization: Bearer pconn_…`
//! 4. token 哈希查库（吊销/未知同形 401，无缓存窗口）
//! 5. 锁定门禁：未解锁 → 503 `vault_locked`，**不消耗**限额（锁屏重试
//!    风暴不锁死 token）
//! 6. 限额：每 token 每分钟 120 请求（固定窗，超限 429；上限写死）
//! 7. 数据面 scope 过滤（core `connect_*`），scope 外/归档/不存在同形 404
//!
//! 响应一律 `{"ok":…}` 包络（错误 `{"ok":false,"error":{"code","message"}}`，
//! 与 server 包络形状对齐）+ `Cache-Control: no-store`（TOTP 码与字段
//! 明文不进任何中间缓存）。scope 判定与 token 生命周期在 core
//! （`persona_core::connect`），本模块只做 HTTP 面编排。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use persona_core::connect::{ConnectItemType, ConnectTokenRow};
use persona_core::{PersonaError, PersonaService};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

/// 每 token 每分钟请求数上限（DR-3：固定窗；上限写死不做配置——
/// 配置面越大误用面越大）。
pub const RATE_LIMIT_PER_MINUTE: u32 = 120;

const RATE_WINDOW: Duration = Duration::from_secs(60);

/// `Arc<tokio::sync::Mutex<Option<PersonaService>>>` 别名（与 AppState
/// 的 service 字段同型，命令层 clone 传入）。
pub type ArcTokService = Arc<TokioMutex<Option<PersonaService>>>;

#[derive(Clone)]
pub struct ConnectServerState {
    /// 与 AppState 共享的同一 service 槽位（token 校验 + 解锁态门禁）。
    pub service: ArcTokService,
    /// 每 token 固定窗计数：token id → (窗口起点, 已计请求数)。纯内存、
    /// 进程重启即清——这是宿主保护（防失控轮询拖垮宿主），不是审计。
    rates: Arc<Mutex<HashMap<Uuid, (Instant, u32)>>>,
}

impl ConnectServerState {
    pub fn new(service: ArcTokService) -> Self {
        Self {
            service,
            rates: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 固定窗计数：窗口过期则重置为 1；未过期且已满返回 false（429）。
    fn consume_rate(&self, token_id: Uuid) -> bool {
        let mut rates = self.rates.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let slot = rates.entry(token_id).or_insert((now, 0));
        if now.duration_since(slot.0) >= RATE_WINDOW {
            *slot = (now, 1);
            return true;
        }
        if slot.1 >= RATE_LIMIT_PER_MINUTE {
            return false;
        }
        slot.1 += 1;
        true
    }
}

/// 组装路由 + 三防线/认证/限额 middleware。测试与生产共用（生产经
/// [`start_connect_server`] bind，测试经 `Router::oneshot` 无网络直驱）。
pub fn build_router(state: ConnectServerState) -> Router {
    Router::new()
        .route("/api/v1/connect/health", get(health))
        .route("/api/v1/connect/identities", get(identities))
        .route("/api/v1/connect/items", get(items))
        .route("/api/v1/connect/items/:id", get(item))
        .route("/api/v1/connect/items/:id/totp", post(item_totp))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// 启动 Connect listener。返回句柄（实际端口 + 关停通道）；bind 失败
/// （端口被占等）向上传播给调用方（设置页显式报错，不静默重试）。
pub async fn start_connect_server(
    service: ArcTokService,
    port: u16,
) -> anyhow::Result<ConnectServerHandle> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual_port = listener.local_addr()?.port();
    let router = build_router(ConnectServerState::new(service));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });
    Ok(ConnectServerHandle {
        port: actual_port,
        shutdown: shutdown_tx,
    })
}

/// 运行中 listener 的句柄。
pub struct ConnectServerHandle {
    /// listener 实际绑定端口（端口 0 = OS 分配后的真实值）。
    pub port: u16,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl ConnectServerHandle {
    /// 触发 graceful shutdown（同步发送；listener 任务自行收尾）。
    pub fn stop(self) {
        let _ = self.shutdown.send(());
    }
}

// -----------------------------------------------------------------------
// 包络与错误映射
// -----------------------------------------------------------------------

/// 成功包络：`{"ok":true,"data":…}` + `no-store` + 严格 JSON。
fn ok_json<T: serde::Serialize>(data: T) -> Response {
    (
        StatusCode::OK,
        no_store_headers(),
        Json(json!({ "ok": true, "data": data })),
    )
        .into_response()
}

/// 错误包络。message 只承载对消费者有操作意义的描述——内部细节
/// （DB/解密错误文本）不外泄，进 tracing 日志。
fn err_json(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        no_store_headers(),
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
        .into_response()
}

fn no_store_headers() -> [(&'static str, &'static str); 2] {
    [
        (header::CONTENT_TYPE.as_str(), "application/json"),
        (header::CACHE_CONTROL.as_str(), "no-store"),
    ]
}

fn is_vault_locked(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<PersonaError>()
            .is_some_and(|pe| matches!(pe, PersonaError::VaultLocked(_)))
    })
}

// -----------------------------------------------------------------------
// 三防线 + 认证 + 限额 middleware
// -----------------------------------------------------------------------

async fn guard(
    State(state): State<ConnectServerState>,
    mut request: Request,
    next: Next,
) -> Response {
    // 防线 1：Host 头白名单。到达 listener 的流量必然打到本机端口，
    // Host 的 host 部分仍必须是 loopback 名——DNS rebinding（evil.com →
    // 127.0.0.1）会带恶意 Host，直接 421。
    let host_ok = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            let authority = h.rsplit_once(':').map_or(h, |(host, _)| host);
            let authority = authority.trim_start_matches('[').trim_end_matches(']');
            authority == "127.0.0.1" || authority == "localhost" || authority == "::1"
        })
        .unwrap_or(false);
    if !host_ok {
        return err_json(
            StatusCode::MISDIRECTED_REQUEST,
            "bad_host",
            "host not allowed",
        );
    }

    // 防线 2：CORS 全关。Origin 出现即 403（含预检 OPTIONS——不返回任何
    // Access-Control-Allow-* 头，浏览器侧直接失败）。
    if request.headers().contains_key(header::ORIGIN) {
        return err_json(
            StatusCode::FORBIDDEN,
            "origin_forbidden",
            "browser-originated requests are not allowed",
        );
    }

    // health 免认证零信息（存活探测用；不含版本以外任何库状态）。
    if request.uri().path() == "/api/v1/connect/health" {
        return next.run(request).await;
    }

    // 防线 3：token 必需。
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let Some(presented) = presented else {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or malformed bearer token",
        );
    };

    // token 哈希查库（未知/吊销同形 None → 401，防探测）。
    let auth = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => match service.connect_authenticate(presented).await {
                Ok(row) => row,
                Err(_) => {
                    return err_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal",
                        "authentication failed",
                    )
                }
            },
            // service 未初始化 = 库未就绪，按锁定语义处理（503，不扣限额）
            None => {
                return err_json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "vault_locked",
                    "vault is not unlocked",
                )
            }
        }
    };
    let Some(row) = auth else {
        return err_json(StatusCode::UNAUTHORIZED, "unauthorized", "invalid token");
    };

    // 锁定门禁在限额计数之前：锁定 503 不扣限额（DR-4）。
    let unlocked = {
        let service_guard = state.service.lock().await;
        service_guard
            .as_ref()
            .map(|s| s.is_unlocked())
            .unwrap_or(false)
    };
    if !unlocked {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault_locked",
            "vault is locked",
        );
    }

    if !state.consume_rate(row.id) {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "token rate limit exceeded (120 req/min)",
        );
    }

    request.extensions_mut().insert(row);
    next.run(request).await
}

// -----------------------------------------------------------------------
// 端点
// -----------------------------------------------------------------------

/// GET /api/v1/connect/health：零库信息，免认证。
async fn health() -> Response {
    ok_json(json!({
        "service": "persona-connect",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(serde::Serialize)]
struct ConnectIdentityView {
    id: Uuid,
    name: String,
}

/// 数据面错误统一映射：锁定 → 503 vault_locked；其余内部错误 → 500
/// （不外泄细节，进 tracing 日志）。
fn internal_or_locked(e: &anyhow::Error) -> Response {
    if is_vault_locked(e) {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault_locked",
            "vault is locked",
        );
    }
    tracing::warn!(error = %e, "connect endpoint internal error");
    err_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

fn locked_response() -> Response {
    err_json(
        StatusCode::SERVICE_UNAVAILABLE,
        "vault_locked",
        "vault is locked",
    )
}

/// GET /api/v1/connect/identities：scope 内身份（id + 名称）。
async fn identities(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_list_identities(&row.scope).await {
        Ok(list) => ok_json(
            list.into_iter()
                .map(|i| ConnectIdentityView {
                    id: i.id,
                    name: i.name,
                })
                .collect::<Vec<_>>(),
        ),
        Err(e) => internal_or_locked(&e),
    }
}

#[derive(Deserialize)]
struct ItemsQuery {
    identity: Option<Uuid>,
    #[serde(rename = "type")]
    item_type: Option<ConnectItemType>,
    title: Option<String>,
}

/// GET /api/v1/connect/items：scope 内条目元数据。
async fn items(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Query(query): Query<ItemsQuery>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service
        .connect_list_items(&row.scope, query.identity, query.item_type, query.title)
        .await
    {
        Ok(list) => ok_json(list.iter().map(item_meta_json).collect::<Vec<_>>()),
        Err(e) => internal_or_locked(&e),
    }
}

/// 条目类型统一用 scope 的枚举词汇表(snake_case,如 `password`),与
/// `?type=`/`item_types` 一致——消费者只学一套。scope 过滤已挡掉不可
/// 授权类型,这里 None 兜底 null(不应出现)。
fn item_type_slug(c: &persona_core::Credential) -> serde_json::Value {
    ConnectItemType::from_credential_type(&c.credential_type)
        .map(|t| serde_json::to_value(t).unwrap_or_default())
        .unwrap_or(serde_json::Value::Null)
}

fn item_meta_json(c: &persona_core::Credential) -> serde_json::Value {
    json!({
        "id": c.id,
        "title": c.name,
        "type": item_type_slug(c),
        "urls": c.url.as_deref().into_iter().collect::<Vec<_>>(),
        "updated_at": c.updated_at.to_rfc3339(),
    })
}

/// GET /api/v1/connect/items/:id：单条全字段（解密后）。scope 外/归档/
/// 不存在同形 404（防探测）。
async fn item(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Path(id): Path<Uuid>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_get_item_data(&row.scope, &id).await {
        Ok(Some((cred, data))) => ok_json(json!({
            "id": cred.id,
            "title": cred.name,
            "type": item_type_slug(&cred),
            "urls": cred.url.as_deref().into_iter().collect::<Vec<_>>(),
            "username": cred.username,
            "updated_at": cred.updated_at.to_rfc3339(),
            "data": data,
        })),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "not_found", "item not found"),
        Err(e) => internal_or_locked(&e),
    }
}

/// POST /api/v1/connect/items/:id/totp：当前 TOTP 码 + 剩余秒。
async fn item_totp(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Path(id): Path<Uuid>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_totp(&row.scope, &id).await {
        Ok(Some(code)) => ok_json(json!({
            "code": code.code,
            "remaining_seconds": code.remaining_seconds,
        })),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "not_found", "item not found"),
        Err(e) => internal_or_locked(&e),
    }
}

// -----------------------------------------------------------------------
// 测试：DR-4 全拒绝路径 + 数据面 + 限额（Router::oneshot 无网络直驱）
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use persona_core::connect::{ConnectTokenScope, ConnectVerb};
    use persona_core::models::{
        CredentialData, CredentialType, IdentityType, PasswordCredentialData, SecurityLevel,
    };
    use persona_core::storage::Database;
    use tower::ServiceExt;

    struct Fixture {
        router: Router,
        state: ConnectServerState,
        token: String,
        token_row_id: Uuid,
        cred_id: Uuid,
        /// unlock 用的盐（重新解锁恢复会话用——lock() 清内存密钥）。
        salt: [u8; 32],
        _db: Database,
    }

    async fn fixture() -> Fixture {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db.clone()).await.unwrap();
        let salt = service.generate_salt();
        service.unlock("test_password", &salt).unwrap();
        let identity = service
            .create_identity("work".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let cred = service
            .create_credential(
                identity.id,
                "login".to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                &CredentialData::Password(PasswordCredentialData {
                    password: "secret".to_string(),
                    email: Some("a@b.c".to_string()),
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        let scope = ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read],
        };
        let (token, row) = service
            .create_connect_token("test token".to_string(), scope)
            .await
            .unwrap();
        let _ = identity;

        // service 本体（含内存主密钥）移入共享槽位：数据面经 router 走，
        // 管理动作（吊销/锁定/解锁）经 state.service 槽位直调。
        let state = ConnectServerState::new(Arc::new(TokioMutex::new(Some(service))));
        let router = build_router(state.clone());
        Fixture {
            router,
            state,
            token,
            token_row_id: row.id,
            cred_id: cred.id,
            salt,
            _db: db,
        }
    }

    async fn send(
        router: Router,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:17000");
        for (k, v) in headers {
            builder = builder.header(*k, v);
        }
        let req = builder.body(Body::empty()).unwrap();
        let response = router.oneshot(req).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn auth_header(token: &str) -> [(&'static str, String); 1] {
        [("authorization", format!("Bearer {token}"))]
    }

    #[tokio::test]
    async fn health_is_unauthenticated_and_free_of_vault_info() {
        let fx = fixture().await;
        let (status, body) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(body["data"]["service"], "persona-connect");
        // 零库信息:无条目数/身份名/锁定状态之外的字段
        assert!(body["data"].get("items").is_none());
    }

    #[tokio::test]
    async fn missing_malformed_and_unknown_tokens_are_401_same_shape() {
        let fx = fixture().await;
        // 缺失
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
        // 畸形(非 Bearer)
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &[("authorization", "Basic dXNlcjpwYXNz".to_string())],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
        // pconn_ 前缀假值(与缺失同形)
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &auth_header("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn foreign_host_is_421_even_with_valid_token() {
        let fx = fixture().await;
        let builder = HttpRequest::builder()
            .method("GET")
            .uri("/api/v1/connect/items")
            .header("host", "evil.example.com")
            .header("authorization", format!("Bearer {}", fx.token));
        let req = builder.body(Body::empty()).unwrap();
        let response = fx.router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn origin_header_is_403_even_with_valid_token() {
        let fx = fixture().await;
        let (status, body) = send(
            fx.router,
            "GET",
            "/api/v1/connect/items",
            &[
                ("origin", "https://evil.example.com".to_string()),
                ("authorization", format!("Bearer {}", fx.token)),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "origin_forbidden");
    }

    #[tokio::test]
    async fn data_plane_serves_envelope_for_all_endpoints() {
        let fx = fixture().await;
        let auth = auth_header(&fx.token);

        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/identities",
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(body["data"][0]["name"], "work");

        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["id"], fx.cred_id.to_string());
        assert_eq!(body["data"][0]["title"], "login");
        assert_eq!(body["data"][0]["type"], "password");

        // title 精确过滤
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items?title=login",
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items?title=nope",
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);

        let path = format!("/api/v1/connect/items/{}", fx.cred_id);
        let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["title"], "login");
        // 全字段含解密 data(明文密码在响应体内——消费者责任,文档警示)。
        // data 是 CredentialData 原生 serde 形状:外部标签枚举
        // {"Password": {…}}(变体名 PascalCase)。
        assert_eq!(body["data"]["data"]["Password"]["password"], "secret");

        // 不存在的条目 → 404 同形
        let missing = format!("/api/v1/connect/items/{}", Uuid::new_v4());
        let (status, body) = send(fx.router.clone(), "GET", &missing, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
        // TOTP 对非 TwoFactor 条目 → 404 同形
        let totp_path = format!("/api/v1/connect/items/{}/totp", fx.cred_id);
        let (status, body) = send(fx.router, "POST", &totp_path, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn revoked_token_is_401_immediately() {
        let fx = fixture().await;
        {
            let guard = fx.state.service.lock().await;
            guard
                .as_ref()
                .unwrap()
                .revoke_connect_token(&fx.token_row_id)
                .await
                .unwrap();
        }
        let (status, body) = send(
            fx.router,
            "GET",
            "/api/v1/connect/items",
            &auth_header(&fx.token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn locked_vault_is_503_and_does_not_consume_rate() {
        let fx = fixture().await;
        {
            let mut guard = fx.state.service.lock().await;
            guard.as_mut().unwrap().lock();
        }
        let auth = auth_header(&fx.token);
        // 锁定期间反复请求都是 503 vault_locked
        for _ in 0..5 {
            let (status, body) =
                send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"]["code"], "vault_locked");
        }
        // 解锁恢复（lock() 清了内存密钥，用盐重新解锁）：锁定期间的请求
        // 不消耗限额——完整 120 次仍可用
        {
            let mut guard = fx.state.service.lock().await;
            guard
                .as_mut()
                .unwrap()
                .unlock("test_password", &fx.salt)
                .unwrap();
        }
        for _ in 0..RATE_LIMIT_PER_MINUTE {
            let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, body) = send(fx.router, "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn health_does_not_consume_rate_limit() {
        let fx = fixture().await;
        let auth = auth_header(&fx.token);
        // health 免认证也不占 token 限额:任意多次后数据面仍全额可用
        for _ in 0..RATE_LIMIT_PER_MINUTE {
            let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, _) = send(fx.router, "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
    }
}
