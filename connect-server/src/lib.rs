//! Connect 本机自动化 HTTP 端点（CONNECT_AUTOMATION_DESIGN DR-1/DR-3/DR-4）。
//!
//! 独立 crate：桌面（DR-1 A1）与 CLI `persona connect serve`（A2）
//! 两个宿主共用同一 router/三防线/限额实现与同一 core 服务层——
//! token 存储（工作区库内 `connect_tokens` 表）跨宿主天然互通。
//! 其余语义见下（模块文档自 desktop 迁移时保持原样）。
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
use axum::http::{header, HeaderValue, StatusCode};
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
        .route("/api/v1/connect/items/{id}", get(item))
        .route("/api/v1/connect/items/{id}/totp", post(item_totp))
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

/// 归一化框架自产 4xx：路由未命中（404）、方法不匹配（405）、提取器
/// 拒绝（400，如 `items/:id` 的非法 UUID）走 axum 默认响应——不经
/// `{"ok":false,"error":{…}}` 包络、不带 `Cache-Control: no-store`（4xx
/// 默认可缓存）。本 crate 自产 4xx 恒带 no-store（`err_json` 是唯一生产
/// 者），故以「4xx 且缺 no-store」识别框架响应：保留状态码与既有响应头
/// （405 的 `Allow` 有调试价值），补 no-store 并换上包络正文（框架正文
/// 为空或一行纯文本，直接丢弃）。
async fn normalize_framework_error(response: Response) -> Response {
    let framework = response.status().is_client_error()
        && !response.headers().contains_key(header::CACHE_CONTROL);
    if !framework {
        return response;
    }
    let status = response.status();
    let (mut parts, body) = response.into_parts();
    // 框架正文极小；无论读取成败都已被消费，统一丢弃
    let _ = axum::body::to_bytes(body, 4096).await;
    parts
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let (code, message) = match status {
        StatusCode::BAD_REQUEST => ("bad_request", "malformed request or path parameter"),
        StatusCode::NOT_FOUND => ("not_found", "route not found"),
        StatusCode::METHOD_NOT_ALLOWED => {
            ("method_not_allowed", "method not allowed for this route")
        }
        _ => (
            "error",
            status.canonical_reason().unwrap_or("request rejected"),
        ),
    };
    (
        status,
        parts.headers,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
        .into_response()
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
            // 括号 IPv6（RFC 9110 §4.1.2）省略端口时不能按 ':' 切端口：
            // "[::1]" 会被 rsplit_once 剩 "[::"，白名单里的 ::1 反被误拒。
            // 仅当整段不以 ']' 结尾（即不是无端口的括号 IPv6）才剥端口。
            let authority = if h.ends_with(']') {
                h
            } else {
                h.rsplit_once(':').map_or(h, |(host, _)| host)
            };
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
    // 归一化同样适用：POST /health 的 405 也该带包络（免认证不豁免路由）。
    if request.uri().path() == "/api/v1/connect/health" {
        return normalize_framework_error(next.run(request).await).await;
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
    normalize_framework_error(next.run(request).await).await
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
    use persona_core::connect::{ConnectItemType, ConnectTokenScope, ConnectVerb};
    use persona_core::models::{
        CredentialData, CredentialType, IdentityType, PasswordCredentialData, SecurityLevel,
        SshKeyData, TwoFactorData,
    };
    use persona_core::storage::Database;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tower::ServiceExt;

    struct Fixture {
        router: Router,
        state: ConnectServerState,
        token: String,
        token_row_id: Uuid,
        identity_id: Uuid,
        cred_id: Uuid,
        /// unlock 用的盐（重新解锁恢复会话用——lock() 清内存密钥）。
        salt: [u8; 32],
        /// 连接池句柄：限额/DB 故障路径要能主动 `close()` 掉池子。
        db: Database,
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

        // service 本体（含内存主密钥）移入共享槽位：数据面经 router 走，
        // 管理动作（吊销/锁定/解锁）经 state.service 槽位直调。
        let state = ConnectServerState::new(Arc::new(TokioMutex::new(Some(service))));
        let router = build_router(state.clone());
        Fixture {
            router,
            state,
            token,
            token_row_id: row.id,
            identity_id: identity.id,
            cred_id: cred.id,
            salt,
            db,
        }
    }

    /// 读权限 scope 构造器。`identities`/`item_types` 传空 = 全部（语义见
    /// core `ConnectTokenScope`）。
    fn read_scope(identities: Vec<Uuid>, item_types: Vec<ConnectItemType>) -> ConnectTokenScope {
        ConnectTokenScope {
            identities,
            item_types,
            verbs: vec![ConnectVerb::Read],
        }
    }

    /// 同一 service 上再签一个 token：共用 router 与限额表，但按 row.id
    /// 分列计数——用来验「限额是 per-token 而非全局」。
    async fn mint_token(fx: &Fixture, label: &str, token_scope: ConnectTokenScope) -> String {
        let guard = fx.state.service.lock().await;
        guard
            .as_ref()
            .unwrap()
            .create_connect_token(label.to_string(), token_scope)
            .await
            .unwrap()
            .0
    }

    async fn add_identity(fx: &Fixture, name: &str) -> Uuid {
        let guard = fx.state.service.lock().await;
        guard
            .as_ref()
            .unwrap()
            .create_identity(name.to_string(), IdentityType::Personal)
            .await
            .unwrap()
            .id
    }

    async fn add_credential(
        fx: &Fixture,
        identity_id: Uuid,
        name: &str,
        credential_type: CredentialType,
        data: CredentialData,
    ) -> Uuid {
        let guard = fx.state.service.lock().await;
        guard
            .as_ref()
            .unwrap()
            .create_credential(
                identity_id,
                name.to_string(),
                credential_type,
                SecurityLevel::High,
                &data,
            )
            .await
            .unwrap()
            .id
    }

    fn password_data() -> CredentialData {
        CredentialData::Password(PasswordCredentialData {
            password: "pw".to_string(),
            email: None,
            security_questions: vec![],
        })
    }

    fn totp_data() -> CredentialData {
        CredentialData::TwoFactor(TwoFactorData {
            secret_key: "JBSWY3DPEHPK3PXP".to_string(),
            issuer: "ACME".to_string(),
            account_name: "a@b.c".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
        })
    }

    /// 带默认 loopback `Host` 的便捷调用：只关心状态码 + 包络 JSON。
    async fn send(
        router: Router,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> (StatusCode, serde_json::Value) {
        let mut with_host: Vec<(&str, String)> = Vec::with_capacity(headers.len() + 1);
        with_host.push(("host", "127.0.0.1:17000".to_string()));
        with_host.extend_from_slice(headers);
        let (status, _, json) = send_capture(router, method, path, &with_host).await;
        (status, json)
    }

    /// 全保真调用：保留响应头，并容忍**非** JSON 正文（防御性：框架
    /// 4xx 已由 `normalize_framework_error` 统一包络，但第三方 layer
    /// 理论上仍可能产非 JSON 正文，解析失败折成 Null 不炸断言）。
    /// `headers` 不自动补 Host——缺 Host 本身就是被测路径。
    async fn send_capture(
        router: Router,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        let mut builder = HttpRequest::builder().method(method).uri(path);
        for (k, v) in headers {
            builder = builder.header(*k, v);
        }
        let req = builder.body(Body::empty()).unwrap();
        let response = router.oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            headers,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// 真 TCP 上发一条 HTTP/1.1 请求并读回全部响应文本（`Connection: close`
    /// 保证服务端发完即关，`read_to_end` 不会挂）。用于驱动
    /// [`start_connect_server`] 起的 listener，验证防线不只存在于 oneshot。
    async fn http_over_tcp(port: u16, method: &str, path: &str, host: &str, extra: &str) -> String {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request =
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await
            .expect("listener 未在 5s 内应答")
            .unwrap();
        String::from_utf8(buf).expect("响应非 UTF-8")
    }

    fn auth_header(token: &str) -> [(&'static str, String); 1] {
        [("authorization", format!("Bearer {token}"))]
    }

    /// `send_capture` 不补 Host，需要 Host + Bearer 的用例走这个（数组元组
    /// 手拼会撞上 `auth_header` 返回的定长数组类型）。
    fn host_and_auth(token: &str) -> Vec<(&'static str, String)> {
        vec![
            ("host", "127.0.0.1:17000".to_string()),
            ("authorization", format!("Bearer {token}")),
        ]
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

    // -------------------------------------------------------------------
    // 防线顺序与响应卫生
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn every_response_carries_no_store_and_json_content_type() {
        let fx = fixture().await;
        // 成功、数据面、以及**错误**响应都必须带 no-store：TOTP 码/字段明文
        // 一旦进了中间缓存就不该再指望 2xx 那侧记得带头。
        // 只覆盖**我们生成的**响应。提取器拒绝/路由未命中走 axum 默认响应
        // （无包络、无 no-store），形状在
        // `unknown_routes_...`/`query_and_path_filters_...` 里单独钉住。
        let missing = Uuid::new_v4().to_string();
        // 第三元 = 是否带合法 token（不带即 401，也是我们的包络）。
        type Case = (&'static str, String, bool);
        let cases: Vec<Case> = vec![
            ("GET", "/api/v1/connect/health".to_string(), false),
            ("GET", "/api/v1/connect/items".to_string(), true),
            ("GET", "/api/v1/connect/items".to_string(), false),
            ("GET", format!("/api/v1/connect/items/{missing}"), true),
            (
                "POST",
                format!("/api/v1/connect/items/{missing}/totp"),
                true,
            ),
        ];
        for (method, path, with_auth) in cases {
            let mut all: Vec<(&str, String)> = vec![("host", "127.0.0.1:17000".to_string())];
            if with_auth {
                all.extend(auth_header(&fx.token));
            }
            let (status, resp_headers, _) =
                send_capture(fx.router.clone(), method, &path, &all).await;
            let cache = resp_headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(cache, "no-store", "{method} {path} → {status} 缺 no-store");
            let ctype = resp_headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert!(
                ctype.starts_with("application/json"),
                "{method} {path} → {status} content-type 应为 JSON，实为 {ctype:?}"
            );
        }
    }

    #[tokio::test]
    async fn absent_host_header_is_421_even_for_health() {
        let fx = fixture().await;
        // health 免认证，但不免 Host 白名单——防线 1 在所有例外之前。
        // send_capture 不补 Host → 这条请求根本没有 Host 头。
        let (status, _, body) =
            send_capture(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(body["error"]["code"], "bad_host");
    }

    #[tokio::test]
    async fn lookalike_hosts_are_421_and_never_treated_as_loopback() {
        let fx = fixture().await;
        // 全部带合法 token：证明拒绝来自 Host 而不是缺认证。前缀/后缀拼是
        // DNS rebinding 之外的典型误放行点（`starts_with("127.0.0.1")` 会放过
        // 127.0.0.1.evil.com）。
        for host in [
            "127.0.0.1.evil.com",
            "127.0.0.1.evil.com:17000",
            "localhost.evil.com",
            "evil-localhost",
            "notlocal",
            "",
            "127.0.0.2",
            // IPv6 字面量在 authority 里必须带方括号（RFC 9110 §4.1.2）；
            // 裸 "::1" 缺括号形式非法，按 ':' 切端口后剩空串 → 拒绝。
            // （括号形式 "[::1]"/"[::1]:port" 的放行见 alias 测试。）
            "::1",
        ] {
            let (status, _, body) = send_capture(
                fx.router.clone(),
                "GET",
                "/api/v1/connect/items",
                &[
                    ("host", host.to_string()),
                    ("authorization", format!("Bearer {}", fx.token)),
                ],
            )
            .await;
            assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "host={host:?}");
            assert_eq!(body["error"]["code"], "bad_host", "host={host:?}");
        }
    }

    #[tokio::test]
    async fn loopback_host_aliases_pass_the_host_guard() {
        let fx = fixture().await;
        // 不带 token → 401 而不是 421，即 Host 这关已经过了（端口与 IPv6
        // 方括号形式都必须剥掉再比对）。
        for host in [
            "127.0.0.1",
            "127.0.0.1:17000",
            "localhost",
            "localhost:17000",
            "[::1]:17000",
            // 省略端口的括号 IPv6（段尾 ']'）：不能按 ':' 切端口，否则
            // "[::1]" 剩 "[::" 被误拒——白名单写着 ::1 就该放行
            "[::1]",
        ] {
            let (status, _, body) = send_capture(
                fx.router.clone(),
                "GET",
                "/api/v1/connect/items",
                &[("host", host.to_string())],
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "host={host:?}");
            assert_eq!(body["error"]["code"], "unauthorized", "host={host:?}");
        }
    }

    #[tokio::test]
    async fn defenses_are_ordered_host_then_origin_then_auth_then_health() {
        let fx = fixture().await;
        // 防线 2 先于 health 例外：带 Origin 的 /health 是 403，不是免检 200。
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/health",
            &[("origin", "http://localhost:3000".to_string())],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "origin_forbidden");
        // 防线 1 先于防线 2：坏 Host + Origin 报 bad_host（421）而非 403。
        let (status, _, body) = send_capture(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/health",
            &[
                ("host", "evil.example.com".to_string()),
                ("origin", "http://localhost:3000".to_string()),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(body["error"]["code"], "bad_host");
        // 防线 3 先于路由：不存在的路径未认证时是 401，不泄露路由表。
        let (status, body) =
            send(fx.router.clone(), "GET", "/api/v1/connect/nonexistent", &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn empty_and_non_bearer_credentials_are_401_shaped_like_unknown_tokens() {
        let fx = fixture().await;
        for value in [
            "Bearer ",
            "Bearer    ",
            "Bearer",
            "bearer pconn_abc",
            "Token pconn_abc",
            "pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let (status, body) = send(
                fx.router.clone(),
                "GET",
                "/api/v1/connect/items",
                &[("authorization", value.to_string())],
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "value={value:?}");
            assert_eq!(body["error"]["code"], "unauthorized", "value={value:?}");
            // message 只有两类：格式不合法（缺/畸形）与查无此 token。既不
            // 泄露「token 存在但被吊销」，也不区分大小写笔误的 scheme。
            let msg = body["error"]["message"].as_str().unwrap_or_default();
            assert!(
                msg == "missing or malformed bearer token" || msg == "invalid token",
                "value={value:?} message={msg:?}"
            );
        }
    }

    #[tokio::test]
    async fn empty_service_slot_is_503_vault_locked_while_health_stays_up() {
        // 宿主尚未初始化库（service 槽位 None）：数据面按锁定语义处理，
        // health 仍可用（存活探测不该被库状态拖成 5xx）。
        let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
        let router = build_router(state.clone());
        let (status, body) = send(
            router.clone(),
            "GET",
            "/api/v1/connect/items",
            &auth_header("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "vault_locked");
        let (status, body) = send(router, "GET", "/api/v1/connect/health", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["service"], "persona-connect");
        // 没有 token 行可记账 → 限额表必须保持空（否则探测能占满内存）
        assert!(state.rates.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn database_failure_is_500_and_leaks_nothing_from_the_cause() {
        let fx = fixture().await;
        let auth = auth_header(&fx.token);
        let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK, "失败注入前数据面可用");

        fx.db.pool().close().await;

        // 鉴权自身查库失败走 guard 的 500 分支——是 internal 不是 401，
        // 否则 DB 抖动会被消费者当成 token 失效去重签。
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal");
        assert_eq!(body["error"]["message"], "authentication failed");
        let leaked = body.to_string().to_lowercase();
        for forbidden in ["sqlx", "sqlite", "pool", "closed", "memory"] {
            assert!(
                !leaked.contains(forbidden),
                "500 响应外泄了内部细节: {leaked}"
            );
        }
        // 同一条 DB 故障路径下 health 仍 200（免鉴权、不落库）。
        let (status, _) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
        assert_eq!(status, StatusCode::OK);
    }

    // -------------------------------------------------------------------
    // 限额：固定窗语义
    // -------------------------------------------------------------------

    #[test]
    fn consume_rate_allows_exactly_the_cap_then_rejects_within_the_window() {
        let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
        let id = Uuid::new_v4();
        for n in 1..=RATE_LIMIT_PER_MINUTE {
            assert!(state.consume_rate(id), "第 {n} 次在预算内");
        }
        assert!(
            !state.consume_rate(id),
            "第 {} 次必须超限（429）",
            RATE_LIMIT_PER_MINUTE + 1
        );
        // 计数按 token 分列，不是全局令牌桶
        assert!(state.consume_rate(Uuid::new_v4()));
    }

    #[test]
    fn consume_rate_resets_the_counter_when_the_window_elapsed() {
        let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
        let id = Uuid::new_v4();
        // 直接种一个「窗口已过期」的槽位：Instant 是单调时钟，构造过去只能
        // 靠 checked_sub；机器开机不足一个窗口时长时无法构造，跳过而非误红。
        let stale = match Instant::now().checked_sub(RATE_WINDOW + Duration::from_secs(1)) {
            Some(at) => at,
            None => {
                eprintln!(
                    "skip: 单调时钟不足 {}s，造不出过期窗口",
                    RATE_WINDOW.as_secs()
                );
                return;
            }
        };
        state
            .rates
            .lock()
            .unwrap()
            .insert(id, (stale, RATE_LIMIT_PER_MINUTE));
        assert!(
            state.consume_rate(id),
            "过期窗口必须重置计数，否则 token 永久锁死"
        );
        // 重置后从 1 重新起算 → 整窗预算仍是 120
        for _ in 1..RATE_LIMIT_PER_MINUTE {
            assert!(state.consume_rate(id));
        }
        assert!(!state.consume_rate(id));
    }

    #[tokio::test]
    async fn rejected_requests_leave_the_rate_map_untouched() {
        let fx = fixture().await;
        for _ in 0..20 {
            // 缺 token / 坏 Origin / 坏 Host / health：全都在记账之前返回。
            send(fx.router.clone(), "GET", "/api/v1/connect/items", &[]).await;
            send(
                fx.router.clone(),
                "GET",
                "/api/v1/connect/items",
                &[("origin", "http://evil".to_string())],
            )
            .await;
            send_capture(
                fx.router.clone(),
                "GET",
                "/api/v1/connect/items",
                &[("host", "evil.example.com".to_string())],
            )
            .await;
            send(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
        }
        assert!(
            fx.state.rates.lock().unwrap().is_empty(),
            "未过检的请求不得占用 token 预算"
        );
        let auth = auth_header(&fx.token);
        for _ in 0..5 {
            let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
            assert_eq!(status, StatusCode::OK);
        }
        let rates = fx.state.rates.lock().unwrap();
        assert_eq!(rates.len(), 1, "只有过检请求记账，且按 token 一条");
        assert_eq!(
            rates[&fx.token_row_id].1, 5,
            "计数应等于成功请求数（含在 handler 里被拒的请求，见下一个测试）"
        );
    }

    #[tokio::test]
    async fn authenticated_requests_consume_budget_even_when_input_is_rejected() {
        let fx = fixture().await;
        // 种到差一次即满：证明计数发生在 guard 内、路由/提取器之前。
        fx.state
            .rates
            .lock()
            .unwrap()
            .insert(fx.token_row_id, (Instant::now(), RATE_LIMIT_PER_MINUTE - 1));
        let auth = auth_header(&fx.token);
        let (status, _, body) = send_capture(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items/not-a-uuid",
            &host_and_auth(&fx.token),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"], "bad_request",
            "提取器拒绝也走统一包络（框架默认正文已由 normalize 包装）"
        );
        let (status, body) = send(fx.router, "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn rate_limit_is_per_token_not_per_process() {
        let fx = fixture().await;
        let second = mint_token(&fx, "second", read_scope(vec![], vec![])).await;
        let first = auth_header(&fx.token);
        for _ in 0..RATE_LIMIT_PER_MINUTE {
            let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &first).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &first).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "rate_limited");
        // 另一个 token 不受牵连（一个失控客户端不能 DoS 其他集成）
        let (status, _) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &auth_header(&second),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fx.state.rates.lock().unwrap().len(), 2);
    }

    // -------------------------------------------------------------------
    // scope 过滤与条目可见性（数据面状态流转）
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn identity_scoped_token_sees_only_its_identity_and_answers_empty_for_others() {
        let fx = fixture().await;
        let other = add_identity(&fx, "personal").await;
        let other_cred = add_credential(
            &fx,
            other,
            "personal-login",
            CredentialType::Password,
            password_data(),
        )
        .await;
        let scoped = mint_token(&fx, "work-only", read_scope(vec![fx.identity_id], vec![])).await;
        let auth = auth_header(&scoped);

        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
        let titles: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles, vec!["login"], "scope 外身份的条目不得出现在列表");

        // scope 外条目 = 与不存在同形的 404（不区分 403，防探测）
        let missing = format!("/api/v1/connect/items/{}", other_cred);
        let (status, body) = send(fx.router.clone(), "GET", &missing, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
        let unknown = format!("/api/v1/connect/items/{}", Uuid::new_v4());
        let (unknown_status, unknown_body) = send(fx.router.clone(), "GET", &unknown, &auth).await;
        assert_eq!(
            (status, &body["error"]["code"]),
            (unknown_status, &unknown_body["error"]["code"]),
            "越权与不存在必须同形"
        );

        // 显式请求 scope 外的身份：200 空列表，而不是 403/404
        let query = format!("/api/v1/connect/items?identity={other}");
        let (status, body) = send(fx.router.clone(), "GET", &query, &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
        let query = format!("/api/v1/connect/items?identity={}", fx.identity_id);
        let (status, body) = send(fx.router.clone(), "GET", &query, &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        // 身份列表同样按 scope 收敛
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/identities",
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 1);

        // 对照组：全 scope token 两条身份都看得见
        let all = auth_header(&fx.token);
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &all).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
        let (status, _) = send(fx.router, "GET", &missing, &all).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn type_scoped_token_hides_other_types_on_every_endpoint() {
        let fx = fixture().await;
        let totp_id = add_credential(
            &fx,
            fx.identity_id,
            "2fa",
            CredentialType::TwoFactor,
            totp_data(),
        )
        .await;
        let scoped = mint_token(
            &fx,
            "password-only",
            read_scope(vec![], vec![ConnectItemType::Password]),
        )
        .await;
        let auth = auth_header(&scoped);

        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        let totp_path = format!("/api/v1/connect/items/{}", totp_id);
        let (status, body) = send(fx.router.clone(), "GET", &totp_path, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
        let totp_post = format!("/api/v1/connect/items/{}/totp", totp_id);
        let (status, body) = send(fx.router.clone(), "POST", &totp_post, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
        // 过滤器本身也不给越权数据
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items?type=totp",
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn sensitive_types_stay_invisible_even_for_an_all_scope_token() {
        let fx = fixture().await;
        let ssh = add_credential(
            &fx,
            fx.identity_id,
            "bastion-key",
            CredentialType::SshKey,
            CredentialData::SshKey(SshKeyData {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAAA".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            }),
        )
        .await;
        let wallet = add_credential(
            &fx,
            fx.identity_id,
            "cold-wallet",
            CredentialType::CryptoWallet,
            CredentialData::Raw(vec![1, 2, 3]),
        )
        .await;
        let custom = add_credential(
            &fx,
            fx.identity_id,
            "legacy-card",
            CredentialType::Custom("card".to_string()),
            CredentialData::Raw(vec![4, 5, 6]),
        )
        .await;
        let auth = auth_header(&fx.token);

        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
        let titles: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles, vec!["login"], "敏感类型恒不可授权：{titles:?}");
        for id in [ssh, wallet, custom] {
            let path = format!("/api/v1/connect/items/{}", id);
            let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{id} 泄漏");
            assert_eq!(body["error"]["code"], "not_found");
        }
    }

    #[tokio::test]
    async fn archived_credential_leaves_the_connect_surface() {
        let fx = fixture().await;
        {
            let guard = fx.state.service.lock().await;
            let service = guard.as_ref().unwrap();
            let mut cred = service
                .get_credential(&fx.cred_id)
                .await
                .unwrap()
                .expect("fixture 条目存在");
            cred.is_active = false;
            service.update_credential(&cred).await.unwrap();
        }
        let auth = auth_header(&fx.token);
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["data"].as_array().unwrap().len(),
            0,
            "归档条目不进列表"
        );
        let path = format!("/api/v1/connect/items/{}", fx.cred_id);
        let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
        let totp = format!("/api/v1/connect/items/{}/totp", fx.cred_id);
        let (status, _) = send(fx.router, "POST", &totp, &auth).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn totp_endpoint_serves_the_current_code_for_a_scoped_twofactor_item() {
        let fx = fixture().await;
        let totp_id = add_credential(
            &fx,
            fx.identity_id,
            "2fa",
            CredentialType::TwoFactor,
            totp_data(),
        )
        .await;
        let auth = auth_header(&fx.token);
        let path = format!("/api/v1/connect/items/{}/totp", totp_id);
        let (status, body) = send(fx.router.clone(), "POST", &path, &auth).await;
        assert_eq!(status, StatusCode::OK);
        let code = body["data"]["code"].as_str().unwrap_or_default();
        assert_eq!(code.len(), 6, "TOTP 码应为 6 位: {code:?}");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "TOTP 码必须是数字: {code:?}"
        );
        let remaining = body["data"]["remaining_seconds"].as_u64().unwrap();
        assert!((1..=30).contains(&remaining), "剩余秒越界: {remaining}");
        // 同一周期内两次取码相同（周期边界附近不做断言，避免抖动）
        if remaining > 5 {
            let (_, second) = send(fx.router.clone(), "POST", &path, &auth).await;
            assert_eq!(second["data"]["code"], code, "同一周期内码不该变");
        }
        // 元数据列表里该条目按 scope 词汇表标成 totp
        let (status, body) = send(fx.router, "GET", "/api/v1/connect/items?type=totp", &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["type"], "totp");
    }

    #[tokio::test]
    async fn query_and_path_filters_are_exact_and_reject_malformed_input() {
        let fx = fixture().await;
        let auth = auth_header(&fx.token);
        // 组合过滤
        let q = format!(
            "/api/v1/connect/items?identity={}&type=password&title=login",
            fx.identity_id
        );
        let (status, body) = send(fx.router.clone(), "GET", &q, &auth).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        // title 是精确匹配（大小写敏感），不是子串
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items?title=Log",
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
        // 畸形参数：4xx 而不是 500（不能把库/解析细节变成服务器错误）
        for path in [
            "/api/v1/connect/items?identity=not-a-uuid",
            "/api/v1/connect/items?type=bogus",
            "/api/v1/connect/items/not-a-uuid",
        ] {
            let (status, _, _) =
                send_capture(fx.router.clone(), "GET", path, &host_and_auth(&fx.token)).await;
            assert!(
                status.is_client_error() && status != StatusCode::UNAUTHORIZED,
                "{path} 应折成请求侧 4xx，实为 {status}"
            );
        }
    }

    /// 端点内读到坏行 → 500 `internal`（`internal_or_locked` 的非锁定臂在
    /// 各 handler 的调用点）。这是那条臂唯一能确定性驱动的入口：guard 之后
    /// 再锁库是竞态，而损坏的行是真实故障（vault 文件被截断/密钥轮换半途）。
    #[tokio::test]
    async fn rows_the_endpoint_cannot_read_are_500_internal_without_leaking_the_cause() {
        let fx = fixture().await;
        let totp_id = add_credential(
            &fx,
            fx.identity_id,
            "2fa",
            CredentialType::TwoFactor,
            totp_data(),
        )
        .await;
        let broken_list = add_credential(
            &fx,
            fx.identity_id,
            "junk",
            CredentialType::Password,
            password_data(),
        )
        .await;
        let auth = auth_header(&fx.token);

        // ① 身份行的时间戳列坏掉 → 行映射失败 → identities 端点 Err。
        fx.db
            .execute(&format!(
                "UPDATE identities SET updated_at = 'not-a-timestamp' WHERE id = '{}'",
                fx.identity_id
            ))
            .await
            .unwrap();
        let (status, body) = send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/identities",
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal");
        assert_eq!(body["error"]["message"], "internal error");

        // ② 密文中间字节翻掉（长度不变，只让 AEAD 校验失败）→ 单条读取 Err。
        for id in [fx.cred_id, totp_id] {
            for (num, den, byte) in [(1u32, 3u32, "5a"), (2, 3, "a5")] {
                fx.db
                    .execute(&format!(
                        "UPDATE credentials SET encrypted_data =                          substr(encrypted_data, 1, length(encrypted_data)*{num}/{den})                          || X'{byte}'                          || substr(encrypted_data, length(encrypted_data)*{num}/{den} + 2)                          WHERE id = '{id}'"
                    ))
                    .await
                    .unwrap();
            }
        }
        let path = format!("/api/v1/connect/items/{}", fx.cred_id);
        let (status, body) = send(fx.router.clone(), "GET", &path, &auth).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "解密失败不能折成 404（消费者会误判条目被删）"
        );
        assert_eq!(body["error"]["code"], "internal");
        let totp_path = format!("/api/v1/connect/items/{}/totp", totp_id);
        let (status, body) = send(fx.router.clone(), "POST", &totp_path, &auth).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal");

        // ③ 列表里任一行读不出来 → 整个列表 500（不静默丢条目）。
        fx.db
            .execute(&format!(
                "UPDATE credentials SET updated_at = 'not-a-timestamp' WHERE id = '{broken_list}'"
            ))
            .await
            .unwrap();
        let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal");

        // 三类内部细节都不许进响应体（只进 tracing 日志）。
        let leaked = body.to_string().to_lowercase();
        for forbidden in [
            "decrypt",
            "invalid",
            "updated_at",
            "timestamp",
            "sql",
            "not-a",
            "credential",
            "gcm",
            "bincode",
        ] {
            assert!(
                !leaked.contains(forbidden),
                "500 响应外泄内部细节: {leaked}"
            );
        }
        // health 不受库损坏影响（不落库），存活探测必须还活着。
        let (status, _) = send(fx.router, "GET", "/api/v1/connect/health", &[]).await;
        assert_eq!(status, StatusCode::OK);
    }

    // 说明：四个 handler 里的 `locked_response()` 分支（service 槽位在 guard
    // 查过 is_unlocked 之后、进 handler 之前变成 None）经路由不可确定性触发
    // ——那是纯竞态，且方向安全（503 而非 5xx 泄漏）。故不为其伪造测试，改由
    // `ok_err_and_locked_envelopes_match_the_documented_shape` 直接钉住
    // `locked_response()` 的状态码与错误码，调用点保持纵深防御原样。

    #[tokio::test]
    async fn unknown_routes_and_methods_404_405_after_authentication() {
        let fx = fixture().await;
        let (status, _, body) = send_capture(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/nonexistent",
            &host_and_auth(&fx.token),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found", "路由未命中也走统一包络");
        let (status, headers, body) = send_capture(
            fx.router.clone(),
            "DELETE",
            "/api/v1/connect/items",
            &host_and_auth(&fx.token),
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body["error"]["code"], "method_not_allowed");
        assert_eq!(
            headers.get("cache-control").and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "框架 405 同样带 no-store（4xx 默认可缓存）"
        );
        // 405 的 Allow 头保留（方法协商对调试有价值）
        assert!(
            headers.get("allow").is_some(),
            "axum 默认 405 的 Allow 头必须保留"
        );
        // health 只认 GET：免认证例外不是免路由（防止 health 变成通配口）；
        // 早退路径同样经归一化——免认证不豁免包络
        let (status, headers, body) = send_capture(
            fx.router.clone(),
            "POST",
            "/api/v1/connect/health",
            &[("host", "127.0.0.1:17000".to_string())],
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body["error"]["code"], "method_not_allowed");
        assert_eq!(
            headers.get("cache-control").and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        // TOTP 端点只认 POST
        let path = format!("/api/v1/connect/items/{}/totp", fx.cred_id);
        let (status, _, body) =
            send_capture(fx.router.clone(), "GET", &path, &host_and_auth(&fx.token)).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body["error"]["code"], "method_not_allowed");
    }

    // -------------------------------------------------------------------
    // 包络/映射纯函数与 listener 生命周期
    // -------------------------------------------------------------------

    #[test]
    fn is_vault_locked_walks_the_whole_cause_chain() {
        let direct: anyhow::Error = PersonaError::VaultLocked("locked".to_string()).into();
        assert!(is_vault_locked(&direct));
        let nested = direct.context("connect endpoint").context("outer wrap");
        assert!(is_vault_locked(&nested), "锁定态可能被多层 context 包住");
        assert!(!is_vault_locked(&anyhow::Error::from(
            PersonaError::Database("no such table".to_string())
        )));
        assert!(!is_vault_locked(&anyhow::anyhow!("plain failure")));
    }

    #[tokio::test]
    async fn internal_or_locked_maps_locked_to_503_and_other_errors_to_500() {
        // 这两个臂经路由不可达：guard 已在鉴权后查过 is_unlocked，鉴权自身
        // 失败又是另一个 500。作为纵深防御保留，故直调纯函数覆盖。
        let locked = anyhow::Error::from(PersonaError::VaultLocked("vault locked".to_string()))
            .context("connect endpoint");
        let (status, body) = response_parts(internal_or_locked(&locked)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "vault_locked");

        let boom = anyhow::anyhow!("sqlite PoolClosed: /home/user/.persona/vault.db");
        let (status, body) = response_parts(internal_or_locked(&boom)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal");
        assert_eq!(body["error"]["message"], "internal error");
        let leaked = body.to_string().to_lowercase();
        for forbidden in ["sqlite", "poolclosed", "vault.db", "/home/"] {
            assert!(!leaked.contains(forbidden), "内部错误文本外泄: {leaked}");
        }
    }

    #[tokio::test]
    async fn ok_err_and_locked_envelopes_match_the_documented_shape() {
        let response = ok_json(json!({ "x": 1 }));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            body_json(response).await,
            json!({ "ok": true, "data": { "x": 1 } })
        );

        let response = err_json(StatusCode::NOT_FOUND, "not_found", "item not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_json(response).await,
            json!({ "ok": false, "error": { "code": "not_found", "message": "item not found" } })
        );

        let (status, body) = response_parts(locked_response()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "vault_locked");
    }

    #[tokio::test]
    async fn item_type_slug_is_the_scope_vocabulary_with_a_null_floor() {
        let fx = fixture().await;
        let base = {
            let guard = fx.state.service.lock().await;
            guard
                .as_ref()
                .unwrap()
                .get_credential(&fx.cred_id)
                .await
                .unwrap()
                .unwrap()
        };
        let mut cred = base.clone();
        cred.credential_type = CredentialType::Password;
        assert_eq!(item_type_slug(&cred), json!("password"));
        cred.credential_type = CredentialType::TwoFactor;
        assert_eq!(item_type_slug(&cred), json!("totp"));
        cred.credential_type = CredentialType::SecureNote;
        assert_eq!(item_type_slug(&cred), json!("note"));
        // 不可映射类型走 null 兜底（scope 过滤已挡住，这里防的是将来漏过滤）
        for ty in [
            CredentialType::SshKey,
            CredentialType::CryptoWallet,
            CredentialType::Custom("card".to_string()),
        ] {
            cred.credential_type = ty.clone();
            assert_eq!(item_type_slug(&cred), serde_json::Value::Null, "{ty:?}");
        }

        let meta = item_meta_json(&base);
        assert_eq!(meta["id"], fx.cred_id.to_string());
        assert_eq!(meta["title"], "login");
        assert_eq!(meta["type"], "password");
        assert_eq!(
            meta["urls"].as_array().unwrap().len(),
            0,
            "无 url 时 urls 仍是数组（不是 null），消费者可无脑迭代"
        );
        assert_eq!(meta["updated_at"], json!(base.updated_at.to_rfc3339()));
        let mut with_url = base.clone();
        with_url.url = Some("https://example.com".to_string());
        assert_eq!(
            item_meta_json(&with_url)["urls"],
            json!(["https://example.com"])
        );
    }

    #[tokio::test]
    async fn listener_binds_loopback_serves_defenses_over_tcp_and_releases_on_stop() {
        // 不需要真 service：listener 生命周期与三防线都不依赖库。
        let service: ArcTokService = Arc::new(TokioMutex::new(None));
        let handle = start_connect_server(service, 0).await.unwrap();
        assert_ne!(handle.port, 0, "端口 0 要回传 OS 分配的真实值");

        let text = http_over_tcp(
            handle.port,
            "GET",
            "/api/v1/connect/health",
            "127.0.0.1",
            "",
        )
        .await;
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "真 socket 上 health 应 200: {text}"
        );
        assert!(text.contains("\"ok\":true"), "响应缺包络: {text}");
        assert!(
            text.to_lowercase().contains("cache-control: no-store"),
            "响应缺 no-store: {text}"
        );
        // 三防线不是 oneshot 专属：走 hyper 解析后同样生效
        let text = http_over_tcp(
            handle.port,
            "GET",
            "/api/v1/connect/health",
            "evil.example.com",
            "",
        )
        .await;
        assert!(
            text.starts_with("HTTP/1.1 421"),
            "DNS rebinding 未拦: {text}"
        );
        let text = http_over_tcp(
            handle.port,
            "GET",
            "/api/v1/connect/health",
            "127.0.0.1",
            "Origin: http://evil.example.com\r\n",
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 403"), "跨源未拦: {text}");
        // 数据面在库未初始化（service None）时 503；health 仍 200（真 socket）
        let service: ArcTokService = Arc::new(TokioMutex::new(None));
        let handle2 = start_connect_server(service, 0).await.unwrap();
        let auth = "Authorization: Bearer pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n";
        let text = http_over_tcp(
            handle2.port,
            "GET",
            "/api/v1/connect/health",
            "127.0.0.1",
            auth,
        )
        .await;
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "health 免鉴权，带 token 也应 200: {text}"
        );
        let text = http_over_tcp(
            handle2.port,
            "GET",
            "/api/v1/connect/items",
            "127.0.0.1",
            auth,
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 503"), "未初始化库应 503: {text}");
        assert!(text.contains("vault_locked"), "503 缺错误码: {text}");
        // 缺 token → 401；真 socket 上的顺序与 oneshot 一致
        let text = http_over_tcp(
            handle2.port,
            "GET",
            "/api/v1/connect/items",
            "127.0.0.1",
            "",
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 401"), "缺 token 应 401: {text}");
        assert_ne!(handle.port, handle2.port, "两次 bind 拿到不同端口");

        let (port1, port2) = (handle.port, handle2.port);
        handle.stop();
        handle2.stop();
        // graceful shutdown 后端口不再接受连接（轮询而非 sleep 猜时长）
        let stopped = async {
            for _ in 0..100 {
                if TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port1)))
                    .await
                    .is_err()
                {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            false
        }
        .await;
        assert!(stopped, "stop() 后 listener 未释放端口 {port1}");
        let still_open = TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port2)))
            .await
            .is_err();
        assert!(still_open, "stop() 后第二个 listener 端口也应关闭");
    }

    #[tokio::test]
    async fn bind_failure_is_propagated_instead_of_silently_retried() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = occupied.local_addr().unwrap().port();
        let service: ArcTokService = Arc::new(TokioMutex::new(None));
        let result = start_connect_server(service, port).await;
        assert!(
            result.is_err(),
            "端口 {port} 被占时 bind 必须报错，不得静默换端口"
        );
        let err = result.err().unwrap();
        let io = err
            .downcast_ref::<std::io::Error>()
            .expect("bind 失败应保持 io::Error 原样，供设置页显式报错");
        assert_eq!(io.kind(), std::io::ErrorKind::AddrInUse, "错误: {err}");
        drop(occupied);
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn response_parts(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        (status, body_json(response).await)
    }
}
