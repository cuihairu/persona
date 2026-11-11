//! Connect 本机自动化 HTTP 端点（CONNECT_AUTOMATION_DESIGN DR-1/DR-3/DR-4）。
//!
//! 独立 crate：桌面（DR-1 A1）与 CLI `persona connect serve`（A2）
//! 两个宿主共用同一 router/三防线/限额实现与同一 core 服务层——
//! token 存储（工作区库内 `connect_tokens` 表）跨宿主天然互通。
//! 其余语义见下（模块文档自 desktop 迁移时保持原样）。
//!
//! listener 内嵌在宿主进程内，双传输（[`ConnectTransport`]）：
//! - **TCP loopback**（默认）：bind 硬编码 `127.0.0.1`（端口 0 = OS 分配；
//!   地址无配置面，「拒绝非 loopback 配置」由硬编码天然满足）。
//! - **Unix domain socket**（`--unix-socket`，仅 unix 平台）：socket 文件
//!   0600 + accept 层 peer-uid 校验（连不上 ≠ 能通过，uid 不符连接即被丢弃），
//!   无 TCP 端口；Windows 无此传输，创建即报错。
//!
//! 默认关闭：不开启 = 不创建 listener。
//!
//! 请求管线（每请求）：
//! 1. Host 头白名单（`127.0.0.1`/`localhost`）→ 否则 421（DNS rebinding）。
//!    **仅 TCP**：unix socket 无名字解析面，DNS rebinding 不可达，跳过该检查
//!    （客户端可发任意 Host，如 Go 生态常用的 `http://unix/…`）。
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

use super::ConnectServerState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use persona_core::PersonaError;
use serde_json::json;

pub(super) fn ok_json<T: serde::Serialize>(data: T) -> Response {
    (
        StatusCode::OK,
        no_store_headers(),
        Json(json!({ "ok": true, "data": data })),
    )
        .into_response()
}

/// 错误包络。message 只承载对消费者有操作意义的描述——内部细节
/// （DB/解密错误文本）不外泄，进 tracing 日志。
pub(super) fn err_json(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        no_store_headers(),
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
        .into_response()
}

pub(super) fn no_store_headers() -> [(&'static str, &'static str); 2] {
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

pub(super) fn is_vault_locked(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<PersonaError>()
            .is_some_and(|pe| matches!(pe, PersonaError::VaultLocked(_)))
    })
}

// -----------------------------------------------------------------------
// 三防线 + 认证 + 限额 middleware
// -----------------------------------------------------------------------

pub(super) async fn guard(
    State(state): State<ConnectServerState>,
    mut request: Request,
    next: Next,
) -> Response {
    // 防线 1：Host 头白名单（仅 loopback TCP）。到达 listener 的流量必然
    // 打到本机端口，Host 的 host 部分仍必须是 loopback 名——DNS rebinding
    // （evil.com → 127.0.0.1）会带恶意 Host，直接 421。unix socket 无名字
    // 解析面（见 `require_loopback_host` 字段文档），跳过。
    if state.require_loopback_host {
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

    // token 已鉴权 + 已解锁：把本次请求记为敏感活动——scoped token 即再
    // 认证（可撤销、有到期、审计在案），桌面端 force_lock_sensitive（敏感
    // 超时 → 锁会话要求再认证）对 token 面不适用，否则登录 5 分钟后的首个
    // 读密文请求永久 500 且无再认证入口。机会性刷新：失败仅 debug，不改变
    // 任何拒绝语义。
    {
        let service_guard = state.service.lock().await;
        if let Some(service) = service_guard.as_ref() {
            if let Err(e) = service.mark_authorized_request().await {
                tracing::debug!("sensitive-activity refresh skipped: {e}");
            }
        }
    }

    request.extensions_mut().insert(row);
    normalize_framework_error(next.run(request).await).await
}
