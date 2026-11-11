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

use super::guard::{err_json, is_vault_locked, ok_json};
use super::ConnectServerState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use persona_core::connect::{ConnectItemType, ConnectTokenRow};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

// -----------------------------------------------------------------------
// 端点
// -----------------------------------------------------------------------

/// GET /api/v1/connect/health：零库信息，免认证。
pub(super) async fn health() -> Response {
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
pub(super) fn internal_or_locked(e: &anyhow::Error) -> Response {
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

pub(super) fn locked_response() -> Response {
    err_json(
        StatusCode::SERVICE_UNAVAILABLE,
        "vault_locked",
        "vault is locked",
    )
}

/// GET /api/v1/connect/identities：scope 内身份（id + 名称）。
pub(super) async fn identities(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_list_identities(&row).await {
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
pub(super) struct ItemsQuery {
    identity: Option<Uuid>,
    #[serde(rename = "type")]
    item_type: Option<ConnectItemType>,
    title: Option<String>,
}

/// GET /api/v1/connect/items：scope 内条目元数据。
pub(super) async fn items(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Query(query): Query<ItemsQuery>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service
        .connect_list_items(&row, query.identity, query.item_type, query.title)
        .await
    {
        Ok(list) => ok_json(list.iter().map(item_meta_json).collect::<Vec<_>>()),
        Err(e) => internal_or_locked(&e),
    }
}

/// 条目类型统一用 scope 的枚举词汇表(snake_case,如 `password`),与
/// `?type=`/`item_types` 一致——消费者只学一套。scope 过滤已挡掉不可
/// 授权类型,这里 None 兜底 null(不应出现)。
pub(super) fn item_type_slug(c: &persona_core::Credential) -> serde_json::Value {
    ConnectItemType::from_credential_type(&c.credential_type)
        .map(|t| serde_json::to_value(t).unwrap_or_default())
        .unwrap_or(serde_json::Value::Null)
}

pub(super) fn item_meta_json(c: &persona_core::Credential) -> serde_json::Value {
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
pub(super) async fn item(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Path(id): Path<Uuid>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_get_item_data(&row, &id).await {
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
pub(super) async fn item_totp(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Path(id): Path<Uuid>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_totp(&row, &id).await {
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
