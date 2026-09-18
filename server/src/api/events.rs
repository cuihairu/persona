//! `POST/GET /api/v1/events`：审计事件批量接入与 SIEM 拉取式查询。
//!
//! 事件词汇表与 core 对齐：`action` 是 core `AuditAction` 的 snake_case
//! 串（未知串按 core `FromStr` 语义由消费方落 `Custom`，这里只做长度
//! 校验）；`resource_type` 用 `ResourceType::from_str` 严格校验。

use std::collections::HashMap;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use persona_core::ResourceType;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::{Pool, Row, Sqlite};
use uuid::Uuid;

use super::{ApiError, ErrorItem};
use crate::state::AppState;

/// 单批事件上限。
pub const MAX_BATCH_SIZE: usize = 500;

const MAX_CURSOR_FETCH: u32 = 1000;
const DEFAULT_LIMIT: u32 = 100;

// ---- POST /api/v1/events ----

#[derive(Deserialize)]
pub struct IngestRequest {
    #[serde(default)]
    events: Vec<IngestEvent>,
}

/// wire 形状参照 core `AuditLog`；`id` 是客户端幂等键（server 重新分配主键）。
#[derive(Deserialize)]
pub struct IngestEvent {
    id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    user_id: Option<String>,
    identity_id: Option<Uuid>,
    credential_id: Option<Uuid>,
    session_id: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    error_message: Option<String>,
    metadata: Option<HashMap<String, String>>,
    /// 客户端时钟，仅存证不可信；排序一律用 server 的 received_at。
    timestamp: DateTime<Utc>,
}

#[derive(Serialize)]
struct IngestResponse {
    accepted: u64,
    duplicates: u64,
}

pub async fn ingest(
    State(state): State<AppState>,
    payload: Result<Json<IngestRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return ApiError::rejection(rejection.status(), rejection.body_text()).into_response()
        }
    };

    // 全有或全无：逐条校验全部通过后才开事务写。
    if let Err(items) = validate(&request.events) {
        tracing::debug!(count = items.len(), "rejecting event batch");
        state
            .metrics
            .add_events_rejected(request.events.len() as u64);
        // 批级错误（空批/超限）issue 直接作顶层 message；逐条错误给计数摘要，
        // 细节在 items 里。
        let message = match items.as_slice() {
            [only] if only.index.is_none() => only.issue.clone(),
            _ => format!("{} invalid event(s) in batch", items.len()),
        };
        return ApiError::validation(message, items).into_response();
    }

    // 同批共用一个 received_at：批内游标键单调，翻页顺序与返回顺序一致。
    let received_at = Utc::now();
    match insert_batch(&state.pool, request.events, received_at).await {
        Ok((accepted, duplicates)) => {
            state.metrics.add_events_ingested(accepted);
            state.metrics.add_events_duplicates(duplicates);
            (
                StatusCode::ACCEPTED,
                Json(IngestResponse {
                    accepted,
                    duplicates,
                }),
            )
                .into_response()
        }
        Err(error) => ApiError::internal(error).into_response(),
    }
}

fn validate(events: &[IngestEvent]) -> Result<(), Vec<ErrorItem>> {
    if events.is_empty() {
        return Err(vec![ErrorItem::batch("events", "batch is empty")]);
    }
    if events.len() > MAX_BATCH_SIZE {
        return Err(vec![ErrorItem::batch(
            "events",
            format!(
                "batch exceeds {MAX_BATCH_SIZE} events (got {})",
                events.len()
            ),
        )]);
    }

    let mut items = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event.action.is_empty() {
            items.push(ErrorItem::at(index, "action", "must not be empty"));
        } else if event.action.len() > 128 {
            items.push(ErrorItem::at(index, "action", "exceeds 128 bytes"));
        }
        if let Err(error) = event.resource_type.parse::<ResourceType>() {
            items.push(ErrorItem::at(index, "resource_type", error));
        }
        check_opt_len(&mut items, index, "id", event.id.as_deref(), 256);
        check_opt_len(
            &mut items,
            index,
            "resource_id",
            event.resource_id.as_deref(),
            256,
        );
        check_opt_len(&mut items, index, "user_id", event.user_id.as_deref(), 256);
        check_opt_len(
            &mut items,
            index,
            "session_id",
            event.session_id.as_deref(),
            256,
        );
        check_opt_len(
            &mut items,
            index,
            "ip_address",
            event.ip_address.as_deref(),
            64,
        );
        check_opt_len(
            &mut items,
            index,
            "user_agent",
            event.user_agent.as_deref(),
            512,
        );
        check_opt_len(
            &mut items,
            index,
            "error_message",
            event.error_message.as_deref(),
            1024,
        );

        if let Some(metadata) = &event.metadata {
            if metadata.len() > 32 {
                items.push(ErrorItem::at(index, "metadata", "exceeds 32 entries"));
            }
            for (key, value) in metadata {
                if key.len() > 64 {
                    items.push(ErrorItem::at(
                        index,
                        "metadata",
                        format!("key {key:?} exceeds 64 bytes"),
                    ));
                }
                if value.len() > 512 {
                    items.push(ErrorItem::at(
                        index,
                        "metadata",
                        format!("value for {key:?} exceeds 512 bytes"),
                    ));
                }
            }
        }
    }

    if items.is_empty() {
        Ok(())
    } else {
        Err(items)
    }
}

fn check_opt_len(
    items: &mut Vec<ErrorItem>,
    index: usize,
    field: &str,
    value: Option<&str>,
    max: usize,
) {
    if let Some(value) = value {
        if value.len() > max {
            items.push(ErrorItem::at(index, field, format!("exceeds {max} bytes")));
        }
    }
}

async fn insert_batch(
    pool: &Pool<Sqlite>,
    events: Vec<IngestEvent>,
    received_at: DateTime<Utc>,
) -> Result<(u64, u64), sqlx::Error> {
    // 不用 INSERT OR IGNORE：那会把 CHECK/NOT NULL 违例也吞成"重复"。
    // 带 WHERE 冲突目标的 DO NOTHING 只命中部分唯一索引。
    const INSERT: &str = "INSERT INTO audit_events \
        (id, client_event_id, user_id, identity_id, credential_id, session_id, \
         action, resource_type, resource_id, ip_address, user_agent, \
         success, error_message, metadata, client_timestamp, received_at, received_at_ms) \
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
        ON CONFLICT(client_event_id) WHERE client_event_id IS NOT NULL DO NOTHING";

    let received_at = received_at.to_rfc3339();
    let received_at_ms = DateTime::parse_from_rfc3339(&received_at)
        .expect("to_rfc3339 output re-parses")
        .timestamp_millis();

    let mut transaction = pool.begin().await?;
    let mut accepted = 0u64;
    let mut duplicates = 0u64;
    for event in events {
        let metadata = event.metadata.unwrap_or_default();
        let metadata = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".into());
        let result = sqlx::query(INSERT)
            .bind(Uuid::new_v4().to_string())
            .bind(event.id)
            .bind(event.user_id)
            .bind(event.identity_id.map(|id| id.to_string()))
            .bind(event.credential_id.map(|id| id.to_string()))
            .bind(event.session_id)
            .bind(event.action)
            .bind(event.resource_type)
            .bind(event.resource_id)
            .bind(event.ip_address)
            .bind(event.user_agent)
            .bind(event.success)
            .bind(event.error_message)
            .bind(metadata)
            .bind(event.timestamp.to_rfc3339())
            .bind(&received_at)
            .bind(received_at_ms)
            .execute(&mut *transaction)
            .await?;
        if result.rows_affected() == 1 {
            accepted += 1;
        } else {
            duplicates += 1;
        }
    }
    transaction.commit().await?;
    Ok((accepted, duplicates))
}

// ---- GET /api/v1/events ----

#[derive(Deserialize)]
pub struct EventQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    action: Option<String>,
    success: Option<bool>,
    /// RFC3339，按 received_at（server 时钟）过滤。
    since: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct StoredEvent {
    id: String,
    client_event_id: Option<String>,
    user_id: Option<String>,
    identity_id: Option<String>,
    credential_id: Option<String>,
    session_id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    error_message: Option<String>,
    metadata: HashMap<String, String>,
    client_timestamp: String,
    received_at: String,
}

#[derive(Serialize)]
struct EventPage {
    events: Vec<StoredEvent>,
    next_cursor: Option<String>,
}

pub async fn query(State(state): State<AppState>, Query(params): Query<EventQuery>) -> Response {
    let limit = match params.limit {
        None => DEFAULT_LIMIT,
        Some(0) => {
            return ApiError::validation(
                "invalid limit",
                vec![ErrorItem::batch("limit", "must be at least 1")],
            )
            .into_response()
        }
        Some(limit) if limit > MAX_CURSOR_FETCH => {
            return ApiError::validation(
                "invalid limit",
                vec![ErrorItem::batch(
                    "limit",
                    format!("must be at most {MAX_CURSOR_FETCH}"),
                )],
            )
            .into_response()
        }
        Some(limit) => limit,
    };
    let cursor = match &params.cursor {
        None => None,
        Some(raw) => match decode_cursor(raw) {
            Ok(cursor) => Some(cursor),
            Err(error) => return error.into_response(),
        },
    };

    // 位置参数一次绑定全量，避免动态拼 SQL。
    const SELECT: &str =
        "SELECT id, client_event_id, user_id, identity_id, credential_id, session_id, \
        action, resource_type, resource_id, ip_address, user_agent, \
        success, error_message, metadata, client_timestamp, received_at, received_at_ms \
        FROM audit_events \
        WHERE (?1 IS NULL OR action = ?1) \
          AND (?2 IS NULL OR success = ?2) \
          AND (?3 IS NULL OR received_at >= ?3) \
          AND (?4 IS NULL OR (received_at_ms, id) > (?4, ?5)) \
        ORDER BY received_at_ms ASC, id ASC \
        LIMIT ?6";

    let since = params.since.map(|since| since.to_rfc3339());
    let rows = match sqlx::query(SELECT)
        .bind(params.action.as_deref())
        .bind(params.success)
        .bind(since.as_deref())
        .bind(cursor.as_ref().map(|(ms, _)| *ms))
        .bind(cursor.as_ref().map(|(_, id)| id.as_str()))
        .bind(i64::from(limit) + 1)
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => rows,
        Err(error) => return ApiError::internal(error).into_response(),
    };

    // 多取 1 行判断是否还有下一页；游标取自最后返回的那行。
    let has_more = rows.len() > limit as usize;
    let next_cursor = if has_more {
        let last = &rows[limit as usize - 1];
        let (ms, id) = match (
            last.try_get::<i64, _>("received_at_ms"),
            last.try_get::<String, _>("id"),
        ) {
            (Ok(ms), Ok(id)) => (ms, id),
            (Err(error), _) | (_, Err(error)) => return ApiError::internal(error).into_response(),
        };
        Some(encode_cursor(ms, &id))
    } else {
        None
    };
    let page = &rows[..rows.len().min(limit as usize)];
    let mut events = Vec::with_capacity(page.len());
    for row in page {
        match row_to_event(row) {
            Ok(event) => events.push(event),
            Err(error) => return error.into_response(),
        }
    }

    (axum::Json(EventPage {
        events,
        next_cursor,
    }))
    .into_response()
}

fn row_to_event(row: &SqliteRow) -> Result<StoredEvent, ApiError> {
    let metadata_raw: String = row.try_get("metadata").map_err(internal_from)?;
    let metadata: HashMap<String, String> =
        serde_json::from_str(&metadata_raw).map_err(ApiError::internal)?;
    let success: i64 = row.try_get("success").map_err(internal_from)?;
    Ok(StoredEvent {
        id: row.try_get("id").map_err(internal_from)?,
        client_event_id: row.try_get("client_event_id").map_err(internal_from)?,
        user_id: row.try_get("user_id").map_err(internal_from)?,
        identity_id: row.try_get("identity_id").map_err(internal_from)?,
        credential_id: row.try_get("credential_id").map_err(internal_from)?,
        session_id: row.try_get("session_id").map_err(internal_from)?,
        action: row.try_get("action").map_err(internal_from)?,
        resource_type: row.try_get("resource_type").map_err(internal_from)?,
        resource_id: row.try_get("resource_id").map_err(internal_from)?,
        ip_address: row.try_get("ip_address").map_err(internal_from)?,
        user_agent: row.try_get("user_agent").map_err(internal_from)?,
        success: success != 0,
        error_message: row.try_get("error_message").map_err(internal_from)?,
        metadata,
        client_timestamp: row.try_get("client_timestamp").map_err(internal_from)?,
        received_at: row.try_get("received_at").map_err(internal_from)?,
    })
}

fn internal_from(error: sqlx::Error) -> ApiError {
    ApiError::internal(error)
}

// ---- 游标编解码：base64url("v1:{received_at_ms}:{id}")，无 padding ----

fn encode_cursor(received_at_ms: i64, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("v1:{received_at_ms}:{id}"))
}

fn decode_cursor(raw: &str) -> Result<(i64, String), ApiError> {
    let invalid = || {
        ApiError::validation(
            "invalid cursor",
            vec![ErrorItem::batch("cursor", "malformed cursor token")],
        )
    };
    let decoded = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    let text = String::from_utf8(decoded).map_err(|_| invalid())?;
    let rest = text.strip_prefix("v1:").ok_or_else(invalid)?;
    let (ms, id) = rest.split_once(':').ok_or_else(invalid)?;
    let ms: i64 = ms.parse().map_err(|_| invalid())?;
    if id.is_empty() {
        return Err(invalid());
    }
    Ok((ms, id.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{decode_cursor, encode_cursor};

    #[test]
    fn cursor_roundtrip() {
        let encoded = encode_cursor(1_758_182_400_123, "0e2c5a6b-1c2d-3e4f-5a6b-7c8d9e0f1a2b");
        let (ms, id) = decode_cursor(&encoded).unwrap();
        assert_eq!(ms, 1_758_182_400_123);
        assert_eq!(id, "0e2c5a6b-1c2d-3e4f-5a6b-7c8d9e0f1a2b");
    }

    #[test]
    fn cursor_rejects_garbage() {
        assert!(decode_cursor("not-a-cursor").is_err());
        assert!(decode_cursor("").is_err());
        // base64url 可解但不是 v1 前缀 / 缺 id / 缺毫秒
        assert!(decode_cursor("aXY6").is_err());
        assert!(decode_cursor("djE6MTIz").is_err()); // "v1:123" 无 id 段
    }
}

#[cfg(test)]
mod endpoint_tests {
    use crate::test_support::*;

    use chrono::DateTime;
    use sqlx::Row;
    use tower::ServiceExt as _;

    const TOKEN: &str = "test-token";

    async fn seed(pool: &sqlx::SqlitePool, ms: i64, id: &str, action: &str, success: bool) {
        // received_at 基准 2026-01-01T00:00:00Z，ms 为其后毫秒偏移
        const BASE_MS: i64 = 1_767_225_600_000;
        let received_at = DateTime::from_timestamp_millis(BASE_MS + ms)
            .unwrap()
            .to_rfc3339();
        sqlx::query(
            "INSERT INTO audit_events (id, client_event_id, action, resource_type, success, metadata, client_timestamp, received_at, received_at_ms) \
             VALUES (?, ?, ?, 'user', ?, '{}', '2026-01-01T00:00:00Z', ?, ?)",
        )
        .bind(id)
        .bind(id)
        .bind(action)
        .bind(success)
        .bind(received_at)
        .bind(BASE_MS + ms)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn count(pool: &sqlx::SqlitePool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    // ---- ingest ----

    #[tokio::test]
    async fn ingest_valid_batch_returns_202_with_accepted_count() {
        let (router, _) = setup(Some(TOKEN)).await;
        let body = format!(
            r#"{{"events":[{},{}]}}"#,
            event_json("e1", "login"),
            event_json("e2", "logout")
        );
        let (status, json) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(json["accepted"], 2);
        assert_eq!(json["duplicates"], 0);
    }

    #[tokio::test]
    async fn ingest_assigns_server_side_ids_and_received_at() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        let body = format!(r#"{{"events":[{}]}}"#, event_json("client-e1", "login"));
        let (status, _) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);

        let row = sqlx::query(
            "SELECT id, client_event_id, action, resource_type, success, received_at FROM audit_events",
        )
        .fetch_one(&app_state.pool)
        .await
        .unwrap();
        let server_id: String = row.try_get("id").unwrap();
        assert_ne!(server_id, "client-e1");
        assert!(uuid::Uuid::parse_str(&server_id).is_ok());
        assert_eq!(
            row.try_get::<String, _>("client_event_id").unwrap(),
            "client-e1"
        );
        assert_eq!(row.try_get::<String, _>("action").unwrap(), "login");
        assert_eq!(row.try_get::<String, _>("resource_type").unwrap(), "user");
        assert_eq!(row.try_get::<i64, _>("success").unwrap(), 1);
        assert!(!row.try_get::<String, _>("received_at").unwrap().is_empty());
    }

    #[tokio::test]
    async fn ingest_empty_batch_is_422() {
        let (router, _) = setup(Some(TOKEN)).await;
        let (status, json) = send(router, post_events(r#"{"events":[]}"#, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["error"]["code"], "validation");
        assert_eq!(json["error"]["items"][0]["issue"], "batch is empty");
    }

    #[tokio::test]
    async fn ingest_malformed_json_maps_to_unified_error_shape() {
        let (router, _) = setup(Some(TOKEN)).await;
        let (status, json) = send(router, post_events("not json at all", Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "bad_request");
        assert!(!json["error"]["message"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ingest_invalid_resource_type_rejects_whole_batch() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        let body = format!(
            r#"{{"events":[{},{{
                "id":"bad","action":"login","resource_type":"galaxy",
                "success":true,"timestamp":"2026-01-01T00:00:00Z"}}]}}"#,
            event_json("e1", "login"),
        );
        let (status, json) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        let items = json["error"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["index"], 1);
        assert_eq!(items[0]["field"], "resource_type");
        // 全有或全无：合法那条也不能入库
        assert_eq!(count(&app_state.pool).await, 0);
    }

    #[tokio::test]
    async fn ingest_missing_timestamp_is_422() {
        let (router, _) = setup(Some(TOKEN)).await;
        let body =
            r#"{"events":[{"id":"e1","action":"login","resource_type":"user","success":true}]}"#;
        let (status, json) = send(router, post_events(body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["error"]["code"], "bad_request"); // serde 缺必填字段 → rejection
    }

    #[tokio::test]
    async fn ingest_invalid_uuid_field_is_422() {
        let (router, _) = setup(Some(TOKEN)).await;
        let body = r#"{"events":[{"id":"e1","action":"login","resource_type":"user","identity_id":"not-a-uuid","success":true,"timestamp":"2026-01-01T00:00:00Z"}]}"#;
        let (status, _) = send(router, post_events(body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn ingest_oversized_batch_over_500_is_422() {
        let (router, _) = setup(Some(TOKEN)).await;
        let events: Vec<String> = (0..501)
            .map(|i| event_json(&format!("e{i}"), "login"))
            .collect();
        let body = format!(r#"{{"events":[{}]}}"#, events.join(","));
        let (status, json) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(json["error"]["message"].as_str().unwrap().contains("500"));
    }

    #[tokio::test]
    async fn ingest_body_over_1mib_is_413() {
        let (router, _) = setup(Some(TOKEN)).await;
        // Content-Length 预检：不读 body，直接 413（小 body + 谎报长度即可测）
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/events")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header("content-length", "2097152")
            .body("{}".to_owned())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn ingest_unknown_action_stored_verbatim() {
        // 未知 action 串按 core FromStr 语义由消费方落 Custom；server 原样存取
        let (router, app_state) = setup(Some(TOKEN)).await;
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e1", "totally_new"));
        let (status, json) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(json["accepted"], 1);

        let action: String =
            sqlx::query_scalar("SELECT action FROM audit_events WHERE client_event_id = 'e1'")
                .fetch_one(&app_state.pool)
                .await
                .unwrap();
        assert_eq!(action, "totally_new");
    }

    #[tokio::test]
    async fn ingest_duplicate_client_event_id_counts_as_duplicate() {
        let (router, _) = setup(Some(TOKEN)).await;

        // 同批内重复
        let body = format!(
            r#"{{"events":[{},{}]}}"#,
            event_json("e1", "login"),
            event_json("e1", "logout")
        );
        let (status, json) = send(router.clone(), post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(json["accepted"], 1);
        assert_eq!(json["duplicates"], 1);

        // 跨请求重复
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e1", "login"));
        let (status, json) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(json["accepted"], 0);
        assert_eq!(json["duplicates"], 1);
    }

    #[tokio::test]
    async fn ingest_null_client_event_ids_are_not_deduplicated() {
        let (router, _) = setup(Some(TOKEN)).await;
        let body = format!(
            r#"{{"events":[{},{}]}}"#,
            event_json("null", "login").replace(r#""id":"null""#, r#""id":null"#),
            event_json("null2", "login").replace(r#""id":"null2""#, r#""id":null"#),
        );
        let (status, json) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(json["accepted"], 2);
        assert_eq!(json["duplicates"], 0);
    }

    // ---- query ----

    #[tokio::test]
    async fn query_returns_events_ordered_by_received_at() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        seed(&app_state.pool, 3000, "c", "login", true).await;
        seed(&app_state.pool, 1000, "a", "login", true).await;
        seed(&app_state.pool, 2000, "b", "login", true).await;

        let (status, json) = send(router, get_events("/api/v1/events", TOKEN)).await;
        assert!(status.is_success());
        let ids: Vec<&str> = json["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
    }

    #[tokio::test]
    async fn query_default_limit_is_100() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        for i in 0..150 {
            seed(&app_state.pool, i as i64, &format!("e{i}"), "login", true).await;
        }
        let (status, json) = send(router, get_events("/api/v1/events", TOKEN)).await;
        assert!(status.is_success());
        assert_eq!(json["events"].as_array().unwrap().len(), 100);
        assert!(json["next_cursor"].is_string());
    }

    #[tokio::test]
    async fn query_limit_bounds_are_enforced() {
        let (router, _) = setup(Some(TOKEN)).await;
        let (status, json) =
            send(router.clone(), get_events("/api/v1/events?limit=0", TOKEN)).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["error"]["items"][0]["field"], "limit");

        let (status, _) = send(router, get_events("/api/v1/events?limit=1001", TOKEN)).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn query_next_cursor_resumes_without_overlap() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        for i in 1..=5 {
            seed(&app_state.pool, i * 1000, &format!("p{i}"), "login", true).await;
        }

        let mut seen = Vec::new();
        let mut uri = "/api/v1/events?limit=2".to_owned();
        loop {
            let (status, json) = send(router.clone(), get_events(&uri, TOKEN)).await;
            assert!(status.is_success());
            for event in json["events"].as_array().unwrap() {
                seen.push(event["id"].as_str().unwrap().to_owned());
            }
            match json["next_cursor"].as_str() {
                Some(cursor) => uri = format!("/api/v1/events?limit=2&cursor={cursor}"),
                None => break,
            }
        }
        assert_eq!(seen, ["p1", "p2", "p3", "p4", "p5"]);
    }

    #[tokio::test]
    async fn query_cursor_is_stable_against_new_inserts() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        seed(&app_state.pool, 1000, "p1", "login", true).await;
        seed(&app_state.pool, 2000, "p2", "login", true).await;

        let (status, json) =
            send(router.clone(), get_events("/api/v1/events?limit=1", TOKEN)).await;
        assert!(status.is_success());
        let cursor = json["next_cursor"].as_str().unwrap().to_owned();

        // 游标之后插入的新事件同样按序出现在后续页，不回头、不重叠
        seed(&app_state.pool, 3000, "p3", "login", true).await;
        let (status, json) = send(
            router,
            get_events(&format!("/api/v1/events?limit=10&cursor={cursor}"), TOKEN),
        )
        .await;
        assert!(status.is_success());
        let ids: Vec<&str> = json["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["p2", "p3"]);
    }

    #[tokio::test]
    async fn query_filters_by_action_success_and_since() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        seed(&app_state.pool, 1000, "f1", "login", true).await;
        seed(&app_state.pool, 2000, "f2", "login", false).await;
        seed(&app_state.pool, 3000, "f3", "logout", true).await;

        let (status, json) = send(
            router.clone(),
            get_events("/api/v1/events?action=login", TOKEN),
        )
        .await;
        assert!(status.is_success());
        assert_eq!(json["events"].as_array().unwrap().len(), 2);

        let (status, json) = send(
            router.clone(),
            get_events("/api/v1/events?success=false", TOKEN),
        )
        .await;
        assert!(status.is_success());
        let ids: Vec<&str> = json["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["f2"]);

        let (status, json) = send(
            router,
            get_events("/api/v1/events?since=2026-01-01T00:00:02.5Z", TOKEN),
        )
        .await;
        assert!(status.is_success());
        let ids: Vec<&str> = json["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["f3"]);
    }

    #[tokio::test]
    async fn query_invalid_cursor_is_422() {
        let (router, _) = setup(Some(TOKEN)).await;
        let (status, json) =
            send(router, get_events("/api/v1/events?cursor=garbage!!", TOKEN)).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["error"]["items"][0]["field"], "cursor");
    }
}
