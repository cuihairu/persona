//! `POST/GET /api/v1/events`: bulk audit-event ingestion and SIEM pull-style queries.
//!
//! The event vocabulary aligns with core: `action` is core's `AuditAction` snake_case
//! string (an unknown string is folded into `Custom` by the consumer per core's `FromStr`
//! semantics; here we only check the length); `resource_type` is strictly validated via
//! `ResourceType::from_str`.

use std::collections::HashMap;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use persona_core::ResourceType;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::{Pool, Row, Sqlite};
use uuid::Uuid;

use super::{decode_cursor, encode_cursor, ApiError, ErrorItem};
use crate::state::AppState;

/// Per-batch event limit.
pub const MAX_BATCH_SIZE: usize = 500;

const MAX_CURSOR_FETCH: u32 = 1000;
const DEFAULT_LIMIT: u32 = 100;

// ---- POST /api/v1/events ----

#[derive(Deserialize)]
pub struct IngestRequest {
    #[serde(default)]
    events: Vec<IngestEvent>,
}

/// Wire shape follows core's `AuditLog`; `id` is the client's idempotency key (the
/// server assigns its own primary key).
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
    /// The client's clock, kept for the record but not trusted; ordering always uses the
    /// server's received_at.
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

    // All or nothing: the write transaction opens only after every entry validates.
    if let Err(items) = validate(&request.events) {
        tracing::debug!(count = items.len(), "rejecting event batch");
        state
            .metrics
            .add_events_rejected(request.events.len() as u64);
        // A batch-level issue (empty batch / over limit) is used as the top-level
        // message as-is; per-entry issues get a count summary, with the details in items.
        let message = match items.as_slice() {
            [only] if only.index.is_none() => only.issue.clone(),
            _ => format!("{} invalid event(s) in batch", items.len()),
        };
        return ApiError::validation(message, items).into_response();
    }

    // One shared received_at for the whole batch: the in-batch cursor key is monotonic,
    // so paging order matches return order.
    let received_at = Utc::now();
    match insert_batch(&state.pool, request.events, received_at).await {
        Ok((accepted, duplicates)) => {
            state.metrics.add_events_ingested(accepted);
            state.metrics.add_events_duplicates(duplicates);
            enforce_events_retention(&state).await;
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

/// Retention policy for the audit event copy (the follow-up to the TODO "known
/// limitation: no retention policy"): rolling deletion of rows older than the window,
/// ordered by received_at_ms (using the idx_audit_events_order index); 0 = no cleanup
/// (the default). Events are an audit copy rather than the source of truth, so the
/// cleanup window is set by the deployer according to its own SIEM harvesting cadence.
/// Failure only warns.
async fn enforce_events_retention(state: &AppState) {
    let days = state.events_retention_days;
    if days == 0 {
        return;
    }
    let cutoff_ms = (Utc::now()
        - chrono::Duration::try_days(i64::from(days)).expect("retention days always fits"))
    .timestamp_millis();
    match sqlx::query("DELETE FROM audit_events WHERE received_at_ms < ?")
        .bind(cutoff_ms)
        .execute(&state.pool)
        .await
    {
        Ok(done) => {
            let removed = done.rows_affected();
            if removed > 0 {
                state.metrics.add_events_pruned(removed);
                tracing::info!(
                    event = "events_retention",
                    removed,
                    days,
                    "pruned audit events"
                );
            }
        }
        Err(error) => tracing::warn!(%error, "events retention skipped"),
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
    // Not INSERT OR IGNORE: that would also swallow CHECK/NOT NULL violations as
    // "duplicates". A DO NOTHING with a WHERE-qualified conflict target matches only the
    // partial unique index.
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
    /// RFC3339; filters on received_at (the server clock).
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

    // Bind every positional parameter in one go, avoiding dynamic SQL string building.
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

    // Fetch one extra row to detect a further page; the cursor comes from the last
    // returned row.
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

#[cfg(test)]
mod endpoint_tests {
    use crate::test_support::*;

    use chrono::{DateTime, Utc};
    use sqlx::Row;
    use tower::ServiceExt as _;

    const TOKEN: &str = "test-token";

    async fn seed(pool: &sqlx::SqlitePool, ms: i64, id: &str, action: &str, success: bool) {
        // received_at baseline 2026-01-01T00:00:00Z; ms is the offset in milliseconds after it
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
    async fn events_retention_prunes_over_window_only() {
        let (router, app_state) = setup_with_retention(Some(TOKEN), 0, 90).await;
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e-old", "login"));
        let (status, _) = send(router.clone(), post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);

        // Roll the row back outside the window
        let stale_ms = (Utc::now() - chrono::Duration::try_days(91).unwrap()).timestamp_millis();
        sqlx::query("UPDATE audit_events SET received_at_ms = ?")
            .bind(stale_ms)
            .execute(&app_state.pool)
            .await
            .unwrap();

        // Ingest one more (exercising the cleanup path): the old row is pruned, the new
        // row survives
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e-fresh", "logout"));
        let (status, json) = send(router.clone(), post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(json["accepted"], 1);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&app_state.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert!(app_state
            .metrics
            .render()
            .contains("persona_events_pruned_total 1"));
    }

    #[tokio::test]
    async fn events_retention_zero_keeps_everything() {
        let (router, app_state) = setup_with_retention(Some(TOKEN), 0, 0).await;
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e-ancient", "login"));
        let (status, _) = send(router.clone(), post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        sqlx::query("UPDATE audit_events SET received_at_ms = 946684800000")
            .execute(&app_state.pool)
            .await
            .unwrap();
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e-new", "logout"));
        let (status, _) = send(router.clone(), post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&app_state.pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
        assert!(app_state
            .metrics
            .render()
            .contains("persona_events_pruned_total 0"));
    }

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
        // All or nothing: the legitimate entry must not be stored either
        assert_eq!(count(&app_state.pool).await, 0);
    }

    #[tokio::test]
    async fn ingest_missing_timestamp_is_422() {
        let (router, _) = setup(Some(TOKEN)).await;
        let body =
            r#"{"events":[{"id":"e1","action":"login","resource_type":"user","success":true}]}"#;
        let (status, json) = send(router, post_events(body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["error"]["code"], "bad_request"); // serde missing a required field -> rejection
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
        // Content-Length pre-check: the body is never read, straight to 413 (a small
        // body with a lying declared length is enough to test it)
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

    /// Builds a gzip batch request (the test side compresses; on the wire core's
    /// ServerEventSink does it). gzip is binary, so `Body::from(Vec<u8>)` carries it;
    /// Content-Length is derived from the length automatically — the same convention as
    /// the wire-side payload_size_guard.
    fn gzipped_request(body: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/events")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use std::io::Write as _;
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn gzip_batch_is_decompressed_and_ingested() {
        let (router, _) = setup(Some(TOKEN)).await;
        let payload = format!(
            r#"{{"events":[{},{}]}}"#,
            event_json("g1", "login"),
            event_json("g2", "unlock")
        );
        let request = gzipped_request(gzip(payload.as_bytes()));
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["accepted"], 2);
    }

    #[tokio::test]
    async fn corrupt_gzip_body_is_4xx() {
        let (router, _) = setup(Some(TOKEN)).await;
        // The header claims gzip but the content is not a gzip stream — the
        // decompression layer fails midway and the JSON extractor's body read errors out
        // into a rejection
        let request = gzipped_request(b"this is not a gzip stream".to_vec());
        let response = router.oneshot(request).await.unwrap();
        assert!(
            response.status() == axum::http::StatusCode::BAD_REQUEST
                || response.status() == axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "expected 4xx, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn decompressed_body_over_10mib_is_413() {
        let (router, _) = setup(Some(TOKEN)).await;
        // Decompression-bomb shape: after compression the wire bytes are far below
        // 1 MiB (payload_size_guard lets it through), while the decompressed plaintext
        // exceeds 10 MiB (the inner DefaultBodyLimit rejects with 413)
        let huge = format!(
            r#"{{"events":[{{"id":"boom","action":"{}","resource_type":"user","success":true,"timestamp":"2026-01-01T00:00:00Z"}}]}}"#,
            "x".repeat(11 * 1024 * 1024) // 11 MiB of plaintext > the 10 MiB limit
        );
        assert!(huge.len() > 10 * 1024 * 1024);
        let compressed = gzip(huge.as_bytes());
        assert!(compressed.len() < 1024 * 1024);
        let request = gzipped_request(compressed);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn ingest_unknown_action_stored_verbatim() {
        // An unknown action string is folded into Custom by the consumer per core's
        // FromStr semantics; the server stores and returns it verbatim
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

        // Duplicates within a single batch
        let body = format!(
            r#"{{"events":[{},{}]}}"#,
            event_json("e1", "login"),
            event_json("e1", "logout")
        );
        let (status, json) = send(router.clone(), post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(json["accepted"], 1);
        assert_eq!(json["duplicates"], 1);

        // Duplicates across requests
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

        // New events inserted after the cursor appear in order on later pages too — no
        // going backwards and no overlap
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
