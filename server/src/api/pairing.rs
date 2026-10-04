//! 同步组动态密码配对中转（S1，`docs/sync-group-mode.md`）。
//!
//! 无账号信箱：session_id 即能力标识；本层不解释 payload（客户端
//! [`persona_core::sync::pairing::PairingMessage`] 的 JSON 字节），只见
//! SRP 公开消息与 AEAD 密文信封（零知识）。TTL、单方向队列上限、payload
//! 上限在此强制——在线爆破面被「短码短时效 + 队列上限 + 单次会话」共同
//! 压住。路由无 Bearer：配对双方本就没有共享凭证（这就是零账号的意义），
//! 中间人由 core 层的短指纹比对 + M1/M2 双向证明拦截。
//!
//! 路由（`/api/v1/pairing/*`）：
//! - `POST /sessions`                        建 session（host，带 KDF salt）
//! - `GET /sessions/{id}`                    元信息（salt + 两方向队列长度）
//! - `DELETE /sessions/{id}`                 任一端完成/放弃后清理
//! - `POST|GET /sessions/{id}/messages/to-host`  guest→host 信箱（GET 即消费）
//! - `POST|GET /sessions/{id}/messages/to-guest` host→guest 信箱（GET 即消费）
//!
//! GET 即消费（取走即删）：消息投递语义恰是「每条至多被对面读到一次」；
//! 拉到空数组即无新消息，双端轮询即可。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;

use super::{ApiError, ErrorItem};
use crate::state::AppState;

/// 会话有效期（秒）：短码本来就是「两台设备同时在线几分钟」的语义。
pub const PAIRING_TTL_SECS: i64 = 600;
/// 单方向消息队列上限（正常配对 2 条/方向；4 条容纳一次协议级重试）。
pub const MAX_MESSAGES_PER_DIRECTION: i64 = 4;
/// 单条消息 payload 字节上限（SRP 公开消息 + AEAD 信封合计远小于此）。
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// salt 字节上限（core 侧为 16 字节，留裕度防将来加长）。
const MAX_SALT_BYTES: usize = 64;

#[derive(Deserialize)]
pub struct CreatePairingSessionRequest {
    /// KDF salt（base64；host 生成，随 session 分发给 guest）。
    pub salt: String,
}

#[derive(Serialize)]
pub struct CreatePairingSessionResponse {
    pub session_id: String,
    pub expires_in_secs: i64,
}

#[derive(Deserialize)]
pub struct PostPairingMessageRequest {
    /// 消息 JSON 的 base64（本层不解释内容）。
    pub payload: String,
}

fn decode_b64(field: &str, value: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let bytes = B64.decode(value).map_err(|_| {
        ApiError::validation(
            "invalid base64",
            vec![ErrorItem::batch(field, "malformed base64")],
        )
    })?;
    if bytes.len() > max_bytes {
        return Err(ApiError::validation(
            "payload too large",
            vec![ErrorItem::batch(field, "exceeds size limit")],
        ));
    }
    Ok(bytes)
}

/// 惰性清理：删掉已过期 session（消息随 ON DELETE CASCADE 走）。
/// 每次建新 session 时顺手执行，避免表无限膨胀。
async fn sweep_expired(pool: &sqlx::SqlitePool) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM pairing_sessions WHERE expires_at <= ?")
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// 取有效 session；不存在或已过期一律 404（过期行顺带删除）。
/// 404 合并两种成因——不向无凭证方泄露会话是否存在过。
async fn live_session(
    state: &AppState,
    session_id: &str,
) -> Result<(String, Vec<u8>, i64), ApiError> {
    let now = Utc::now().to_rfc3339();
    let row: Option<SqliteRow> =
        sqlx::query("SELECT salt, expires_at FROM pairing_sessions WHERE id = ?")
            .bind(session_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::internal)?;
    let row = row.ok_or_else(ApiError::not_found)?;
    let expires_at: String = row.get("expires_at");
    if expires_at <= now {
        sqlx::query("DELETE FROM pairing_sessions WHERE id = ?")
            .bind(session_id)
            .execute(&state.pool)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::not_found());
    }
    let salt: Vec<u8> = row.get("salt");
    let expires_in = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map_err(ApiError::internal)?
        .timestamp()
        - Utc::now().timestamp();
    Ok((session_id.to_owned(), salt, expires_in.max(0)))
}

/// POST /api/v1/pairing/sessions —— host 建会话。
pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreatePairingSessionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let salt = decode_b64("salt", &req.salt, MAX_SALT_BYTES)?;
    sweep_expired(&state.pool).await?;

    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO pairing_sessions (id, salt, created_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&salt)
    .bind(now.to_rfc3339())
    .bind((now + chrono::Duration::seconds(PAIRING_TTL_SECS)).to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(CreatePairingSessionResponse {
            session_id: id,
            expires_in_secs: PAIRING_TTL_SECS,
        }),
    ))
}

/// GET /api/v1/pairing/sessions/{id} —— 元信息（guest 用它取 salt）。
pub async fn session_info(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let (_, salt, expires_in) = live_session(&state, &session_id).await?;
    let (to_host, to_guest) = queue_lengths(&state, &session_id).await?;
    Ok(Json(json!({
        "salt": B64.encode(salt),
        "expires_in_secs": expires_in,
        "to_host_len": to_host,
        "to_guest_len": to_guest,
    })))
}

/// DELETE /api/v1/pairing/sessions/{id} —— 完成/放弃后清理（幂等）。
pub async fn delete_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    sqlx::query("DELETE FROM pairing_sessions WHERE id = ?")
        .bind(&session_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn queue_lengths(state: &AppState, session_id: &str) -> Result<(i64, i64), ApiError> {
    let row: SqliteRow = sqlx::query(
        "SELECT
            COALESCE(SUM(CASE WHEN direction = 'to_host' THEN 1 ELSE 0 END), 0) AS to_host,
            COALESCE(SUM(CASE WHEN direction = 'to_guest' THEN 1 ELSE 0 END), 0) AS to_guest
         FROM pairing_messages WHERE session_id = ?",
    )
    .bind(session_id)
    .fetch_one(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok((row.get("to_host"), row.get("to_guest")))
}

async fn post_message(
    state: &AppState,
    session_id: &str,
    direction: &str,
    payload_b64: &str,
) -> Result<impl IntoResponse, ApiError> {
    live_session(state, session_id).await?;
    let payload = decode_b64("payload", payload_b64, MAX_PAYLOAD_BYTES)?;
    let (to_host, to_guest) = queue_lengths(state, session_id).await?;
    let queued = if direction == "to_host" {
        to_host
    } else {
        to_guest
    };
    if queued >= MAX_MESSAGES_PER_DIRECTION {
        return Err(ApiError::validation(
            "pairing queue full",
            vec![ErrorItem::batch(
                "payload",
                "too many pending messages; restart pairing",
            )],
        ));
    }
    sqlx::query(
        "INSERT INTO pairing_messages (session_id, direction, payload, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(session_id)
    .bind(direction)
    .bind(&payload)
    .bind(Utc::now().to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(StatusCode::ACCEPTED)
}

async fn take_messages(
    state: &AppState,
    session_id: &str,
    direction: &str,
) -> Result<impl IntoResponse, ApiError> {
    live_session(state, session_id).await?;
    let rows: Vec<SqliteRow> = sqlx::query(
        "SELECT id, payload FROM pairing_messages
         WHERE session_id = ? AND direction = ? ORDER BY id ASC",
    )
    .bind(session_id)
    .bind(direction)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    let mut messages = Vec::with_capacity(rows.len());
    let mut taken = Vec::with_capacity(rows.len());
    for row in rows {
        taken.push(row.get::<i64, _>("id"));
        let payload: Vec<u8> = row.get("payload");
        messages.push(B64.encode(payload));
    }
    // 取即消费：逐条删除（session 仍留给后续消息）。
    for id in taken {
        sqlx::query("DELETE FROM pairing_messages WHERE id = ?")
            .bind(id)
            .execute(&state.pool)
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(Json(json!({ "messages": messages })))
}

/// POST /api/v1/pairing/sessions/{id}/messages/to-host —— guest 发。
pub async fn post_to_host(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(req): Json<PostPairingMessageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    post_message(&state, &session_id, "to_host", &req.payload).await
}

/// GET /api/v1/pairing/sessions/{id}/messages/to-host —— host 取（即消费）。
pub async fn take_to_host(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    take_messages(&state, &session_id, "to_host").await
}

/// POST /api/v1/pairing/sessions/{id}/messages/to-guest —— host 发。
pub async fn post_to_guest(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(req): Json<PostPairingMessageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    post_message(&state, &session_id, "to_guest", &req.payload).await
}

/// GET /api/v1/pairing/sessions/{id}/messages/to-guest —— guest 取（即消费）。
pub async fn take_to_guest(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    take_messages(&state, &session_id, "to_guest").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt as _;

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    async fn create_session_for(router: &axum::Router, salt: &[u8]) -> String {
        let body = serde_json::json!({ "salt": b64(salt) }).to_string();
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/pairing/sessions")
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["session_id"].as_str().unwrap().to_owned()
    }

    async fn post_message_for(
        router: &axum::Router,
        session_id: &str,
        direction: &str,
        payload: &[u8],
    ) -> StatusCode {
        let body = serde_json::json!({ "payload": b64(payload) }).to_string();
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/pairing/sessions/{session_id}/messages/{direction}"
            ))
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        router.clone().oneshot(req).await.unwrap().status()
    }

    async fn take_for(
        router: &axum::Router,
        session_id: &str,
        direction: &str,
    ) -> (StatusCode, Vec<Vec<u8>>) {
        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/pairing/sessions/{session_id}/messages/{direction}"
            ))
            .body(String::new())
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let messages = json["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| B64.decode(m.as_str().unwrap()).unwrap())
            .collect();
        (status, messages)
    }

    #[tokio::test]
    async fn pairing_relay_full_flow_two_clients_zero_bearer() {
        let (router, _state) = setup(Some("unused-token")).await;

        // host 建会话（无 Bearer）
        let session_id = create_session_for(&router, &[7u8; 16]).await;

        // guest 取 salt
        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("/api/v1/pairing/sessions/{session_id}"))
            .body(String::new())
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let info: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            B64.decode(info["salt"].as_str().unwrap()).unwrap(),
            vec![7u8; 16]
        );

        // 四条消息按序双向递送，GET 即消费
        assert_eq!(
            post_message_for(&router, &session_id, "to-host", b"m1").await,
            StatusCode::ACCEPTED
        );
        let (status, got) = take_for(&router, &session_id, "to-host").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got, vec![b"m1".to_vec()]);
        // 取后即空
        let (_, empty) = take_for(&router, &session_id, "to-host").await;
        assert!(empty.is_empty());

        assert_eq!(
            post_message_for(&router, &session_id, "to-guest", b"m2").await,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            post_message_for(&router, &session_id, "to-guest", b"m3").await,
            StatusCode::ACCEPTED
        );
        let (_, got) = take_for(&router, &session_id, "to-guest").await;
        assert_eq!(got, vec![b"m2".to_vec(), b"m3".to_vec()]);
    }

    #[tokio::test]
    async fn pairing_relay_enforces_queue_limit_and_unknown_session() {
        let (router, _state) = setup(Some("unused-token")).await;
        let session_id = create_session_for(&router, &[1u8; 16]).await;

        for i in 0..MAX_MESSAGES_PER_DIRECTION {
            assert_eq!(
                post_message_for(&router, &session_id, "to-host", format!("m{i}").as_bytes()).await,
                StatusCode::ACCEPTED
            );
        }
        // 队列满：再投递被拒
        assert_eq!(
            post_message_for(&router, &session_id, "to-host", b"overflow").await,
            StatusCode::UNPROCESSABLE_ENTITY
        );

        // 未知 session 一律 404
        let req = HttpRequest::builder()
            .method("GET")
            .uri("/api/v1/pairing/sessions/no-such-id")
            .body(String::new())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post_message_for(&router, "no-such-id", "to-host", b"x").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn pairing_relay_rejects_bad_base64_and_oversize_payload() {
        let (router, _state) = setup(Some("unused-token")).await;
        let session_id = create_session_for(&router, &[2u8; 16]).await;

        let body = serde_json::json!({ "payload": "!!!not-base64!!!" }).to_string();
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/pairing/sessions/{session_id}/messages/to-host"
            ))
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let body = serde_json::json!({ "payload": b64(&[0u8; MAX_PAYLOAD_BYTES + 1]) }).to_string();
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/pairing/sessions/{session_id}/messages/to-host"
            ))
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn pairing_relay_drives_real_core_protocol_end_to_end() {
        use persona_core::sync::pairing::{PairingGuest, PairingHost, PairingMessage};

        let (router, _state) = setup(Some("unused-token")).await;

        // host 建会话
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let group_key: [u8; 32] = rand::random();
        let session_id = create_session_for(&router, &invite.salt).await;

        // guest 拉 salt，起配，交 client_public
        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("/api/v1/pairing/sessions/{session_id}"))
            .body(String::new())
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let info: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let salt: Vec<u8> = B64.decode(info["salt"].as_str().unwrap()).unwrap();
        let (mut guest, guest_msg) = PairingGuest::start_message(&invite.code, &salt).unwrap();
        assert_eq!(
            post_message_for(
                &router,
                &session_id,
                "to-host",
                &serde_json::to_vec(&guest_msg).unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );

        // host 取 client_public → ServerOffer → 指纹已可展示
        let (_, got) = take_for(&router, &session_id, "to-host").await;
        let msg: PairingMessage = serde_json::from_slice(&got[0]).unwrap();
        let reply = host.handle_message(msg, &group_key).unwrap().unwrap();
        assert!(host.fingerprint().is_some());

        assert_eq!(
            post_message_for(
                &router,
                &session_id,
                "to-guest",
                &serde_json::to_vec(&reply).unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );

        // guest 取 ServerOffer → ClientProof → 指纹与 host 一致
        let (_, got) = take_for(&router, &session_id, "to-guest").await;
        let msg: PairingMessage = serde_json::from_slice(&got[0]).unwrap();
        let reply = guest.handle_message(msg).unwrap().unwrap();
        assert_eq!(guest.fingerprint(), host.fingerprint());

        assert_eq!(
            post_message_for(
                &router,
                &session_id,
                "to-host",
                &serde_json::to_vec(&reply).unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );

        // host 取 ClientProof → Handoff
        let (_, got) = take_for(&router, &session_id, "to-host").await;
        let msg: PairingMessage = serde_json::from_slice(&got[0]).unwrap();
        let reply = host.handle_message(msg, &group_key).unwrap().unwrap();
        assert_eq!(
            post_message_for(
                &router,
                &session_id,
                "to-guest",
                &serde_json::to_vec(&reply).unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );

        // guest 取 Handoff → 配对完成，组密钥一致（中转全程零知识）
        let (_, got) = take_for(&router, &session_id, "to-guest").await;
        let msg: PairingMessage = serde_json::from_slice(&got[0]).unwrap();
        assert!(guest.handle_message(msg).unwrap().is_none());
        assert_eq!(guest.group_key(), Some(&group_key));

        // 清理：任一端 DELETE 后 session 不可再访问
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/api/v1/pairing/sessions/{session_id}"))
            .body(String::new())
            .unwrap();
        assert_eq!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn pairing_relay_delete_then_404() {
        let (router, _state) = setup(Some("unused-token")).await;
        let session_id = create_session_for(&router, &[3u8; 16]).await;

        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/api/v1/pairing/sessions/{session_id}"))
            .body(String::new())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
        // 删除后不可再取（404），重复 DELETE 幂等
        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("/api/v1/pairing/sessions/{session_id}"))
            .body(String::new())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/api/v1/pairing/sessions/{session_id}"))
            .body(String::new())
            .unwrap();
        assert_eq!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
    }
}
