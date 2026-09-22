//! `/api/v1/sync/*`：E2EE 同步中继（阶段 2 批 3，E2EE_SYNC_DESIGN §5/§6）。
//!
//! 服务器定位 = **纯中继 + 密文保管**：oplog 载荷与 group key 信封全部是
//! 密文字节，服务器盲存、按到达顺序追加、按游标转发——**不做任何胜负
//! 判定或合并**（DR-4：让服务器裁决等于把合并语义交给一个我们拒绝信任
//! 其诚实的组件）。真实性边界：本阶段不校验 op.device_id 与认证身份的
//! 对应（静态 token 与 SRP token 混用，无统一映射），写入真实性由
//! Bearer 认证 + 远期「设备私钥签名 oplog」（§11）承担；THREAT_MODEL
//! 已登记「恶意客户端无法靠服务器根除」。
//!
//! 认证：整个子路由挂 `require_bearer`——静态令牌与 SRP 短期令牌自然
//! 兼容（auth.rs 的同一中间件）。
//!
//! fail-closed 的授权语义：「有信封 = 已授权」。未授权设备 GET 拿得到
//! 别人的信封，但拆不开（X25519：无对应私钥，tag 校验必失败）——拿不到
//! group key 也解不开任何条目，由密码学而非服务器 ACL 保证。

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::{decode_cursor, encode_cursor, ApiError, ErrorItem};
use crate::auth::DeviceName;
use crate::AppState;

/// push 单批条数上限（沿 events 的 500 条惯例，设计稿 §5）。
pub(crate) const MAX_BATCH_OPS: usize = 500;
/// 单条 op 的 ciphertext / wrapped_item_key 解码后字节上限。凭据密文 KB 级；
/// 更大的载荷（附件）是 §11 开放问题，走 v2 通道。
pub(crate) const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
/// pull 单页默认/最大条数（沿 events 的游标分页惯例）。
const PULL_DEFAULT_LIMIT: u32 = 200;
const PULL_MAX_FETCH: u32 = 500;

// ---- wire 类型 ----
// 与 core/src/sync/oplog.rs 的 SyncOp 对齐；kind/checked 字段用 String 接，
// 逐条校验给出 422 + index（uuid 直接 typed 反序列化会把单条错误放大成
// 整批 400，不利于客户端定位）。

#[derive(Debug, Deserialize, Serialize)]
pub struct WireOp {
    pub op_id: String,
    pub item_id: String,
    pub kind: String,
    /// "put" | "delete"（delete = tombstone，payload 必空）
    pub op: String,
    pub lamport: u64,
    pub device_id: String,
    /// 客户端自报 rfc3339，仅展示——服务器不信任、不参与排序（DR-4）。
    pub timestamp: Option<String>,
    pub payload: Option<WirePayload>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WirePayload {
    /// base64（STANDARD，含 padding——与 core remote_http 同一引擎）。
    pub ciphertext: String,
    pub wrapped_item_key: String,
}

#[derive(Debug, Serialize)]
struct PushResponse {
    accepted: u64,
    duplicates: u64,
}

#[derive(Debug, Deserialize)]
pub struct PushRequest {
    ops: Vec<WireOp>,
}

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    limit: Option<u32>,
    /// pull 游标（上次响应的 next_cursor）。
    since: Option<String>,
}

#[derive(Debug, Serialize)]
struct PullResponse {
    ops: Vec<WireOp>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    device_name: String,
    /// X25519 公钥，base64（STANDARD），解码后必须恰 32 字节。
    public_key: String,
}

#[derive(Debug, Serialize)]
struct RegisterDeviceResponse {
    device_id: Uuid,
}

#[derive(Debug, Serialize)]
struct DeviceInfo {
    id: Uuid,
    device_name: String,
    public_key: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct DeviceListResponse {
    devices: Vec<DeviceInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PutGroupKeyRequest {
    /// 信封归属的设备（必须已登记——fail-closed：信封不能挂幽灵设备）。
    device_id: String,
    /// persona-dev-env-1 信封（DR-1），base64，解码后恰 80 字节。
    envelope: String,
}

#[derive(Debug, Serialize)]
struct GroupKeyEntry {
    device_id: Uuid,
    envelope: String,
    sealed_by: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct GroupKeysResponse {
    keys: Vec<GroupKeyEntry>,
}

// ---- /sync/devices ----

/// POST /sync/devices：登记设备（公钥 + 设备名）。重名 409——公钥不可被
/// 静默替换（攻陷 token 后换公钥 = 劫持该设备的信封通道）。
pub async fn register_device(
    State(state): State<AppState>,
    Json(request): Json<RegisterDeviceRequest>,
) -> Response {
    let name = request.device_name.trim();
    if name.is_empty() || name.len() > 128 {
        return ApiError::validation(
            "invalid device_name",
            vec![ErrorItem::batch("device_name", "must be 1..=128 bytes")],
        )
        .into_response();
    }
    let public_key = match B64.decode(&request.public_key) {
        Ok(key) if key.len() == 32 => key,
        Ok(key) => {
            return ApiError::validation(
                "invalid public_key",
                vec![ErrorItem::batch(
                    "public_key",
                    format!("must decode to 32 bytes, got {}", key.len()),
                )],
            )
            .into_response()
        }
        Err(_) => {
            return ApiError::validation(
                "invalid public_key",
                vec![ErrorItem::batch("public_key", "malformed base64")],
            )
            .into_response()
        }
    };
    let device_id = Uuid::new_v4();
    if let Err(error) =
        sqlx::query("INSERT INTO sync_devices (id, device_name, public_key) VALUES (?, ?, ?)")
            .bind(device_id.to_string())
            .bind(name)
            .bind(&public_key)
            .execute(&state.pool)
            .await
    {
        if format!("{error}").contains("UNIQUE") {
            return ApiError::conflict(format!("device_name {name:?} is already registered"))
                .into_response();
        }
        return ApiError::internal(error).into_response();
    }
    (
        StatusCode::CREATED,
        Json(RegisterDeviceResponse { device_id }),
    )
        .into_response()
}

/// GET /sync/devices：列出全部已登记设备。
pub async fn list_devices(State(state): State<AppState>) -> Response {
    let rows = match sqlx::query(
        "SELECT id, device_name, public_key, created_at FROM sync_devices ORDER BY created_at, id",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return ApiError::internal(error).into_response(),
    };
    let devices = rows
        .iter()
        .filter_map(|row| {
            Some(DeviceInfo {
                id: Uuid::parse_str(&row.get::<String, _>("id")).ok()?,
                device_name: row.get("device_name"),
                public_key: B64.encode(row.get::<Vec<u8>, _>("public_key")),
                created_at: row.get("created_at"),
            })
        })
        .collect();
    (Json(DeviceListResponse { devices })).into_response()
}

/// DELETE /sync/devices/:id：吊销设备（删登记与其信封）。幂等；被吊销
/// 设备已知的 group key 不可追溯撤销（DR-3 诚实边界，轮换是 §11 远期项）。
pub async fn delete_device(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let device_id = match Uuid::parse_str(&id) {
        Ok(id) => id.to_string(),
        Err(_) => return StatusCode::NO_CONTENT.into_response(),
    };
    let result: Result<(), sqlx::Error> = async {
        sqlx::query("DELETE FROM sync_group_keys WHERE device_id = ?")
            .bind(&device_id)
            .execute(&state.pool)
            .await?;
        sqlx::query("DELETE FROM sync_devices WHERE id = ?")
            .bind(&device_id)
            .execute(&state.pool)
            .await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => ApiError::internal(error).into_response(),
    }
}

// ---- /sync/group-keys ----

/// GET /sync/group-keys：全部设备信封。客户端只认自己 device_id 的那条；
/// 未授权设备取到别人的信封也拆不开（见模块文档 fail-closed）。
pub async fn get_group_keys(State(state): State<AppState>) -> Response {
    let rows = match sqlx::query(
        "SELECT k.device_id, k.envelope, k.sealed_by, k.created_at
         FROM sync_group_keys k
         JOIN sync_devices d ON d.id = k.device_id
         ORDER BY k.device_id",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return ApiError::internal(error).into_response(),
    };
    let keys = rows
        .iter()
        .filter_map(|row| {
            Some(GroupKeyEntry {
                device_id: Uuid::parse_str(&row.get::<String, _>("device_id")).ok()?,
                envelope: B64.encode(row.get::<Vec<u8>, _>("envelope")),
                sealed_by: row.get("sealed_by"),
                created_at: row.get("created_at"),
            })
        })
        .collect();
    (Json(GroupKeysResponse { keys })).into_response()
}

/// PUT /sync/group-keys：上传/更新某设备的信封（授权动作 = 既有设备为
/// 新设备包好并上传；重包轮换 = 覆盖 upsert）。
pub async fn put_group_key(
    State(state): State<AppState>,
    Extension(device): Extension<DeviceName>,
    Json(request): Json<PutGroupKeyRequest>,
) -> Response {
    let device_id = match Uuid::parse_str(&request.device_id) {
        Ok(id) => id.to_string(),
        Err(_) => {
            return ApiError::validation(
                "invalid device_id",
                vec![ErrorItem::batch("device_id", "must be a UUID")],
            )
            .into_response()
        }
    };
    let envelope = match B64.decode(&request.envelope) {
        Ok(env) if env.len() == 80 => env, // persona-dev-env-1：32+32+16（DR-1）
        Ok(env) => {
            return ApiError::validation(
                "invalid envelope",
                vec![ErrorItem::batch(
                    "envelope",
                    format!("must decode to 80 bytes, got {}", env.len()),
                )],
            )
            .into_response()
        }
        Err(_) => {
            return ApiError::validation(
                "invalid envelope",
                vec![ErrorItem::batch("envelope", "malformed base64")],
            )
            .into_response()
        }
    };
    enum GkError {
        NotEnrolled,
        Db(String),
    }
    let result: Result<(), GkError> = async {
        let enrolled: Option<String> = sqlx::query("SELECT id FROM sync_devices WHERE id = ?")
            .bind(&device_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| GkError::Db(e.to_string()))?
            .map(|row| row.get("id"));
        if enrolled.is_none() {
            return Err(GkError::NotEnrolled);
        }
        sqlx::query(
            "INSERT INTO sync_group_keys (device_id, envelope, sealed_by)
             VALUES (?, ?, ?)
             ON CONFLICT(device_id) DO UPDATE SET envelope = excluded.envelope,
                 sealed_by = excluded.sealed_by,
                 created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(&device_id)
        .bind(&envelope)
        .bind(&device.0)
        .execute(&state.pool)
        .await
        .map_err(|e| GkError::Db(e.to_string()))?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => (StatusCode::NO_CONTENT).into_response(),
        Err(GkError::NotEnrolled) => ApiError::validation(
            "device not enrolled",
            vec![ErrorItem::batch(
                "device_id",
                "envelopes may only be attached to enrolled devices",
            )],
        )
        .into_response(),
        Err(GkError::Db(error)) => {
            tracing::error!(%error, "group key upsert failed");
            ApiError::internal("group key upsert failed").into_response()
        }
    }
}

// ---- /sync/oplog ----

fn validate_op(index: usize, op: &WireOp) -> Vec<ErrorItem> {
    let mut issues = Vec::new();
    let mut check = |field: &str, result: Result<(), String>| {
        if let Err(issue) = result {
            issues.push(ErrorItem::at(index, field, issue));
        }
    };
    check("op_id", parse_uuid(&op.op_id).map(|_| ()));
    check("item_id", parse_uuid(&op.item_id).map(|_| ()));
    check("device_id", parse_uuid(&op.device_id).map(|_| ()));
    if op.kind.is_empty() || op.kind.len() > 64 {
        check("kind", Err("must be 1..=64 bytes".to_string()));
    }
    match op.op.as_str() {
        "put" => match &op.payload {
            None => check("payload", Err("required for put".to_string())),
            Some(payload) => {
                for field in ["ciphertext", "wrapped_item_key"] {
                    let raw = match field {
                        "ciphertext" => &payload.ciphertext,
                        _ => &payload.wrapped_item_key,
                    };
                    let decoded = B64.decode(raw).map(|bytes| bytes.len());
                    check(
                        field,
                        decoded
                            .map_err(|_| "malformed base64".to_string())
                            .and_then(|len| {
                                if len > MAX_PAYLOAD_BYTES {
                                    Err(format!("exceeds {MAX_PAYLOAD_BYTES} bytes"))
                                } else {
                                    Ok(())
                                }
                            }),
                    );
                }
            }
        },
        "delete" => {
            if op.payload.is_some() {
                check(
                    "payload",
                    Err("must be null for delete (tombstone)".to_string()),
                );
            }
        }
        _ => check("op", Err("must be \"put\" or \"delete\"".to_string())),
    }
    if let Some(ts) = &op.timestamp {
        check(
            "timestamp",
            chrono::DateTime::parse_from_rfc3339(ts)
                .map(|_| ())
                .map_err(|error| error.to_string()),
        );
    }
    issues
}

fn parse_uuid(raw: &str) -> Result<Uuid, String> {
    Uuid::parse_str(raw).map_err(|_| "must be a UUID".to_string())
}

/// POST /sync/oplog：push 本地新 oplog 段。按 op_id 幂等（INSERT OR
/// IGNORE）；按到达顺序追加，不排序、不裁决。
pub async fn push(
    State(state): State<AppState>,
    payload: Result<Json<PushRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let request = match payload {
        Ok(Json(request)) => request,
        Err(rejection) => {
            return ApiError::rejection(rejection.status(), rejection.body_text()).into_response()
        }
    };
    if request.ops.len() > MAX_BATCH_OPS {
        return ApiError::validation(
            "too many ops",
            vec![ErrorItem::batch(
                "ops",
                format!("batch exceeds {MAX_BATCH_OPS} ops"),
            )],
        )
        .into_response();
    }
    let mut issues = Vec::new();
    for (index, op) in request.ops.iter().enumerate() {
        issues.extend(validate_op(index, op));
    }
    if !issues.is_empty() {
        return ApiError::validation("invalid ops", issues).into_response();
    }

    let mut accepted = 0u64;
    for op in &request.ops {
        let (ciphertext, wrapped_item_key) = match &op.payload {
            Some(payload) => (
                B64.decode(&payload.ciphertext).unwrap_or_default(),
                B64.decode(&payload.wrapped_item_key).unwrap_or_default(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        let (ciphertext, wrapped_item_key) = if ciphertext.is_empty() && wrapped_item_key.is_empty()
        {
            (None::<Vec<u8>>, None::<Vec<u8>>)
        } else {
            (Some(ciphertext), Some(wrapped_item_key))
        };
        let result = sqlx::query(
            "INSERT OR IGNORE INTO sync_oplog
                (op_id, item_id, kind, op, lamport, device_id, timestamp,
                 ciphertext, wrapped_item_key)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&op.op_id)
        .bind(&op.item_id)
        .bind(&op.kind)
        .bind(&op.op)
        .bind(op.lamport as i64)
        .bind(&op.device_id)
        .bind(op.timestamp.as_deref())
        .bind(ciphertext)
        .bind(wrapped_item_key)
        .execute(&state.pool)
        .await;
        match result {
            Ok(done) => accepted += done.rows_affected(),
            Err(error) => return ApiError::internal(error).into_response(),
        }
    }
    let duplicates = request.ops.len() as u64 - accepted;
    (Json(PushResponse {
        accepted,
        duplicates,
    }))
    .into_response()
}

/// GET /sync/oplog?since=cursor：pull 增量（seq 游标分页，沿 events 惯例）。
pub async fn pull(State(state): State<AppState>, Query(params): Query<PullQuery>) -> Response {
    let limit = match params.limit {
        None => PULL_DEFAULT_LIMIT,
        Some(0) => {
            return ApiError::validation(
                "invalid limit",
                vec![ErrorItem::batch("limit", "must be at least 1")],
            )
            .into_response()
        }
        Some(limit) if limit > PULL_MAX_FETCH => {
            return ApiError::validation(
                "invalid limit",
                vec![ErrorItem::batch(
                    "limit",
                    format!("must be at most {PULL_MAX_FETCH}"),
                )],
            )
            .into_response()
        }
        Some(limit) => limit,
    };
    let cursor = match &params.since {
        None => None,
        Some(raw) => match decode_cursor(raw) {
            Ok(cursor) => Some(cursor),
            Err(error) => return error.into_response(),
        },
    };
    const SELECT: &str = "SELECT seq, op_id, item_id, kind, op, lamport, device_id, timestamp, ciphertext, wrapped_item_key \
        FROM sync_oplog \
        WHERE (?1 IS NULL OR (seq, op_id) > (?1, ?2)) \
        ORDER BY seq ASC, op_id ASC \
        LIMIT ?3";
    let rows = match sqlx::query(SELECT)
        .bind(cursor.as_ref().map(|(seq, _)| *seq))
        .bind(cursor.as_ref().map(|(_, id)| id.as_str()))
        .bind(i64::from(limit) + 1)
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => rows,
        Err(error) => return ApiError::internal(error).into_response(),
    };
    let has_more = rows.len() > limit as usize;
    let page = &rows[..rows.len().min(limit as usize)];
    let mut ops = Vec::with_capacity(page.len());
    for row in page {
        let ciphertext: Option<Vec<u8>> = row.get("ciphertext");
        let wrapped_item_key: Option<Vec<u8>> = row.get("wrapped_item_key");
        ops.push(WireOp {
            op_id: row.get("op_id"),
            item_id: row.get("item_id"),
            kind: row.get("kind"),
            op: row.get("op"),
            lamport: row.get::<i64, _>("lamport") as u64,
            device_id: row.get("device_id"),
            timestamp: row.get("timestamp"),
            payload: match (ciphertext, wrapped_item_key) {
                (Some(c), Some(w)) => Some(WirePayload {
                    ciphertext: B64.encode(c),
                    wrapped_item_key: B64.encode(w),
                }),
                (None, None) => None,
                _ => {
                    return ApiError::internal("oplog payload columns partially null")
                        .into_response()
                }
            },
        });
    }
    let next_cursor = if has_more {
        let last = &rows[limit as usize - 1];
        Some(encode_cursor(
            last.get::<i64, _>("seq"),
            &last.get::<String, _>("op_id"),
        ))
    } else {
        None
    };
    (Json(PullResponse { ops, next_cursor })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{request, send, setup};
    use axum::http::StatusCode;
    use serde_json::{json, Value};

    const TOKEN: &str = "sync-test-token";

    async fn router() -> axum::Router {
        let (router, _state) = setup(Some(TOKEN)).await;
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

    async fn register_device(router: &axum::Router, name: &str) -> Uuid {
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/devices",
                &json!({
                    "device_name": name,
                    "public_key": b64(&[7u8; 32]),
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        Uuid::parse_str(body["device_id"].as_str().unwrap()).unwrap()
    }

    fn put_op_json(op_id: &str, item_id: &str, lamport: u64, device: &Uuid, tag: &[u8]) -> Value {
        json!({
            "op_id": op_id,
            "item_id": item_id,
            "kind": "credential",
            "op": "put",
            "lamport": lamport,
            "device_id": device.to_string(),
            "timestamp": "2026-09-22T00:00:00Z",
            "payload": {
                "ciphertext": b64(tag),
                "wrapped_item_key": b64(&[1u8; 32]),
            }
        })
    }

    #[tokio::test]
    async fn device_register_list_delete_round_trip() {
        let router = router().await;
        let id = register_device(&router, "laptop").await;

        let (status, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["devices"].as_array().unwrap().len(), 1);
        assert_eq!(body["devices"][0]["device_name"], "laptop");
        // 公钥 b64 往返
        let key = B64
            .decode(body["devices"][0]["public_key"].as_str().unwrap())
            .unwrap();
        assert_eq!(key, vec![7u8; 32]);

        let (status, _) = send(
            router.clone(),
            req("DELETE", &format!("/api/v1/sync/devices/{id}"), ""),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
        assert_eq!(body["devices"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn device_registration_rejects_duplicate_name_and_bad_key() {
        let router = router().await;
        register_device(&router, "phone").await;
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/devices",
                &json!({"device_name": "phone", "public_key": b64(&[7u8; 32])}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // 公钥长度错（31B）与坏 b64 都是 422
        for bad in [b64(&[7u8; 31]), "!!!not-base64!!!".to_string()] {
            let (status, body) = send(
                router.clone(),
                req(
                    "POST",
                    "/api/v1/sync/devices",
                    &json!({"device_name": "other", "public_key": bad}).to_string(),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        }
    }

    #[tokio::test]
    async fn group_key_envelope_round_trip_and_fail_closed() {
        let router = router().await;
        let device = register_device(&router, "laptop").await;
        let envelope_bytes: Vec<u8> = (0..80).map(|i| i as u8).collect();

        // 未登记设备挂信封 → 422（fail-closed 的服务器侧一半）
        let ghost = Uuid::new_v4();
        let (status, body) = send(
            router.clone(),
            req(
                "PUT",
                "/api/v1/sync/group-keys",
                &json!({"device_id": ghost.to_string(), "envelope": b64(&envelope_bytes)})
                    .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // 正常上传 → GET 原样取回
        let (status, _) = send(
            router.clone(),
            req(
                "PUT",
                "/api/v1/sync/group-keys",
                &json!({"device_id": device.to_string(), "envelope": b64(&envelope_bytes)})
                    .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["device_id"], device.to_string());
        assert_eq!(
            B64.decode(keys[0]["envelope"].as_str().unwrap()).unwrap(),
            envelope_bytes
        );
        assert_eq!(keys[0]["sealed_by"], "default"); // AuthTokens::single 的设备名

        // 长度不是 80B 的信封拒绝
        let (status, _) = send(
            router.clone(),
            req(
                "PUT",
                "/api/v1/sync/group-keys",
                &json!({"device_id": device.to_string(), "envelope": b64(&[0u8; 79])}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // 吊销设备 → 信封随之消失
        send(
            router.clone(),
            req("DELETE", &format!("/api/v1/sync/devices/{device}"), ""),
        )
        .await;
        let (_, body) = send(router, get_req("/api/v1/sync/group-keys")).await;
        assert_eq!(body["keys"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn oplog_push_pull_round_trip_with_cursor() {
        let router = router().await;
        let device = register_device(&router, "laptop").await;
        let item = Uuid::new_v4();
        let ops: Vec<Value> = (0..3)
            .map(|i| {
                put_op_json(
                    &Uuid::new_v4().to_string(),
                    &item.to_string(),
                    i + 1,
                    &device,
                    &[i as u8; 8],
                )
            })
            .collect();
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": ops}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["accepted"], 3);
        assert_eq!(body["duplicates"], 0);

        // 第一页 limit=2 → 2 条 + next_cursor
        let (status, body) = send(router.clone(), get_req("/api/v1/sync/oplog?limit=2")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ops"].as_array().unwrap().len(), 2);
        let cursor = body["next_cursor"].as_str().unwrap().to_string();

        // since 游标续拉 → 剩 1 条，无更多
        let (status, body) = send(
            router.clone(),
            get_req(&format!("/api/v1/sync/oplog?since={cursor}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rest = body["ops"].as_array().unwrap();
        assert_eq!(rest.len(), 1);
        assert!(body["next_cursor"].is_null());

        // 载荷 b64 round-trip
        let payload = rest[0]["payload"].as_object().unwrap();
        let ciphertext = B64.decode(payload["ciphertext"].as_str().unwrap()).unwrap();
        assert_eq!(ciphertext.len(), 8);
    }

    #[tokio::test]
    async fn oplog_push_is_idempotent_by_op_id() {
        let router = router().await;
        let device = register_device(&router, "laptop").await;
        let item = Uuid::new_v4().to_string();
        let op = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[9u8; 4]);
        let body_text = json!({"ops": [op.clone()]}).to_string();

        let (_, body) = send(
            router.clone(),
            req("POST", "/api/v1/sync/oplog", &body_text),
        )
        .await;
        assert_eq!(
            (body["accepted"].as_u64(), body["duplicates"].as_u64()),
            (Some(1), Some(0))
        );

        // 同批原样重推（网络重试）：全量 duplicates，库不重复
        let (_, body) = send(
            router.clone(),
            req("POST", "/api/v1/sync/oplog", &body_text),
        )
        .await;
        assert_eq!(
            (body["accepted"].as_u64(), body["duplicates"].as_u64()),
            (Some(0), Some(1))
        );

        let (_, body) = send(router, get_req("/api/v1/sync/oplog")).await;
        assert_eq!(body["ops"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn oplog_rejects_oversized_batch_and_malformed_ops() {
        let router = router().await;
        let device = register_device(&router, "laptop").await;
        let item = Uuid::new_v4().to_string();

        // 501 条 → 422
        let flood: Vec<Value> = (0..501)
            .map(|_| put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[0u8; 4]))
            .collect();
        let (status, _) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": flood}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // 单条多字段错误带 index：[0] 缺 payload 的 put、[1] delete 带 payload
        let bad_ops = json!({"ops": [
            {"op_id": Uuid::new_v4().to_string(), "item_id": item, "kind": "credential",
             "op": "put", "lamport": 1, "device_id": device.to_string(),
             "timestamp": null, "payload": null},
            {"op_id": Uuid::new_v4().to_string(), "item_id": item, "kind": "credential",
             "op": "delete", "lamport": 2, "device_id": device.to_string(),
             "timestamp": null,
             "payload": {"ciphertext": b64(&[1u8; 4]), "wrapped_item_key": b64(&[1u8; 32])}},
        ]});
        let (status, body) = send(
            router.clone(),
            req("POST", "/api/v1/sync/oplog", &bad_ops.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let items = body["error"]["items"].as_array().unwrap();
        assert!(items
            .iter()
            .any(|i| i["index"] == 0 && i["field"] == "payload"));
        assert!(items
            .iter()
            .any(|i| i["index"] == 1 && i["field"] == "payload"));

        // 非 UUID 的 op_id → 逐条 422
        let bad_uuid = json!({"ops": [
            {"op_id": "not-a-uuid", "item_id": item, "kind": "credential",
             "op": "put", "lamport": 1, "device_id": device.to_string(),
             "timestamp": null,
             "payload": {"ciphertext": b64(&[1u8; 4]), "wrapped_item_key": b64(&[1u8; 32])}}
        ]});
        let (status, body) = send(
            router,
            req("POST", "/api/v1/sync/oplog", &bad_uuid.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }

    /// 服务器 = 纯中继的直接断言：给一个含明文魔数的「密文」push 上去，
    /// 数据库行里该魔数只出现在 ciphertext 列——服务器没有（也不可能有）
    /// 任何明文副本列。真正的明文泄露面为空。
    #[tokio::test]
    async fn server_stores_only_ciphertext() {
        let (router, app_state) = crate::test_support::setup(Some(TOKEN)).await;
        let device = register_device(&router, "laptop").await;
        let magic = b"TOPSECRET-PLAINTEXT-MUST-NOT-LEAK";
        let item = Uuid::new_v4().to_string();
        let op = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, magic);
        let (status, body) = send(
            router,
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [op]}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let rows = sqlx::query(
            "SELECT op_id, item_id, kind, op, lamport, device_id, timestamp, ciphertext, wrapped_item_key FROM sync_oplog",
        )
        .fetch_all(&app_state.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        let stored: Vec<u8> = row.get("ciphertext");
        assert_eq!(stored, magic); // 密文列 == 客户端上传字节（中继保真）
                                   // 其余任何列都不含该魔数
        for column in ["op_id", "item_id", "kind", "device_id"] {
            let text: String = row.get(column);
            assert!(
                !text.as_bytes().windows(magic.len()).any(|w| w == magic),
                "plaintext leaked in column {column}"
            );
        }
        assert!(row.get::<Option<String>, _>("timestamp").is_some());
    }

    /// 服务器不做胜负判定（DR-4）：同 item 同 lamport 异 device 的两条
    /// 真冲突 op 原样双存、pull 原样双回——裁决权完全在客户端。
    #[tokio::test]
    async fn server_does_not_arbitrate_conflicts() {
        let router = router().await;
        let device_a = register_device(&router, "device-a").await;
        let device_b = register_device(&router, "device-b").await;
        let item = Uuid::new_v4().to_string();
        let ops = vec![
            put_op_json(&Uuid::new_v4().to_string(), &item, 7, &device_a, &[1u8; 4]),
            put_op_json(&Uuid::new_v4().to_string(), &item, 7, &device_b, &[2u8; 4]),
        ];
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": ops}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["accepted"], 2);

        let (_, body) = send(router, get_req("/api/v1/sync/oplog")).await;
        let pulled = body["ops"].as_array().unwrap();
        assert_eq!(pulled.len(), 2);
        let lamports: Vec<u64> = pulled
            .iter()
            .map(|op| op["lamport"].as_u64().unwrap())
            .collect();
        assert_eq!(lamports, vec![7, 7]);
        let devices: Vec<&str> = pulled
            .iter()
            .map(|op| op["device_id"].as_str().unwrap())
            .collect();
        assert!(devices.contains(&device_a.to_string().as_str()));
        assert!(devices.contains(&device_b.to_string().as_str()));
    }

    #[tokio::test]
    async fn unauthenticated_sync_request_is_rejected() {
        let router = router().await;
        let (status, _) = send(
            router,
            request("GET", "/api/v1/sync/devices", None, None, ""),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
