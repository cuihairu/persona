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
use chrono::{SecondsFormat, Utc};
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
    /// 全组轮换代数（rotate-begin 乐观锁的基线；0006 迁移）。
    epoch: u64,
}

/// POST /sync/group-key/rotate-begin 请求：if_epoch = 客户端最近读到的
/// 代数。服务器 CAS（epoch = if_epoch 才允许 +1）——两台设备并发轮换时
/// 后到者 409 fail-closed 中止，不再覆盖先到者的信封族。
#[derive(Debug, Deserialize)]
pub struct RotateBeginRequest {
    if_epoch: u64,
}

#[derive(Debug, Serialize)]
struct RotateBeginResponse {
    /// 抢占成功后的当前代数（= if_epoch + 1）。
    epoch: u64,
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
/// 设备已知的 group key 不可追溯撤销（DR-3 诚实边界——由「轮换组密钥」
/// 闭环，已落地）。生命周期级联（2026-09 吊销闭环）：同名 SRP 登记
/// （`auth_devices`，以设备名为键）一并删除，其已签发的短期令牌即刻
/// 失效、未决握手丢弃——被吊销设备不能再用既有凭证继续认证/推送。
pub async fn delete_device(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let device_id = match Uuid::parse_str(&id) {
        Ok(id) => id.to_string(),
        Err(_) => return StatusCode::NO_CONTENT.into_response(),
    };
    // 同名 = 同设备：SRP 登记与 sync_devices 共用设备名命名。先查名再删
    // （级联以名为键）；删行顺序安全敏感者先行——SRP 行 → 信封 → 登记，
    // 中途失败可整体重试（幂等）。
    let name =
        match sqlx::query_scalar::<_, String>("SELECT device_name FROM sync_devices WHERE id = ?")
            .bind(&device_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(name) => name,
            Err(error) => return ApiError::internal(error).into_response(),
        };
    let result: Result<(), sqlx::Error> = async {
        if let Some(name) = &name {
            sqlx::query("DELETE FROM auth_devices WHERE device_name = ?")
                .bind(name)
                .execute(&state.pool)
                .await?;
        }
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
    // DB 级联成功后清内存态：既有令牌即刻失效 + 未决握手丢弃（SRP 未
    // 启用则无内存态可清）
    if result.is_ok() {
        if let (Some(name), Some(srp)) = (&name, state.srp.as_ref()) {
            let evicted = srp.revoke_device(name);
            if evicted > 0 {
                tracing::info!(device = %name, evicted, "revoked SRP tokens on sync device deletion");
            }
        }
    }
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
    let epoch: i64 = match sqlx::query_scalar(
        "SELECT COALESCE((SELECT epoch FROM sync_group_epoch WHERE id = 1), 0)",
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(epoch) => epoch,
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
    (Json(GroupKeysResponse {
        keys,
        epoch: epoch.max(0) as u64,
    }))
    .into_response()
}

/// POST /sync/group-key/rotate-begin：轮换互斥点（§11 开放问题 2）。
/// 乐观锁抢占：epoch 与 if_epoch 相等才 +1（成功 = 获得写信封族的互斥
/// 窗口）；不相等 = 另一台设备已并发轮换，409 让后到者干净中止（未写
/// 任何信封、未重包）。epoch 单调递增不复位——重试方重读 group-keys
/// 拿新基线再来。begin 之后若轮换者崩溃，信封族停留在新旧混合态：与
/// 既有「轮换中途崩溃」边界一致，重试即重跑（幂等面 = 信封 upsert +
/// 重包以主库为准）。
pub async fn rotate_begin(
    State(state): State<AppState>,
    // 设备名未参与 CAS（互斥对象是全组而非单设备）；持 Extension 保持与
    // 其他写端点一致的中间件形态（require_bearer 已认证）。
    Extension(_device): Extension<DeviceName>,
    Json(request): Json<RotateBeginRequest>,
) -> Response {
    let result: Result<Option<u64>, String> = async {
        let mut tx = state.pool.begin().await.map_err(|e| e.to_string())?;
        // 事务内读当前代数并 CAS：命中才 +1
        let current: i64 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT epoch FROM sync_group_epoch WHERE id = 1), 0)",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        if current.max(0) as u64 != request.if_epoch {
            return Ok(None);
        }
        sqlx::query("UPDATE sync_group_epoch SET epoch = epoch + 1 WHERE id = 1")
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        let next = (current + 1).max(0) as u64;
        // 显式 commit：事务 drop 即回滚，漏掉等于互斥形同虚设
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(Some(next))
    }
    .await;
    match result {
        Ok(Some(epoch)) => (Json(RotateBeginResponse { epoch })).into_response(),
        Ok(None) => ApiError::conflict(format!(
            "concurrent group key rotation detected: epoch is no longer {}; re-read group-keys and retry",
            request.if_epoch
        ))
        .into_response(),
        Err(error) => {
            tracing::error!(%error, "rotate begin failed");
            ApiError::internal("rotate begin failed").into_response()
        }
    }
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

/// server 侧 oplog 保留策略（E2EE_SYNC_DESIGN §11 开放问题 3 收口）：
/// 按 received_at 滚动删除超过保留窗口的中继行，0 = 不清理（默认，
/// 保持纯中继现状）。窗口语义 = 放弃向「离线超过窗口」的设备补发历史
/// 的责任：游标重置重拉会拿到缩水子集（LWW 对子集仍收敛，缺失部分靠
/// 各端本地事实源与重推幂等补齐——客户端 push 队列持底稿，重推同 op_id
/// 经 INSERT OR IGNORE 原样重建）。清理失败仅告警：增长治理不是中继
/// 正确性的前置条件。
async fn enforce_oplog_retention(state: &AppState) {
    let days = state.oplog_retention_days;
    if days == 0 {
        return;
    }
    let cutoff = (Utc::now()
        - chrono::Duration::try_days(i64::from(days)).expect("retention days always fits"))
    .to_rfc3339_opts(SecondsFormat::Millis, true);
    match sqlx::query("DELETE FROM sync_oplog WHERE received_at < ?")
        .bind(&cutoff)
        .execute(&state.pool)
        .await
    {
        Ok(done) => {
            let removed = done.rows_affected();
            if removed > 0 {
                state.metrics.add_sync_ops_pruned(removed);
                tracing::info!(
                    event = "oplog_retention",
                    removed,
                    days,
                    "pruned relayed ops"
                );
            }
        }
        Err(error) => tracing::warn!(%error, "oplog retention skipped"),
    }
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
    enforce_oplog_retention(&state).await;
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
    // 非空页恒返回该页最后一行的游标（与 events 的 has_more 语义有意
    // 分叉）：sync 客户端（core engine.pull_cycle）按「空页才停」循环，
    // 游标必须始终指向已处理位置——最后一页处理完即存游标，崩溃重启
    // 不重拉。空页给 null，客户端 break。
    let next_cursor = page
        .last()
        .map(|last| encode_cursor(last.get::<i64, _>("seq"), &last.get::<String, _>("op_id")));
    (Json(PullResponse { ops, next_cursor })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{request, send, setup, setup_with_retention};
    use axum::http::StatusCode;
    use chrono::Utc;
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

    // ---- 并发轮换互斥（§11 开放问题 2：epoch 乐观锁）----

    #[tokio::test]
    async fn rotate_begin_cas_mutex_and_epoch_exposure() {
        let router = router().await;

        // 初始 epoch = 0，group-keys 响应携带基线
        let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
        assert_eq!(body["epoch"], 0);

        // CAS 命中：0 → 1
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/group-key/rotate-begin",
                &json!({"if_epoch": 0}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["epoch"], 1);

        // 陈旧基线重放 → 409 fail-closed（后到者干净中止）
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/group-key/rotate-begin",
                &json!({"if_epoch": 0}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // 重读新基线后可再抢（重试路径）：1 → 2
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/group-key/rotate-begin",
                &json!({"if_epoch": 1}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["epoch"], 2);

        // group-keys 反映最新代数
        let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
        assert_eq!(body["epoch"], 2);
    }

    /// 两台设备并发轮换：先到者抢到互斥窗口，后到者拿陈旧基线 begin 得
    /// ConcurrentConflict（core 侧 409 映射）；重读新基线后可完成重试。
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_rotation_second_device_fails_closed() {
        use persona_core::sync::device::DeviceIdentity;
        use persona_core::sync::remote::SyncAdminApi;

        const TOKEN: &str = "sync-rotate-race-token";
        let (router, _state) = setup(Some(TOKEN)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        let base = format!("http://{addr}");
        let admin_a = SyncAdminApi::new(&base, TOKEN).unwrap();
        let admin_b = SyncAdminApi::new(&base, TOKEN).unwrap();

        // A 自举建组（epoch 仍 0）
        let dev_a = DeviceIdentity::generate("racer-a").unwrap();
        let id_a = admin_a
            .register_device("racer-a", dev_a.key_pair.public_bytes())
            .await
            .unwrap();
        assert!(admin_a
            .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
            .await
            .unwrap());

        // 两台各自读到同一基线
        let (_, baseline_b) = admin_b.group_keys_with_epoch().await.unwrap();
        assert_eq!(baseline_b, 0);

        // A 抢到互斥（0 → 1）；B 拿陈旧基线 begin → ConcurrentConflict
        let won = admin_a.begin_group_rotation(baseline_b).await.unwrap();
        assert_eq!(won, 1);
        let err = admin_b.begin_group_rotation(baseline_b).await.unwrap_err();
        assert!(
            err.downcast_ref::<persona_core::PersonaError>()
                .is_some_and(|e| matches!(e, persona_core::PersonaError::ConcurrentConflict(_))),
            "unexpected error: {err}"
        );

        // B 重读新基线 → 重试成功（1 → 2）
        let (_, fresh) = admin_b.group_keys_with_epoch().await.unwrap();
        assert_eq!(fresh, 1);
        assert_eq!(admin_b.begin_group_rotation(fresh).await.unwrap(), 2);

        task.abort();
    }

    // ---- server 侧 oplog 保留策略（§11 开放问题 3 收口）----

    #[tokio::test]
    async fn oplog_retention_prunes_over_window_and_repush_rebuilds() {
        let (router, state) = setup_with_retention(Some(TOKEN), 30, 0).await;
        let device = register_device(&router, "laptop").await;
        let item = Uuid::new_v4();
        let old_op = put_op_json(
            &Uuid::new_v4().to_string(),
            &item.to_string(),
            1,
            &device,
            &[1u8; 8],
        );
        let fresh_op = put_op_json(
            &Uuid::new_v4().to_string(),
            &item.to_string(),
            2,
            &device,
            &[2u8; 8],
        );

        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [old_op, fresh_op]}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["accepted"], 2);

        // 第一条回拨到窗口外
        let stale_received_at = (Utc::now() - chrono::Duration::try_days(31).unwrap())
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        sqlx::query("UPDATE sync_oplog SET received_at = ? WHERE lamport = 1")
            .bind(&stale_received_at)
            .execute(&state.pool)
            .await
            .unwrap();

        // 再 push（触发清理路径）：fresh 重推 = duplicates，不新增
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [fresh_op]}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["accepted"], 0);
        assert_eq!(body["duplicates"], 1);

        // pull 只剩窗口内的 fresh
        let (_, body) = send(router.clone(), get_req("/api/v1/sync/oplog")).await;
        let ops = body["ops"].as_array().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["lamport"], 2);
        assert!(state
            .metrics
            .render()
            .contains("persona_sync_ops_pruned_total 1"));

        // 协同语义：被清的 op 重推 → op_id 幂等重建（游标重置重拉不丢底稿）
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [old_op]}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["accepted"], 1);
        let (_, body) = send(router.clone(), get_req("/api/v1/sync/oplog")).await;
        assert_eq!(body["ops"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn oplog_retention_zero_keeps_everything() {
        let (router, state) = setup_with_retention(Some(TOKEN), 0, 0).await;
        let device = register_device(&router, "laptop").await;
        let item = Uuid::new_v4();
        let op = put_op_json(
            &Uuid::new_v4().to_string(),
            &item.to_string(),
            1,
            &device,
            &[1u8; 8],
        );
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [op]}).to_string(),
            ),
        )
        .await;
        assert_eq!(body["accepted"], 1, "{status}");

        // 回拨到很远再 push 触发清理路径：0 = 不清理，行仍在
        sqlx::query("UPDATE sync_oplog SET received_at = '2000-01-01T00:00:00.000Z'")
            .execute(&state.pool)
            .await
            .unwrap();
        let (_, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/oplog",
                &json!({"ops": [put_op_json(
                    &Uuid::new_v4().to_string(),
                    &item.to_string(),
                    2,
                    &device,
                    &[2u8; 8],
                )]})
                .to_string(),
            ),
        )
        .await;
        assert_eq!(body["accepted"], 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sync_oplog")
                .fetch_one(&state.pool)
                .await
                .unwrap(),
            2
        );
        assert!(state
            .metrics
            .render()
            .contains("persona_sync_ops_pruned_total 0"));
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

        // 第一页 limit=2 → 2 条 + next_cursor（指向第 2 行）
        let (status, body) = send(router.clone(), get_req("/api/v1/sync/oplog?limit=2")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ops"].as_array().unwrap().len(), 2);
        let cursor = body["next_cursor"].as_str().unwrap().to_string();

        // since 游标续拉 → 剩 1 条；非空页恒返回游标（指向第 3 行）
        let (status, body) = send(
            router.clone(),
            get_req(&format!("/api/v1/sync/oplog?since={cursor}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rest = body["ops"].as_array().unwrap();
        assert_eq!(rest.len(), 1);
        let last_cursor = body["next_cursor"].as_str().unwrap().to_string();

        // 从最后一行游标再拉 → 空页 + null 游标（客户端循环的停点）
        let (status, body) = send(
            router.clone(),
            get_req(&format!("/api/v1/sync/oplog?since={last_cursor}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ops"].as_array().unwrap().len(), 0);
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

    // E2EE_SYNC_DESIGN 阶段 2 批 4 验收「两端收敛测试」：真 HTTP 栈 +
    // 客户端 wire 层（core HttpSyncRemote）+ 两份独立 oplog（各挂
    // SyncEngine）。覆盖：单向 push→pull、双端同 lamport 离线编辑的真
    // 冲突（两端收敛到同一主位 + 双版本保留）、重建 engine 实例（状态全
    // 在库：local_lamport/游标/pending 不随实例走——换主密码零影响同步
    // 的构造性证明：SyncEngine 全链路无主密码参数，实例可弃可换）。
    #[tokio::test(flavor = "multi_thread")]
    async fn two_devices_converge_over_real_tcp_conflict_keeps_both_versions() {
        use persona_core::storage::sync_repository::SyncRepository;
        use persona_core::storage::Database;
        use persona_core::sync::engine::SyncEngine;
        use persona_core::sync::oplog::{item_view, ItemKind, OpType, SyncPayload};
        use persona_core::sync::remote::HttpSyncRemote;

        const TOKEN: &str = "sync-e2e-token";
        let (router, _state) = setup(Some(TOKEN)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        let base = format!("http://{addr}");

        async fn fresh_repo() -> (SyncRepository, Database) {
            let db = Database::in_memory().await.unwrap();
            db.migrate().await.unwrap();
            let repo = SyncRepository::new(db.clone());
            (repo, db)
        }

        fn engine_for(
            db: Database,
            base: &str,
            token: &str,
            device_id: Uuid,
        ) -> SyncEngine<HttpSyncRemote> {
            SyncEngine::new(
                SyncRepository::new(db),
                HttpSyncRemote::new(base, token).unwrap(),
                device_id,
                Box::new(|| false),
            )
        }

        fn payload(tag: u8) -> Option<SyncPayload> {
            Some(SyncPayload {
                ciphertext: vec![tag; 8],
                wrapped_item_key: vec![tag; 32],
            })
        }

        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        let (repo_a, db_a) = fresh_repo().await;
        let (repo_b, db_b) = fresh_repo().await;
        let engine_a = engine_for(db_a.clone(), &base, TOKEN, device_a);
        let engine_b = engine_for(db_b, &base, TOKEN, device_b);

        // A 离线写 lamport 1 并 push
        let item = Uuid::new_v4();
        let a1 = engine_a
            .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xA1))
            .await
            .unwrap();
        assert_eq!(a1.lamport, 1);
        assert_eq!(engine_a.push_cycle().await.unwrap().pushed, 1);

        // B 上线拉到 A1，看到的主位就是 A 的版本
        let pull = engine_b.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 1);
        assert_eq!(repo_b.get_state().await.unwrap().local_lamport, 1);
        let view_b = item_view(repo_b.item_ops(item).await.unwrap());
        assert_eq!(view_b.primary.as_ref().unwrap().device_id, device_a);
        assert!(view_b.conflicts.is_empty());

        // 双端离线同 lamport 编辑：B 从 lamport 1 出发写 2 并 push；A 不
        // 知情（没拉过 B2），也从 1 出发写 2——真冲突的典型形态
        let b2 = engine_b
            .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xB2))
            .await
            .unwrap();
        assert_eq!(b2.lamport, 2);
        assert_eq!(engine_b.push_cycle().await.unwrap().pushed, 1);

        // A 端重建 engine 实例（同一库句柄）：时钟延续正确——下一条仍接
        // lamport 2（local_lamport 在库不在实例）
        let engine_a2 = engine_for(db_a, &base, TOKEN, device_a);
        let a2 = engine_a2
            .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xA2))
            .await
            .unwrap();
        assert_eq!(a2.lamport, 2);
        assert_eq!(engine_a2.push_cycle().await.unwrap().pushed, 1);

        // 双端各拉一轮 → 各自 oplog 持有 {A1, B2, A2} 全集
        let pull_a = engine_a2.pull_cycle().await.unwrap();
        assert_eq!(pull_a.applied, 1); // A1 是自己的本地 op，去重跳过
        let pull_b = engine_b.pull_cycle().await.unwrap();
        assert_eq!(pull_b.applied, 1);

        // 收敛断言：两端 oplog 全集一致，主位收敛到同一 op（全序裁决），
        // 冲突区恰一条，胜者/负者双版本密文都在（数据不丢）
        let ops_a = repo_a.item_ops(item).await.unwrap();
        let ops_b = repo_b.item_ops(item).await.unwrap();
        assert_eq!(ops_a.len(), 3);
        assert_eq!(ops_b.len(), 3);
        let view_a = item_view(ops_a);
        let view_b = item_view(ops_b);
        let primary_a = view_a.primary.as_ref().unwrap();
        let primary_b = view_b.primary.as_ref().unwrap();
        assert_eq!(primary_a.op_id, primary_b.op_id);
        assert_eq!(primary_a.device_id, device_a.max(device_b)); // 字典序大者胜
        assert_eq!(view_a.conflicts.len(), 1);
        assert_eq!(view_b.conflicts.len(), 1);
        assert_eq!(view_a.conflicts[0].op_id, view_b.conflicts[0].op_id);
        // 双版本密文都可读且可区分（胜者/负者都不丢——数据不丢的落库证明）
        let primary_tag = primary_a.payload.as_ref().unwrap().ciphertext[0];
        let conflict_tag = view_a.conflicts[0].payload.as_ref().unwrap().ciphertext[0];
        assert_ne!(primary_tag, conflict_tag);

        task.abort();
    }

    // SyncAdminApi（core 客户端 wire 层）与 server 契约的真 TCP 对齐测试：
    // handler 语义已由上面的单测覆盖（409/422/级联等），这里验证客户端侧
    // 类型转换（device_id Uuid、public_key [u8;32]、envelope 字节原样往返）
    // 与错误路径（409 message 透传到 Err、幽灵设备 fail-closed）。
    #[tokio::test(flavor = "multi_thread")]
    async fn admin_api_client_manages_devices_and_group_keys_over_real_tcp() {
        use persona_core::sync::remote::SyncAdminApi;

        const TOKEN: &str = "sync-admin-token";
        let (router, _state) = setup(Some(TOKEN)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        let base = format!("http://{addr}");

        let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

        // 注册两台设备
        let laptop_id = admin
            .register_device("laptop", &[7u8; 32])
            .await
            .expect("register laptop");
        let phone_id = admin
            .register_device("phone", &[9u8; 32])
            .await
            .expect("register phone");
        assert_ne!(laptop_id, phone_id);

        // 重名 → 409，message 透传到 Err（客户端不吞服务器语义）
        let dup = admin
            .register_device("laptop", &[1u8; 32])
            .await
            .unwrap_err();
        assert!(
            dup.to_string().contains("already registered"),
            "unexpected error: {dup:#}"
        );

        // 列表：名称 + 公钥字节级还原
        let devices = admin.list_devices().await.expect("list devices");
        assert_eq!(devices.len(), 2);
        let laptop = devices
            .iter()
            .find(|d| d.id == laptop_id)
            .expect("laptop in list");
        assert_eq!(laptop.device_name, "laptop");
        assert_eq!(laptop.public_key, [7u8; 32]);
        assert!(!laptop.created_at.is_empty());

        // 起始无信封
        assert!(admin.group_keys().await.expect("empty keys").is_empty());

        // 上传信封（恰 80B）→ 原样取回，sealed_by = AuthTokens::single 的设备名
        let envelope: Vec<u8> = (0..80).map(|i| i as u8).collect();
        admin
            .put_group_key(laptop_id, &envelope)
            .await
            .expect("put group key");
        // 幽灵设备 fail-closed → Err
        admin
            .put_group_key(Uuid::new_v4(), &[0u8; 80])
            .await
            .expect_err("ghost device must be rejected");
        // 同设备覆盖（upsert）不报错
        admin
            .put_group_key(laptop_id, &[0xAA; 80])
            .await
            .expect("overwrite group key");

        let keys = admin.group_keys().await.expect("group keys");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].device_id, laptop_id);
        assert_eq!(keys[0].envelope, vec![0xAA; 80]);
        assert_eq!(keys[0].sealed_by, "default");

        // 吊销 laptop：幂等（二次删除同 204）+ 信封级联消失
        admin.delete_device(laptop_id).await.expect("revoke laptop");
        admin
            .delete_device(laptop_id)
            .await
            .expect("revoke laptop twice is idempotent");
        let devices = admin.list_devices().await.expect("list after revoke");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, phone_id);
        assert!(admin
            .group_keys()
            .await
            .expect("keys after revoke")
            .is_empty());

        task.abort();
    }

    // 首设备自举：全新服务器上第一台设备 join 时无人能授权它（信封由
    // 「既有设备」封出，而此刻不存在既有设备）——bootstrap_group_if_empty
    // 在空组上自建组密钥 + 自封信封，第二台设备起恢复「等既有设备授权」
    // 流程。这是 join 流程能在真机上跑通的前提（阶段 3 演示脚本第一步）。
    #[tokio::test(flavor = "multi_thread")]
    async fn admin_api_bootstrap_creates_group_on_fresh_server_and_second_device_still_pends() {
        use persona_core::sync::device::DeviceIdentity;
        use persona_core::sync::envelope::{open_group_key, seal_group_key};
        use persona_core::sync::remote::SyncAdminApi;

        const TOKEN: &str = "sync-bootstrap-token";
        let (router, _state) = setup(Some(TOKEN)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        let base = format!("http://{addr}");

        let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

        // 首设备：登记后空组自举 → true，且本机能拆开自己的信封
        let laptop = DeviceIdentity::generate("laptop").unwrap();
        let laptop_id = admin
            .register_device("laptop", laptop.key_pair.public_bytes())
            .await
            .expect("register first device");
        let bootstrapped = admin
            .bootstrap_group_if_empty(laptop_id, laptop.key_pair.public_bytes())
            .await
            .expect("bootstrap on fresh server");
        assert!(bootstrapped);
        let keys = admin.group_keys().await.expect("keys after bootstrap");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].device_id, laptop_id);
        let group = open_group_key(&keys[0].envelope, laptop.key_pair.secret_bytes())
            .expect("own envelope opens");

        // 第二台设备：组已非空 → 不自举（false），等首设备授权
        let phone = DeviceIdentity::generate("phone").unwrap();
        let phone_id = admin
            .register_device("phone", phone.key_pair.public_bytes())
            .await
            .expect("register second device");
        let bootstrapped = admin
            .bootstrap_group_if_empty(phone_id, phone.key_pair.public_bytes())
            .await
            .expect("bootstrap on non-empty group");
        assert!(!bootstrapped);

        // 首设备代授权：拆自己的 group key → 用对方公钥封新信封上传
        let envelope = seal_group_key(&group, phone.key_pair.public_bytes());
        admin
            .put_group_key(phone_id, &envelope)
            .await
            .expect("authorize phone");
        let keys = admin.group_keys().await.expect("keys after authorize");
        assert_eq!(keys.len(), 2);
        let phone_entry = keys.iter().find(|k| k.device_id == phone_id).unwrap();
        let group_phone = open_group_key(&phone_entry.envelope, phone.key_pair.secret_bytes())
            .expect("phone opens its envelope");
        assert_eq!(group, group_phone, "both devices hold the same group key");

        task.abort();
    }

    // group key 轮换全流程（真 TCP，阶段 3d）：A 自举建组并授权 B → A
    // rotate（换信封 + 全量重包）→ 信封集仍恰好覆盖两台授权设备、全部拆出
    // **新** key；随后 B 与后入组的 C 各自开会话拉全量——重包 op 全部可读
    // 物化（旧 key 批次按「严格旧版本」忽略，当前态由重包 op 补齐）。
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_group_key_swaps_envelopes_and_new_devices_read_rewrapped_ops() {
        use persona_core::crypto::encryption::EncryptionService;
        use persona_core::crypto::key_hierarchy::KeyHierarchy;
        use persona_core::models::credential::{
            Credential, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
        };
        use persona_core::models::identity::{Identity, IdentityType};
        use persona_core::storage::repository::IdentityRepository;
        use persona_core::storage::{CredentialRepository, Database, Repository};
        use persona_core::sync::device::DeviceIdentity;
        use persona_core::sync::envelope::{open_group_key, seal_group_key};
        use persona_core::sync::remote::SyncAdminApi;
        use persona_core::sync::runtime::SyncSession;

        const TOKEN: &str = "sync-rotate-token";
        let (router, _state) = setup(Some(TOKEN)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        let base = format!("http://{addr}");
        let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

        // A 自举建组；授权 B（旧组密钥信封）。登记后 with_device_id 回填
        // 服务器分配的 UUID（与桌面版 sync_join 同序）。
        let dev_a = DeviceIdentity::generate("rotator-a").unwrap();
        let id_a = admin
            .register_device("rotator-a", dev_a.key_pair.public_bytes())
            .await
            .expect("register A");
        let dev_a = dev_a.with_device_id(id_a);
        assert!(admin
            .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
            .await
            .expect("bootstrap A"));
        let group_old = open_group_key(
            &admin.group_keys().await.unwrap()[0].envelope,
            dev_a.key_pair.secret_bytes(),
        )
        .expect("A opens own envelope");

        let dev_b = DeviceIdentity::generate("member-b").unwrap();
        let id_b = admin
            .register_device("member-b", dev_b.key_pair.public_bytes())
            .await
            .expect("register B");
        let dev_b = dev_b.with_device_id(id_b);
        admin
            .put_group_key(
                id_b,
                &seal_group_key(&group_old, dev_b.key_pair.public_bytes()),
            )
            .await
            .expect("authorize B");

        // A 的本地库：两条凭据 + 真会话（HttpSyncRemote）
        let db_a = Database::in_memory().await.unwrap();
        db_a.migrate().await.unwrap();
        let owner = Identity::new("seed".to_string(), IdentityType::Personal);
        IdentityRepository::new(db_a.clone())
            .create(&owner)
            .await
            .unwrap();
        let master_a = EncryptionService::new(&EncryptionService::generate_key());
        let cred_repo = CredentialRepository::new(db_a.clone());
        for (name, secret) in [("cred-one", "one"), ("cred-two", "two")] {
            let item_key = EncryptionService::generate_key();
            let wrapped = master_a.encrypt(&item_key).unwrap();
            let plaintext = CredentialData::Password(PasswordCredentialData {
                password: secret.to_string(),
                email: None,
                security_questions: vec![],
            })
            .to_bytes()
            .unwrap();
            let ciphertext = KeyHierarchy::new(&master_a)
                .encrypt_with_item_key(&item_key, &plaintext)
                .unwrap();
            cred_repo
                .create(&Credential::new(
                    owner.id,
                    name.to_string(),
                    CredentialType::Password,
                    SecurityLevel::High,
                    ciphertext,
                    Some(wrapped),
                ))
                .await
                .unwrap();
        }

        let session_a = SyncSession::open(&db_a, &dev_a, &base, TOKEN, Box::new(|| false))
            .await
            .expect("session A");
        assert_eq!(session_a.backfill_existing(&master_a).await.unwrap(), 2);

        // 轮换：前置 drain（旧 key 批次 2 条）+ 重包（2 条）+ 再 drain
        let report = session_a.rotate_group_key(&master_a, &admin).await.unwrap();
        assert_eq!((report.rewrapped, report.skipped), (2, 0));
        assert_eq!(report.pushed, 4);

        // 信封集：仍恰好两台授权设备，且都拆出**新** key（≠旧 key）
        let keys = admin.group_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        let group_new = open_group_key(
            &keys.iter().find(|k| k.device_id == id_a).unwrap().envelope,
            dev_a.key_pair.secret_bytes(),
        )
        .expect("A opens rotated envelope");
        let group_new_b = open_group_key(
            &keys.iter().find(|k| k.device_id == id_b).unwrap().envelope,
            dev_b.key_pair.secret_bytes(),
        )
        .expect("B opens rotated envelope");
        assert_eq!(group_new, group_new_b);
        assert_ne!(group_new, group_old);

        // B（会话开在轮换后 → 只持新 key）拉全量：重包 op 全部物化
        let (db_b, master_b) = member_db(owner.id).await;
        let session_b = SyncSession::open(&db_b, &dev_b, &base, TOKEN, Box::new(|| false))
            .await
            .expect("session B");
        let report_b = session_b.run_cycle(&master_b).await.unwrap();
        assert_eq!(report_b.pulled, 4);
        assert_eq!(report_b.materialized, 2);
        assert_eq!(report_b.conflicts, 0);
        assert_eq!(report_b.pending_identity, 0);
        assert_stored_credentials(&db_b, &master_b).await;

        // 后入组的 C：授权拿到新 key，拉全量同样全部可读
        let dev_c = DeviceIdentity::generate("late-c").unwrap();
        let id_c = admin
            .register_device("late-c", dev_c.key_pair.public_bytes())
            .await
            .expect("register C");
        let dev_c = dev_c.with_device_id(id_c);
        admin
            .put_group_key(
                id_c,
                &seal_group_key(&group_new, dev_c.key_pair.public_bytes()),
            )
            .await
            .expect("authorize C");
        let (db_c, master_c) = member_db(owner.id).await;
        let session_c = SyncSession::open(&db_c, &dev_c, &base, TOKEN, Box::new(|| false))
            .await
            .expect("session C");
        let report_c = session_c.run_cycle(&master_c).await.unwrap();
        assert_eq!(report_c.pulled, 4);
        assert_eq!(report_c.materialized, 2);
        assert_stored_credentials(&db_c, &master_c).await;

        task.abort();
    }

    /// 成员设备的本地库：同 id 身份行（身份不经 oplog 同步，测试直接对齐）
    /// + 独立主密钥。
    async fn member_db(
        identity_id: Uuid,
    ) -> (
        persona_core::storage::Database,
        persona_core::crypto::encryption::EncryptionService,
    ) {
        use persona_core::crypto::encryption::EncryptionService;
        use persona_core::models::identity::{Identity, IdentityType};
        use persona_core::storage::repository::IdentityRepository;
        use persona_core::storage::{Database, Repository};

        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut owner = Identity::new("seed".to_string(), IdentityType::Personal);
        owner.id = identity_id;
        IdentityRepository::new(db.clone())
            .create(&owner)
            .await
            .unwrap();
        let master = EncryptionService::new(&EncryptionService::generate_key());
        (db, master)
    }

    /// 断言库中两条凭据名称与密码和 A 侧种子一致（经本机 master 读回）。
    async fn assert_stored_credentials(
        db: &persona_core::storage::Database,
        master: &persona_core::crypto::encryption::EncryptionService,
    ) {
        use persona_core::crypto::key_hierarchy::KeyHierarchy;
        use persona_core::models::credential::CredentialData;
        use persona_core::storage::CredentialRepository;

        let creds = CredentialRepository::new(db.clone())
            .list_all()
            .await
            .unwrap();
        assert_eq!(creds.len(), 2);
        let hierarchy = KeyHierarchy::new(master);
        let mut found: Vec<(String, String)> = creds
            .iter()
            .map(|cred| {
                let plaintext = hierarchy
                    .decrypt_with_wrapped_key(
                        cred.wrapped_item_key.as_deref().expect("wrapped item key"),
                        &cred.encrypted_data,
                    )
                    .expect("decrypt with local master");
                match CredentialData::from_bytes(&plaintext).unwrap() {
                    CredentialData::Password(p) => (cred.name.clone(), p.password),
                    other => panic!("unexpected credential data: {other:?}"),
                }
            })
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                ("cred-one".to_string(), "one".to_string()),
                ("cred-two".to_string(), "two".to_string())
            ]
        );
    }

    // 设备吊销闭环（真 TCP）：同名 SRP 登记随同步设备吊销级联——既有
    // 短期令牌**即刻**失效（不等 15 分钟 TTL），重新登录被拒（与未注册
    // 同形 401）；吊销幂等。THREAT_MODEL「SRP 设备认证端点」已知限制
    // 「auth_devices 无删除路径」由本路径关闭。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoked_sync_device_loses_srp_access_and_outstanding_tokens() {
        use persona_core::auth::remote_http::HttpRemoteAuthProvider;
        use persona_core::sync::remote::SyncAdminApi;

        const TOKEN: &str = "sync-revoke-closure-token";
        let (router, _state) = setup(Some(TOKEN)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        let base = format!("http://{addr}");

        let admin = SyncAdminApi::new(&base, TOKEN).unwrap();
        let id = admin
            .register_device("laptop", &[7u8; 32])
            .await
            .expect("register sync device");

        // 同名 SRP 登记 + 登录拿短期令牌
        let provider = HttpRemoteAuthProvider::new(base.clone()).unwrap();
        provider
            .register_device(TOKEN, "laptop", "pw-for-device")
            .await
            .expect("SRP enroll");
        let outcome = provider
            .begin_login("laptop")
            .await
            .unwrap()
            .finish("pw-for-device")
            .await
            .expect("SRP login");

        // 令牌可用：过 require_bearer 访问 sync 端点
        let client = reqwest::Client::new();
        let probe = client
            .get(format!("{base}/api/v1/sync/devices"))
            .bearer_auth(&outcome.token)
            .send()
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::OK, "{probe:?}");

        // 吊销同步设备：级联删 SRP 行 + 即吊内存令牌
        admin.delete_device(id).await.expect("revoke");

        // 既有令牌即刻 401（不等 TTL）
        let probe = client
            .get(format!("{base}/api/v1/sync/devices"))
            .bearer_auth(&outcome.token)
            .send()
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::UNAUTHORIZED, "{probe:?}");
        // 重新 SRP 登录 401（登记行已删——challenge 与未注册同形 401，
        // 登录链路任一步失败均算闭包成立）
        let err = match provider.begin_login("laptop").await {
            Ok(handle) => handle
                .finish("pw-for-device")
                .await
                .err()
                .map(|e| e.to_string()),
            Err(e) => Some(e.to_string()),
        };
        let err = err.expect("login must fail after revocation");
        assert!(err.contains("HTTP 401"), "{err}");
        // 二次吊销幂等
        admin.delete_device(id).await.expect("revoke twice");

        task.abort();
    }
}
