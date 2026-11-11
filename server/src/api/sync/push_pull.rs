use super::oplog::{enforce_oplog_retention, validate_op};
use super::*;

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
