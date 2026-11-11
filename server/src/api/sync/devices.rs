use super::*;

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
        "SELECT id, device_name, public_key, created_at, remark FROM sync_devices ORDER BY created_at, id",
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
                remark: row.get("remark"),
            })
        })
        .collect();
    (Json(DeviceListResponse { devices })).into_response()
}

/// PUT /sync/devices/remark：改**自己**的备注（S4 设备面）。目标行由
/// 令牌归属的设备名锁定（不接 device_id 参数——接口形态上就改不了
/// 别人的），≤128 字节，空串 = 清除。
pub async fn put_device_remark(
    State(state): State<AppState>,
    Extension(device): Extension<DeviceName>,
    Json(request): Json<PutRemarkRequest>,
) -> Response {
    let remark = request.remark.trim();
    if remark.len() > 128 {
        return ApiError::validation(
            "invalid remark",
            vec![ErrorItem::batch("remark", "must be at most 128 bytes")],
        )
        .into_response();
    }
    match sqlx::query("UPDATE sync_devices SET remark = ? WHERE device_name = ?")
        .bind(remark)
        .bind(&device.0)
        .execute(&state.pool)
        .await
    {
        Ok(updated) if updated.rows_affected() == 1 => (
            StatusCode::OK,
            Json(serde_json::json!({ "device_name": device.0, "remark": remark })),
        )
            .into_response(),
        Ok(_) => ApiError::absent("device not registered").into_response(),
        Err(error) => ApiError::internal(error).into_response(),
    }
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
