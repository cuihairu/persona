use super::*;

// ---- /sync/devices ----

/// POST /sync/devices: register a device (public key + device name). A duplicate name is 409 —
/// the public key must not be silently replaced (swapping the key after compromising the token
/// would hijack that device's envelope channel).
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

/// GET /sync/devices: list all registered devices.
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

/// PUT /sync/devices/remark: change **your own** remark (S4 device surface). The target row is
/// pinned to the device name owned by the token (no device_id parameter — it is structurally
/// impossible to change someone else's), at most 128 bytes, and an empty string clears it.
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

/// DELETE /sync/devices/:id: revoke a device (deletes the registration and its envelope).
/// Idempotent; a group key already known to the revoked device cannot be retroactively
/// withdrawn (DR-3 honest boundary — closed out by "rotate the group key", already
/// implemented). Lifecycle cascade (2026-09 revocation closeout): the same-named SRP
/// registration (`auth_devices`, keyed by device name) is deleted as well, its issued
/// short-lived tokens become invalid immediately and pending handshakes are dropped — a
/// revoked device can no longer keep authenticating/pushing with its existing credentials.
pub async fn delete_device(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let device_id = match Uuid::parse_str(&id) {
        Ok(id) => id.to_string(),
        Err(_) => return StatusCode::NO_CONTENT.into_response(),
    };
    // Same name = same device: the SRP registration and sync_devices share device-name
    // naming. Look the name up before deleting (the cascade is keyed by name); delete the
    // safety-sensitive rows first — SRP row -> envelope -> registration —
    // a mid-way failure can be retried as a whole (idempotent).
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
    // Once the DB cascade succeeds, clear the in-memory state: existing tokens become
    // invalid immediately + pending handshakes are dropped (if SRP is not enabled there is
    // no in-memory state to clear)
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

/// GET /sync/group-keys: all device envelopes. Clients only honor the entry for their own
/// device_id; an unauthorized device cannot open someone else's envelope even if it fetches
/// it (see the module docs for the fail-closed stance).
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

/// POST /sync/group-key/rotate-begin: the rotation mutual-exclusion point (§11 open question 2).
/// Optimistic-lock preemption: epoch is incremented only if it still equals if_epoch (success =
/// acquiring the exclusive window for writing the envelope family); otherwise another device has
/// rotated concurrently, and 409 lets the latecomer abort cleanly (having written no envelopes and
/// re-sealed nothing). epoch increases monotonically and never resets — a retrier re-reads
/// group-keys for the new baseline and tries again. If the rotator crashes after begin, the
/// envelope family is left in a mixed old/new state: consistent with the existing
/// "crash mid-rotation" boundary, and a retry simply re-runs it (the idempotent surface = envelope
/// upsert + re-sealing, both judged against the primary store).
pub async fn rotate_begin(
    State(state): State<AppState>,
    // The device name does not take part in the CAS (the mutex covers the whole group, not a
    // single device); holding the Extension keeps the middleware shape consistent with the
    // other write endpoints (require_bearer has already authenticated).
    Extension(_device): Extension<DeviceName>,
    Json(request): Json<RotateBeginRequest>,
) -> Response {
    let result: Result<Option<u64>, String> = async {
        let mut tx = state.pool.begin().await.map_err(|e| e.to_string())?;
        // Read the current generation inside the transaction and CAS: increment only on a hit
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
        // Commit explicitly: dropping the transaction rolls it back, which would make the
        // mutual exclusion meaningless
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

/// PUT /sync/group-keys: upload/update a device's envelope (the authorized action = an existing
/// device seals it for the new device and uploads it; re-sealing during rotation = overwrite upsert).
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
