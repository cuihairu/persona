use super::*;

#[derive(Deserialize)]
pub struct AuthorizeDeviceRequest {
    pub device_id: String,  // sync_devices.id
    pub public_key: String, // base64, 32 bytes X25519
}

#[derive(Serialize)]
pub struct AuthorizeDeviceResponse {
    pub id: String,
    pub status: String,
}

/// POST /api/v1/accounts/:account_id/devices
/// Authorizes a sync device for this account (requires auth).
pub async fn authorize_device(
    State(state): State<AppState>,
    Extension(device): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
    Json(req): Json<AuthorizeDeviceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists
    let _ = sqlx::query("SELECT id FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;

    // Verify sync device exists
    let sync_device =
        sqlx::query("SELECT id, device_name, public_key FROM sync_devices WHERE id = ?")
            .bind(&req.device_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(|| {
                ApiError::validation(
                    "device not found",
                    vec![ErrorItem::batch("device_id", "not enrolled")],
                )
            })?;

    let device_name: String = sync_device.get("device_name");
    let public_key: Vec<u8> = sync_device.get("public_key");

    // Verify public key matches
    let provided_key = B64.decode(&req.public_key).map_err(|_| {
        ApiError::validation(
            "invalid public_key",
            vec![ErrorItem::batch("public_key", "malformed base64")],
        )
    })?;
    if provided_key != public_key {
        return Err(ApiError::validation(
            "public key mismatch",
            vec![ErrorItem::batch(
                "public_key",
                "does not match enrolled device",
            )],
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO account_devices (id, account_id, device_id, device_name, public_key, status, authorized_by, authorized_at, created_at)
         VALUES (?, ?, ?, ?, ?, 'authorized', ?, ?, ?)
         ON CONFLICT(account_id, device_id) DO UPDATE SET
             status = 'authorized',
             authorized_by = excluded.authorized_by,
             authorized_at = excluded.authorized_at,
             device_name = excluded.device_name,
             public_key = excluded.public_key",
    )
    .bind(&id)
    .bind(&account_id)
    .bind(&req.device_id)
    .bind(&device_name)
    .bind(&public_key)
    .bind(&device.0)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(AuthorizeDeviceResponse {
            id,
            status: "authorized".to_string(),
        }),
    ))
}

/// GET /api/v1/accounts/:account_id/devices
/// Lists all authorized devices for this account.
pub async fn list_account_devices(
    State(state): State<AppState>,
    Extension(_device): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let rows = sqlx::query(
        "SELECT id, device_id, device_name, public_key, status, authorized_by, authorized_at, revoked_at, revoked_by, created_at
         FROM account_devices WHERE account_id = ? ORDER BY created_at",
    )
    .bind(&account_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    #[derive(Serialize)]
    struct AccountDeviceInfo {
        id: String,
        device_id: String,
        device_name: String,
        public_key: String,
        status: String,
        authorized_by: Option<String>,
        authorized_at: Option<String>,
        revoked_at: Option<String>,
        revoked_by: Option<String>,
        created_at: String,
    }

    let devices: Vec<AccountDeviceInfo> = rows
        .iter()
        .map(|row| AccountDeviceInfo {
            id: row.get("id"),
            device_id: row.get("device_id"),
            device_name: row.get("device_name"),
            public_key: B64.encode(row.get::<Vec<u8>, _>("public_key")),
            status: row.get("status"),
            authorized_by: row.get("authorized_by"),
            authorized_at: row.get("authorized_at"),
            revoked_at: row.get("revoked_at"),
            revoked_by: row.get("revoked_by"),
            created_at: row.get("created_at"),
        })
        .collect();

    Ok(Json(serde_json::json!({ "devices": devices })))
}

/// DELETE /api/v1/accounts/:account_id/devices/:device_id
/// Revokes a device from this account.
pub async fn revoke_account_device(
    State(state): State<AppState>,
    Extension(device): Extension<crate::auth::DeviceName>,
    Path((account_id, device_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE account_devices SET status = 'revoked', revoked_by = ?, revoked_at = ?
         WHERE account_id = ? AND device_id = ? AND status = 'authorized'",
    )
    .bind(&device.0)
    .bind(&now)
    .bind(&account_id)
    .bind(&device_id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- Account Login (Session) ----
