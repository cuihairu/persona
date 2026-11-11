use super::*;

// ---- Account Registration ----

#[derive(Deserialize)]
pub struct RegisterAccountRequest {
    /// Username (email or handle), unique
    username: String,
    /// Optional display name
    display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterAccountResponse {
    pub account_id: String,
    pub username: String,
    pub display_name: Option<String>,
}

/// POST /api/v1/accounts/register
/// Creates a new account. No auth required (public registration).
pub async fn register_account(
    State(state): State<AppState>,
    Json(req): Json<RegisterAccountRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let username = req.username.trim().to_ascii_lowercase();
    if username.is_empty() || username.len() > 256 {
        return Err(ApiError::validation(
            "invalid username",
            vec![ErrorItem::batch("username", "must be 1..=256 bytes")],
        ));
    }
    let display_name = req
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let account_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "INSERT INTO accounts (id, username, display_name, created_at, updated_at, status, version)
         VALUES (?, ?, ?, ?, ?, 'active', 1)",
    )
    .bind(&account_id)
    .bind(&username)
    .bind(&display_name)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(RegisterAccountResponse {
                account_id,
                username,
                display_name: display_name.clone(),
            }),
        )),
        Err(e) => {
            if format!("{e}").contains("UNIQUE") {
                Err(ApiError::conflict("username already exists"))
            } else {
                Err(ApiError::internal(e))
            }
        }
    }
}

// ---- Account Login (Passkey) ----
