use super::*;

/// Generate recovery codes for an account
#[derive(Serialize)]
pub struct GenerateRecoveryCodesResponse {
    pub codes: Vec<String>,
}

/// POST /api/v1/accounts/:account_id/recovery-codes
/// Generates a new set of recovery codes (requires auth).
pub async fn generate_recovery_codes(
    State(state): State<AppState>,
    Extension(_device): Extension<crate::auth::DeviceName>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify account exists and user owns it (in real impl, check device authorization)
    let _ = sqlx::query("SELECT id FROM accounts WHERE id = ?")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;

    // Delete existing unused recovery codes
    sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = ? AND used_at IS NULL")
        .bind(&account_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;

    // Generate 8 recovery codes
    let mut codes = Vec::new();
    let now = Utc::now().to_rfc3339();
    for _ in 0..8 {
        let raw: [u8; 16] = rand::random();
        let code: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        codes.push(code.clone());

        // Hash with Argon2id using proper algorithm
        let hash = hash_recovery_code(&code)?;

        sqlx::query(
            "INSERT INTO account_recovery_codes (id, account_id, code_hash, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&hash)
        .bind(&now)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    }

    Ok(Json(GenerateRecoveryCodesResponse { codes }))
}

/// Hash a recovery code using Argon2id
fn hash_recovery_code(code: &str) -> Result<String, ApiError> {
    let hasher = PasswordHasher::new();
    hasher
        .hash_password(code)
        .map_err(|e| ApiError::internal(format!("Hashing failed: {}", e)))
}

/// Verify a recovery code
#[derive(Deserialize)]
pub struct VerifyRecoveryCodeRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyRecoveryCodeResponse {
    pub success: bool,
}

/// POST /api/v1/accounts/:account_id/recovery-codes/verify
/// Verifies and consumes a recovery code.
pub async fn verify_recovery_code(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(req): Json<VerifyRecoveryCodeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let code = req.code.trim().replace('-', "");
    if code.len() != 32 {
        return Err(ApiError::validation(
            "invalid code format",
            vec![ErrorItem::batch("code", "must be 32 hex chars")],
        ));
    }

    // Decode the hex code to bytes for verification
    let code_bytes = hex::decode(&code).map_err(|_| {
        ApiError::validation(
            "invalid code format",
            vec![ErrorItem::batch("code", "not valid hex")],
        )
    })?;

    // Find unused recovery codes for this account
    let rows = sqlx::query(
        "SELECT id, code_hash FROM account_recovery_codes WHERE account_id = ? AND used_at IS NULL",
    )
    .bind(&account_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    for row in rows {
        let code_id: String = row.get("id");
        let stored_hash: String = row.get("code_hash");

        // Verify the code against the stored hash
        // The hash format is: $argon2id$v=19$m=19456,t=2,p=1$salt$hash
        // We need to extract salt and hash, then verify
        let verified = verify_recovery_code_hash(&stored_hash, &code_bytes);

        if verified {
            // Mark as used
            let now = Utc::now().to_rfc3339();
            sqlx::query("UPDATE account_recovery_codes SET used_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&code_id)
                .execute(&state.pool)
                .await
                .map_err(ApiError::internal)?;

            return Ok(Json(VerifyRecoveryCodeResponse { success: true }));
        }
    }

    Ok(Json(VerifyRecoveryCodeResponse { success: false }))
}

/// Verify a recovery code against an Argon2id hash
fn verify_recovery_code_hash(hash: &str, code_bytes: &[u8]) -> bool {
    let code_hex = hex::encode(code_bytes);
    let hasher = PasswordHasher::new();
    hasher.verify_password(&code_hex, hash).unwrap_or(false)
}

// ---- Account Device Management ----
