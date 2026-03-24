use crate::auth::authentication::{AuthFactor, UserAuth};
use crate::storage::Database;
use crate::{PersonaError, Result};
use sqlx::Row;
use std::time::SystemTime;
use uuid::Uuid;

/// Repository for user authentication records (single-user MVP)
pub struct UserAuthRepository {
    db: Database,
}

impl UserAuthRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Return true if any user exists
    pub async fn has_any(&self) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(1) as cnt FROM user_auth")
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        let cnt: i64 = row.get("cnt");
        Ok(cnt > 0)
    }

    /// Get the first (and only) user for MVP
    pub async fn get_first(&self) -> Result<Option<UserAuth>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, master_password_hash, master_key_salt, enabled_factors,
                   failed_attempts, locked_until, last_auth, password_change_required,
                   created_at, updated_at
            FROM user_auth LIMIT 1
            "#,
        )
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.row_to_user_auth(row)?)),
            None => Ok(None),
        }
    }

    /// Get by id
    pub async fn get_by_id(&self, user_id: &Uuid) -> Result<Option<UserAuth>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, master_password_hash, master_key_salt, enabled_factors,
                   failed_attempts, locked_until, last_auth, password_change_required,
                   created_at, updated_at
            FROM user_auth WHERE user_id = ?
            "#,
        )
        .bind(user_id.to_string())
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.row_to_user_auth(row)?)),
            None => Ok(None),
        }
    }

    /// Create a new user auth record
    pub async fn create(&self, auth: &UserAuth) -> Result<()> {
        let enabled_factors = serde_json::to_string(&auth.enabled_factors)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize factors: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO user_auth (
                user_id, master_password_hash, master_key_salt, enabled_factors,
                failed_attempts, locked_until, last_auth, password_change_required,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(auth.user_id.to_string())
        .bind(&auth.master_password_hash)
        .bind(&auth.master_key_salt)
        .bind(enabled_factors)
        .bind(auth.failed_attempts as i64)
        .bind(system_time_to_rfc3339(auth.locked_until))
        .bind(system_time_to_rfc3339(auth.last_auth))
        .bind(auth.password_change_required)
        .bind(system_time_to_rfc3339(Some(auth.created_at)).unwrap())
        .bind(system_time_to_rfc3339(Some(auth.updated_at)).unwrap())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update an existing user auth record
    pub async fn update(&self, auth: &UserAuth) -> Result<()> {
        let enabled_factors = serde_json::to_string(&auth.enabled_factors)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize factors: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE user_auth SET
                master_password_hash = ?,
                master_key_salt = ?,
                enabled_factors = ?,
                failed_attempts = ?,
                locked_until = ?,
                last_auth = ?,
                password_change_required = ?,
                updated_at = ?
            WHERE user_id = ?
            "#,
        )
        .bind(&auth.master_password_hash)
        .bind(&auth.master_key_salt)
        .bind(enabled_factors)
        .bind(auth.failed_attempts as i64)
        .bind(system_time_to_rfc3339(auth.locked_until))
        .bind(system_time_to_rfc3339(auth.last_auth))
        .bind(auth.password_change_required)
        .bind(system_time_to_rfc3339(Some(auth.updated_at)).unwrap())
        .bind(auth.user_id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(())
    }

    fn row_to_user_auth(&self, row: sqlx::sqlite::SqliteRow) -> Result<UserAuth> {
        let user_id_str: String = row.get("user_id");
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;

        let mut user = UserAuth::new(user_id);
        user.master_password_hash = row.get("master_password_hash");
        user.master_key_salt = row.get("master_key_salt");

        // Deserialize enabled factors
        let factors_json: String = row.get("enabled_factors");
        let factors: Vec<AuthFactor> = serde_json::from_str(&factors_json).unwrap_or_default();
        user.enabled_factors = factors;

        let failed_attempts: i64 = row.get("failed_attempts");
        user.failed_attempts = failed_attempts as u32;

        user.locked_until = rfc3339_to_system_time(row.get("locked_until"));
        user.last_auth = rfc3339_to_system_time(row.get("last_auth"));
        user.password_change_required = row.get("password_change_required");
        // created_at/updated_at are informational; keep defaults
        Ok(user)
    }
}

fn system_time_to_rfc3339(time: Option<SystemTime>) -> Option<String> {
    time.map(|t| {
        let datetime: chrono::DateTime<chrono::Utc> = t.into();
        datetime.to_rfc3339()
    })
}

fn rfc3339_to_system_time(opt: Option<String>) -> Option<SystemTime> {
    opt.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authentication::{AuthFactor, BiometricType, UserAuth};

    #[tokio::test]
    async fn user_auth_repository_create_get_update_roundtrip() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let repo = UserAuthRepository::new(db.clone());
        assert!(!repo.has_any().await.unwrap());
        assert!(repo.get_first().await.unwrap().is_none());

        let user_id = Uuid::new_v4();
        let mut auth = UserAuth::new(user_id);
        auth.master_password_hash = Some("hash".to_string());
        auth.master_key_salt = Some(hex::encode([1u8; 32]));
        auth.enabled_factors = vec![
            AuthFactor::MasterPassword,
            AuthFactor::Biometric(BiometricType::TouchId),
        ];
        auth.failed_attempts = 2;
        auth.password_change_required = true;
        auth.locked_until = Some(SystemTime::now());
        auth.last_auth = Some(SystemTime::now());

        repo.create(&auth).await.unwrap();

        assert!(repo.has_any().await.unwrap());
        let fetched_first = repo.get_first().await.unwrap().unwrap();
        assert_eq!(fetched_first.user_id, user_id);
        assert_eq!(fetched_first.master_password_hash.as_deref(), Some("hash"));
        assert_eq!(fetched_first.master_key_salt, auth.master_key_salt);
        assert_eq!(fetched_first.failed_attempts, 2);
        assert!(fetched_first.password_change_required);
        assert!(fetched_first.locked_until.is_some());
        assert!(fetched_first.last_auth.is_some());
        assert!(fetched_first
            .enabled_factors
            .contains(&AuthFactor::MasterPassword));

        let fetched = repo.get_by_id(&user_id).await.unwrap().unwrap();
        assert_eq!(fetched.user_id, user_id);

        let mut updated = auth.clone();
        updated.failed_attempts = 9;
        updated.password_change_required = false;
        updated.enabled_factors = vec![AuthFactor::MasterPassword];
        updated.updated_at = SystemTime::now();
        repo.update(&updated).await.unwrap();

        let fetched_after_update = repo.get_by_id(&user_id).await.unwrap().unwrap();
        assert_eq!(fetched_after_update.failed_attempts, 9);
        assert!(!fetched_after_update.password_change_required);
        assert_eq!(fetched_after_update.enabled_factors.len(), 1);
        assert_eq!(
            fetched_after_update.enabled_factors[0],
            AuthFactor::MasterPassword
        );
    }
}
