use crate::models::auto_lock_policy::{AutoLockPolicy, PolicyStatistics};
use crate::storage::Database;
use crate::{PersonaError, Result};
use serde_json;
use sqlx::{sqlite::SqliteRow, Row};
use std::sync::Arc;
use uuid::Uuid;

/// Repository for AutoLockPolicy persistence (SQLite implementation)
#[derive(Clone)]
pub struct AutoLockPolicyRepository {
    db: Arc<Database>,
}

impl AutoLockPolicyRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn create(&self, policy: &AutoLockPolicy) -> Result<AutoLockPolicy> {
        let mut tx = self.db.begin_transaction().await?;

        sqlx::query(
            r#"
            INSERT INTO auto_lock_policies (
                id, name, description, security_level,
                inactivity_timeout_secs, absolute_timeout_secs,
                sensitive_operation_timeout_secs, max_concurrent_sessions,
                enable_warnings, warning_time_secs, force_lock_sensitive,
                activity_grace_period_secs, background_check_interval_secs,
                metadata, is_active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(policy.id.to_string())
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(policy.security_level.to_string())
        .bind(policy.inactivity_timeout_secs as i64)
        .bind(policy.absolute_timeout_secs as i64)
        .bind(policy.sensitive_operation_timeout_secs as i64)
        .bind(policy.max_concurrent_sessions as i64)
        .bind(policy.enable_warnings)
        .bind(policy.warning_time_secs as i64)
        .bind(policy.force_lock_sensitive)
        .bind(policy.activity_grace_period_secs as i64)
        .bind(policy.background_check_interval_secs as i64)
        .bind(serde_json::to_string(&policy.metadata)?)
        .bind(policy.is_active)
        .bind(policy.created_at.to_rfc3339())
        .bind(policy.updated_at.to_rfc3339())
        .execute(&mut *tx)
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to create auto-lock policy: {}", e)))?;

        tx.commit().await.map_err(|e| {
            PersonaError::Database(format!("Failed to commit policy creation: {}", e))
        })?;

        Ok(self
            .find_by_id(&policy.id)
            .await?
            .ok_or_else(|| PersonaError::Database("Created policy not found".into()))?)
    }

    pub async fn update(&self, policy: &AutoLockPolicy) -> Result<AutoLockPolicy> {
        let updated_at = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE auto_lock_policies SET
                name = ?, description = ?, security_level = ?, inactivity_timeout_secs = ?,
                absolute_timeout_secs = ?, sensitive_operation_timeout_secs = ?,
                max_concurrent_sessions = ?, enable_warnings = ?, warning_time_secs = ?,
                force_lock_sensitive = ?, activity_grace_period_secs = ?,
                background_check_interval_secs = ?, metadata = ?, is_active = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(policy.security_level.to_string())
        .bind(policy.inactivity_timeout_secs as i64)
        .bind(policy.absolute_timeout_secs as i64)
        .bind(policy.sensitive_operation_timeout_secs as i64)
        .bind(policy.max_concurrent_sessions as i64)
        .bind(policy.enable_warnings)
        .bind(policy.warning_time_secs as i64)
        .bind(policy.force_lock_sensitive)
        .bind(policy.activity_grace_period_secs as i64)
        .bind(policy.background_check_interval_secs as i64)
        .bind(serde_json::to_string(&policy.metadata)?)
        .bind(policy.is_active)
        .bind(updated_at.to_rfc3339())
        .bind(policy.id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to update policy: {}", e)))?;

        Ok(self
            .find_by_id(&policy.id)
            .await?
            .ok_or_else(|| PersonaError::Database("Updated policy not found".into()))?)
    }

    pub async fn find_by_id(&self, id: &Uuid) -> Result<Option<AutoLockPolicy>> {
        let row = sqlx::query("SELECT * FROM auto_lock_policies WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to fetch policy: {}", e)))?;

        row.map(|row| self.row_to_policy(row)).transpose()
    }

    pub async fn find_all(&self) -> Result<Vec<AutoLockPolicy>> {
        let rows = sqlx::query("SELECT * FROM auto_lock_policies ORDER BY name")
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to fetch policies: {}", e)))?;

        rows.into_iter()
            .map(|row| self.row_to_policy(row))
            .collect()
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM auto_lock_policies WHERE id = ?")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to delete policy: {}", e)))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn find_active(&self) -> Result<Vec<AutoLockPolicy>> {
        let rows =
            sqlx::query("SELECT * FROM auto_lock_policies WHERE is_active = 1 ORDER BY name")
                .fetch_all(self.db.pool())
                .await
                .map_err(|e| PersonaError::Database(format!("Failed to fetch policies: {}", e)))?;

        rows.into_iter()
            .map(|row| self.row_to_policy(row))
            .collect()
    }

    pub async fn find_by_security_level(
        &self,
        level: &crate::models::auto_lock_policy::AutoLockSecurityLevel,
    ) -> Result<Vec<AutoLockPolicy>> {
        let rows = sqlx::query(
            "SELECT * FROM auto_lock_policies WHERE security_level = ? AND is_active = 1 ORDER BY name",
        )
        .bind(level.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to fetch policies: {}", e)))?;

        rows.into_iter()
            .map(|row| self.row_to_policy(row))
            .collect()
    }

    pub async fn find_by_name_like(&self, name_pattern: &str) -> Result<Vec<AutoLockPolicy>> {
        let like = format!("%{}%", name_pattern);
        let rows = sqlx::query(
            "SELECT * FROM auto_lock_policies WHERE name LIKE ? AND is_active = 1 ORDER BY name",
        )
        .bind(like)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to search policies: {}", e)))?;

        rows.into_iter()
            .map(|row| self.row_to_policy(row))
            .collect()
    }

    pub async fn get_statistics(&self, _policy_id: &Uuid) -> Result<Option<PolicyStatistics>> {
        // Placeholder implementation for SQLite (no join tables implemented yet)
        Ok(Some(PolicyStatistics::default()))
    }

    pub async fn assign_to_user(&self, policy_id: &Uuid, user_id: &Uuid) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO user_auto_lock_policies (user_id, policy_id, assigned_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                policy_id = excluded.policy_id,
                assigned_at = excluded.assigned_at
            "#,
        )
        .bind(user_id.to_string())
        .bind(policy_id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to assign policy to user: {}", e)))?;
        Ok(())
    }

    pub async fn get_user_policy(&self, user_id: &Uuid) -> Result<Option<AutoLockPolicy>> {
        let row = sqlx::query(
            r#"
            SELECT p.* FROM auto_lock_policies p
            INNER JOIN user_auto_lock_policies ulp ON p.id = ulp.policy_id
            WHERE ulp.user_id = ? AND p.is_active = 1
            "#,
        )
        .bind(user_id.to_string())
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to fetch user policy: {}", e)))?;

        row.map(|r| self.row_to_policy(r)).transpose()
    }

    pub async fn remove_user_assignment(&self, user_id: &Uuid) -> Result<()> {
        sqlx::query("DELETE FROM user_auto_lock_policies WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to remove assignment: {}", e)))?;
        Ok(())
    }

    pub async fn get_default_policy(&self) -> Result<Option<AutoLockPolicy>> {
        let row = sqlx::query(
            "SELECT * FROM auto_lock_policies WHERE is_default = 1 AND is_active = 1 LIMIT 1",
        )
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to fetch default policy: {}", e)))?;

        row.map(|r| self.row_to_policy(r)).transpose()
    }

    pub async fn set_as_default(&self, policy_id: &Uuid) -> Result<()> {
        let mut tx = self.db.begin_transaction().await?;

        sqlx::query("UPDATE auto_lock_policies SET is_default = 0")
            .execute(&mut *tx)
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to reset defaults: {}", e)))?;

        sqlx::query("UPDATE auto_lock_policies SET is_default = 1 WHERE id = ?")
            .bind(policy_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to set default policy: {}", e)))?;

        tx.commit().await.map_err(|e| {
            PersonaError::Database(format!("Failed to commit default policy change: {}", e))
        })?;
        Ok(())
    }

    fn row_to_policy(&self, row: SqliteRow) -> Result<AutoLockPolicy> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;
        let metadata_json: String = row.get("metadata");
        let metadata = serde_json::from_str(&metadata_json)
            .map_err(|e| PersonaError::Database(format!("Invalid metadata: {}", e)))?;

        let created_at_str: String = row.get("created_at");
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| PersonaError::Database(format!("Invalid created_at: {}", e)))?
            .with_timezone(&chrono::Utc);
        let updated_at_str: String = row.get("updated_at");
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| PersonaError::Database(format!("Invalid updated_at: {}", e)))?
            .with_timezone(&chrono::Utc);

        Ok(AutoLockPolicy {
            id,
            name: row.get("name"),
            description: row.get::<Option<String>, _>("description"),
            security_level: row
                .get::<String, _>("security_level")
                .parse()
                .map_err(|e| PersonaError::Database(format!("Invalid security level: {}", e)))?,
            inactivity_timeout_secs: row.get::<i64, _>("inactivity_timeout_secs") as u64,
            absolute_timeout_secs: row.get::<i64, _>("absolute_timeout_secs") as u64,
            sensitive_operation_timeout_secs: row.get::<i64, _>("sensitive_operation_timeout_secs")
                as u64,
            max_concurrent_sessions: row.get::<i64, _>("max_concurrent_sessions") as usize,
            enable_warnings: row.get("enable_warnings"),
            warning_time_secs: row.get::<i64, _>("warning_time_secs") as u64,
            force_lock_sensitive: row.get("force_lock_sensitive"),
            activity_grace_period_secs: row.get::<i64, _>("activity_grace_period_secs") as u64,
            background_check_interval_secs: row.get::<i64, _>("background_check_interval_secs")
                as u64,
            metadata,
            is_active: row.get("is_active"),
            created_at,
            updated_at,
        })
    }
}
