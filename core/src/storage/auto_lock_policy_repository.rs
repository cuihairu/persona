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
                metadata, is_active, is_default, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(policy.id.to_string())
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(policy.security_level.to_string().to_lowercase())
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
        .bind(policy.is_default)
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
                background_check_interval_secs = ?, metadata = ?, is_active = ?,
                is_default = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(policy.security_level.to_string().to_lowercase())
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
        .bind(policy.is_default)
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
        .bind(level.to_string().to_lowercase())
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
            is_default: row.get("is_default"),
            created_at,
            updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auto_lock_policy::AutoLockSecurityLevel;

    async fn setup() -> (Arc<Database>, AutoLockPolicyRepository) {
        let db = Database::in_memory().await.expect("in-memory database");
        db.migrate().await.expect("migrations");
        let db = Arc::new(db);
        let repo = AutoLockPolicyRepository::new(db.clone());
        (db, repo)
    }

    fn make_policy(name: &str, level: AutoLockSecurityLevel) -> AutoLockPolicy {
        AutoLockPolicy::new(name.to_string(), level, 600)
    }

    #[tokio::test]
    async fn create_round_trips_all_fields() {
        let (_db, repo) = setup().await;

        let mut policy = make_policy("Custom High Policy", AutoLockSecurityLevel::High);
        policy.description = Some("desc".to_string());
        policy.metadata.tags = vec!["tag1".to_string()];
        policy
            .metadata
            .custom_settings
            .insert("k".to_string(), "v".to_string());
        policy.metadata.version = 3;

        let created = repo.create(&policy).await.unwrap();
        assert_eq!(created.id, policy.id);
        assert_eq!(created.name, "Custom High Policy");
        assert_eq!(created.description.as_deref(), Some("desc"));
        assert_eq!(created.security_level, AutoLockSecurityLevel::High);
        assert_eq!(created.inactivity_timeout_secs, 600);
        assert_eq!(created.absolute_timeout_secs, 1800);
        assert_eq!(created.sensitive_operation_timeout_secs, 180);
        assert_eq!(created.max_concurrent_sessions, 3);
        assert!(created.enable_warnings);
        assert_eq!(created.warning_time_secs, 30);
        assert!(created.force_lock_sensitive);
        assert_eq!(created.activity_grace_period_secs, 5);
        assert_eq!(created.background_check_interval_secs, 30);
        assert_eq!(created.metadata.tags, vec!["tag1".to_string()]);
        assert_eq!(
            created
                .metadata
                .custom_settings
                .get("k")
                .map(String::as_str),
            Some("v")
        );
        assert_eq!(created.metadata.version, 3);
        assert!(created.is_active);

        let fetched = repo.find_by_id(&policy.id).await.unwrap().unwrap();
        assert_eq!(fetched, created);
    }

    #[tokio::test]
    async fn find_by_id_returns_none_for_unknown() {
        let (_db, repo) = setup().await;
        assert!(repo.find_by_id(&Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_persists_changes() {
        let (_db, repo) = setup().await;
        let policy = make_policy("Before Update", AutoLockSecurityLevel::Medium);
        repo.create(&policy).await.unwrap();

        let mut updated = policy.clone();
        updated.name = "After Update".to_string();
        updated.description = Some("new desc".to_string());
        updated.security_level = AutoLockSecurityLevel::Maximum;
        updated.inactivity_timeout_secs = 120;
        updated.enable_warnings = false;
        updated.is_active = false;

        let result = repo.update(&updated).await.unwrap();
        assert_eq!(result.name, "After Update");
        assert_eq!(result.security_level, AutoLockSecurityLevel::Maximum);
        assert_eq!(result.inactivity_timeout_secs, 120);
        assert!(!result.enable_warnings);
        assert!(!result.is_active);

        let fetched = repo.find_by_id(&policy.id).await.unwrap().unwrap();
        assert_eq!(fetched, result);
    }

    #[tokio::test]
    async fn update_missing_policy_is_database_error() {
        let (_db, repo) = setup().await;
        let ghost = make_policy("Ghost", AutoLockSecurityLevel::Low);
        let err = repo
            .update(&ghost)
            .await
            .expect_err("missing row must fail");
        assert!(matches!(
            err.downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
    }

    #[tokio::test]
    async fn find_all_lists_seeded_and_created_policies() {
        let (_db, repo) = setup().await;
        // Migration 008 seeds four built-in policies.
        let seeded = repo.find_all().await.unwrap();
        assert_eq!(seeded.len(), 4);

        let policy = make_policy("Extra Policy", AutoLockSecurityLevel::Low);
        repo.create(&policy).await.unwrap();
        assert_eq!(repo.find_all().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn delete_reports_whether_a_row_was_removed() {
        let (_db, repo) = setup().await;
        let policy = make_policy("Doomed Policy", AutoLockSecurityLevel::Low);
        repo.create(&policy).await.unwrap();

        assert!(repo.delete(&policy.id).await.unwrap());
        assert!(!repo.delete(&policy.id).await.unwrap());
        assert!(repo.find_by_id(&policy.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn find_active_excludes_inactive_policies() {
        let (_db, repo) = setup().await;
        let active = make_policy("Active Custom", AutoLockSecurityLevel::Low);
        repo.create(&active).await.unwrap();

        let mut inactive = make_policy("Inactive Custom", AutoLockSecurityLevel::Medium);
        inactive.is_active = false;
        repo.create(&inactive).await.unwrap();

        let names: Vec<String> = repo
            .find_active()
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert!(names.contains(&"Active Custom".to_string()));
        assert!(!names.contains(&"Inactive Custom".to_string()));
        // Seeded policies are active.
        assert_eq!(names.len(), 5);
    }

    #[tokio::test]
    async fn find_by_security_level_matches_lowercase_storage() {
        let (_db, repo) = setup().await;
        let custom = make_policy("Another High", AutoLockSecurityLevel::High);
        repo.create(&custom).await.unwrap();

        let high = repo
            .find_by_security_level(&AutoLockSecurityLevel::High)
            .await
            .unwrap();
        assert_eq!(high.len(), 2); // seeded "High Security Policy" + custom
        assert!(high.iter().all(|p| p.is_active));

        let none = repo
            .find_by_security_level(&AutoLockSecurityLevel::Low)
            .await
            .unwrap()
            .into_iter()
            .filter(|p| p.name == "Another High")
            .count();
        assert_eq!(none, 0);
    }

    #[tokio::test]
    async fn find_by_name_like_filters_by_substring_and_active_state() {
        let (_db, repo) = setup().await;
        let matches = repo.find_by_name_like("Security").await.unwrap();
        assert_eq!(matches.len(), 4); // all seeded policies end in "Security Policy"

        let medium = repo.find_by_name_like("Medium").await.unwrap();
        assert_eq!(medium.len(), 1);
        assert_eq!(medium[0].name, "Medium Security Policy");

        let mut hidden = make_policy("Hidden Substring Policy", AutoLockSecurityLevel::Low);
        hidden.is_active = false;
        repo.create(&hidden).await.unwrap();
        assert!(repo.find_by_name_like("Hidden").await.unwrap().is_empty());

        assert!(repo
            .find_by_name_like("no-such-name")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn get_statistics_returns_placeholder_defaults() {
        let (_db, repo) = setup().await;
        let policy = make_policy("Stats Policy", AutoLockSecurityLevel::Medium);
        repo.create(&policy).await.unwrap();

        let stats = repo.get_statistics(&policy.id).await.unwrap().unwrap();
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.assigned_users, 0);
        assert_eq!(stats.avg_session_duration_secs, 0);
        assert_eq!(stats.recent_lock_events, 0);
        assert_eq!(stats.compliance_score, 0);
    }

    #[tokio::test]
    async fn user_assignment_upsert_and_remove() {
        let (_db, repo) = setup().await;
        let first = make_policy("First Assigned", AutoLockSecurityLevel::Low);
        let second = make_policy("Second Assigned", AutoLockSecurityLevel::High);
        repo.create(&first).await.unwrap();
        repo.create(&second).await.unwrap();

        let user_id = Uuid::new_v4();
        assert!(repo.get_user_policy(&user_id).await.unwrap().is_none());

        repo.assign_to_user(&first.id, &user_id).await.unwrap();
        let assigned = repo.get_user_policy(&user_id).await.unwrap().unwrap();
        assert_eq!(assigned.id, first.id);

        // Upsert: assigning again replaces the previous mapping.
        repo.assign_to_user(&second.id, &user_id).await.unwrap();
        let reassigned = repo.get_user_policy(&user_id).await.unwrap().unwrap();
        assert_eq!(reassigned.id, second.id);

        repo.remove_user_assignment(&user_id).await.unwrap();
        assert!(repo.get_user_policy(&user_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_user_policy_ignores_inactive_policies() {
        let (_db, repo) = setup().await;
        let mut inactive = make_policy("Inactive Assigned", AutoLockSecurityLevel::Low);
        inactive.is_active = false;
        repo.create(&inactive).await.unwrap();

        let user_id = Uuid::new_v4();
        repo.assign_to_user(&inactive.id, &user_id).await.unwrap();
        assert!(repo.get_user_policy(&user_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn default_policy_flow_switches_between_policies() {
        let (_db, repo) = setup().await;
        // Migration seeds "Medium Security Policy" as the default.
        let initial = repo.get_default_policy().await.unwrap().unwrap();
        assert_eq!(initial.name, "Medium Security Policy");

        let replacement = make_policy("New Default", AutoLockSecurityLevel::Maximum);
        repo.create(&replacement).await.unwrap();
        repo.set_as_default(&replacement.id).await.unwrap();

        let now_default = repo.get_default_policy().await.unwrap().unwrap();
        assert_eq!(now_default.id, replacement.id);

        let old = repo.find_by_id(&initial.id).await.unwrap().unwrap();
        assert!(!old.is_default);
    }

    #[tokio::test]
    async fn get_default_policy_returns_none_when_no_default() {
        let (db, repo) = setup().await;
        sqlx::query("UPDATE auto_lock_policies SET is_default = 0")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(repo.get_default_policy().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn row_to_policy_rejects_corrupt_rows() {
        let (db, repo) = setup().await;

        // PRAGMA state is per-connection: pin one connection for the raw inserts.
        let mut conn = db.pool().acquire().await.unwrap();

        // Corrupt UUID.
        sqlx::query(
            r#"INSERT INTO auto_lock_policies (id, name, security_level, inactivity_timeout_secs,
               absolute_timeout_secs, sensitive_operation_timeout_secs, max_concurrent_sessions,
               warning_time_secs, metadata, created_at, updated_at)
               VALUES ('not-a-uuid', 'Bad UUID', 'low', 1, 1, 1, 1, 0, '{}',
                       '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')"#,
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        // Bypass CHECK constraints for the remaining corrupt rows.
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *conn)
            .await
            .unwrap();

        // Corrupt metadata JSON.
        sqlx::query(
            r#"INSERT INTO auto_lock_policies (id, name, security_level, inactivity_timeout_secs,
               absolute_timeout_secs, sensitive_operation_timeout_secs, max_concurrent_sessions,
               warning_time_secs, metadata, created_at, updated_at)
               VALUES ('11111111-2222-3333-4444-555555555555', 'Bad Metadata', 'low', 1, 1, 1, 1,
                       0, 'not-json', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')"#,
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        // Corrupt security level.
        sqlx::query(
            r#"INSERT INTO auto_lock_policies (id, name, security_level, inactivity_timeout_secs,
               absolute_timeout_secs, sensitive_operation_timeout_secs, max_concurrent_sessions,
               warning_time_secs, metadata, created_at, updated_at)
               VALUES ('66666666-7777-8888-9999-000000000000', 'Bad Level', 'ultra', 1, 1, 1, 1,
                       0, '{}', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')"#,
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        // Corrupt created_at.
        sqlx::query(
            r#"INSERT INTO auto_lock_policies (id, name, security_level, inactivity_timeout_secs,
               absolute_timeout_secs, sensitive_operation_timeout_secs, max_concurrent_sessions,
               warning_time_secs, metadata, created_at, updated_at)
               VALUES ('aaaa0000-0000-0000-0000-000000000000', 'Bad Date', 'low', 1, 1, 1, 1,
                       0, '{}', 'not-a-date', '2024-01-01T00:00:00Z')"#,
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        sqlx::query("PRAGMA ignore_check_constraints = OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);

        // A full scan hits the bad-UUID row first.
        let bad_uuid = repo.find_all().await.unwrap_err();
        assert!(matches!(
            bad_uuid.downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));

        let bad_metadata = repo
            .find_by_id(&Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            bad_metadata.downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));

        let bad_level = repo
            .find_by_id(&Uuid::parse_str("66666666-7777-8888-9999-000000000000").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            bad_level.downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));

        let bad_date = repo
            .find_by_id(&Uuid::parse_str("aaaa0000-0000-0000-0000-000000000000").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            bad_date.downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
    }

    #[tokio::test]
    async fn dropped_tables_surface_database_errors() {
        let (db, repo) = setup().await;
        let policy = make_policy("Ghost Policy", AutoLockSecurityLevel::Low);

        sqlx::query("DROP TABLE auto_lock_policies")
            .execute(db.pool())
            .await
            .unwrap();

        // Every statement now fails at the SQL level; each query must map the
        // driver error into PersonaError::Database. Transactions still begin
        // fine, so the write paths fail on their INSERT/UPDATE statements.
        assert!(matches!(
            repo.create(&policy)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.update(&policy)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.find_by_id(&policy.id)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.find_all()
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.delete(&policy.id)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.find_active()
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.find_by_security_level(&AutoLockSecurityLevel::Low)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.find_by_name_like("ghost")
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.get_user_policy(&policy.id)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.get_default_policy()
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.set_as_default(&policy.id)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));

        sqlx::query("DROP TABLE user_auto_lock_policies")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(matches!(
            repo.assign_to_user(&policy.id, &Uuid::new_v4())
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
        assert!(matches!(
            repo.remove_user_assignment(&policy.id)
                .await
                .unwrap_err()
                .downcast_ref::<PersonaError>(),
            Some(PersonaError::Database(_))
        ));
    }
}
