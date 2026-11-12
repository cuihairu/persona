//! Audit log 仓储：`SECURITY_SENSITIVE_AUDIT_ACTIONS`、`AuditLogRepository`、
//! `Repository<AuditLog>` 与 `AuditLogStatistics`。原 repository.rs 拆分
//! （LAY-017）：audit 段原样迁出（含统计类型）。

use super::Repository;
use crate::models::{AuditAction, AuditLog, ResourceType};
use crate::storage::Database;
use crate::{PersonaError, Result};
use async_trait::async_trait;
use sqlx::AssertSqlSafe;
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

/// 安全敏感的审计动作列表（与 `AuditLogRepository::find_security_sensitive` 保持一致，
/// 供服务层做内存过滤）。
pub const SECURITY_SENSITIVE_AUDIT_ACTIONS: [&str; 9] = [
    "login",
    "login_failed",
    "password_change",
    "credential_decrypted",
    "credential_exported",
    "unauthorized_access",
    "brute_force_detected",
    "suspicious_activity",
    "data_exfiltration",
];

/// Audit log repository for security monitoring
#[derive(Clone)]
pub struct AuditLogRepository {
    db: Database,
}

impl AuditLogRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Detach audit logs from an identity before deleting the identity.
    ///
    /// SQLite enforces the `audit_logs.identity_id -> identities.id` foreign key, and we want to
    /// keep audit records even after an identity is removed.
    pub async fn clear_identity_reference(&self, identity_id: &Uuid) -> Result<u64> {
        let res = sqlx::query("UPDATE audit_logs SET identity_id = NULL WHERE identity_id = ?")
            .bind(identity_id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(res.rows_affected())
    }

    /// Detach audit logs from a credential before deleting the credential.
    pub async fn clear_credential_reference(&self, credential_id: &Uuid) -> Result<u64> {
        let res = sqlx::query("UPDATE audit_logs SET credential_id = NULL WHERE credential_id = ?")
            .bind(credential_id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(res.rows_affected())
    }

    /// Find audit logs by user ID
    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find audit logs by identity ID
    pub async fn find_by_identity(&self, identity_id: &Uuid) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE identity_id = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(identity_id.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find audit logs by action type
    pub async fn find_by_action(&self, action: &AuditAction) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE action = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(action.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find failed operations
    pub async fn find_failures(&self) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE success = 0 ORDER BY timestamp DESC
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find security-sensitive operations
    pub async fn find_security_sensitive(&self) -> Result<Vec<AuditLog>> {
        let security_actions = SECURITY_SENSITIVE_AUDIT_ACTIONS;

        let placeholders = security_actions
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE action IN ({}) ORDER BY timestamp DESC
            "#,
            placeholders
        );

        let mut query_builder = sqlx::query(AssertSqlSafe(query.as_str()));
        for action in &security_actions {
            query_builder = query_builder.bind(action);
        }

        let rows = query_builder
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find logs within time range
    pub async fn find_by_time_range(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC
            "#,
        )
        .bind(start.to_rfc3339())
        .bind(end.to_rfc3339())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Search logs by IP address
    pub async fn find_by_ip(&self, ip_address: &str) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE ip_address = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(ip_address)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Get log statistics
    pub async fn get_statistics(&self) -> Result<AuditLogStatistics> {
        // Total logs count
        let total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        // Failed operations count
        let failed_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE success = 0")
                .fetch_one(self.db.pool())
                .await
                .map_err(|e| PersonaError::Database(e.to_string()))?;

        // Recent login attempts (last 24 hours)
        let yesterday = chrono::Utc::now() - chrono::Duration::hours(24);
        let recent_logins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action IN ('login', 'login_failed') AND timestamp >= ?"
        )
        .bind(yesterday.to_rfc3339())
        .fetch_one(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        // Unique users (last 7 days)
        let last_week = chrono::Utc::now() - chrono::Duration::days(7);
        let active_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT user_id) FROM audit_logs WHERE timestamp >= ? AND user_id IS NOT NULL"
        )
        .bind(last_week.to_rfc3339())
        .fetch_one(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(AuditLogStatistics {
            total_logs: total_count as u64,
            failed_operations: failed_count as u64,
            recent_login_attempts: recent_logins as u64,
            active_users_last_week: active_users as u64,
        })
    }

    /// Clean up old logs (retain logs for specified days)
    pub async fn cleanup_old_logs(&self, retain_days: u32) -> Result<u64> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(retain_days as i64);
        let result = sqlx::query("DELETE FROM audit_logs WHERE timestamp < ?")
            .bind(cutoff_date.to_rfc3339())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Convert database row to AuditLog
    fn row_to_audit_log(&self, row: sqlx::sqlite::SqliteRow) -> Result<AuditLog> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;

        let action_str: String = row.get("action");
        let action = action_str
            .parse::<AuditAction>()
            .map_err(|e| PersonaError::Database(format!("Invalid action: {}", e)))?;

        let resource_type_str: String = row.get("resource_type");
        let resource_type = resource_type_str
            .parse::<ResourceType>()
            .map_err(|e| PersonaError::Database(format!("Invalid resource type: {}", e)))?;

        let metadata_json: String = row.get("metadata");
        let metadata: HashMap<String, String> = serde_json::from_str(&metadata_json)
            .map_err(|e| PersonaError::Database(format!("Invalid metadata JSON: {}", e)))?;

        let timestamp_str: String = row.get("timestamp");
        let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
            .map_err(|e| PersonaError::Database(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&chrono::Utc);

        // Handle optional fields
        let user_id: Option<String> = row.get("user_id");

        let identity_id: Option<Uuid> = row
            .get::<Option<String>, _>("identity_id")
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| PersonaError::Database(format!("Invalid identity UUID: {}", e)))?;

        let credential_id: Option<Uuid> = row
            .get::<Option<String>, _>("credential_id")
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| PersonaError::Database(format!("Invalid credential UUID: {}", e)))?;

        Ok(AuditLog {
            id,
            user_id,
            identity_id,
            credential_id,
            session_id: row.get("session_id"),
            action,
            resource_type,
            resource_id: row.get("resource_id"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            success: row.get("success"),
            error_message: row.get("error_message"),
            metadata,
            timestamp,
        })
    }
}

#[async_trait]
impl Repository<AuditLog> for AuditLogRepository {
    async fn create(&self, log: &AuditLog) -> Result<AuditLog> {
        let metadata_json = serde_json::to_string(&log.metadata)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize metadata: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id, user_id, identity_id, credential_id, session_id, action,
                resource_type, resource_id, ip_address, user_agent, success,
                error_message, metadata, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(log.id.to_string())
        .bind(&log.user_id)
        .bind(log.identity_id.map(|id| id.to_string()))
        .bind(log.credential_id.map(|id| id.to_string()))
        .bind(&log.session_id)
        .bind(log.action.to_string())
        .bind(log.resource_type.to_string())
        .bind(&log.resource_id)
        .bind(&log.ip_address)
        .bind(&log.user_agent)
        .bind(log.success)
        .bind(&log.error_message)
        .bind(&metadata_json)
        .bind(log.timestamp.to_rfc3339())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(log.clone())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<AuditLog>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE id = ?
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.row_to_audit_log(row)?)),
            None => Ok(None),
        }
    }

    async fn find_all(&self) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs ORDER BY timestamp DESC LIMIT 1000
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    async fn update(&self, log: &AuditLog) -> Result<AuditLog> {
        // 审计日志通常不允许更新，为了数据完整性
        // 但这里提供实现以满足 Repository trait 要求
        let metadata_json = serde_json::to_string(&log.metadata)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize metadata: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE audit_logs SET
                user_id = ?, identity_id = ?, credential_id = ?, action = ?,
                resource_type = ?, resource_id = ?, ip_address = ?, user_agent = ?,
                success = ?, error_message = ?, metadata = ?, timestamp = ?
            WHERE id = ?
            "#,
        )
        .bind(&log.user_id)
        .bind(log.identity_id.map(|id| id.to_string()))
        .bind(log.credential_id.map(|id| id.to_string()))
        .bind(log.action.to_string())
        .bind(log.resource_type.to_string())
        .bind(&log.resource_id)
        .bind(&log.ip_address)
        .bind(&log.user_agent)
        .bind(log.success)
        .bind(&log.error_message)
        .bind(&metadata_json)
        .bind(log.timestamp.to_rfc3339())
        .bind(log.id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(log.clone())
    }

    async fn delete(&self, id: &Uuid) -> Result<bool> {
        // 审计日志通常不允许删除，为了数据完整性
        // 但这里提供实现以满足 Repository trait 要求
        let result = sqlx::query("DELETE FROM audit_logs WHERE id = ?")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}

/// Audit log statistics
#[derive(Debug, Clone)]
pub struct AuditLogStatistics {
    pub total_logs: u64,
    pub failed_operations: u64,
    pub recent_login_attempts: u64,
    pub active_users_last_week: u64,
}
