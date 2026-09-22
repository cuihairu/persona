//! `connect_tokens` 表访问（CONNECT_AUTOMATION_DESIGN DR-2；迁移 015）。
//!
//! 只做行存取；token 生成/哈希/scope 判定在 [`crate::connect::token`]，
//! 解锁态与审计编排在 `PersonaService` 的 `connect_*` 方法。哈希列 UNIQUE，
//! 呈现值永不落库。

use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::connect::token::{fingerprint_from_hash, ConnectTokenRow, ConnectTokenScope};
use crate::storage::Database;
use crate::{PersonaError, PersonaResult};

pub struct ConnectTokenRepository {
    db: Database,
}

impl ConnectTokenRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn insert(&self, row: &ConnectTokenRow) -> PersonaResult<()> {
        let scope_json =
            serde_json::to_string(&row.scope).map_err(|e| PersonaError::Database(e.to_string()))?;
        sqlx::query(
            "INSERT INTO connect_tokens (id, label, hash, fingerprint, scope, created_at, last_used_at, revoked_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(row.id.to_string())
        .bind(&row.label)
        .bind(&row.hash)
        .bind(&row.fingerprint)
        .bind(&scope_json)
        .bind(row.created_at.to_rfc3339())
        .bind(row.last_used_at.map(|t| t.to_rfc3339()))
        .bind(row.revoked_at.map(|t| t.to_rfc3339()))
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    /// 全量列表（含已吊销——管理面要展示吊销状态）；按创建时间倒序。
    pub async fn list_all(&self) -> PersonaResult<Vec<ConnectTokenRow>> {
        let rows = sqlx::query(
            "SELECT id, label, hash, fingerprint, scope, created_at, last_used_at, revoked_at
             FROM connect_tokens ORDER BY created_at DESC",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        rows.iter().map(row_to_token).collect()
    }

    /// 哈希查表；无命中返回 `None`（与吊销同形，调用方不再区分）。
    pub async fn find_by_hash(&self, hash: &str) -> PersonaResult<Option<ConnectTokenRow>> {
        let row = sqlx::query(
            "SELECT id, label, hash, fingerprint, scope, created_at, last_used_at, revoked_at
             FROM connect_tokens WHERE hash = ?",
        )
        .bind(hash)
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        match row {
            Some(row) => Ok(Some(row_to_token(&row)?)),
            None => Ok(None),
        }
    }

    /// 更新 `last_used_at`；调用方负责节流（DR-2：每请求计数、批量落库）。
    pub async fn touch_last_used(&self, id: &Uuid, now: DateTime<Utc>) -> PersonaResult<()> {
        sqlx::query("UPDATE connect_tokens SET last_used_at = ? WHERE id = ?")
            .bind(now.to_rfc3339())
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    /// 吊销；返回是否确实有行被置吊销（重复吊销返回 `false`，幂等）。
    pub async fn revoke(&self, id: &Uuid, now: DateTime<Utc>) -> PersonaResult<bool> {
        let result = sqlx::query(
            "UPDATE connect_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(now.to_rfc3339())
        .bind(id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }
}

fn row_to_token(row: &sqlx::sqlite::SqliteRow) -> PersonaResult<ConnectTokenRow> {
    let scope_json: String = row.get("scope");
    let scope: ConnectTokenScope = serde_json::from_str(&scope_json)
        .map_err(|e| PersonaError::Database(format!("corrupt connect token scope: {e}")))?;
    let parse_time = |v: Option<String>| -> PersonaResult<Option<DateTime<Utc>>> {
        v.map(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|e| PersonaError::Database(format!("corrupt timestamp: {e}")))
        })
        .transpose()
    };
    Ok(ConnectTokenRow {
        id: Uuid::parse_str(row.get::<String, _>("id").as_str())
            .map_err(|e| PersonaError::Database(format!("corrupt token id: {e}")))?,
        label: row.get("label"),
        hash: row.get("hash"),
        fingerprint: {
            // 兼容手工插入的行：空指纹可从哈希重导出。
            let stored: String = row.get("fingerprint");
            if stored.is_empty() {
                fingerprint_from_hash(row.get::<String, _>("hash").as_str())
            } else {
                stored
            }
        },
        scope,
        created_at: parse_time(Some(row.get("created_at")))?.unwrap_or_else(Utc::now),
        last_used_at: parse_time(row.get("last_used_at"))?,
        revoked_at: parse_time(row.get("revoked_at"))?,
    })
}
