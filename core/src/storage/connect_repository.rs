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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::connect::token::{ConnectItemType, ConnectVerb};

    fn sample_row(hash: &str, fingerprint: &str, created_at: DateTime<Utc>) -> ConnectTokenRow {
        ConnectTokenRow {
            id: Uuid::new_v4(),
            label: "ci token".to_string(),
            hash: hash.to_string(),
            fingerprint: fingerprint.to_string(),
            scope: ConnectTokenScope {
                identities: vec![Uuid::new_v4()],
                item_types: vec![ConnectItemType::Password, ConnectItemType::ApiKey],
                verbs: vec![ConnectVerb::Read],
            },
            created_at,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn insert_find_touch_revoke_roundtrip_and_listing_order() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let repo = ConnectTokenRepository::new(db);

        assert!(repo.find_by_hash("nope").await.unwrap().is_none());

        let older = sample_row(
            &"a".repeat(64),
            "aaaaaaaaaaaaaaaa",
            Utc::now() - chrono::Duration::seconds(30),
        );
        let newer = sample_row(&"b".repeat(64), "bbbbbbbbbbbbbbbb", Utc::now());
        repo.insert(&older).await.unwrap();
        repo.insert(&newer).await.unwrap();

        // list_all：含全部行，按 created_at 倒序
        let all = repo.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, newer.id);

        // find_by_hash：字段与 scope 三维完整回读
        let found = repo.find_by_hash(&older.hash).await.unwrap().unwrap();
        assert_eq!(found.id, older.id);
        assert_eq!(found.label, "ci token");
        assert_eq!(found.fingerprint, "aaaaaaaaaaaaaaaa");
        assert_eq!(found.scope, older.scope);
        assert!(found.last_used_at.is_none());
        assert!(!found.revoked());

        // touch_last_used：回读时间戳逐秒一致
        let used_at = Utc::now();
        repo.touch_last_used(&older.id, used_at).await.unwrap();
        let found = repo.find_by_hash(&older.hash).await.unwrap().unwrap();
        assert_eq!(found.last_used_at, Some(used_at));

        // revoke：首吊销 true，重复吊销幂等 false
        let revoked_at = Utc::now();
        assert!(repo.revoke(&older.id, revoked_at).await.unwrap());
        let found = repo.find_by_hash(&older.hash).await.unwrap().unwrap();
        assert_eq!(found.revoked_at, Some(revoked_at));
        assert!(found.revoked());
        assert!(!repo.revoke(&older.id, Utc::now()).await.unwrap());
    }

    /// 兼容手工插入行：空指纹从哈希重导出（row_to_token 的 is_empty 臂）。
    #[tokio::test]
    async fn empty_fingerprint_is_rederived_from_hash() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let repo = ConnectTokenRepository::new(db);

        let hash = format!("{}deadbeef", "0123456789abcdef".repeat(4));
        let row = sample_row(&hash, "", Utc::now());
        repo.insert(&row).await.unwrap();

        for found in repo.list_all().await.unwrap() {
            assert_eq!(
                found.fingerprint,
                fingerprint_from_hash(&hash),
                "empty stored fingerprint must re-derive from hash prefix"
            );
            assert_eq!(found.fingerprint, &hash[..16]);
        }
        let found = repo.find_by_hash(&hash).await.unwrap().unwrap();
        assert_eq!(found.fingerprint, fingerprint_from_hash(&hash));
    }
}
