use crate::models::FaviconCacheEntry;
use crate::storage::Database;
use crate::{PersonaError, Result};
use sqlx::Row;

/// Repository for favicon cache operations（host 级去重的公开数据缓存）
pub struct FaviconRepository {
    db: Database,
}

impl FaviconRepository {
    /// Create a new favicon repository
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// 按 host 查缓存；未命中返回 None
    pub async fn get(&self, host: &str) -> Result<Option<FaviconCacheEntry>> {
        let query = r#"
            SELECT host, mime_type, data, created_at, updated_at
            FROM favicon_cache WHERE host = ?
        "#;

        let row = sqlx::query(query)
            .bind(host)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to find favicon: {}", e)))?;

        match row {
            Some(row) => Ok(Some(row_to_entry(row)?)),
            None => Ok(None),
        }
    }

    /// 批量查缓存。数量级为列表页 hosts（数十~数百），逐 host 索引点查足够，
    /// 避免动态 IN 占位符拼接；调用方负责去重。
    pub async fn get_many(&self, hosts: &[String]) -> Result<Vec<FaviconCacheEntry>> {
        let mut entries = Vec::new();
        for host in hosts {
            if let Some(entry) = self.get(host).await? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// 抓取成功后 upsert；保留首次 created_at，仅刷新 mime/data/updated_at
    pub async fn upsert(&self, host: &str, mime_type: &str, data: &[u8]) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = r#"
            INSERT INTO favicon_cache (host, mime_type, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                mime_type = excluded.mime_type,
                data = excluded.data,
                updated_at = excluded.updated_at
        "#;

        sqlx::query(query)
            .bind(host)
            .bind(mime_type)
            .bind(data)
            .bind(&now)
            .bind(&now)
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to upsert favicon: {}", e)))?;

        Ok(())
    }
}

fn row_to_entry(row: sqlx::sqlite::SqliteRow) -> Result<FaviconCacheEntry> {
    let created_at: String = row
        .try_get("created_at")
        .map_err(|e| PersonaError::Database(format!("Failed to read created_at: {}", e)))?;
    let updated_at: String = row
        .try_get("updated_at")
        .map_err(|e| PersonaError::Database(format!("Failed to read updated_at: {}", e)))?;

    Ok(FaviconCacheEntry {
        host: row
            .try_get("host")
            .map_err(|e| PersonaError::Database(format!("Failed to read host: {}", e)))?,
        mime_type: row
            .try_get("mime_type")
            .map_err(|e| PersonaError::Database(format!("Failed to read mime_type: {}", e)))?,
        data: row
            .try_get::<Vec<u8>, _>("data")
            .map_err(|e| PersonaError::Database(format!("Failed to read data: {}", e)))?,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
            .map_err(|e| PersonaError::Database(format!("Invalid created_at: {}", e)))?
            .with_timezone(&chrono::Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at)
            .map_err(|e| PersonaError::Database(format!("Invalid updated_at: {}", e)))?
            .with_timezone(&chrono::Utc),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        let db = Database::in_memory().await.expect("in-memory db");
        db.migrate().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn upsert_then_get_round_trips_entry() {
        let db = test_db().await;
        let repo = FaviconRepository::new(db);

        repo.upsert("example.com", "image/png", b"png-bytes")
            .await
            .expect("upsert");

        let entry = repo.get("example.com").await.expect("get").expect("hit");
        assert_eq!(entry.host, "example.com");
        assert_eq!(entry.mime_type, "image/png");
        assert_eq!(entry.data, b"png-bytes");
    }

    #[tokio::test]
    async fn upsert_keeps_created_at_and_refreshes_payload() {
        let db = test_db().await;
        let repo = FaviconRepository::new(db);

        repo.upsert("example.com", "image/x-icon", b"old")
            .await
            .unwrap();
        let first = repo.get("example.com").await.unwrap().unwrap();

        // 时间戳列是秒级精度依赖 rfc3339；同瞬间内 created_at 必须保留
        repo.upsert("example.com", "image/png", b"new-bytes")
            .await
            .unwrap();
        let second = repo.get("example.com").await.unwrap().unwrap();

        assert_eq!(second.created_at, first.created_at);
        assert_eq!(second.mime_type, "image/png");
        assert_eq!(second.data, b"new-bytes");
    }

    #[tokio::test]
    async fn get_returns_none_on_miss() {
        let db = test_db().await;
        let repo = FaviconRepository::new(db);

        assert!(repo.get("missing.com").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn get_many_returns_only_hits_in_query_order() {
        let db = test_db().await;
        let repo = FaviconRepository::new(db);

        repo.upsert("a.com", "image/png", b"a").await.unwrap();
        repo.upsert("b.com", "image/png", b"b").await.unwrap();

        let hosts = vec![
            "missing.com".to_string(),
            "b.com".to_string(),
            "a.com".to_string(),
        ];
        let entries = repo.get_many(&hosts).await.expect("get_many");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].host, "b.com");
        assert_eq!(entries[1].host, "a.com");
    }

    #[tokio::test]
    async fn corrupt_timestamps_report_database_error() {
        let db = test_db().await;
        let repo = FaviconRepository::new(db.clone());
        repo.upsert("bad.com", "image/png", b"x").await.unwrap();

        // 绕过仓储直接写入非法时间戳，行解析应报 Database 错而非 panic
        sqlx::query("UPDATE favicon_cache SET created_at = 'not-a-date' WHERE host = 'bad.com'")
            .execute(db.pool())
            .await
            .unwrap();

        let err = repo.get("bad.com").await.expect_err("should fail");
        assert!(
            err.downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::Database(_))),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn methods_fail_with_database_error_after_table_drop() {
        let db = test_db().await;
        let repo = FaviconRepository::new(db.clone());

        sqlx::query("DROP TABLE favicon_cache")
            .execute(db.pool())
            .await
            .unwrap();

        let get_err = repo.get("a.com").await.unwrap_err();
        assert!(
            get_err
                .downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::Database(_))),
            "got: {get_err}"
        );
        let upsert_err = repo.upsert("a.com", "image/png", b"x").await.unwrap_err();
        assert!(
            upsert_err
                .downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::Database(_))),
            "got: {upsert_err}"
        );
    }
}
