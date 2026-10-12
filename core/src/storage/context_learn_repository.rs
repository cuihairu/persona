//! Local learning history for context-aware suggestion（设计
//! docs/CONTEXT_AWARE_DESIGN.md §4.1 阶段 2，migration 020）。
//!
//! 红线：本表**只在本机**——不进同步 oplog、不上服务器（设计 §3 隐私边界）。
//! 记录的是「用户确认了什么」（switch 落点），cwd 只存哈希不存原文；
//! 开关默认关，未显式开启前不产生任何记录。

use crate::storage::Database;
use crate::{PersonaError, Result};
use sqlx::Row;

/// 开关在 `context_settings` 里的键。
const LEARN_ENABLED_KEY: &str = "context_learn_enabled";

/// 仓库层：学习记录 + 学习开关（同一本地库）。
pub struct ContextLearnRepository {
    db: Database,
}

impl ContextLearnRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// 学习开关（默认关：键不存在 = off）。
    pub async fn learn_enabled(&self) -> Result<bool> {
        let row = sqlx::query("SELECT value FROM context_settings WHERE key = ?")
            .bind(LEARN_ENABLED_KEY)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to read learn flag: {e}")))?;
        Ok(row
            .map(|r| r.get::<String, _>("value") == "on")
            .unwrap_or(false))
    }

    /// 打开/关闭学习。关不掉已存在的记录（数据保留，只停写）。
    pub async fn set_learn_enabled(&self, on: bool) -> Result<()> {
        let value = if on { "on" } else { "off" };
        sqlx::query(
            "INSERT INTO context_settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(LEARN_ENABLED_KEY)
        .bind(value)
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to write learn flag: {e}")))?;
        Ok(())
    }

    /// 记录一次确认：分身名 + 目录哈希 + 主机 + 时间（RFC3339）。
    pub async fn record(
        &self,
        identity_name: &str,
        cwd_hash: &str,
        host: Option<&str>,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO context_learn (identity_name, cwd_hash, host, ts) VALUES (?, ?, ?, ?)",
        )
        .bind(identity_name)
        .bind(cwd_hash)
        .bind(host)
        .bind(ts.to_rfc3339())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to record learn entry: {e}")))?;
        Ok(())
    }

    /// 同一目录（cwd_hash 等值）在 `since` 之后的分身使用计数，
    /// 按 (次数降序, 名字升序) 返回——纯函数层的平局规则依赖这个顺序。
    pub async fn counts_since(
        &self,
        cwd_hash: &str,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(String, u64)>> {
        let rows = sqlx::query(
            "SELECT identity_name, COUNT(*) AS cnt FROM context_learn
             WHERE cwd_hash = ? AND ts >= ?
             GROUP BY identity_name",
        )
        .bind(cwd_hash)
        .bind(since.to_rfc3339())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(format!("Failed to count learn entries: {e}")))?;
        let mut counts: Vec<(String, u64)> = rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("identity_name"),
                    r.get::<i64, _>("cnt").max(0) as u64,
                )
            })
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(counts)
    }

    /// 学习记录总条数（`context learn status` 用）。
    pub async fn record_count(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS total FROM context_learn")
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to count learn entries: {e}")))?;
        Ok(row.get::<i64, _>("total").max(0) as u64)
    }

    /// 清空全部学习记录（隐私出口：关掉之外还能彻底删除）。
    pub async fn clear(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM context_learn")
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to clear learn entries: {e}")))?;
        Ok(result.rows_affected() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    #[tokio::test]
    async fn learn_flag_defaults_off_and_roundtrips() {
        let db = test_db().await;
        let repo = ContextLearnRepository::new(db);
        assert!(!repo.learn_enabled().await.unwrap(), "default is off");
        repo.set_learn_enabled(true).await.unwrap();
        assert!(repo.learn_enabled().await.unwrap());
        repo.set_learn_enabled(false).await.unwrap();
        assert!(!repo.learn_enabled().await.unwrap());
    }

    #[tokio::test]
    async fn record_and_count_groups_by_identity_in_window() {
        let db = test_db().await;
        let repo = ContextLearnRepository::new(db);
        let now = chrono::Utc::now();
        let hash = "a".repeat(64);

        for _ in 0..3 {
            repo.record("Client-A", &hash, Some("dev-pc"), now)
                .await
                .unwrap();
        }
        repo.record("Other", &hash, Some("dev-pc"), now)
            .await
            .unwrap();
        // 不同目录的记录不进同一组。
        repo.record("Client-A", &"b".repeat(64), None, now)
            .await
            .unwrap();
        // 30 天窗口外的记录不计入。
        let old = now - chrono::Duration::days(31);
        repo.record("Client-A", &hash, None, old).await.unwrap();

        let counts = repo
            .counts_since(&hash, now - chrono::Duration::days(30))
            .await
            .unwrap();
        assert_eq!(
            counts,
            vec![("Client-A".to_string(), 3), ("Other".to_string(), 1)]
        );

        assert_eq!(repo.record_count().await.unwrap(), 6);
    }

    #[tokio::test]
    async fn counts_tie_breaks_by_name_ascending() {
        let db = test_db().await;
        let repo = ContextLearnRepository::new(db);
        let now = chrono::Utc::now();
        let hash = "c".repeat(64);
        // 插入顺序与名字序相反，验证输出仍按名字升序。
        repo.record("Zeta", &hash, None, now).await.unwrap();
        repo.record("Alpha", &hash, None, now).await.unwrap();
        let counts = repo
            .counts_since(&hash, now - chrono::Duration::days(30))
            .await
            .unwrap();
        assert_eq!(
            counts,
            vec![("Alpha".to_string(), 1), ("Zeta".to_string(), 1)]
        );
    }

    #[tokio::test]
    async fn clear_removes_every_record_but_keeps_flag() {
        let db = test_db().await;
        let repo = ContextLearnRepository::new(db);
        let now = chrono::Utc::now();
        repo.set_learn_enabled(true).await.unwrap();
        repo.record("A", &"d".repeat(64), None, now).await.unwrap();
        assert_eq!(repo.clear().await.unwrap(), 1);
        assert_eq!(repo.record_count().await.unwrap(), 0);
        assert!(
            repo.learn_enabled().await.unwrap(),
            "clear must not flip the flag"
        );
    }
}
