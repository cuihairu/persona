//! Local learning history for context-aware suggestion (design
//! docs/CONTEXT_AWARE_DESIGN.md §4.1, phase 2, migration 020).
//!
//! Red line: this table is **local only** — it never enters the sync oplog and
//! never leaves for the server (the privacy boundary in design §3). What is
//! recorded is "what the user confirmed" (where the switch landed); cwd is
//! stored as a hash, never as plain text; the flag defaults to off, so no
//! records are produced until it is explicitly enabled.

use crate::storage::Database;
use crate::{PersonaError, Result};
use sqlx::Row;

/// The flag's key inside `context_settings`.
const LEARN_ENABLED_KEY: &str = "context_learn_enabled";

/// Repository layer: learning records plus the learning flag (same local db).
pub struct ContextLearnRepository {
    db: Database,
}

impl ContextLearnRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// The learning flag (off by default: a missing key means off).
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

    /// Turn learning on or off. Turning it off cannot remove existing records
    /// (the data is retained; only further writes stop).
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

    /// Record one confirmation: identity name + directory hash + host + time
    /// (RFC3339).
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

    /// Per-identity usage counts for the same directory (cwd_hash equality)
    /// since `since`, returned ordered by (count descending, name ascending) —
    /// the tie-break rule in the pure-function layer depends on this order.
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

    /// Total number of learning records (used by `context learn status`).
    pub async fn record_count(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS total FROM context_learn")
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to count learn entries: {e}")))?;
        Ok(row.get::<i64, _>("total").max(0) as u64)
    }

    /// Clear every learning record (a privacy exit: in addition to turning it off,
    /// the data can be deleted outright).
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
        // Records from a different directory do not land in the same group.
        repo.record("Client-A", &"b".repeat(64), None, now)
            .await
            .unwrap();
        // Records outside the 30-day window are not counted.
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
        // Insertion order is the reverse of name order, to verify the output is still
        // ascending by name.
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
