use crate::models::{ChangeHistory, ChangeHistoryQuery, ChangeHistoryStats, EntityType};
use crate::storage::Database;
use crate::{PersonaError, Result};
use sqlx::Row;
use uuid::Uuid;

/// Repository for change history operations
pub struct ChangeHistoryRepository {
    db: Database,
}

impl ChangeHistoryRepository {
    /// Create a new change history repository
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Record a change
    pub async fn record(&self, history: &ChangeHistory) -> Result<()> {
        let query = r#"
            INSERT INTO change_history (
                id, entity_type, entity_id, change_type, user_id,
                previous_state, new_state, changes_summary, reason,
                ip_address, user_agent, metadata, timestamp, version, is_reversible
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(history.id.to_string())
            .bind(history.entity_type.to_string())
            .bind(history.entity_id.to_string())
            .bind(history.change_type.to_string())
            .bind(&history.user_id)
            .bind(
                history
                    .previous_state
                    .as_ref()
                    .map(|v| serde_json::to_string(v).unwrap_or_default()),
            )
            .bind(
                history
                    .new_state
                    .as_ref()
                    .map(|v| serde_json::to_string(v).unwrap_or_default()),
            )
            .bind(
                serde_json::to_string(&history.changes_summary)
                    .unwrap_or_else(|_| "{}".to_string()),
            )
            .bind(&history.reason)
            .bind(&history.ip_address)
            .bind(&history.user_agent)
            .bind(serde_json::to_string(&history.metadata).unwrap_or_else(|_| "{}".to_string()))
            .bind(history.timestamp.to_rfc3339())
            .bind(history.version as i64)
            .bind(history.is_reversible)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersonaError::Database(format!("Failed to record change history: {}", e))
            })?;

        Ok(())
    }

    /// Get history for a specific entity
    pub async fn get_entity_history(
        &self,
        entity_type: EntityType,
        entity_id: &Uuid,
    ) -> Result<Vec<ChangeHistory>> {
        let query = r#"
            SELECT id, entity_type, entity_id, change_type, user_id,
                   previous_state, new_state, changes_summary, reason,
                   ip_address, user_agent, metadata, timestamp, version, is_reversible
            FROM change_history
            WHERE entity_type = ? AND entity_id = ?
            ORDER BY version DESC, timestamp DESC
        "#;

        let rows = sqlx::query(query)
            .bind(entity_type.to_string())
            .bind(entity_id.to_string())
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| {
                PersonaError::Database(format!("Failed to fetch entity history: {}", e))
            })?;

        rows.into_iter()
            .map(|row| self.row_to_history(row))
            .collect()
    }

    /// Get specific version of an entity
    pub async fn get_version(
        &self,
        entity_type: EntityType,
        entity_id: &Uuid,
        version: u32,
    ) -> Result<Option<ChangeHistory>> {
        let query = r#"
            SELECT id, entity_type, entity_id, change_type, user_id,
                   previous_state, new_state, changes_summary, reason,
                   ip_address, user_agent, metadata, timestamp, version, is_reversible
            FROM change_history
            WHERE entity_type = ? AND entity_id = ? AND version = ?
        "#;

        let row = sqlx::query(query)
            .bind(entity_type.to_string())
            .bind(entity_id.to_string())
            .bind(version as i64)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to fetch version: {}", e)))?;

        match row {
            Some(row) => Ok(Some(self.row_to_history(row)?)),
            None => Ok(None),
        }
    }

    /// Query change history with filters
    pub async fn query(&self, query_opts: &ChangeHistoryQuery) -> Result<Vec<ChangeHistory>> {
        let mut sql = String::from(
            r#"
            SELECT id, entity_type, entity_id, change_type, user_id,
                   previous_state, new_state, changes_summary, reason,
                   ip_address, user_agent, metadata, timestamp, version, is_reversible
            FROM change_history
            WHERE 1=1
        "#,
        );

        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref entity_type) = query_opts.entity_type {
            sql.push_str(" AND entity_type = ?");
            bindings.push(entity_type.to_string());
        }

        if let Some(ref entity_id) = query_opts.entity_id {
            sql.push_str(" AND entity_id = ?");
            bindings.push(entity_id.to_string());
        }

        if let Some(ref change_type) = query_opts.change_type {
            sql.push_str(" AND change_type = ?");
            bindings.push(change_type.to_string());
        }

        if let Some(ref user_id) = query_opts.user_id {
            sql.push_str(" AND user_id = ?");
            bindings.push(user_id.clone());
        }

        if let Some(ref from_date) = query_opts.from_date {
            sql.push_str(" AND timestamp >= ?");
            bindings.push(from_date.to_rfc3339());
        }

        if let Some(ref to_date) = query_opts.to_date {
            sql.push_str(" AND timestamp <= ?");
            bindings.push(to_date.to_rfc3339());
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = query_opts.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = query_opts.offset {
            // SQLite only accepts OFFSET together with LIMIT; LIMIT -1 means
            // "no limit" and keeps a standalone offset valid.
            if query_opts.limit.is_none() {
                sql.push_str(" LIMIT -1");
            }
            sql.push_str(&format!(" OFFSET {}", offset));
        }

        let mut query = sqlx::query(&sql);
        for binding in bindings {
            query = query.bind(binding);
        }

        let rows = query
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to query history: {}", e)))?;

        rows.into_iter()
            .map(|row| self.row_to_history(row))
            .collect()
    }

    /// Get the latest version number for an entity
    pub async fn get_latest_version(
        &self,
        entity_type: EntityType,
        entity_id: &Uuid,
    ) -> Result<u32> {
        let query = r#"
            SELECT MAX(version) as max_version
            FROM change_history
            WHERE entity_type = ? AND entity_id = ?
        "#;

        let row = sqlx::query(query)
            .bind(entity_type.to_string())
            .bind(entity_id.to_string())
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get latest version: {}", e)))?;

        let version: Option<i64> = row.get("max_version");
        Ok(version.unwrap_or(0) as u32)
    }

    /// Get change history statistics
    pub async fn get_stats(&self) -> Result<ChangeHistoryStats> {
        let mut stats = ChangeHistoryStats::default();

        // Total changes
        let count_query = "SELECT COUNT(*) as total FROM change_history";
        let row = sqlx::query(count_query)
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get stats: {}", e)))?;
        stats.total_changes = row.get::<i64, _>("total") as usize;

        // By entity type
        let entity_query = r#"
            SELECT entity_type, COUNT(*) as count
            FROM change_history
            GROUP BY entity_type
        "#;
        let entity_rows = sqlx::query(entity_query)
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get entity stats: {}", e)))?;

        for row in entity_rows {
            let entity_type_str: String = row.get("entity_type");
            if let Ok(entity_type) = entity_type_str.parse::<EntityType>() {
                let count: i64 = row.get("count");
                stats.by_entity_type.insert(entity_type, count as usize);
            }
        }

        // By change type
        let change_query = r#"
            SELECT change_type, COUNT(*) as count
            FROM change_history
            GROUP BY change_type
        "#;
        let change_rows = sqlx::query(change_query)
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get change stats: {}", e)))?;

        for row in change_rows {
            let change_type: String = row.get("change_type");
            let count: i64 = row.get("count");
            stats.by_change_type.insert(change_type, count as usize);
        }

        // Recent changes
        let recent_query = r#"
            SELECT id, entity_type, entity_id, change_type, user_id,
                   previous_state, new_state, changes_summary, reason,
                   ip_address, user_agent, metadata, timestamp, version, is_reversible
            FROM change_history
            ORDER BY timestamp DESC
            LIMIT 10
        "#;
        let recent_rows = sqlx::query(recent_query)
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get recent changes: {}", e)))?;

        stats.recent_changes = recent_rows
            .into_iter()
            .map(|row| self.row_to_history(row))
            .collect::<Result<Vec<_>>>()?;

        Ok(stats)
    }

    /// Delete old history entries (for cleanup/GDPR)
    pub async fn delete_before_date(&self, before: chrono::DateTime<chrono::Utc>) -> Result<usize> {
        let query = "DELETE FROM change_history WHERE timestamp < ?";

        let result = sqlx::query(query)
            .bind(before.to_rfc3339())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to delete old history: {}", e)))?;

        Ok(result.rows_affected() as usize)
    }

    /// Convert database row to ChangeHistory
    fn row_to_history(&self, row: sqlx::sqlite::SqliteRow) -> Result<ChangeHistory> {
        let previous_state_str: Option<String> = row.get("previous_state");
        let new_state_str: Option<String> = row.get("new_state");
        let changes_summary_str: String = row.get("changes_summary");
        let metadata_str: String = row.get("metadata");

        Ok(ChangeHistory {
            id: Uuid::parse_str(&row.get::<String, _>("id"))
                .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?,
            entity_type: row
                .get::<String, _>("entity_type")
                .parse()
                .map_err(|e| PersonaError::Database(format!("Invalid entity type: {}", e)))?,
            entity_id: Uuid::parse_str(&row.get::<String, _>("entity_id"))
                .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?,
            change_type: row
                .get::<String, _>("change_type")
                .parse()
                .map_err(|e| PersonaError::Database(format!("Invalid change type: {}", e)))?,
            user_id: row.get("user_id"),
            previous_state: previous_state_str.and_then(|s| serde_json::from_str(&s).ok()),
            new_state: new_state_str.and_then(|s| serde_json::from_str(&s).ok()),
            changes_summary: serde_json::from_str(&changes_summary_str).unwrap_or_default(),
            reason: row.get("reason"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
            timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("timestamp"))
                .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
                .with_timezone(&chrono::Utc),
            version: row.get::<i64, _>("version") as u32,
            is_reversible: row.get("is_reversible"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ChangeType, EntityType};

    async fn create_test_db() -> Database {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    #[tokio::test]
    async fn test_record_and_get_history() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let entity_id = Uuid::new_v4();
        let history = ChangeHistory::new(EntityType::Identity, entity_id, ChangeType::Created)
            .with_user("user123".to_string())
            .with_version(1);

        // Record change
        repo.record(&history).await.unwrap();

        // Get history
        let histories = repo
            .get_entity_history(EntityType::Identity, &entity_id)
            .await
            .unwrap();
        assert_eq!(histories.len(), 1);
        assert_eq!(histories[0].entity_id, entity_id);
        assert_eq!(histories[0].version, 1);
    }

    #[tokio::test]
    async fn test_get_latest_version() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let entity_id = Uuid::new_v4();

        // Record multiple versions
        for v in 1..=3 {
            let history =
                ChangeHistory::new(EntityType::Credential, entity_id, ChangeType::Updated)
                    .with_version(v);
            repo.record(&history).await.unwrap();
        }

        let latest = repo
            .get_latest_version(EntityType::Credential, &entity_id)
            .await
            .unwrap();
        assert_eq!(latest, 3);
    }

    #[tokio::test]
    async fn test_query_with_filters() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let entity_id = Uuid::new_v4();
        let history = ChangeHistory::new(EntityType::Identity, entity_id, ChangeType::Updated)
            .with_user("user456".to_string());

        repo.record(&history).await.unwrap();

        let query = ChangeHistoryQuery::new()
            .entity_type(EntityType::Identity)
            .change_type(ChangeType::Updated);

        let results = repo.query(&query).await.unwrap();
        assert!(!results.is_empty());
    }

    async fn seed_three_versions(
        repo: &ChangeHistoryRepository,
    ) -> (Uuid, Uuid, chrono::DateTime<chrono::Utc>) {
        let entity_a = Uuid::new_v4();
        let entity_b = Uuid::new_v4();
        let base = chrono::Utc::now() - chrono::Duration::hours(3);

        let mut created = ChangeHistory::new(EntityType::Identity, entity_a, ChangeType::Created)
            .with_user("alice".to_string())
            .with_states(None, Some(serde_json::json!({"name": "new"})))
            .with_reason("initial creation".to_string())
            .with_version(1);
        created.timestamp = base;
        created.ip_address = Some("127.0.0.1".to_string());
        created.user_agent = Some("persona-cli".to_string());
        created.add_metadata("source".to_string(), "test".to_string());
        created.add_field_change("name".to_string(), "".to_string(), "new".to_string());
        repo.record(&created).await.unwrap();

        let mut updated = ChangeHistory::new(EntityType::Identity, entity_a, ChangeType::Updated)
            .with_user("alice".to_string())
            .with_states(
                Some(serde_json::json!({"name": "new"})),
                Some(serde_json::json!({"name": "newer"})),
            )
            .with_version(2);
        updated.timestamp = base + chrono::Duration::hours(1);
        repo.record(&updated).await.unwrap();

        let mut other = ChangeHistory::new(EntityType::Credential, entity_b, ChangeType::Deleted)
            .with_user("bob".to_string())
            .with_version(1);
        other.timestamp = base + chrono::Duration::hours(2);
        repo.record(&other).await.unwrap();

        (entity_a, entity_b, base)
    }

    #[tokio::test]
    async fn test_record_round_trips_every_field() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let (entity_a, _, _) = seed_three_versions(&repo).await;

        let entries = repo
            .get_entity_history(EntityType::Identity, &entity_a)
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);

        let created = &entries[1]; // ordered by version ASC within same timestamp? DESC by version → created is last
        assert_eq!(created.change_type, ChangeType::Created);
        assert_eq!(created.user_id.as_deref(), Some("alice"));
        assert_eq!(created.previous_state, None);
        assert_eq!(created.new_state, Some(serde_json::json!({"name": "new"})));
        assert_eq!(
            created
                .changes_summary
                .get("name")
                .map(|f| f.new_value.as_str()),
            Some("new")
        );
        assert_eq!(created.reason.as_deref(), Some("initial creation"));
        assert_eq!(created.ip_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(created.user_agent.as_deref(), Some("persona-cli"));
        assert_eq!(
            created.metadata.get("source").map(String::as_str),
            Some("test")
        );
        assert!(created.is_reversible);
    }

    #[tokio::test]
    async fn test_get_entity_history_empty_for_unknown_entity() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let entries = repo
            .get_entity_history(EntityType::Config, &Uuid::new_v4())
            .await
            .unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_get_version_found_and_missing() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let (entity_a, _, _) = seed_three_versions(&repo).await;

        let v2 = repo
            .get_version(EntityType::Identity, &entity_a, 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v2.version, 2);
        assert_eq!(v2.change_type, ChangeType::Updated);

        assert!(repo
            .get_version(EntityType::Identity, &entity_a, 99)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_get_latest_version_zero_when_unknown() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let latest = repo
            .get_latest_version(EntityType::Workspace, &Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(latest, 0);
    }

    #[tokio::test]
    async fn test_query_supports_every_filter_and_paging() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let (entity_a, entity_b, base) = seed_three_versions(&repo).await;

        // entity_id filter.
        let results = repo
            .query(&ChangeHistoryQuery::new().entity_id(entity_a))
            .await
            .unwrap();
        assert_eq!(results.len(), 2);

        // user_id filter.
        let results = repo
            .query(&ChangeHistoryQuery::new().user("bob".to_string()))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity_id, entity_b);

        // change_type filter.
        let results = repo
            .query(&ChangeHistoryQuery::new().change_type(ChangeType::Deleted))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        // from_date excludes older rows.
        let results = repo
            .query(
                &ChangeHistoryQuery::new()
                    .date_range(base + chrono::Duration::hours(1), chrono::Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 2);

        // to_date alone caps the upper bound.
        let results = repo
            .query(&ChangeHistoryQuery::new().date_range(base - chrono::Duration::hours(1), base))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        // limit truncates; offset skips the newest rows.
        let results = repo
            .query(&ChangeHistoryQuery::new().limit(1))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        let results = repo
            .query(&ChangeHistoryQuery::new().offset(2))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        // Newest first ordering.
        let results = repo.query(&ChangeHistoryQuery::new()).await.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].timestamp >= results[1].timestamp);
        assert!(results[1].timestamp >= results[2].timestamp);
    }

    #[tokio::test]
    async fn test_get_stats_aggregates_types_and_recent() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let (entity_a, entity_b, _) = seed_three_versions(&repo).await;

        let stats = repo.get_stats().await.unwrap();
        assert_eq!(stats.total_changes, 3);
        assert_eq!(stats.by_entity_type.get(&EntityType::Identity), Some(&2));
        assert_eq!(stats.by_entity_type.get(&EntityType::Credential), Some(&1));
        assert_eq!(stats.by_change_type.get("created"), Some(&1));
        assert_eq!(stats.by_change_type.get("updated"), Some(&1));
        assert_eq!(stats.by_change_type.get("deleted"), Some(&1));
        assert_eq!(stats.recent_changes.len(), 3);
        assert!(stats
            .recent_changes
            .iter()
            .any(|e| e.entity_id == entity_a && e.entity_id != entity_b));
    }

    #[tokio::test]
    async fn test_get_stats_skips_unparseable_entity_types() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db.clone());

        let (entity_a, _, base) = seed_three_versions(&repo).await;

        // Pad to 10 valid rows so the corrupt row (timestamped oldest) stays
        // out of the top-10 recent list while still exercising the
        // entity-type aggregation skip.
        for i in 0..7 {
            let mut filler =
                ChangeHistory::new(EntityType::Workspace, Uuid::new_v4(), ChangeType::Archived);
            filler.timestamp = base + chrono::Duration::hours(i);
            repo.record(&filler).await.unwrap();
        }

        // A row with an unknown entity_type is skipped in the aggregation.
        let mut conn = db.pool().acquire().await.unwrap();
        sqlx::query(
            "INSERT INTO change_history (id, entity_type, entity_id, change_type, timestamp)
             VALUES ('99999999-9999-4999-8999-999999999999', 'bogus', ?, 'created', '2020-01-01T00:00:00+00:00')",
        )
        .bind(entity_a.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);

        let stats = repo.get_stats().await.unwrap();
        assert_eq!(stats.total_changes, 11);
        // The corrupt row is excluded from the per-type aggregation...
        assert!(!stats
            .by_entity_type
            .keys()
            .any(|k| k.to_string() == "bogus"));
        assert_eq!(stats.by_entity_type.get(&EntityType::Workspace), Some(&7));
        // ...and from the recent list, which only holds the 10 valid rows
        // (the corrupt row carries the oldest timestamp and is cut by LIMIT).
        assert_eq!(stats.recent_changes.len(), 10);
        assert_eq!(
            stats
                .recent_changes
                .iter()
                .filter(|e| e.entity_type == EntityType::Workspace)
                .count(),
            7
        );
    }

    #[tokio::test]
    async fn test_delete_before_date_removes_only_old_entries() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db);

        let (_, _, base) = seed_three_versions(&repo).await;

        let deleted = repo
            .delete_before_date(base + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        let stats = repo.get_stats().await.unwrap();
        assert_eq!(stats.total_changes, 2);
    }

    #[tokio::test]
    async fn test_corrupt_rows_surface_database_errors() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db.clone());

        let entity_id = Uuid::new_v4();
        let mut conn = db.pool().acquire().await.unwrap();

        // Bad UUID.
        sqlx::query(
            "INSERT INTO change_history (id, entity_type, entity_id, change_type, timestamp)
             VALUES ('not-a-uuid', 'identity', ?, 'created', '2024-01-01T00:00:00+00:00')",
        )
        .bind(entity_id.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(repo
            .get_entity_history(EntityType::Identity, &entity_id)
            .await
            .is_err());

        // Bad entity_type: a filterless query scans it.
        sqlx::query(
            "INSERT INTO change_history (id, entity_type, entity_id, change_type, timestamp)
             VALUES ('11111111-2222-4333-8444-555555555555', 'bogus', ?, 'created', '2024-01-01T00:00:00+00:00')",
        )
        .bind(entity_id.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(repo.query(&ChangeHistoryQuery::new()).await.is_err());

        // Bad change_type.
        sqlx::query(
            "INSERT INTO change_history (id, entity_type, entity_id, change_type, timestamp)
             VALUES ('22222222-2222-4333-8444-555555555555', 'identity', ?, 'exploded', '2024-01-01T00:00:00+00:00')",
        )
        .bind(entity_id.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(repo
            .get_entity_history(EntityType::Identity, &entity_id)
            .await
            .is_err());

        // Bad timestamp.
        sqlx::query(
            "INSERT INTO change_history (id, entity_type, entity_id, change_type, timestamp)
             VALUES ('33333333-3333-4333-8444-555555555555', 'identity', ?, 'created', 'whenever')",
        )
        .bind(entity_id.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(repo
            .get_entity_history(EntityType::Identity, &entity_id)
            .await
            .is_err());

        drop(conn);
    }

    #[tokio::test]
    async fn dropped_table_surfaces_database_errors() {
        let db = create_test_db().await;
        let repo = ChangeHistoryRepository::new(db.clone());

        sqlx::query("DROP TABLE change_history")
            .execute(db.pool())
            .await
            .unwrap();

        // Every statement now fails at the SQL level; each query must map the
        // driver error into PersonaError::Database.
        let entity_id = Uuid::new_v4();
        let history = ChangeHistory::new(EntityType::Identity, entity_id, ChangeType::Created);
        let query = ChangeHistoryQuery::new();
        let errors = vec![
            repo.record(&history).await.unwrap_err(),
            repo.get_entity_history(EntityType::Identity, &entity_id)
                .await
                .unwrap_err(),
            repo.get_version(EntityType::Identity, &entity_id, 1)
                .await
                .unwrap_err(),
            repo.query(&query).await.unwrap_err(),
            repo.get_latest_version(EntityType::Identity, &entity_id)
                .await
                .unwrap_err(),
            repo.get_stats().await.unwrap_err(),
            repo.delete_before_date(chrono::Utc::now())
                .await
                .unwrap_err(),
        ];
        for err in errors {
            assert!(
                matches!(
                    err.downcast_ref::<PersonaError>(),
                    Some(PersonaError::Database(_))
                ),
                "expected a database error, got: {err}"
            );
        }
    }
}
