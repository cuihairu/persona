use crate::{PersonaError, Result};
use sqlx::AssertSqlSafe;
use sqlx::{Pool, Sqlite, SqlitePool};
use std::path::Path;

/// Database wrapper for SQLite operations
#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    /// Create a new database connection
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Create a database from file path
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        // Ensure SQLite creates the DB file when it does not exist.
        //
        // Without `mode=rwc`, sqlx/sqlite will default to read-write and fail
        // with "unable to open database file" if the DB file is missing.
        let database_url = format!("sqlite:{}?mode=rwc", path.display());
        Self::new(&database_url).await
    }

    /// Create an in-memory database
    pub async fn in_memory() -> Result<Self> {
        Self::new("sqlite::memory:").await
    }

    /// Run database migrations.
    ///
    /// On failure the error carries a two-sided schema fingerprint (what the
    /// vault has applied vs what this build embeds) plus the provenance stamps
    /// from the `meta` table, so a checksum/era mismatch between an older or
    /// newer application build and the vault file is diagnosable from the
    /// message alone instead of by comparing raw checksums by hand.
    pub async fn migrate(&self) -> Result<()> {
        let migrator = sqlx::migrate!("./migrations");
        if let Err(e) = migrator.run(&self.pool).await {
            let context = Self::migration_failure_context(&self.pool, &migrator).await;
            return Err(PersonaError::Database(format!("{context}; sqlx: {e}")).into());
        }
        self.stamp_app_version().await?;
        Ok(())
    }

    /// Record which application build created the vault and which one opened
    /// it last (`meta` rows `app_version_created` / `app_version_last_open`).
    /// Only runs after migrations succeeded, so the `meta` table exists.
    async fn stamp_app_version(&self) -> Result<()> {
        let version = env!("CARGO_PKG_VERSION");
        sqlx::query("INSERT INTO meta(key, value) VALUES('app_version_created', ?1) ON CONFLICT(key) DO NOTHING")
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        sqlx::query("INSERT INTO meta(key, value) VALUES('app_version_last_open', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    /// Build the diagnostic context for a failed migration run: the vault's
    /// applied schema fingerprint (version=checksum pairs from
    /// `_sqlx_migrations`), this build's embedded fingerprint, and the
    /// provenance stamps recorded in `meta` when they are available.
    async fn migration_failure_context(
        pool: &Pool<Sqlite>,
        migrator: &sqlx::migrate::Migrator,
    ) -> String {
        let vault_rows: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(pool)
                .await
                .unwrap_or_default();
        let fingerprint = |rows: &[(i64, Vec<u8>)]| -> String {
            if rows.is_empty() {
                return "(none)".to_string();
            }
            rows.iter()
                .map(|(v, c)| format!("v{v}={}", hex_prefix(c)))
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut parts = vec![format!(
            "vault schema fingerprint [{}]",
            fingerprint(&vault_rows)
        )];
        let app_rows: Vec<(i64, Vec<u8>)> = migrator
            .iter()
            .map(|m| (m.version, m.checksum.to_vec()))
            .collect();
        parts.push(format!("this build embeds [{}]", fingerprint(&app_rows)));
        let created = sqlx::query_as::<_, (String,)>(
            "SELECT value FROM meta WHERE key = 'app_version_created'",
        )
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        if let Some((v,)) = created {
            parts.push(format!("vault created by app {v}"));
        }
        let opened = sqlx::query_as::<_, (String,)>(
            "SELECT value FROM meta WHERE key = 'app_version_last_open'",
        )
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        if let Some((v,)) = opened {
            parts.push(format!("last opened by app {v}"));
        }
        parts.push("mismatch between the two fingerprints means the vault and this build come from different build eras; update the application (never edit applied migration files)".to_string());
        parts.join("; ")
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    /// Execute a query that returns the number of affected rows
    pub async fn execute(&self, query: &str) -> Result<u64> {
        let result = sqlx::query(AssertSqlSafe(query.to_owned()))
            .execute(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Execute a query that returns a single row
    pub async fn fetch_one(&self, query: &str) -> Result<sqlx::sqlite::SqliteRow> {
        let row = sqlx::query(AssertSqlSafe(query.to_owned()))
            .fetch_one(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(row)
    }

    /// Execute a query that returns multiple rows
    pub async fn fetch_all(&self, query: &str) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
        let rows = sqlx::query(AssertSqlSafe(query.to_owned()))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(rows)
    }

    /// Execute a query that may return a row
    pub async fn fetch_optional(&self, query: &str) -> Result<Option<sqlx::sqlite::SqliteRow>> {
        let row = sqlx::query(AssertSqlSafe(query.to_owned()))
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(row)
    }

    /// Begin a database transaction
    pub async fn begin_transaction(&self) -> Result<sqlx::Transaction<'_, Sqlite>> {
        Ok(self
            .pool
            .begin()
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?)
    }

    /// Close the database connection
    pub async fn close(self) {
        self.pool.close().await;
    }
}

/// First 8 bytes of a checksum as 16 lowercase hex chars — short enough for
/// an error message, long enough to be unambiguous in practice.
fn hex_prefix(checksum: &[u8]) -> String {
    checksum
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Database transaction helper
pub struct Transaction<'a> {
    tx: sqlx::Transaction<'a, Sqlite>,
}

impl<'a> Transaction<'a> {
    /// Create a new transaction wrapper
    pub fn new(tx: sqlx::Transaction<'a, Sqlite>) -> Self {
        Self { tx }
    }

    /// Execute a query within the transaction
    pub async fn execute(&mut self, query: &str) -> Result<u64> {
        let result = sqlx::query(AssertSqlSafe(query.to_owned()))
            .execute(&mut *self.tx)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Commit the transaction
    pub async fn commit(self) -> Result<()> {
        Ok(self
            .tx
            .commit()
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?)
    }

    /// Rollback the transaction
    pub async fn rollback(self) -> Result<()> {
        Ok(self
            .tx
            .rollback()
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    /// Migration 21 was published with this checksum. sqlx verifies the whole
    /// file (comments included) against the value recorded in existing vaults,
    /// so even a comment-only edit makes every existing database fail to open
    /// with "migration 21 was previously applied but has been modified".
    /// Keep this pin in sync ONLY by adding a new migration, never by editing 21.
    #[test]
    fn published_migration_21_checksum_is_unchanged() {
        const PUBLISHED: [u8; 48] = [
            0x95, 0x01, 0x71, 0x39, 0x87, 0x2d, 0xb8, 0xe3, 0x2b, 0x40, 0xdd, 0x01, 0x88, 0x9e,
            0xf7, 0xc0, 0xda, 0x9b, 0x98, 0x96, 0xb6, 0xb2, 0x27, 0x22, 0x35, 0x97, 0x28, 0xd4,
            0xea, 0x62, 0xfb, 0x55, 0x0f, 0x15, 0x85, 0x8a, 0x85, 0x54, 0x88, 0xc4, 0x9d, 0x6a,
            0x6e, 0xd9, 0xd2, 0xa0, 0x76, 0x9b,
        ];
        let migrator = sqlx::migrate!("./migrations");
        let migration = migrator
            .iter()
            .find(|m| m.version == 21)
            .expect("migration 21 must exist");
        assert_eq!(
            migration.checksum.as_ref(),
            PUBLISHED,
            "migration 21 was modified; existing vaults will refuse to open"
        );
    }

    #[tokio::test]
    async fn meta_table_stamps_app_version_provenance() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let created: (String,) =
            sqlx::query_as("SELECT value FROM meta WHERE key='app_version_created'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let opened: (String,) =
            sqlx::query_as("SELECT value FROM meta WHERE key='app_version_last_open'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(created.0, env!("CARGO_PKG_VERSION"));
        assert_eq!(opened.0, env!("CARGO_PKG_VERSION"));

        // Re-running migrate keeps the creation stamp and refreshes the
        // last-open stamp (same value here, but the upsert must not fail).
        db.migrate().await.unwrap();
        let created2: (String,) =
            sqlx::query_as("SELECT value FROM meta WHERE key='app_version_created'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(created2.0, created.0);
    }

    #[tokio::test]
    async fn migration_checksum_mismatch_error_names_both_fingerprints() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // Corrupt the recorded checksum of migration 21: exactly what a vault
        // written by a different build era looks like to this binary.
        sqlx::query("UPDATE _sqlx_migrations SET checksum = zeroblob(48) WHERE version = 21")
            .execute(db.pool())
            .await
            .unwrap();

        let err = db.migrate().await.unwrap_err().to_string();
        // The vault side shows the (corrupted) recorded fingerprint, the app
        // side shows the embedded published checksum, and the provenance
        // stamps from meta are included for era diagnosis.
        assert!(err.contains("vault schema fingerprint ["), "{err}");
        assert!(err.contains("this build embeds ["), "{err}");
        assert!(
            err.contains("95017139"),
            "embedded checksum prefix missing: {err}"
        );
        assert!(err.contains("vault created by app"), "{err}");
        assert!(err.contains("last opened by app"), "{err}");
        assert!(err.contains("different build eras"), "{err}");
    }

    #[tokio::test]
    async fn test_in_memory_database() {
        let db = Database::in_memory().await.unwrap();

        // Create a test table
        db.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
            .await
            .unwrap();

        // Insert data
        let name = "test_name";
        sqlx::query("INSERT INTO test (name) VALUES (?)")
            .bind(name)
            .execute(db.pool())
            .await
            .unwrap();

        // Query data
        let row = db
            .fetch_one("SELECT name FROM test WHERE id = 1")
            .await
            .unwrap();
        let retrieved_name: String = row.get("name");
        assert_eq!(retrieved_name, "test_name");
    }

    #[tokio::test]
    async fn test_from_file_creates_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("persist.db");

        // mode=rwc must create the file when missing.
        let db = Database::from_file(&db_path).await.unwrap();
        db.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)")
            .await
            .unwrap();
        db.execute("INSERT INTO kv (k, v) VALUES ('a', '1')")
            .await
            .unwrap();
        db.close().await;
        assert!(db_path.exists());

        // Reopening keeps the data.
        let reopened = Database::from_file(&db_path).await.unwrap();
        let rows = reopened.fetch_all("SELECT k, v FROM kv").await.unwrap();
        assert_eq!(rows.len(), 1);
        reopened.close().await;
    }

    #[tokio::test]
    async fn test_fetch_helpers_and_error_paths() {
        let db = Database::in_memory().await.unwrap();
        db.execute("CREATE TABLE nums (n INTEGER)").await.unwrap();
        db.execute("INSERT INTO nums (n) VALUES (7)").await.unwrap();

        // fetch_one errors when no row matches.
        assert!(db
            .fetch_one("SELECT n FROM nums WHERE n = 1")
            .await
            .is_err());
        // fetch_optional returns None instead.
        assert!(db
            .fetch_optional("SELECT n FROM nums WHERE n = 1")
            .await
            .unwrap()
            .is_none());
        let some = db
            .fetch_optional("SELECT n FROM nums WHERE n = 7")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(some.get::<i64, _>("n"), 7);

        // Invalid SQL surfaces a Database error through every helper.
        assert!(db.execute("NOT SQL").await.is_err());
        assert!(db.fetch_one("ALSO NOT SQL").await.is_err());
        assert!(db.fetch_all("STILL NOT SQL").await.is_err());
        assert!(db.fetch_optional("NOT SQL EITHER").await.is_err());

        // Connecting to an impossible location fails cleanly.
        assert!(Database::new("sqlite:/nonexistent-root-dir/x.db?mode=rw")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_transaction_commit_and_rollback() {
        let db = Database::in_memory().await.unwrap();
        db.execute("CREATE TABLE ledger (amount INTEGER)")
            .await
            .unwrap();

        // Commit persists the writes made through the wrapper.
        let tx = db.begin_transaction().await.unwrap();
        let mut tx = Transaction::new(tx);
        tx.execute("INSERT INTO ledger (amount) VALUES (10)")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            db.fetch_all("SELECT amount FROM ledger")
                .await
                .unwrap()
                .len(),
            1
        );

        // Rollback discards them.
        let tx = db.begin_transaction().await.unwrap();
        let mut tx = Transaction::new(tx);
        tx.execute("INSERT INTO ledger (amount) VALUES (99)")
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        let rows = db.fetch_all("SELECT amount FROM ledger").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<i64, _>("amount"), 10);

        // Invalid SQL inside a transaction reports an error.
        let tx = db.begin_transaction().await.unwrap();
        let mut tx = Transaction::new(tx);
        assert!(tx.execute("BAD SQL").await.is_err());
        tx.rollback().await.unwrap();
    }
}
