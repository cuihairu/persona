use crate::{PersonaError, Result};
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

    /// Run database migrations
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    /// Execute a query that returns the number of affected rows
    pub async fn execute(&self, query: &str) -> Result<u64> {
        let result = sqlx::query(query)
            .execute(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Execute a query that returns a single row
    pub async fn fetch_one(&self, query: &str) -> Result<sqlx::sqlite::SqliteRow> {
        let row = sqlx::query(query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(row)
    }

    /// Execute a query that returns multiple rows
    pub async fn fetch_all(&self, query: &str) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
        let rows = sqlx::query(query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(rows)
    }

    /// Execute a query that may return a row
    pub async fn fetch_optional(&self, query: &str) -> Result<Option<sqlx::sqlite::SqliteRow>> {
        let row = sqlx::query(query)
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
        let result = sqlx::query(query)
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
