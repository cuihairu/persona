use sqlx::{Pool, Sqlite, SqlitePool, Row, Arguments};
use std::path::Path;
use crate::{Result, PersonaError};

/// Database wrapper for SQLite operations
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
        let database_url = format!("sqlite:{}", path.display());
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

    /// Execute a query with parameters
    pub async fn execute_with_params(&self, query: &str, params: &[&(dyn sqlx::Encode<Sqlite> + sqlx::Type<Sqlite> + Sync)]) -> Result<u64> {
        let mut query_builder = sqlx::query(query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        let result = query_builder
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
        Ok(self.pool
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
        Ok(self.tx
            .commit()
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?)
    }
    
    /// Rollback the transaction
    pub async fn rollback(self) -> Result<()> {
        Ok(self.tx
            .rollback()
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_in_memory_database() {
        let db = Database::in_memory().await.unwrap();

        // Create a test table
        db.execute(
            "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)"
        ).await.unwrap();

        // Insert data
        let name = "test_name";
        db.execute_with_params(
            "INSERT INTO test (name) VALUES (?)",
            &[&name]
        ).await.unwrap();

        // Query data
        let row = db.fetch_one("SELECT name FROM test WHERE id = 1").await.unwrap();
        let retrieved_name: String = row.get("name");
        assert_eq!(retrieved_name, "test_name");
    }
}