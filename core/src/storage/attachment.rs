use crate::models::{Attachment, AttachmentChunk, AttachmentStats};
use crate::storage::Database;
use crate::{PersonaError, Result};
use sqlx::Row;
use uuid::Uuid;

/// Repository for attachment operations
pub struct AttachmentRepository {
    db: Database,
}

impl AttachmentRepository {
    /// Create a new attachment repository
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a new attachment
    pub async fn create(&self, attachment: &Attachment) -> Result<()> {
        let query = r#"
            INSERT INTO attachments (
                id, credential_id, filename, mime_type, size,
                storage_path, content_hash, is_encrypted, encryption_key_id,
                chunk_count, chunk_size, tags, metadata,
                created_at, updated_at, last_accessed, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(attachment.id.to_string())
            .bind(attachment.credential_id.to_string())
            .bind(&attachment.filename)
            .bind(&attachment.mime_type)
            .bind(attachment.size as i64)
            .bind(&attachment.storage_path)
            .bind(&attachment.content_hash)
            .bind(attachment.is_encrypted)
            .bind(&attachment.encryption_key_id)
            .bind(attachment.chunk_count as i32)
            .bind(attachment.chunk_size as i32)
            .bind(serde_json::to_string(&attachment.tags).unwrap_or_else(|_| "[]".to_string()))
            .bind(serde_json::to_string(&attachment.metadata).unwrap_or_else(|_| "{}".to_string()))
            .bind(attachment.created_at.to_rfc3339())
            .bind(attachment.updated_at.to_rfc3339())
            .bind(attachment.last_accessed.map(|d| d.to_rfc3339()))
            .bind(attachment.is_active)
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to create attachment: {}", e)))?;

        Ok(())
    }

    /// Find attachment by ID
    pub async fn find_by_id(&self, id: &Uuid) -> Result<Option<Attachment>> {
        let query = r#"
            SELECT id, credential_id, filename, mime_type, size,
                   storage_path, content_hash, is_encrypted, encryption_key_id,
                   chunk_count, chunk_size, tags, metadata,
                   created_at, updated_at, last_accessed, is_active
            FROM attachments WHERE id = ?
        "#;

        let row = sqlx::query(query)
            .bind(id.to_string())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to find attachment: {}", e)))?;

        match row {
            Some(row) => Ok(Some(self.row_to_attachment(row)?)),
            None => Ok(None),
        }
    }

    /// Find all attachments for a credential
    pub async fn find_by_credential(&self, credential_id: &Uuid) -> Result<Vec<Attachment>> {
        let query = r#"
            SELECT id, credential_id, filename, mime_type, size,
                   storage_path, content_hash, is_encrypted, encryption_key_id,
                   chunk_count, chunk_size, tags, metadata,
                   created_at, updated_at, last_accessed, is_active
            FROM attachments
            WHERE credential_id = ? AND is_active = 1
            ORDER BY created_at DESC
        "#;

        let rows = sqlx::query(query)
            .bind(credential_id.to_string())
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to find attachments: {}", e)))?;

        rows.into_iter()
            .map(|row| self.row_to_attachment(row))
            .collect()
    }

    /// Update attachment
    pub async fn update(&self, attachment: &Attachment) -> Result<()> {
        let query = r#"
            UPDATE attachments SET
                filename = ?, mime_type = ?, size = ?, storage_path = ?,
                content_hash = ?, is_encrypted = ?, encryption_key_id = ?,
                chunk_count = ?, chunk_size = ?, tags = ?, metadata = ?,
                updated_at = ?, last_accessed = ?, is_active = ?
            WHERE id = ?
        "#;

        sqlx::query(query)
            .bind(&attachment.filename)
            .bind(&attachment.mime_type)
            .bind(attachment.size as i64)
            .bind(&attachment.storage_path)
            .bind(&attachment.content_hash)
            .bind(attachment.is_encrypted)
            .bind(&attachment.encryption_key_id)
            .bind(attachment.chunk_count as i32)
            .bind(attachment.chunk_size as i32)
            .bind(serde_json::to_string(&attachment.tags).unwrap_or_else(|_| "[]".to_string()))
            .bind(serde_json::to_string(&attachment.metadata).unwrap_or_else(|_| "{}".to_string()))
            .bind(attachment.updated_at.to_rfc3339())
            .bind(attachment.last_accessed.map(|d| d.to_rfc3339()))
            .bind(attachment.is_active)
            .bind(attachment.id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to update attachment: {}", e)))?;

        Ok(())
    }

    /// Delete attachment (soft delete)
    pub async fn delete(&self, id: &Uuid) -> Result<()> {
        let query = "UPDATE attachments SET is_active = 0, updated_at = ? WHERE id = ?";

        sqlx::query(query)
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to delete attachment: {}", e)))?;

        Ok(())
    }

    /// Permanently delete attachment
    pub async fn permanent_delete(&self, id: &Uuid) -> Result<()> {
        let query = "DELETE FROM attachments WHERE id = ?";

        sqlx::query(query)
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersonaError::Database(format!("Failed to permanently delete attachment: {}", e))
            })?;

        Ok(())
    }

    /// Get attachment statistics
    pub async fn get_stats(&self) -> Result<AttachmentStats> {
        let query = r#"
            SELECT
                COUNT(*) as total,
                SUM(size) as total_size,
                SUM(CASE WHEN is_encrypted = 1 THEN 1 ELSE 0 END) as encrypted,
                SUM(CASE WHEN chunk_count > 1 THEN 1 ELSE 0 END) as chunked
            FROM attachments WHERE is_active = 1
        "#;

        let row = sqlx::query(query)
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get stats: {}", e)))?;

        let mut stats = AttachmentStats {
            total_attachments: row.get::<i64, _>("total") as usize,
            total_size: row.get::<i64, _>("total_size") as u64,
            encrypted_count: row.get::<i64, _>("encrypted") as usize,
            chunked_count: row.get::<i64, _>("chunked") as usize,
            by_mime_type: std::collections::HashMap::new(),
        };

        // Get MIME type distribution
        let mime_query = r#"
            SELECT mime_type, COUNT(*) as count
            FROM attachments
            WHERE is_active = 1
            GROUP BY mime_type
        "#;

        let mime_rows = sqlx::query(mime_query)
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get MIME stats: {}", e)))?;

        for row in mime_rows {
            let mime_type: String = row.get("mime_type");
            let count: i64 = row.get("count");
            stats.by_mime_type.insert(mime_type, count as usize);
        }

        Ok(stats)
    }

    /// Create attachment chunk
    pub async fn create_chunk(&self, chunk: &AttachmentChunk) -> Result<()> {
        let query = r#"
            INSERT INTO attachment_chunks (
                id, attachment_id, chunk_index, size, content_hash,
                storage_path, is_encrypted, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(chunk.id.to_string())
            .bind(chunk.attachment_id.to_string())
            .bind(chunk.chunk_index as i32)
            .bind(chunk.size as i32)
            .bind(&chunk.content_hash)
            .bind(&chunk.storage_path)
            .bind(chunk.is_encrypted)
            .bind(chunk.created_at.to_rfc3339())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to create chunk: {}", e)))?;

        Ok(())
    }

    /// Get all chunks for an attachment
    pub async fn get_chunks(&self, attachment_id: &Uuid) -> Result<Vec<AttachmentChunk>> {
        let query = r#"
            SELECT id, attachment_id, chunk_index, size, content_hash,
                   storage_path, is_encrypted, created_at
            FROM attachment_chunks
            WHERE attachment_id = ?
            ORDER BY chunk_index ASC
        "#;

        let rows = sqlx::query(query)
            .bind(attachment_id.to_string())
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to get chunks: {}", e)))?;

        rows.into_iter().map(|row| self.row_to_chunk(row)).collect()
    }

    /// Delete all chunks for an attachment
    pub async fn delete_chunks(&self, attachment_id: &Uuid) -> Result<()> {
        let query = "DELETE FROM attachment_chunks WHERE attachment_id = ?";

        sqlx::query(query)
            .bind(attachment_id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(format!("Failed to delete chunks: {}", e)))?;

        Ok(())
    }

    /// Convert database row to Attachment
    fn row_to_attachment(&self, row: sqlx::sqlite::SqliteRow) -> Result<Attachment> {
        let tags_str: String = row.get("tags");
        let metadata_str: String = row.get("metadata");

        Ok(Attachment {
            id: Uuid::parse_str(&row.get::<String, _>("id"))
                .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?,
            credential_id: Uuid::parse_str(&row.get::<String, _>("credential_id"))
                .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?,
            filename: row.get("filename"),
            mime_type: row.get("mime_type"),
            size: row.get::<i64, _>("size") as u64,
            storage_path: row.get("storage_path"),
            content_hash: row.get("content_hash"),
            is_encrypted: row.get("is_encrypted"),
            encryption_key_id: row.get("encryption_key_id"),
            chunk_count: row.get::<i32, _>("chunk_count") as u32,
            chunk_size: row.get::<i32, _>("chunk_size") as u32,
            tags: serde_json::from_str(&tags_str).unwrap_or_default(),
            metadata: serde_json::from_str(&metadata_str).unwrap_or(serde_json::json!({})),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
                .with_timezone(&chrono::Utc),
            last_accessed: row
                .get::<Option<String>, _>("last_accessed")
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc)),
            is_active: row.get("is_active"),
        })
    }

    /// Convert database row to AttachmentChunk
    fn row_to_chunk(&self, row: sqlx::sqlite::SqliteRow) -> Result<AttachmentChunk> {
        Ok(AttachmentChunk {
            id: Uuid::parse_str(&row.get::<String, _>("id"))
                .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?,
            attachment_id: Uuid::parse_str(&row.get::<String, _>("attachment_id"))
                .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?,
            chunk_index: row.get::<i32, _>("chunk_index") as u32,
            size: row.get::<i32, _>("size") as u32,
            content_hash: row.get("content_hash"),
            storage_path: row.get("storage_path"),
            is_encrypted: row.get("is_encrypted"),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
                .with_timezone(&chrono::Utc),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Attachment;

    async fn create_test_db() -> Database {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    async fn seed_identity_and_credential(db: &Database) -> Uuid {
        let identity_id = Uuid::new_v4();
        let credential_id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO identities (
              id, name, identity_type, description, email, phone, ssh_key, gpg_key,
              tags, attributes, created_at, updated_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(identity_id.to_string())
        .bind("Test Identity")
        .bind("personal")
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind("[]")
        .bind("{}")
        .bind(&now)
        .bind(&now)
        .bind(true)
        .execute(db.pool())
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO credentials (
              id, identity_id, name, credential_type, security_level, url, username,
              encrypted_data, notes, tags, metadata, created_at, updated_at, last_accessed,
              is_active, is_favorite
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(credential_id.to_string())
        .bind(identity_id.to_string())
        .bind("Test Credential")
        .bind("password")
        .bind("medium")
        .bind::<Option<String>>(None)
        .bind::<Option<String>>(None)
        .bind(vec![0u8; 16])
        .bind::<Option<String>>(None)
        .bind("[]")
        .bind("{}")
        .bind(&now)
        .bind(&now)
        .bind::<Option<String>>(None)
        .bind(true)
        .bind(false)
        .execute(db.pool())
        .await
        .unwrap();

        credential_id
    }

    #[tokio::test]
    async fn test_create_and_find_attachment() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        let credential_id = seed_identity_and_credential(&repo.db).await;
        let attachment = Attachment::new(
            credential_id,
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            1024,
            "path/to/test.pdf".to_string(),
            "abc123".to_string(),
        );

        // Create attachment
        repo.create(&attachment).await.unwrap();

        // Find attachment
        let found = repo.find_by_id(&attachment.id).await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.filename, "test.pdf");
        assert_eq!(found.size, 1024);
    }

    #[tokio::test]
    async fn test_update_attachment() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        let credential_id = seed_identity_and_credential(&repo.db).await;
        let mut attachment = Attachment::new(
            credential_id,
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            1024,
            "path/to/test.pdf".to_string(),
            "abc123".to_string(),
        );

        repo.create(&attachment).await.unwrap();

        // Update attachment
        attachment.filename = "updated.pdf".to_string();
        attachment.update();
        repo.update(&attachment).await.unwrap();

        // Verify update
        let found = repo.find_by_id(&attachment.id).await.unwrap().unwrap();
        assert_eq!(found.filename, "updated.pdf");
    }

    #[tokio::test]
    async fn test_delete_attachment() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        let credential_id = seed_identity_and_credential(&repo.db).await;
        let attachment = Attachment::new(
            credential_id,
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            1024,
            "path/to/test.pdf".to_string(),
            "abc123".to_string(),
        );

        repo.create(&attachment).await.unwrap();

        // Soft delete
        repo.delete(&attachment.id).await.unwrap();

        // Verify it's marked as inactive
        let found = repo.find_by_id(&attachment.id).await.unwrap().unwrap();
        assert!(!found.is_active);
    }

    fn make_attachment(credential_id: Uuid, name: &str) -> Attachment {
        Attachment::new(
            credential_id,
            name.to_string(),
            "application/pdf".to_string(),
            1024,
            format!("path/to/{name}"),
            "hash".to_string(),
        )
    }

    #[tokio::test]
    async fn test_find_by_id_missing_returns_none() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        assert!(repo.find_by_id(&Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_find_by_credential_lists_active_only() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        let credential_id = seed_identity_and_credential(&repo.db).await;
        let keep = make_attachment(credential_id, "keep.pdf");
        let drop = make_attachment(credential_id, "drop.pdf");
        repo.create(&keep).await.unwrap();
        repo.create(&drop).await.unwrap();

        repo.delete(&drop.id).await.unwrap();

        let listed = repo.find_by_credential(&credential_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, keep.id);
        assert!(!listed.iter().any(|a| a.id == drop.id));
    }

    #[tokio::test]
    async fn test_permanent_delete_removes_row() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        let credential_id = seed_identity_and_credential(&repo.db).await;
        let attachment = make_attachment(credential_id, "gone.pdf");
        repo.create(&attachment).await.unwrap();

        repo.permanent_delete(&attachment.id).await.unwrap();
        assert!(repo.find_by_id(&attachment.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_stats_aggregates_active_attachments() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        // Empty table: SUM(size) is NULL and must not panic.
        let empty = repo.get_stats().await.unwrap();
        assert_eq!(empty.total_attachments, 0);
        assert_eq!(empty.total_size, 0);
        assert_eq!(empty.encrypted_count, 0);
        assert_eq!(empty.chunked_count, 0);

        let credential_id = seed_identity_and_credential(&repo.db).await;

        let mut plain = make_attachment(credential_id, "plain.pdf");
        plain.size = 100;
        let mut encrypted = make_attachment(credential_id, "enc.pdf");
        encrypted.size = 300;
        encrypted.enable_encryption("key-1".to_string());
        let mut chunked = make_attachment(credential_id, "chunked.pdf");
        chunked.size = 500;
        chunked.set_chunks(4, 128);
        let mut soft_deleted = make_attachment(credential_id, "deleted.pdf");
        soft_deleted.size = 10_000;

        for attachment in [&plain, &encrypted, &chunked, &soft_deleted] {
            repo.create(attachment).await.unwrap();
        }
        repo.delete(&soft_deleted.id).await.unwrap();

        let stats = repo.get_stats().await.unwrap();
        assert_eq!(stats.total_attachments, 3);
        assert_eq!(stats.total_size, 900);
        assert_eq!(stats.encrypted_count, 1);
        assert_eq!(stats.chunked_count, 1);
        assert_eq!(stats.by_mime_type.get("application/pdf"), Some(&3));
    }

    #[tokio::test]
    async fn test_chunk_lifecycle_and_ordering() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        let credential_id = seed_identity_and_credential(&repo.db).await;
        let attachment = make_attachment(credential_id, "chunked.pdf");
        repo.create(&attachment).await.unwrap();

        assert!(repo.get_chunks(&attachment.id).await.unwrap().is_empty());

        // Insert out of order; retrieval must order by chunk_index.
        for index in [2u32, 0, 1] {
            let chunk = AttachmentChunk::new(
                attachment.id,
                index,
                128,
                format!("hash-{index}"),
                format!("chunks/chunk_{index:04}"),
            );
            repo.create_chunk(&chunk).await.unwrap();
        }

        let chunks = repo.get_chunks(&attachment.id).await.unwrap();
        assert_eq!(chunks.len(), 3);
        let indexes: Vec<u32> = chunks.iter().map(|c| c.chunk_index).collect();
        assert_eq!(indexes, vec![0, 1, 2]);
        assert_eq!(chunks[2].content_hash, "hash-2");
        assert!(!chunks[0].is_encrypted);

        repo.delete_chunks(&attachment.id).await.unwrap();
        assert!(repo.get_chunks(&attachment.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_last_accessed_and_encryption_roundtrip() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);

        let credential_id = seed_identity_and_credential(&repo.db).await;
        let mut attachment = make_attachment(credential_id, "accessed.pdf");
        attachment.touch();
        attachment.enable_encryption("key-42".to_string());
        attachment.tags = vec!["archive".to_string()];
        attachment.metadata = serde_json::json!({"origin": "import"});

        repo.create(&attachment).await.unwrap();
        let found = repo.find_by_id(&attachment.id).await.unwrap().unwrap();
        assert!(found.last_accessed.is_some());
        assert!(found.is_encrypted);
        assert_eq!(found.encryption_key_id.as_deref(), Some("key-42"));
        assert_eq!(found.tags, vec!["archive".to_string()]);
        assert_eq!(found.metadata["origin"], "import");

        // update() persists touched timestamps too.
        let mut updated = found.clone();
        updated.touch();
        repo.update(&updated).await.unwrap();
        let reloaded = repo.find_by_id(&attachment.id).await.unwrap().unwrap();
        assert!(reloaded.last_accessed.is_some());
    }

    #[tokio::test]
    async fn test_corrupt_rows_surface_database_errors() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);
        let credential_id = seed_identity_and_credential(&repo.db).await;

        // Corrupt UUID in the id column: any full listing must fail.
        sqlx::query(
            "INSERT INTO attachments (id, credential_id, filename, mime_type, size, storage_path,
             content_hash, created_at, updated_at)
             VALUES ('not-a-uuid', ?, 'bad', 'application/pdf', 1, 'p', 'h',
                     '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00')",
        )
        .bind(credential_id.to_string())
        .execute(repo.db.pool())
        .await
        .unwrap();
        assert!(repo.find_by_credential(&credential_id).await.is_err());

        // Remove it, then corrupt created_at on a valid UUID instead.
        sqlx::query("DELETE FROM attachments WHERE id = 'not-a-uuid'")
            .execute(repo.db.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO attachments (id, credential_id, filename, mime_type, size, storage_path,
             content_hash, created_at, updated_at)
             VALUES ('11111111-2222-3333-4444-555555555555', ?, 'bad', 'application/pdf', 1, 'p',
                     'h', 'not-a-date', '2024-01-01T00:00:00+00:00')",
        )
        .bind(credential_id.to_string())
        .execute(repo.db.pool())
        .await
        .unwrap();
        assert!(repo.find_by_credential(&credential_id).await.is_err());

        // A corrupt chunk row breaks get_chunks for its attachment.
        sqlx::query("DELETE FROM attachments WHERE id = '11111111-2222-3333-4444-555555555555'")
            .execute(repo.db.pool())
            .await
            .unwrap();
        let base = make_attachment(credential_id, "base.pdf");
        repo.create(&base).await.unwrap();
        sqlx::query(
            "INSERT INTO attachment_chunks (id, attachment_id, chunk_index, size, content_hash,
             storage_path, is_encrypted, created_at)
             VALUES ('not-a-uuid', ?, 0, 1, 'h', 'p', 0, '2024-01-01T00:00:00+00:00')",
        )
        .bind(base.id.to_string())
        .execute(repo.db.pool())
        .await
        .unwrap();

        assert!(repo.get_chunks(&base.id).await.is_err());
    }

    #[tokio::test]
    async fn dropped_tables_surface_database_errors() {
        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db.clone());

        sqlx::query("DROP TABLE attachments")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("DROP TABLE attachment_chunks")
            .execute(db.pool())
            .await
            .unwrap();

        // Every statement now fails at the SQL level; each query must map the
        // driver error into PersonaError::Database.
        let attachment = make_attachment(Uuid::new_v4(), "ghost.pdf");
        let chunk = AttachmentChunk::new(
            attachment.id,
            0,
            8,
            "hash".to_string(),
            "chunks/chunk_0000".to_string(),
        );
        let errors = vec![
            repo.create(&attachment).await.unwrap_err(),
            repo.find_by_id(&attachment.id).await.unwrap_err(),
            repo.find_by_credential(&attachment.credential_id)
                .await
                .unwrap_err(),
            repo.update(&attachment).await.unwrap_err(),
            repo.delete(&attachment.id).await.unwrap_err(),
            repo.permanent_delete(&attachment.id).await.unwrap_err(),
            repo.get_stats().await.unwrap_err(),
            repo.create_chunk(&chunk).await.unwrap_err(),
            repo.get_chunks(&attachment.id).await.unwrap_err(),
            repo.delete_chunks(&attachment.id).await.unwrap_err(),
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
