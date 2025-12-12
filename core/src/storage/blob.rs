use crate::crypto::EncryptionService;
use crate::models::{Attachment, AttachmentChunk};
use crate::storage::{AttachmentRepository, FileSystem};
use crate::{PersonaError, Result};
use anyhow::anyhow;
use ring::digest::{Context, SHA256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Default chunk size: 1MB
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum file size for chunking: 100MB
const MAX_SINGLE_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Blob store for managing attachment file storage
pub struct BlobStore {
    storage_root: PathBuf,
    chunk_size: usize,
}

impl BlobStore {
    /// Create a new blob store
    pub fn new<P: AsRef<Path>>(storage_root: P) -> Self {
        Self {
            storage_root: storage_root.as_ref().to_path_buf(),
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Create a new blob store with custom chunk size
    pub fn with_chunk_size<P: AsRef<Path>>(storage_root: P, chunk_size: usize) -> Self {
        Self {
            storage_root: storage_root.as_ref().to_path_buf(),
            chunk_size,
        }
    }

    /// Initialize storage (create directories)
    pub async fn init(&self) -> Result<()> {
        FileSystem::create_dir_all(&self.storage_root).await
    }

    /// Store a file and return attachment metadata
    pub async fn store_file<P: AsRef<Path>>(
        &self,
        file_path: P,
        credential_id: Uuid,
        encrypt: bool,
        encryption_key: Option<&[u8]>,
    ) -> Result<Attachment> {
        let file_path = file_path.as_ref();

        // Validate file exists
        if !FileSystem::exists(file_path).await {
            return Err(anyhow!("File does not exist"));
        }

        // Get file metadata
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("Invalid filename"))?
            .to_string();

        let file_size = FileSystem::file_size(file_path).await?;
        let mime_type = self.detect_mime_type(&filename);

        // Read file content
        let mut content = FileSystem::read(file_path).await?;

        // Encrypt if requested
        let (is_encrypted, encryption_key_id) = if encrypt {
            if let Some(key) = encryption_key {
                let enc_service = EncryptionService::new(
                    key.try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid encryption key length"))?,
                );
                let encrypted = enc_service
                    .encrypt(&content)
                    .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
                content = encrypted;
                (true, Some(hex::encode(&key[..16]))) // Use first 16 bytes as key ID
            } else {
                return Err(anyhow::anyhow!("Encryption key required").into());
            }
        } else {
            (false, None)
        };

        // Calculate content hash
        let content_hash = self.calculate_hash(&content);

        // Determine if chunking is needed
        let should_chunk = file_size > MAX_SINGLE_FILE_SIZE;

        let mut attachment = Attachment::new(
            credential_id,
            filename.clone(),
            mime_type,
            file_size,
            String::new(), // Will be set below
            content_hash.clone(),
        );

        if should_chunk {
            // Store as chunks
            let chunks = self.chunk_data(&content);
            attachment.set_chunks(chunks.len() as u32, self.chunk_size as u32);

            for (i, chunk_data) in chunks.iter().enumerate() {
                let _chunk_hash = self.calculate_hash(chunk_data);
                let chunk_path = self.get_chunk_path(&credential_id, &attachment.id, i);

                // Ensure parent directory exists
                if let Some(parent) = chunk_path.parent() {
                    FileSystem::create_dir_all(parent).await?;
                }

                // Write chunk
                FileSystem::write(&chunk_path, chunk_data).await?;

                // Store chunk path relative to storage root
                let relative_path = chunk_path
                    .strip_prefix(&self.storage_root)
                    .unwrap_or(&chunk_path)
                    .to_string_lossy()
                    .to_string();

                attachment.storage_path = relative_path;
            }
        } else {
            // Store as single file
            let file_path = self.get_file_path(&credential_id, &attachment.id, &filename);

            // Ensure parent directory exists
            if let Some(parent) = file_path.parent() {
                FileSystem::create_dir_all(parent).await?;
            }

            // Write file
            FileSystem::write(&file_path, &content).await?;

            // Store path relative to storage root
            let relative_path = file_path
                .strip_prefix(&self.storage_root)
                .unwrap_or(&file_path)
                .to_string_lossy()
                .to_string();

            attachment.storage_path = relative_path;
        }

        if is_encrypted {
            attachment.enable_encryption(encryption_key_id.unwrap());
        }

        Ok(attachment)
    }

    /// Retrieve a file from storage
    pub async fn retrieve_file(
        &self,
        attachment: &Attachment,
        chunks: &[AttachmentChunk],
        decrypt: bool,
        decryption_key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut content = if attachment.chunk_count > 1 {
            // Reconstruct from chunks
            let mut full_content = Vec::new();

            for chunk in chunks {
                let chunk_path = self.storage_root.join(&chunk.storage_path);
                let chunk_data = FileSystem::read(&chunk_path).await?;

                // Verify chunk hash
                let calculated_hash = self.calculate_hash(&chunk_data);
                if calculated_hash != chunk.content_hash {
                    return Err(anyhow::anyhow!("Chunk {} hash mismatch", chunk.chunk_index).into());
                }

                full_content.extend_from_slice(&chunk_data);
            }

            full_content
        } else {
            // Read single file
            let file_path = self.storage_root.join(&attachment.storage_path);
            FileSystem::read(&file_path).await?
        };

        // Verify content hash
        let calculated_hash = self.calculate_hash(&content);
        if calculated_hash != attachment.content_hash {
            return Err(anyhow::anyhow!("Content hash mismatch").into());
        }

        // Decrypt if needed
        if decrypt && attachment.is_encrypted {
            if let Some(key) = decryption_key {
                let enc_service = EncryptionService::new(
                    key.try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid decryption key length"))?,
                );
                content = enc_service
                    .decrypt(&content)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
            } else {
                return Err(anyhow::anyhow!("Decryption key required").into());
            }
        }

        Ok(content)
    }

    /// Delete a file from storage
    pub async fn delete_file(
        &self,
        attachment: &Attachment,
        chunks: &[AttachmentChunk],
    ) -> Result<()> {
        if attachment.chunk_count > 1 {
            // Delete all chunks
            for chunk in chunks {
                let chunk_path = self.storage_root.join(&chunk.storage_path);
                if FileSystem::exists(&chunk_path).await {
                    FileSystem::remove_file(&chunk_path).await?;
                }
            }

            // Delete chunk directory if empty
            let chunk_dir = self.get_chunk_dir(&attachment.credential_id, &attachment.id);
            if FileSystem::exists(&chunk_dir).await {
                // Try to remove directory (will fail if not empty, which is fine)
                let _ = FileSystem::remove_dir_all(&chunk_dir).await;
            }
        } else {
            // Delete single file
            let file_path = self.storage_root.join(&attachment.storage_path);
            if FileSystem::exists(&file_path).await {
                FileSystem::remove_file(&file_path).await?;
            }
        }

        Ok(())
    }

    /// Calculate SHA-256 hash of data using ring
    fn calculate_hash(&self, data: &[u8]) -> String {
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();
        hex::encode(digest.as_ref())
    }

    /// Split data into chunks
    fn chunk_data(&self, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(self.chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Detect MIME type from filename
    fn detect_mime_type(&self, filename: &str) -> String {
        let extension = filename.rsplit('.').next().unwrap_or("");

        match extension.to_lowercase().as_str() {
            "pdf" => "application/pdf",
            "doc" => "application/msword",
            "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls" => "application/vnd.ms-excel",
            "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "txt" => "text/plain",
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            "zip" => "application/zip",
            "json" => "application/json",
            "xml" => "application/xml",
            _ => "application/octet-stream",
        }
        .to_string()
    }

    /// Get file storage path
    fn get_file_path(&self, credential_id: &Uuid, attachment_id: &Uuid, filename: &str) -> PathBuf {
        self.storage_root
            .join(credential_id.to_string())
            .join(attachment_id.to_string())
            .join(filename)
    }

    /// Get chunk directory
    fn get_chunk_dir(&self, credential_id: &Uuid, attachment_id: &Uuid) -> PathBuf {
        self.storage_root
            .join(credential_id.to_string())
            .join(attachment_id.to_string())
            .join("chunks")
    }

    /// Get chunk storage path
    fn get_chunk_path(
        &self,
        credential_id: &Uuid,
        attachment_id: &Uuid,
        chunk_index: usize,
    ) -> PathBuf {
        self.get_chunk_dir(credential_id, attachment_id)
            .join(format!("chunk_{:04}", chunk_index))
    }
}

/// Attachment manager combining repository and blob store
pub struct AttachmentManager {
    repository: AttachmentRepository,
    blob_store: BlobStore,
}

impl AttachmentManager {
    /// Create a new attachment manager
    pub fn new(repository: AttachmentRepository, blob_store: BlobStore) -> Self {
        Self {
            repository,
            blob_store,
        }
    }

    /// Initialize storage
    pub async fn init(&self) -> Result<()> {
        self.blob_store.init().await
    }

    /// Store an attachment
    pub async fn store<P: AsRef<Path>>(
        &self,
        file_path: P,
        credential_id: Uuid,
        encrypt: bool,
        encryption_key: Option<&[u8]>,
    ) -> Result<Uuid> {
        // Store file in blob store
        let attachment = self
            .blob_store
            .store_file(file_path, credential_id, encrypt, encryption_key)
            .await?;

        // Save metadata to database
        self.repository.create(&attachment).await?;

        // If chunked, save chunk metadata
        if attachment.chunk_count > 1 {
            // Create chunks from stored data
            for i in 0..attachment.chunk_count {
                let chunk_path =
                    self.blob_store
                        .get_chunk_path(&credential_id, &attachment.id, i as usize);
                let chunk_data = FileSystem::read(&chunk_path).await?;
                let chunk_hash = self.blob_store.calculate_hash(&chunk_data);

                let chunk = AttachmentChunk::new(
                    attachment.id,
                    i,
                    chunk_data.len() as u32,
                    chunk_hash,
                    chunk_path
                        .strip_prefix(&self.blob_store.storage_root)
                        .unwrap_or(&chunk_path)
                        .to_string_lossy()
                        .to_string(),
                );

                self.repository.create_chunk(&chunk).await?;
            }
        }

        Ok(attachment.id)
    }

    /// Retrieve an attachment
    pub async fn retrieve(
        &self,
        attachment_id: &Uuid,
        decrypt: bool,
        decryption_key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Load metadata
        let attachment = self
            .repository
            .find_by_id(attachment_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Attachment not found"))?;

        // Load chunks if needed
        let chunks = if attachment.chunk_count > 1 {
            self.repository.get_chunks(attachment_id).await?
        } else {
            Vec::new()
        };

        // Retrieve file from blob store
        self.blob_store
            .retrieve_file(&attachment, &chunks, decrypt, decryption_key)
            .await
    }

    /// Delete an attachment
    pub async fn delete(&self, attachment_id: &Uuid) -> Result<()> {
        // Load metadata
        let attachment = self
            .repository
            .find_by_id(attachment_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Attachment not found"))?;

        // Load chunks if needed
        let chunks = if attachment.chunk_count > 1 {
            self.repository.get_chunks(attachment_id).await?
        } else {
            Vec::new()
        };

        // Delete from blob store
        self.blob_store.delete_file(&attachment, &chunks).await?;

        // Delete chunks metadata
        if attachment.chunk_count > 1 {
            self.repository.delete_chunks(attachment_id).await?;
        }

        // Delete metadata
        self.repository.permanent_delete(attachment_id).await?;

        Ok(())
    }

    /// List attachments for a credential
    pub async fn list_for_credential(&self, credential_id: &Uuid) -> Result<Vec<Attachment>> {
        self.repository.find_by_credential(credential_id).await
    }

    /// Get attachment statistics
    pub async fn get_stats(&self) -> Result<crate::models::AttachmentStats> {
        self.repository.get_stats().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;
    use tempfile::tempdir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

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
    async fn test_store_and_retrieve_small_file() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let test_file = temp_dir.path().join("test.txt");

        // Create test file
        let mut file = File::create(&test_file).await.unwrap();
        file.write_all(b"Hello, World!").await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        // Create manager
        let db = create_test_db().await;
        let credential_id = seed_identity_and_credential(&db).await;
        let repo = AttachmentRepository::new(db);
        let blob_store = BlobStore::new(&storage_dir);
        let manager = AttachmentManager::new(repo, blob_store);
        manager.init().await.unwrap();

        // Store file
        let attachment_id = manager
            .store(&test_file, credential_id, false, None)
            .await
            .unwrap();

        // Retrieve file
        let content = manager.retrieve(&attachment_id, false, None).await.unwrap();

        assert_eq!(content, b"Hello, World!");
    }

    #[tokio::test]
    async fn test_store_and_retrieve_with_encryption() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let test_file = temp_dir.path().join("secret.txt");

        // Create test file
        let mut file = File::create(&test_file).await.unwrap();
        file.write_all(b"Secret content").await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        // Create manager
        let db = create_test_db().await;
        let credential_id = seed_identity_and_credential(&db).await;
        let repo = AttachmentRepository::new(db);
        let blob_store = BlobStore::new(&storage_dir);
        let manager = AttachmentManager::new(repo, blob_store);
        manager.init().await.unwrap();
        let encryption_key = b"0123456789abcdef0123456789abcdef"; // 32 bytes key

        // Store file with encryption
        let attachment_id = manager
            .store(&test_file, credential_id, true, Some(encryption_key))
            .await
            .unwrap();

        // Retrieve file with decryption
        let content = manager
            .retrieve(&attachment_id, true, Some(encryption_key))
            .await
            .unwrap();

        assert_eq!(content, b"Secret content");
    }

    #[tokio::test]
    async fn test_delete_attachment() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let test_file = temp_dir.path().join("test.txt");

        // Create test file
        let mut file = File::create(&test_file).await.unwrap();
        file.write_all(b"Delete me").await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        // Create manager
        let db = create_test_db().await;
        let credential_id = seed_identity_and_credential(&db).await;
        let repo = AttachmentRepository::new(db);
        let blob_store = BlobStore::new(&storage_dir);
        let manager = AttachmentManager::new(repo, blob_store);
        manager.init().await.unwrap();

        // Store file
        let attachment_id = manager
            .store(&test_file, credential_id, false, None)
            .await
            .unwrap();

        // Delete attachment
        manager.delete(&attachment_id).await.unwrap();

        // Try to retrieve (should fail)
        let result = manager.retrieve(&attachment_id, false, None).await;
        assert!(result.is_err());
    }
}
