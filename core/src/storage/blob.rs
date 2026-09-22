use crate::crypto::EncryptionService;
use crate::models::{Attachment, AttachmentChunk};
use crate::storage::{AttachmentRepository, FileSystem};
use crate::Result;
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
    max_single_file_size: u64,
}

impl BlobStore {
    /// 存储根目录（只读透传；travel mode 打包附件文件用）
    pub fn storage_root(&self) -> &Path {
        &self.storage_root
    }

    /// Create a new blob store
    pub fn new<P: AsRef<Path>>(storage_root: P) -> Self {
        Self::with_chunk_size(storage_root, DEFAULT_CHUNK_SIZE)
    }

    /// Create a new blob store with custom chunk size
    pub fn with_chunk_size<P: AsRef<Path>>(storage_root: P, chunk_size: usize) -> Self {
        Self {
            storage_root: storage_root.as_ref().to_path_buf(),
            chunk_size,
            max_single_file_size: MAX_SINGLE_FILE_SIZE,
        }
    }

    /// Create a blob store with fully configurable limits (test helper).
    ///
    /// Production behavior is identical; the only difference is that the
    /// single-file chunking threshold is configurable so tests can exercise
    /// the chunked code paths without writing >100MB files.
    #[cfg(test)]
    #[allow(dead_code)]
    fn with_test_limits<P: AsRef<Path>>(
        storage_root: P,
        chunk_size: usize,
        max_single_file_size: u64,
    ) -> Self {
        Self {
            storage_root: storage_root.as_ref().to_path_buf(),
            chunk_size,
            max_single_file_size,
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
                return Err(anyhow::anyhow!("Encryption key required"));
            }
        } else {
            (false, None)
        };

        // Calculate content hash
        let content_hash = self.calculate_hash(&content);

        // Determine if chunking is needed
        let should_chunk = file_size > self.max_single_file_size;

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

                // Ensure the parent directory exists. `chunk_path` is always
                // nested below `storage_root`, so `parent()` is `Some`; the
                // fallback never fires.
                let chunk_dir = chunk_path.parent().unwrap_or(self.storage_root.as_path());
                FileSystem::create_dir_all(chunk_dir).await?;

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

            // Ensure the parent directory exists. `file_path` is always
            // nested below `storage_root`, so `parent()` is `Some`; the
            // fallback never fires.
            let parent = file_path.parent().unwrap_or(self.storage_root.as_path());
            FileSystem::create_dir_all(parent).await?;

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
                    return Err(anyhow::anyhow!("Chunk {} hash mismatch", chunk.chunk_index));
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
            return Err(anyhow::anyhow!("Content hash mismatch"));
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
                return Err(anyhow::anyhow!("Decryption key required"));
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

    /// 附件根目录（travel mode 打包/恢复 blob 文件用；storage_path 列
    /// 存的是相对此根的路径）
    pub fn storage_root(&self) -> &Path {
        self.blob_store.storage_root()
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

    /// Look up attachment metadata without touching the blob
    pub async fn get(&self, attachment_id: &Uuid) -> Result<Option<Attachment>> {
        self.repository.find_by_id(attachment_id).await
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

    fn small_test_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        use std::io::Write;
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
        path
    }

    #[test]
    fn test_detect_mime_type_covers_known_extensions() {
        let store = BlobStore::new("/tmp/unused");
        let cases = [
            ("a.pdf", "application/pdf"),
            ("a.doc", "application/msword"),
            (
                "a.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            ("a.xls", "application/vnd.ms-excel"),
            (
                "a.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            ("a.txt", "text/plain"),
            ("a.jpg", "image/jpeg"),
            ("a.jpeg", "image/jpeg"),
            ("a.png", "image/png"),
            ("a.gif", "image/gif"),
            ("a.zip", "application/zip"),
            ("a.json", "application/json"),
            ("a.xml", "application/xml"),
            ("a.unknownext", "application/octet-stream"),
            ("noextension", "application/octet-stream"),
            ("UPPER.PNG", "image/png"),
        ];
        for (filename, expected) in cases {
            assert_eq!(store.detect_mime_type(filename), expected, "for {filename}");
        }
    }

    #[test]
    fn test_chunk_and_path_helpers() {
        let root = Path::new("/tmp/blob-root");
        let store = BlobStore::with_chunk_size(root, 4);
        let credential_id = Uuid::new_v4();
        let attachment_id = Uuid::new_v4();

        // Chunking splits on the configured chunk size, last chunk keeps the rest.
        assert_eq!(
            store.chunk_data(&[1, 2, 3, 4, 5, 6]),
            vec![vec![1, 2, 3, 4], vec![5, 6]]
        );
        assert!(store.chunk_data(&[]).is_empty());

        let file_path = store.get_file_path(&credential_id, &attachment_id, "f.txt");
        assert_eq!(
            file_path,
            root.join(credential_id.to_string())
                .join(attachment_id.to_string())
                .join("f.txt")
        );

        let chunk_dir = store.get_chunk_dir(&credential_id, &attachment_id);
        assert_eq!(
            chunk_dir,
            root.join(credential_id.to_string())
                .join(attachment_id.to_string())
                .join("chunks")
        );

        let chunk_path = store.get_chunk_path(&credential_id, &attachment_id, 3);
        assert_eq!(chunk_path, chunk_dir.join("chunk_0003"));

        // Known SHA-256 vector.
        assert_eq!(
            store.calculate_hash(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[tokio::test]
    async fn test_store_file_missing_errors() {
        let temp_dir = tempdir().unwrap();
        let store = BlobStore::new(temp_dir.path().join("storage"));

        let err = store
            .store_file(
                temp_dir.path().join("nope.txt"),
                Uuid::new_v4(),
                false,
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("File does not exist"));
    }

    #[tokio::test]
    async fn test_store_file_rejects_unnameable_path() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let store = BlobStore::new(&storage_dir);
        store.init().await.unwrap();

        // `storage/..` resolves to an existing directory but has no file name.
        let weird = storage_dir.join("..");
        let err = store
            .store_file(&weird, Uuid::new_v4(), false, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid filename"));
    }

    #[tokio::test]
    async fn test_store_file_encryption_requires_key_and_valid_length() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let store = BlobStore::new(&storage_dir);
        store.init().await.unwrap();
        let file = small_test_file(temp_dir.path(), "secret.txt", b"payload");

        // encrypt=true but no key.
        let err = store
            .store_file(&file, Uuid::new_v4(), true, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Encryption key required"));

        // Key that is not 32 bytes.
        let err = store
            .store_file(&file, Uuid::new_v4(), true, Some(&b"short"[..]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid encryption key length"));
    }

    #[tokio::test]
    async fn test_chunked_store_retrieve_and_hash_mismatch() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        // Chunk threshold of 8 bytes forces chunking for a 16-byte file.
        let store = BlobStore::with_test_limits(&storage_dir, 8, 8);
        store.init().await.unwrap();
        let credential_id = Uuid::new_v4();

        let contents = b"0123456789abcdef"; // 16 bytes → 2 chunks of 8
        let file = small_test_file(temp_dir.path(), "big.bin", contents);

        let mut attachment = store
            .store_file(&file, credential_id, false, None)
            .await
            .unwrap();
        assert!(attachment.chunk_count > 1);
        assert_eq!(attachment.size as usize, contents.len());

        // Collect the chunk metadata the store just wrote.
        let chunk_dir = store.get_chunk_dir(&credential_id, &attachment.id);
        let mut paths = FileSystem::read_dir(&chunk_dir).await.unwrap();
        paths.sort();
        let mut chunks = Vec::new();
        for (i, p) in paths.iter().enumerate() {
            let data = FileSystem::read(p).await.unwrap();
            let relative = p
                .strip_prefix(&storage_dir)
                .unwrap()
                .to_string_lossy()
                .to_string();
            chunks.push(AttachmentChunk::new(
                attachment.id,
                i as u32,
                data.len() as u32,
                store.calculate_hash(&data),
                relative,
            ));
        }

        // Clean reconstruction works.
        let rebuilt = store
            .retrieve_file(&attachment, &chunks, false, None)
            .await
            .unwrap();
        assert_eq!(rebuilt, contents);

        // Corrupting one chunk hash must abort reconstruction.
        let mut tampered = chunks.clone();
        tampered[1].content_hash = "0".repeat(64);
        let err = store
            .retrieve_file(&attachment, &tampered, false, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));

        // Tampering with the whole-content hash must also fail.
        attachment.content_hash = "f".repeat(64);
        let err = store
            .retrieve_file(&attachment, &chunks, false, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Content hash mismatch"));

        // Deleting the chunked attachment removes every chunk and the directory.
        store.delete_file(&attachment, &chunks).await.unwrap();
        assert!(!FileSystem::exists(&chunk_dir).await);
        // Deleting again is a no-op (paths already gone).
        store.delete_file(&attachment, &chunks).await.unwrap();
    }

    #[tokio::test]
    async fn test_retrieve_single_file_content_hash_mismatch_and_missing() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let store = BlobStore::new(&storage_dir);
        store.init().await.unwrap();
        let credential_id = Uuid::new_v4();

        let mut attachment = Attachment::new(
            credential_id,
            "f.txt".to_string(),
            "text/plain".to_string(),
            5,
            "f.txt".to_string(),
            store.calculate_hash(b"hello"),
        );
        FileSystem::write(&storage_dir.join("f.txt"), b"hello")
            .await
            .unwrap();

        // Corrupt the recorded hash.
        attachment.content_hash = "0".repeat(64);
        let err = store
            .retrieve_file(&attachment, &[], false, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Content hash mismatch"));

        // Missing file surfaces an IO error.
        attachment.content_hash = store.calculate_hash(b"hello");
        attachment.storage_path = "gone.txt".to_string();
        assert!(store
            .retrieve_file(&attachment, &[], false, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_retrieve_encrypted_requires_key_and_valid_length() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let store = BlobStore::new(&storage_dir);
        store.init().await.unwrap();

        let file = small_test_file(temp_dir.path(), "enc.txt", b"top secret");
        let key = [7u8; 32];
        let attachment = store
            .store_file(&file, Uuid::new_v4(), true, Some(&key))
            .await
            .unwrap();
        assert!(attachment.is_encrypted);
        assert!(attachment.encryption_key_id.is_some());

        // Encrypted content cannot be decrypted without a key.
        let err = store
            .retrieve_file(&attachment, &[], true, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Decryption key required"));

        // A wrongly-sized key is rejected before decryption.
        let err = store
            .retrieve_file(&attachment, &[], true, Some(&[1u8; 16]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid decryption key length"));

        // Correct key restores the plaintext.
        let plaintext = store
            .retrieve_file(&attachment, &[], true, Some(&key))
            .await
            .unwrap();
        assert_eq!(plaintext, b"top secret");
    }

    #[tokio::test]
    async fn test_delete_single_file_and_missing_file_noop() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let store = BlobStore::new(&storage_dir);
        store.init().await.unwrap();
        let credential_id = Uuid::new_v4();

        let attachment = Attachment::new(
            credential_id,
            "doomed.txt".to_string(),
            "text/plain".to_string(),
            4,
            "doomed.txt".to_string(),
            store.calculate_hash(b"bye!"),
        );
        FileSystem::write(&storage_dir.join("doomed.txt"), b"bye!")
            .await
            .unwrap();

        store.delete_file(&attachment, &[]).await.unwrap();
        assert!(!FileSystem::exists(&storage_dir.join("doomed.txt")).await);

        // Deleting an already-missing single file is fine.
        store.delete_file(&attachment, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn test_manager_chunked_round_trip_stats_and_list() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let contents = b"chunked-content-0123456789"; // 26 bytes
        let test_file = small_test_file(temp_dir.path(), "chunked.bin", contents);

        let db = create_test_db().await;
        let credential_id = seed_identity_and_credential(&db).await;
        let repo = AttachmentRepository::new(db);
        // Chunk threshold of 8 bytes forces chunking for a 26-byte file.
        let blob_store = BlobStore::with_test_limits(&storage_dir, 8, 8);
        let manager = AttachmentManager::new(repo, blob_store);
        manager.init().await.unwrap();

        let attachment_id = manager
            .store(&test_file, credential_id, false, None)
            .await
            .unwrap();

        // Chunked retrieval reconstructs the original bytes.
        let content = manager.retrieve(&attachment_id, false, None).await.unwrap();
        assert_eq!(content, contents);

        // Stats see one chunked attachment.
        let stats = manager.get_stats().await.unwrap();
        assert_eq!(stats.total_attachments, 1);
        assert_eq!(stats.chunked_count, 1);
        assert_eq!(stats.total_size, contents.len() as u64);

        // Listing by credential finds it.
        assert_eq!(
            manager
                .list_for_credential(&credential_id)
                .await
                .unwrap()
                .len(),
            1
        );

        // Deleting removes metadata and the on-disk chunks.
        manager.delete(&attachment_id).await.unwrap();
        assert!(manager
            .list_for_credential(&credential_id)
            .await
            .unwrap()
            .is_empty());
        assert!(manager.retrieve(&attachment_id, false, None).await.is_err());
    }

    #[tokio::test]
    async fn test_manager_retrieve_and_delete_missing_attachment() {
        let temp_dir = tempdir().unwrap();
        let storage_dir = temp_dir.path().join("storage");

        let db = create_test_db().await;
        let repo = AttachmentRepository::new(db);
        let blob_store = BlobStore::new(&storage_dir);
        let manager = AttachmentManager::new(repo, blob_store);
        manager.init().await.unwrap();

        let missing = Uuid::new_v4();
        let err = manager.retrieve(&missing, false, None).await.unwrap_err();
        assert!(err.to_string().contains("Attachment not found"));

        let err = manager.delete(&missing).await.unwrap_err();
        assert!(err.to_string().contains("Attachment not found"));
    }
}
