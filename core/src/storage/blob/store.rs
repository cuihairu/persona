use crate::crypto::EncryptionService;
use crate::models::{Attachment, AttachmentChunk};
use crate::storage::FileSystem;
use crate::Result;
use anyhow::anyhow;
use ring::digest::{Context, SHA256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::{BlobStore, DEFAULT_CHUNK_SIZE, MAX_SINGLE_FILE_SIZE};

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
    pub(super) fn with_test_limits<P: AsRef<Path>>(
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
                let chunk_path = self.resolve_within_root(&chunk.storage_path)?;
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
            let file_path = self.resolve_within_root(&attachment.storage_path)?;
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
                let chunk_path = self.resolve_within_root(&chunk.storage_path)?;
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
            let file_path = self.resolve_within_root(&attachment.storage_path)?;
            if FileSystem::exists(&file_path).await {
                FileSystem::remove_file(&file_path).await?;
            }
        }

        Ok(())
    }

    /// 把（理论上已相对根的）storage_path 安全拼到存储根下。
    ///
    /// 写入方生成的路径永远是 Normal 组件（uuid/uuid/filename），这里防的是
    /// DB 脏数据 / 导入归档里的越权路径：绝对路径或含 `..`/`.` 等非常规组件
    /// 一律拒绝（对齐 travel.rs:538-552 的逃逸检查口径，防御纵深）。
    fn resolve_within_root(&self, storage_path: &str) -> Result<PathBuf> {
        let relative = Path::new(storage_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(anyhow::anyhow!(
                "attachment storage_path escapes storage root: {storage_path}"
            ));
        }
        Ok(self.storage_root.join(relative))
    }

    /// Calculate SHA-256 hash of data using ring
    pub(super) fn calculate_hash(&self, data: &[u8]) -> String {
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();
        hex::encode(digest.as_ref())
    }

    /// Split data into chunks
    pub(super) fn chunk_data(&self, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(self.chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Detect MIME type from filename
    pub(super) fn detect_mime_type(&self, filename: &str) -> String {
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
    pub(super) fn get_file_path(
        &self,
        credential_id: &Uuid,
        attachment_id: &Uuid,
        filename: &str,
    ) -> PathBuf {
        self.storage_root
            .join(credential_id.to_string())
            .join(attachment_id.to_string())
            .join(filename)
    }

    /// Get chunk directory
    pub(super) fn get_chunk_dir(&self, credential_id: &Uuid, attachment_id: &Uuid) -> PathBuf {
        self.storage_root
            .join(credential_id.to_string())
            .join(attachment_id.to_string())
            .join("chunks")
    }

    /// Get chunk storage path
    pub(super) fn get_chunk_path(
        &self,
        credential_id: &Uuid,
        attachment_id: &Uuid,
        chunk_index: usize,
    ) -> PathBuf {
        self.get_chunk_dir(credential_id, attachment_id)
            .join(format!("chunk_{:04}", chunk_index))
    }
}
