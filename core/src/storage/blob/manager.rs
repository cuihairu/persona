use crate::models::{Attachment, AttachmentChunk};
use crate::storage::{AttachmentRepository, FileSystem};
use crate::Result;
use std::path::Path;
use uuid::Uuid;

use super::BlobStore;

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
