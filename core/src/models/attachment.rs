use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Attachment metadata
/// 附件元数据，存储在数据库中
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Unique identifier
    pub id: Uuid,

    /// Parent credential ID
    pub credential_id: Uuid,

    /// Original filename
    pub filename: String,

    /// MIME type
    pub mime_type: String,

    /// File size in bytes
    pub size: u64,

    /// Storage path (relative to attachments directory)
    pub storage_path: String,

    /// SHA-256 hash of the file content
    pub content_hash: String,

    /// Is the file encrypted
    pub is_encrypted: bool,

    /// Encryption key ID (if encrypted)
    pub encryption_key_id: Option<String>,

    /// Number of chunks (for large files)
    pub chunk_count: u32,

    /// Chunk size in bytes
    pub chunk_size: u32,

    /// Metadata tags
    pub tags: Vec<String>,

    /// Additional metadata
    pub metadata: serde_json::Value,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Last access timestamp
    pub last_accessed: Option<DateTime<Utc>>,

    /// Is the attachment active
    pub is_active: bool,
}

impl Attachment {
    /// Create a new attachment
    pub fn new(
        credential_id: Uuid,
        filename: String,
        mime_type: String,
        size: u64,
        storage_path: String,
        content_hash: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            credential_id,
            filename,
            mime_type,
            size,
            storage_path,
            content_hash,
            is_encrypted: false,
            encryption_key_id: None,
            chunk_count: 1,
            chunk_size: 0,
            tags: Vec::new(),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_accessed: None,
            is_active: true,
        }
    }

    /// Mark attachment as accessed
    pub fn touch(&mut self) {
        self.last_accessed = Some(Utc::now());
    }

    /// Update attachment metadata
    pub fn update(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Enable encryption
    pub fn enable_encryption(&mut self, key_id: String) {
        self.is_encrypted = true;
        self.encryption_key_id = Some(key_id);
        self.update();
    }

    /// Set chunk information for large files
    pub fn set_chunks(&mut self, chunk_count: u32, chunk_size: u32) {
        self.chunk_count = chunk_count;
        self.chunk_size = chunk_size;
        self.update();
    }

    /// Deactivate attachment (soft delete)
    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.update();
    }

    /// Calculate expected storage path
    pub fn calculate_storage_path(&self) -> String {
        // Store files in a hierarchical structure: credential_id/attachment_id/filename
        format!("{}/{}/{}", self.credential_id, self.id, self.filename)
    }
}

/// Attachment chunk for large file storage
/// 用于大文件分块存储
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentChunk {
    /// Chunk ID
    pub id: Uuid,

    /// Parent attachment ID
    pub attachment_id: Uuid,

    /// Chunk index (0-based)
    pub chunk_index: u32,

    /// Chunk size in bytes
    pub size: u32,

    /// SHA-256 hash of chunk content
    pub content_hash: String,

    /// Storage path for this chunk
    pub storage_path: String,

    /// Is this chunk encrypted
    pub is_encrypted: bool,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl AttachmentChunk {
    /// Create a new chunk
    pub fn new(
        attachment_id: Uuid,
        chunk_index: u32,
        size: u32,
        content_hash: String,
        storage_path: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            attachment_id,
            chunk_index,
            size,
            content_hash,
            storage_path,
            is_encrypted: false,
            created_at: Utc::now(),
        }
    }
}

/// Attachment statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentStats {
    pub total_attachments: usize,
    pub total_size: u64,
    pub encrypted_count: usize,
    pub chunked_count: usize,
    pub by_mime_type: std::collections::HashMap<String, usize>,
}

impl Default for AttachmentStats {
    fn default() -> Self {
        Self {
            total_attachments: 0,
            total_size: 0,
            encrypted_count: 0,
            chunked_count: 0,
            by_mime_type: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_attachment() {
        let credential_id = Uuid::new_v4();
        let attachment = Attachment::new(
            credential_id,
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            1024,
            "path/to/test.pdf".to_string(),
            "abc123".to_string(),
        );

        assert_eq!(attachment.credential_id, credential_id);
        assert_eq!(attachment.filename, "test.pdf");
        assert_eq!(attachment.size, 1024);
        assert!(!attachment.is_encrypted);
        assert_eq!(attachment.chunk_count, 1);
    }

    #[test]
    fn test_enable_encryption() {
        let mut attachment = Attachment::new(
            Uuid::new_v4(),
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            1024,
            "path/to/test.pdf".to_string(),
            "abc123".to_string(),
        );

        attachment.enable_encryption("key123".to_string());
        assert!(attachment.is_encrypted);
        assert_eq!(attachment.encryption_key_id, Some("key123".to_string()));
    }

    #[test]
    fn test_set_chunks() {
        let mut attachment = Attachment::new(
            Uuid::new_v4(),
            "large_file.zip".to_string(),
            "application/zip".to_string(),
            10485760, // 10MB
            "path/to/large_file.zip".to_string(),
            "def456".to_string(),
        );

        attachment.set_chunks(10, 1048576); // 10 chunks of 1MB each
        assert_eq!(attachment.chunk_count, 10);
        assert_eq!(attachment.chunk_size, 1048576);
    }

    #[test]
    fn test_calculate_storage_path() {
        let credential_id = Uuid::new_v4();
        let attachment = Attachment::new(
            credential_id,
            "document.pdf".to_string(),
            "application/pdf".to_string(),
            2048,
            "".to_string(),
            "hash789".to_string(),
        );

        let path = attachment.calculate_storage_path();
        assert!(path.contains(&credential_id.to_string()));
        assert!(path.contains(&attachment.id.to_string()));
        assert!(path.contains("document.pdf"));
    }
}
