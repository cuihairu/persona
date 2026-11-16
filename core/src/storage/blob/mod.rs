use std::path::PathBuf;

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

mod manager;
mod store;

pub use manager::AttachmentManager;

#[cfg(test)]
mod tests;
