use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Upper limit on hosts per batched cache read (guards against IPC abuse;
/// placed outside feature gates so both the service's batched-read and fetch
/// modules can share it)
pub const MAX_HOSTS_PER_REQUEST: usize = 500;

/// Favicon cache row (host-level dedup; public data stored in plaintext,
/// outside the encryption scheme)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaviconCacheEntry {
    pub host: String,
    pub mime_type: String,
    pub data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
