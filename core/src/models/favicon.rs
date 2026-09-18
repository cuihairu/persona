use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 单次批量读缓存上限（防 IPC 滥用；放非 feature 门控处，
/// service 的批量读与抓取模块共用）
pub const MAX_HOSTS_PER_REQUEST: usize = 500;

/// favicon 缓存行（host 级去重；公开数据明文存储，不参与加密体系）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaviconCacheEntry {
    pub host: String,
    pub mime_type: String,
    pub data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
