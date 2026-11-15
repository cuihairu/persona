//! travel pack 的数据模型：pack 载荷、附件文件、数量报告与状态快照。

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// 附件 blob 文件（磁盘原始字节，保持密封态——恢复时行原样插回，
/// 文件也必须原样归位，任何解密/再加密都会破坏与行的对应关系）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TravelBlobFile {
    pub storage_path: String,
    /// 内容 hex sha256（来自 attachments/attachment_chunks 行的
    /// content_hash 列，读入时复核）。
    pub sha256: String,
    pub data_b64: String,
}

/// 打包数据（gzip 前的明文 JSON）。
#[derive(Debug, Serialize, Deserialize)]
pub struct TravelPack {
    pub format_name: String,
    pub format_version: u32,
    pub created_at: String,
    pub app_version: String,
    /// enter 前 workspace 指向被移除身份时的原指针（exit 时还原；否则为 None）。
    pub active_identity_id: Option<String>,
    /// 冗余索引：被移除身份 id 集。
    pub identity_ids: Vec<String>,
    /// 表名 → 原始行（BLOB 单元格为 `{"b64": "..."}`）。
    pub tables: std::collections::BTreeMap<String, Vec<Map<String, Value>>>,
    pub attachment_files: Vec<TravelBlobFile>,
}

/// enter/exit 的数量报告（审计 metadata 与 UI 反馈）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TravelCounts {
    pub identities: u32,
    pub credentials: u32,
    pub attachments: u32,
    pub passkeys: u32,
    pub wallets: u32,
    pub history_rows: u32,
    pub files: u32,
}

impl TravelCounts {
    pub(crate) fn from_pack(pack: &TravelPack) -> Self {
        let table = |name: &str| pack.tables.get(name).map(Vec::len).unwrap_or(0);
        Self {
            identities: table("identities") as u32,
            credentials: table("credentials") as u32,
            attachments: table("attachments") as u32,
            passkeys: table("passkeys") as u32,
            wallets: table("crypto_wallets") as u32,
            history_rows: table("change_history") as u32,
            files: pack.attachment_files.len() as u32,
        }
    }
}

/// 旅行模式状态（读取不需要 travel 口令；给 UI/CLI 展示用）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TravelStatus {
    /// settings 里的 travel_mode 旗标。
    pub active: bool,
    /// 进入时刻（RFC3339；enter 写入、exit 清空）。
    pub entered_at: Option<String>,
    /// sidecar 文件是否存在于 `<db dir>/travel.persenc`。
    pub sidecar_exists: bool,
    /// `active && !sidecar_exists`：旗标说在旅行模式，但数据容器没了
    /// （被手删或损毁）——数据已丢失，诚实呈现而非假装可恢复。
    pub inconsistent: bool,
}
