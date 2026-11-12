//! 同步与配对的 wire 类型（设备状态/join/sync now/status/rotate/冲突/配对结果）。

use serde::Serialize;

/// `sync_device_status` 返回：本机设备身份状态（纯本地 keyring，免解锁）。
#[derive(Debug, Clone, Serialize)]
pub struct SyncDeviceStatus {
    /// keyring 有可解析的设备身份。
    pub joined: bool,
    /// keyring 有记录但解析失败（损坏/被手改）——UI 提示重新 join（leave
    /// 仍可清理，服务器侧残留可由其他设备 revoke）。
    pub corrupted: bool,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}

/// `sync_join` 返回：登记结果。`pending = true` 表示已登记但尚未被授权
/// （group-keys 无本机信封），需在另一台已授权设备上执行授权。
#[derive(Debug, Clone, Serialize)]
pub struct SyncJoinOutcome {
    pub device_id: String,
    pub device_name: String,
    pub pending: bool,
}

/// `sync_list_devices` 的单行视图：服务器登记行 + 授权状态 + 本机标记。
#[derive(Debug, Clone, Serialize)]
pub struct SyncDeviceView {
    pub id: String,
    pub device_name: String,
    pub created_at: String,
    /// 设备主人的自由备注（S4：仅设备本人可写，全员可读）。
    pub remark: String,
    /// group-keys 有该设备的信封（「有信封 = 已授权」，fail-closed）。
    pub authorized: bool,
    pub this_device: bool,
}

/// `sync_now` 返回：一轮同步的计数汇总（字段与 core `SyncNowReport`
/// 一一对应，供 UI 展示「拉取 N / 灌入 N / 冲突 N」）。
#[derive(Debug, Clone, Serialize)]
pub struct SyncNowReport {
    /// 新拉取落库的远端 op 条数。
    pub pulled: usize,
    /// 物化进主库的条目数（新行或更新）。
    pub materialized: usize,
    /// 冲突败方留驻 oplog 的条目数（数据不丢，待裁决）。
    pub conflicts: usize,
    /// 因身份未同步而挂起的条目数（下轮补齐）。
    pub pending_identity: usize,
    /// push 出去的本地 op 条数。
    pub pushed: usize,
    /// 本次灌入 oplog 的存量凭据条数（通常只在首次同步非零）。
    pub backfilled: u64,
}

impl From<persona_core::sync::runtime::SyncNowReport> for SyncNowReport {
    fn from(report: persona_core::sync::runtime::SyncNowReport) -> Self {
        Self {
            pulled: report.pulled,
            materialized: report.materialized,
            conflicts: report.conflicts,
            pending_identity: report.pending_identity,
            pushed: report.pushed,
            backfilled: report.backfilled,
        }
    }
}

/// `sync_status_report` 返回：组同步水位快照（sync-group-mode §二.5.5
/// 状态显示——组最新版本号 / 本机已同步水位 / 落后 N / 待推 N / 最近同步时间）。
/// 字段与 core `engine::SyncStatusReport` 对应；`last_sync_at` 为 RFC3339。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusInfo {
    pub head_seq: i64,
    pub local_watermark: i64,
    pub behind: i64,
    pub pending_push: i64,
    pub last_sync_at: Option<String>,
}

impl From<persona_core::sync::engine::SyncStatusReport> for SyncStatusInfo {
    fn from(report: persona_core::sync::engine::SyncStatusReport) -> Self {
        Self {
            head_seq: report.head_seq,
            local_watermark: report.local_watermark,
            behind: report.behind,
            pending_push: report.pending_push,
            last_sync_at: report.last_sync_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// `sync_rotate` 返回：一次 group key 轮换的计数汇总（字段与 core
/// `SyncRotateReport` 一一对应，供 UI 展示「重包 N / 跳过 N / 推送 N」）。
#[derive(Debug, Clone, Serialize)]
pub struct SyncRotateReport {
    /// 以新组密钥重新入账的凭据条数。
    pub rewrapped: u64,
    /// 因 legacy（无 wrapped item key）/解密失败跳过的条数——轮换后仍只有
    /// 旧组密文，对只有新信封的设备不可见。
    pub skipped: u64,
    /// 轮换全程（前置清队列 + 重包批次）push 出去的 op 总条数。
    pub pushed: u64,
}

impl From<persona_core::sync::runtime::SyncRotateReport> for SyncRotateReport {
    fn from(report: persona_core::sync::runtime::SyncRotateReport) -> Self {
        Self {
            rewrapped: report.rewrapped,
            skipped: report.skipped,
            pushed: report.pushed,
        }
    }
}

/// `sync_conflicts_list` 的单个版本视图：冲突条目的主位或副本
/// （字段与 core `resolve::ConflictVersion` 一一对应）。
#[derive(Debug, Clone, Serialize)]
pub struct SyncConflictVersion {
    /// 采纳时传给 `sync_conflict_resolve` 的 op id。
    pub op_id: String,
    /// 产生该版本的设备（前端据此标「本机/其他设备」）。
    pub device_id: String,
    pub lamport: u64,
    /// 仅展示，不参与裁决排序（LWW 只看 lamport + device）。
    pub timestamp: Option<String>,
    /// tombstone 版本：采纳 = 删除该条目；此时 `snapshot` 为空。
    pub deleted: bool,
    /// put 版本的解密快照（解锁会话内的明文，前端做版本对比）。
    pub snapshot: Option<persona_core::sync::snapshot::SyncItemSnapshot>,
}

/// `sync_conflicts_list` 的单条：一个条目的冲突视图（主位 + 待裁决副本）。
#[derive(Debug, Clone, Serialize)]
pub struct SyncConflictEntry {
    pub item_id: String,
    pub primary: SyncConflictVersion,
    pub copies: Vec<SyncConflictVersion>,
}

impl From<persona_core::sync::resolve::ConflictVersion> for SyncConflictVersion {
    fn from(version: persona_core::sync::resolve::ConflictVersion) -> Self {
        Self {
            op_id: version.op_id.to_string(),
            device_id: version.device_id.to_string(),
            lamport: version.lamport,
            timestamp: version.timestamp.map(|ts| ts.to_rfc3339()),
            deleted: version.deleted,
            snapshot: version.snapshot,
        }
    }
}

impl From<persona_core::sync::resolve::ConflictEntry> for SyncConflictEntry {
    fn from(entry: persona_core::sync::resolve::ConflictEntry) -> Self {
        Self {
            item_id: entry.item_id.to_string(),
            primary: entry.primary.into(),
            copies: entry.copies.into_iter().map(Into::into).collect(),
        }
    }
}

/// `sync_group_pairing_create` 返回：出码面（动态密码 + 邀请串 + 中转会话）。
#[derive(Debug, Clone, Serialize)]
pub struct SyncPairingCreateOutcome {
    /// 动态密码（9 位 Crockford base32；与对方人工核对的是它）。
    pub code: String,
    /// 邀请串 `persona-pair-1.<b64url>`（QR / 剪贴板递给 guest）。
    pub invite_link: String,
    /// 中转会话 id（前端不再关心，只用于 poll/cancel 定位会话）。
    pub session_id: String,
    /// 中转会话剩余有效期（秒；TTL 600，过期需重新出码）。
    pub expires_in_secs: i64,
}

/// `sync_group_pairing_poll` 返回：host 侧等待结果。
#[derive(Debug, Clone, Serialize)]
pub struct SyncPairingPollOutcome {
    /// 配对完成（组密钥已递交 guest 并落本机 keyring）。
    pub completed: bool,
    /// host 侧短指纹（6 位数字；完成时返回，与 guest 侧展示一致）。
    pub fingerprint: Option<String>,
}

/// `sync_group_join_begin` 返回：guest 输码面（指纹比对门禁前）。
#[derive(Debug, Clone, Serialize)]
pub struct SyncJoinBeginOutcome {
    /// guest 侧短指纹（6 位数字；与 host 端展示比对，一致才 confirm）。
    pub fingerprint: String,
    /// 邀请串里的动态密码（与用户手输的码应一致，多一层人工核对）。
    pub code: String,
    /// 中转会话 id（confirm/cancel 定位用）。
    pub session_id: String,
}
