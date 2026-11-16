//! oplog 线路类型与 base64 编解码：[`WirePayload`]/[`WireOp`] 系列与
//! [`SyncOp`] 的手工互转（serde 默认的 `Vec<u8>` 数字数组与服务器 base64
//! 文本契约对不上，见模块文档）。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::sync::oplog::{ItemKind, OpType, SyncOp, SyncPayload};

// ---- wire 类型（与 server/src/api/sync.rs 的 WireOp/WirePayload 对齐）----

#[derive(Debug, serde::Deserialize)]
pub(super) struct WirePayload {
    pub(super) ciphertext: String,
    pub(super) wrapped_item_key: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct WireOp {
    pub(super) op_id: String,
    pub(super) item_id: String,
    pub(super) kind: String,
    pub(super) op: String,
    pub(super) lamport: u64,
    pub(super) device_id: String,
    /// 服务器原样转发的 rfc3339，仅展示。
    pub(super) timestamp: Option<String>,
    pub(super) payload: Option<WirePayload>,
}

/// push 侧 wire op（只序列化，字段与 [`WireOp`] 相同但独立定义：
/// pull 侧的 kind 等字段对本端没有构造语义）。
#[derive(Debug, serde::Serialize)]
pub(super) struct WireOpOut {
    pub(super) op_id: String,
    pub(super) item_id: String,
    pub(super) kind: String,
    pub(super) op: String,
    pub(super) lamport: u64,
    pub(super) device_id: String,
    pub(super) timestamp: Option<String>,
    pub(super) payload: Option<WirePayloadOut>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct WirePayloadOut {
    pub(super) ciphertext: String,
    pub(super) wrapped_item_key: String,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct PushRequestWire {
    pub(super) ops: Vec<WireOpOut>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PushResponseWire {
    pub(super) accepted: u64,
    pub(super) duplicates: u64,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PullResponseWire {
    pub(super) ops: Vec<WireOp>,
    pub(super) next_cursor: Option<String>,
}

/// `GET /sync/status`：组指令流水位（§二.5.5）。旧 server（无此路由）
/// 返回 404 → 本层如实报错，状态显示降级为不可用，不谎报 0。
#[derive(Debug, serde::Deserialize)]
pub(super) struct StatusResponseWire {
    pub(super) head_seq: i64,
}

// ---- 库级快照 wire（S2，与 server PutSnapshotRequest/PutSnapshotResponse
// 对齐：ciphertext 是 base64 文本——Vec<u8> 的 serde 默认是数字数组，
// 与服务器 base64 wire 对不上，手工编解码）----

#[derive(Debug, serde::Serialize)]
pub(super) struct WirePutSnapshot<'a> {
    pub(super) seq: i64,
    pub(super) device_id: &'a str,
    pub(super) ciphertext: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct WirePutSnapshotResponse {
    pub(super) seq: i64,
    pub(super) pruned_ops: u64,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct WireSnapshot {
    pub(super) seq: i64,
    pub(super) ciphertext: String,
}

fn kind_to_wire(kind: ItemKind) -> String {
    match kind {
        ItemKind::Credential => "credential".to_string(),
        ItemKind::Identity => "identity".to_string(),
        ItemKind::Passkey => "passkey".to_string(),
        // 前向兼容的折返：未知 kind 本就不产生本地写（见 oplog 模块文档）
        ItemKind::Unknown => "unknown".to_string(),
    }
}

pub(super) fn kind_from_wire(raw: &str) -> ItemKind {
    match raw {
        "credential" => ItemKind::Credential,
        "identity" => ItemKind::Identity,
        "passkey" => ItemKind::Passkey,
        _ => ItemKind::Unknown,
    }
}

fn op_type_from_wire(raw: &str) -> Option<OpType> {
    match raw {
        "put" => Some(OpType::Put),
        "delete" => Some(OpType::Delete),
        _ => None,
    }
}

pub(super) fn op_to_wire(op: &SyncOp) -> WireOpOut {
    WireOpOut {
        op_id: op.op_id.to_string(),
        item_id: op.item_id.to_string(),
        kind: kind_to_wire(op.kind),
        op: match op.op {
            OpType::Put => "put",
            OpType::Delete => "delete",
        }
        .to_string(),
        lamport: op.lamport,
        device_id: op.device_id.to_string(),
        timestamp: op.timestamp.map(|t| t.to_rfc3339()),
        payload: op.payload.as_ref().map(|p| WirePayloadOut {
            ciphertext: B64.encode(&p.ciphertext),
            wrapped_item_key: B64.encode(&p.wrapped_item_key),
        }),
    }
}

/// wire op → SyncOp。任何一处不可解析 → `None`（调用方跳过该条）。
pub(super) fn op_from_wire(wire: WireOp) -> Option<SyncOp> {
    let op_id = Uuid::parse_str(&wire.op_id).ok()?;
    let item_id = Uuid::parse_str(&wire.item_id).ok()?;
    let device_id = Uuid::parse_str(&wire.device_id).ok()?;
    let op = op_type_from_wire(&wire.op)?;
    // payload 形状不变量（服务器 validate_op 已保证，这里防存储侧错乱）：
    // put 恒有载荷，delete（tombstone）恒无载荷
    let payload = match (op, wire.payload) {
        (OpType::Put, Some(raw)) => Some(SyncPayload {
            ciphertext: B64.decode(&raw.ciphertext).ok()?,
            wrapped_item_key: B64.decode(&raw.wrapped_item_key).ok()?,
        }),
        (OpType::Delete, None) => None,
        _ => return None,
    };
    // timestamp 仅展示：解析失败降级为 None，不因此丢弃 op
    let timestamp = wire
        .timestamp
        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
        .map(|t| t.with_timezone(&Utc));
    Some(SyncOp {
        op_id,
        item_id,
        kind: kind_from_wire(&wire.kind),
        op,
        lamport: wire.lamport,
        device_id,
        timestamp,
        payload,
    })
}
