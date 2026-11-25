//! Oplog wire types and base64 (de)coding: the [`WirePayload`]/[`WireOp`] families and the hand-written
//! conversions to/from [`SyncOp`] (serde's default `Vec<u8>` number array does not match the server's
//! base64 text contract — see the module docs).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::sync::oplog::{ItemKind, OpType, SyncOp, SyncPayload};

// ---- wire types (aligned with WireOp/WirePayload in server/src/api/sync.rs) ----

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
    /// The rfc3339 the server forwards verbatim, display only.
    pub(super) timestamp: Option<String>,
    pub(super) payload: Option<WirePayload>,
}

/// Wire op for the push side (serialize only, same fields as [`WireOp`] but defined separately:
/// pull-side kind and similar fields carry no construction semantics for this end).
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

/// `GET /sync/status`: the group instruction stream high-water mark (§2.5.5). An old server (without this
/// route) returns 404 → this layer reports the error as-is and the status display degrades to unavailable,
/// rather than falsely reporting 0.
#[derive(Debug, serde::Deserialize)]
pub(super) struct StatusResponseWire {
    pub(super) head_seq: i64,
}

// ---- Vault-level snapshot wire (S2, aligned with server PutSnapshotRequest/PutSnapshotResponse:
// ciphertext is base64 text — serde's default Vec<u8> is a number array that does not match the server's
// base64 wire, so (de)coding is done by hand) ----

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
        // Round trip for forward compatibility: an unknown kind never produces a local write (see the oplog module docs)
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

/// Wire op → SyncOp. If any field is unparsable → `None` (the caller skips that entry).
pub(super) fn op_from_wire(wire: WireOp) -> Option<SyncOp> {
    let op_id = Uuid::parse_str(&wire.op_id).ok()?;
    let item_id = Uuid::parse_str(&wire.item_id).ok()?;
    let device_id = Uuid::parse_str(&wire.device_id).ok()?;
    let op = op_type_from_wire(&wire.op)?;
    // Payload shape invariant (guaranteed by the server's validate_op; defended here against storage-side corruption):
    // a put always carries a payload, a delete (tombstone) never does
    let payload = match (op, wire.payload) {
        (OpType::Put, Some(raw)) => Some(SyncPayload {
            ciphertext: B64.decode(&raw.ciphertext).ok()?,
            wrapped_item_key: B64.decode(&raw.wrapped_item_key).ok()?,
        }),
        (OpType::Delete, None) => None,
        _ => return None,
    };
    // Timestamp is display only: on a parse failure it degrades to None rather than dropping the op
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
