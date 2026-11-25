use super::*;

// ---- Wire types ----
// Aligned with SyncOp in core/src/sync/oplog.rs; the kind/checked fields are accepted as
// String and validated per entry to yield 422 + index (directly typed-deserializing a
// UUID would amplify a single bad entry into a whole-batch 400, which makes it harder
// for clients to pinpoint the problem).

#[derive(Debug, Deserialize, Serialize)]
pub struct WireOp {
    pub op_id: String,
    pub item_id: String,
    pub kind: String,
    /// "put" | "delete" (delete = tombstone, payload must be empty)
    pub op: String,
    pub lamport: u64,
    pub device_id: String,
    /// Client-reported rfc3339, display only — the server does not trust it and it
    /// takes no part in ordering (DR-4).
    pub timestamp: Option<String>,
    pub payload: Option<WirePayload>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WirePayload {
    /// base64 (STANDARD, padding included — the same engine as core's remote_http).
    pub ciphertext: String,
    pub wrapped_item_key: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PushResponse {
    pub(crate) accepted: u64,
    pub(crate) duplicates: u64,
}

#[derive(Debug, Deserialize)]
pub struct PushRequest {
    pub(crate) ops: Vec<WireOp>,
}

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    pub(crate) limit: Option<u32>,
    /// Pull cursor (the previous response's next_cursor).
    pub(crate) since: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PullResponse {
    pub(crate) ops: Vec<WireOp>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub(crate) device_name: String,
    /// X25519 public key, base64 (STANDARD); must decode to exactly 32 bytes.
    pub(crate) public_key: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegisterDeviceResponse {
    pub(crate) device_id: Uuid,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceInfo {
    pub(crate) id: Uuid,
    pub(crate) device_name: String,
    pub(crate) public_key: String,
    pub(crate) created_at: String,
    /// The device's own remark (S4 device surface; only the device itself can change it,
    /// via PUT /sync/devices/remark).
    pub(crate) remark: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PutRemarkRequest {
    /// The full remark text (at most 128 bytes; an empty string clears it).
    pub(crate) remark: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceListResponse {
    pub(crate) devices: Vec<DeviceInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PutGroupKeyRequest {
    /// The device the envelope belongs to (must already be registered — fail-closed: an
    /// envelope may not be attached to a ghost device).
    pub(crate) device_id: String,
    /// persona-dev-env-1 envelope (DR-1), base64; must decode to exactly 80 bytes.
    pub(crate) envelope: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GroupKeyEntry {
    pub(crate) device_id: Uuid,
    pub(crate) envelope: String,
    pub(crate) sealed_by: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GroupKeysResponse {
    pub(crate) keys: Vec<GroupKeyEntry>,
    /// The group-wide rotation generation (the baseline for rotate-begin's optimistic
    /// lock; migration 0006).
    pub(crate) epoch: u64,
}

/// POST /sync/group-key/rotate-begin request: if_epoch = the generation the client most
/// recently read. The server CASes (epoch +1 is allowed only when epoch = if_epoch) — when
/// two devices rotate concurrently, the latecomer gets a 409 fail-closed abort instead of
/// overwriting the first arriver's envelope family.
#[derive(Debug, Deserialize)]
pub struct RotateBeginRequest {
    pub(crate) if_epoch: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct RotateBeginResponse {
    /// The current generation after a successful preemption (= if_epoch + 1).
    pub(crate) epoch: u64,
}
