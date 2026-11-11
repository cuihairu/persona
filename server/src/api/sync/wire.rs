use super::*;

// ---- wire 类型 ----
// 与 core/src/sync/oplog.rs 的 SyncOp 对齐；kind/checked 字段用 String 接，
// 逐条校验给出 422 + index（uuid 直接 typed 反序列化会把单条错误放大成
// 整批 400，不利于客户端定位）。

#[derive(Debug, Deserialize, Serialize)]
pub struct WireOp {
    pub op_id: String,
    pub item_id: String,
    pub kind: String,
    /// "put" | "delete"（delete = tombstone，payload 必空）
    pub op: String,
    pub lamport: u64,
    pub device_id: String,
    /// 客户端自报 rfc3339，仅展示——服务器不信任、不参与排序（DR-4）。
    pub timestamp: Option<String>,
    pub payload: Option<WirePayload>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WirePayload {
    /// base64（STANDARD，含 padding——与 core remote_http 同一引擎）。
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
    /// pull 游标（上次响应的 next_cursor）。
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
    /// X25519 公钥，base64（STANDARD），解码后必须恰 32 字节。
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
    /// 设备自备注（S4 设备面，仅本设备经 PUT /sync/devices/remark 可改自己的）。
    pub(crate) remark: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PutRemarkRequest {
    /// 自备注全文（≤ 128 字节，空串 = 清除）。
    pub(crate) remark: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceListResponse {
    pub(crate) devices: Vec<DeviceInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PutGroupKeyRequest {
    /// 信封归属的设备（必须已登记——fail-closed：信封不能挂幽灵设备）。
    pub(crate) device_id: String,
    /// persona-dev-env-1 信封（DR-1），base64，解码后恰 80 字节。
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
    /// 全组轮换代数（rotate-begin 乐观锁的基线；0006 迁移）。
    pub(crate) epoch: u64,
}

/// POST /sync/group-key/rotate-begin 请求：if_epoch = 客户端最近读到的
/// 代数。服务器 CAS（epoch = if_epoch 才允许 +1）——两台设备并发轮换时
/// 后到者 409 fail-closed 中止，不再覆盖先到者的信封族。
#[derive(Debug, Deserialize)]
pub struct RotateBeginRequest {
    pub(crate) if_epoch: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct RotateBeginResponse {
    /// 抢占成功后的当前代数（= if_epoch + 1）。
    pub(crate) epoch: u64,
}
