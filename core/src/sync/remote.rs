//! 同步远端的 HTTP 客户端（feature `remote-auth`）：[`super::engine::SyncRemote`]
//! 接 persona-server 的 `/api/v1/sync/oplog`（oplog 收发），[`SyncAdminApi`]
//! 接 `/devices` + `/group-keys`（设备登记/group key 信封，§6 设备生命周期）。
//! wire 契约的权威定义在 `server/src/api/sync.rs`：base64 STANDARD、错误
//! 包络 `{"error":{"code","message",…}}`。
//!
//! `Vec<u8>` 的 serde 默认是数字数组而非 base64 字符串，与服务器 wire 层
//! （`WirePayload` 收发 base64 文本）对不上——本模块用 [`WireOp`]/[`WirePayload`]
//! 中间结构手工转换，不直接序列化 `SyncOp`。
//!
//! 条目级损坏的容错口径（[`SyncRemote`] trait 约定）：pull 单条 op 解析
//! 失败（坏 UUID / 坏 base64 / put-delete 与 payload 形状矛盾）→ 跳过该条，
//! 不废整批。oplog 是 append-only 密文中继，一条损坏不应卡死其余条目的
//! 收敛；跳过只影响该条，不影响游标推进。push 侧载荷是本地刚产出的密文，
//! 无损坏路径。未知 `kind` → [`ItemKind::Unknown`] 落库（前向兼容，不跳过）。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use std::time::Duration;
use uuid::Uuid;

use super::engine::SyncRemote;
use super::oplog::{ItemKind, OpType, SyncOp, SyncPayload};
use crate::{PersonaError, Result};

// ---- wire 类型（与 server/src/api/sync.rs 的 WireOp/WirePayload 对齐）----

#[derive(Debug, serde::Deserialize)]
struct WirePayload {
    ciphertext: String,
    wrapped_item_key: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireOp {
    op_id: String,
    item_id: String,
    kind: String,
    op: String,
    lamport: u64,
    device_id: String,
    /// 服务器原样转发的 rfc3339，仅展示。
    timestamp: Option<String>,
    payload: Option<WirePayload>,
}

/// push 侧 wire op（只序列化，字段与 [`WireOp`] 相同但独立定义：
/// pull 侧的 kind 等字段对本端没有构造语义）。
#[derive(Debug, serde::Serialize)]
struct WireOpOut {
    op_id: String,
    item_id: String,
    kind: String,
    op: String,
    lamport: u64,
    device_id: String,
    timestamp: Option<String>,
    payload: Option<WirePayloadOut>,
}

#[derive(Debug, serde::Serialize)]
struct WirePayloadOut {
    ciphertext: String,
    wrapped_item_key: String,
}

#[derive(Debug, serde::Serialize)]
struct PushRequestWire {
    ops: Vec<WireOpOut>,
}

#[derive(Debug, serde::Deserialize)]
struct PushResponseWire {
    accepted: u64,
    duplicates: u64,
}

#[derive(Debug, serde::Deserialize)]
struct PullResponseWire {
    ops: Vec<WireOp>,
    next_cursor: Option<String>,
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

fn kind_from_wire(raw: &str) -> ItemKind {
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

fn op_to_wire(op: &SyncOp) -> WireOpOut {
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
fn op_from_wire(wire: WireOp) -> Option<SyncOp> {
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

/// 共享 HTTP 底座：base URL 归一、bearer 注入、非 2xx 统一转错。
/// [`HttpSyncRemote`]（oplog 推拉）与 [`SyncAdminApi`]（设备/信封管理）共用。
#[derive(Clone)]
struct SyncHttp {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl SyncHttp {
    /// `base_url` 形如 `http://127.0.0.1:8080`（尾部 `/` 容忍）。请求超时
    /// 60s：单批最多 500 条 KB 级密文，要覆盖慢速链路，但远小于备份链的
    /// 300s。
    fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                PersonaError::ConfigurationError(format!("HTTP client init failed: {e}"))
            })?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1/sync{path}", self.base_url)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, self.url(path))
            .bearer_auth(&self.token)
    }

    /// 非 2xx 统一转 [`PersonaError::Io`]：带状态码与服务器 error.message
    /// 摘要（无则省略）。401/503 语义（令牌过期 / API 未配置）由调用方按
    /// 状态码字符串自行提示——本层不区分重试策略。
    async fn ensure_success(resp: reqwest::Response, step: &str) -> Result<reqwest::Response> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            });
        match detail {
            Some(message) => Err(PersonaError::Io(format!(
                "sync {step} failed (HTTP {status}): {message}"
            ))
            .into()),
            None => Err(PersonaError::Io(format!("sync {step} failed (HTTP {status})")).into()),
        }
    }
}

/// 对 persona-server `/api/v1/sync/oplog` 的同步远端。token 每请求携带
/// （静态令牌或 SRP 短期令牌——服务器同一 `require_bearer`）。
#[derive(Clone)]
pub struct HttpSyncRemote {
    http: SyncHttp,
}

impl HttpSyncRemote {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: SyncHttp::new(base_url, token)?,
        })
    }
}

#[async_trait::async_trait]
impl SyncRemote for HttpSyncRemote {
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
        let request = PushRequestWire {
            ops: ops.iter().map(op_to_wire).collect(),
        };
        let resp = self
            .http
            .request(reqwest::Method::POST, "/oplog")
            .json(&request)
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync push request failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "push").await?;
        let body: PushResponseWire = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync push response".to_string()))?;
        Ok((body.accepted, body.duplicates))
    }

    async fn pull_ops(
        &self,
        since: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<SyncOp>, Option<String>)> {
        let mut builder = self
            .http
            .request(reqwest::Method::GET, "/oplog")
            .query(&[("limit", limit.to_string())]);
        if let Some(cursor) = since {
            builder = builder.query(&[("since", cursor)]);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync pull request failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "pull").await?;
        let body: PullResponseWire = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync pull response".to_string()))?;
        let mut ops = Vec::with_capacity(body.ops.len());
        for wire in body.ops {
            if let Some(op) = op_from_wire(wire) {
                ops.push(op);
            }
            // else：条目级损坏，跳过（模块文档的容错口径）
        }
        Ok((ops, body.next_cursor))
    }
}

// ---- 设备与 group key 信封管理（§6 设备生命周期，desktop/CLI 共用）----

/// 已登记设备（server `sync_devices` 行的客户端视图）。`public_key` 已解
/// base64——坏值让本层报错，不让调用方处理编码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDevice {
    pub id: Uuid,
    pub device_name: String,
    pub public_key: [u8; 32],
    pub created_at: String,
}

/// group key 信封条目（server `sync_group_keys` 行的客户端视图）。
/// 信封字节保持原样（`envelope::open_group_key` 的输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncGroupKeyEntry {
    pub device_id: Uuid,
    pub envelope: Vec<u8>,
    pub sealed_by: String,
    pub created_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireDeviceInfo {
    id: String,
    device_name: String,
    public_key: String,
    created_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireDeviceList {
    devices: Vec<WireDeviceInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct WireGroupKeyEntry {
    device_id: String,
    envelope: String,
    sealed_by: String,
    created_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireGroupKeys {
    keys: Vec<WireGroupKeyEntry>,
    #[serde(default)]
    epoch: u64,
}

#[derive(Debug, serde::Serialize)]
struct WireRotateBegin {
    if_epoch: u64,
}

#[derive(Debug, serde::Deserialize)]
struct WireRotateBeginResponse {
    epoch: u64,
}

#[derive(Debug, serde::Serialize)]
struct WireRegisterDevice<'a> {
    device_name: &'a str,
    public_key: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireRegisterDeviceResponse {
    device_id: String,
}

#[derive(Debug, serde::Serialize)]
struct WirePutGroupKey<'a> {
    device_id: String,
    envelope: &'a str,
}

fn decode_b32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = B64
        .decode(s)
        .map_err(|_| PersonaError::Io(format!("malformed {what} in sync response (bad base64)")))?;
    let key: [u8; 32] = bytes.try_into().map_err(|_: Vec<u8>| {
        PersonaError::Io(format!("malformed {what} in sync response (bad length)"))
    })?;
    Ok(key)
}

/// `/api/v1/sync/devices` + `/api/v1/sync/group-keys` 的管理客户端——
/// 注册/列出/吊销设备、收发 group key 信封（DR-1/DR-3）。授权流在调用方
/// 组装：拆自己可开的信封得 group key → 用新设备公钥包新信封上传。
#[derive(Clone)]
pub struct SyncAdminApi {
    http: SyncHttp,
}

impl SyncAdminApi {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: SyncHttp::new(base_url, token)?,
        })
    }

    /// 登记设备（公钥 + 设备名），返回服务器分配的 device_id。
    /// 重名 409（公钥不可被静默替换）——错误串含服务器 message。
    pub async fn register_device(&self, device_name: &str, public_key: &[u8; 32]) -> Result<Uuid> {
        let resp = self
            .http
            .request(reqwest::Method::POST, "/devices")
            .json(&WireRegisterDevice {
                device_name,
                public_key: B64.encode(public_key),
            })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync register request failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "register device").await?;
        let body: WireRegisterDeviceResponse = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync register response".to_string()))?;
        let device_id = Uuid::parse_str(&body.device_id).map_err(|_| {
            PersonaError::Io("malformed device_id in sync register response".to_string())
        })?;
        Ok(device_id)
    }

    /// 列出全部已登记设备（含待授权的——信封未上传的设备）。
    pub async fn list_devices(&self) -> Result<Vec<SyncDevice>> {
        let resp = self
            .http
            .request(reqwest::Method::GET, "/devices")
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync list devices failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "list devices").await?;
        let body: WireDeviceList = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync device list".to_string()))?;
        let mut devices = Vec::with_capacity(body.devices.len());
        for wire in body.devices {
            let id = Uuid::parse_str(&wire.id).map_err(|_| {
                PersonaError::Io("malformed device id in sync device list".to_string())
            })?;
            let public_key = decode_b32(&wire.public_key, "device public_key")?;
            devices.push(SyncDevice {
                id,
                device_name: wire.device_name,
                public_key,
                created_at: wire.created_at,
            });
        }
        Ok(devices)
    }

    /// 吊销设备（删登记与其信封；幂等，204）。已知的 group key 不可追溯
    /// 撤销（DR-3 诚实边界）——提示文案归调用方。
    pub async fn delete_device(&self, device_id: Uuid) -> Result<()> {
        let resp = self
            .http
            .request(reqwest::Method::DELETE, &format!("/devices/{device_id}"))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync revoke device failed: {e}")))?;
        SyncHttp::ensure_success(resp, "revoke device").await?;
        Ok(())
    }

    /// 取全部设备信封。调用方只认自己 device_id 的那条；未授权设备拿到
    /// 别人的信封也拆不开（fail-closed）。
    pub async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>> {
        Ok(self.group_keys_with_epoch().await?.0)
    }

    /// [`Self::group_keys`] + 全组轮换代数（rotate-begin 乐观锁的基线）。
    /// 老服务器无 epoch 字段时 serde default 到 0——与「从未轮换过」一致，
    /// begin 时若服务器实际有表则自然 409 提示重读，方向安全。
    pub async fn group_keys_with_epoch(&self) -> Result<(Vec<SyncGroupKeyEntry>, u64)> {
        let resp = self
            .http
            .request(reqwest::Method::GET, "/group-keys")
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync get group keys failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "get group keys").await?;
        let body: WireGroupKeys = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync group keys".to_string()))?;
        let mut keys = Vec::with_capacity(body.keys.len());
        for wire in body.keys {
            let device_id = Uuid::parse_str(&wire.device_id).map_err(|_| {
                PersonaError::Io("malformed device_id in sync group keys".to_string())
            })?;
            let envelope = B64.decode(&wire.envelope).map_err(|_| {
                PersonaError::Io("malformed envelope in sync group keys (bad base64)".to_string())
            })?;
            keys.push(SyncGroupKeyEntry {
                device_id,
                envelope,
                sealed_by: wire.sealed_by,
                created_at: wire.created_at,
            });
        }
        Ok((keys, body.epoch))
    }

    /// 轮换互斥点（E2EE_SYNC_DESIGN §11 开放问题 2）：epoch 乐观锁抢占。
    /// 返回抢占后的新代数；另一台设备已并发轮换时 409 →
    /// [`PersonaError::ConcurrentConflict`]（调用方 fail-closed 中止，
    /// 未写任何信封、未重包，重读状态后可重试）。
    pub async fn begin_group_rotation(&self, if_epoch: u64) -> Result<u64> {
        let resp = self
            .http
            .request(reqwest::Method::POST, "/group-key/rotate-begin")
            .json(&WireRotateBegin { if_epoch })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync rotate begin failed: {e}")))?;
        if resp.status() == reqwest::StatusCode::CONFLICT {
            return Err(PersonaError::ConcurrentConflict(
                "group key rotation lost the race: another device rotated concurrently; \
                 re-sync and retry"
                    .to_string(),
            )
            .into());
        }
        let resp = SyncHttp::ensure_success(resp, "rotate begin").await?;
        let body: WireRotateBeginResponse = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed rotate begin response".to_string()))?;
        Ok(body.epoch)
    }

    /// 首设备自举（空组建组）：服务器上尚无任何 group key 信封时，本机生成
    /// group key 并用自己的公钥封唯一信封上传。全新服务器上不存在「既有
    /// 设备」可代为授权——令牌持有者本来就能读到全部密文，首台设备自建组
    /// 不放大信任面。返回 `true` = 本机完成自举（即已授权）；`false` = 组
    /// 非空，走既有流程等他机授权。
    ///
    /// 已知边界：两台设备在彼此可见前先后见到空组会各自建组（并发自举），
    /// 各自只能拆开自己的信封、对方条目解不开按容错跳过——事后在重复的
    /// 一侧 leave 重走即可。全员离开后组回到空态，下一个加入者自举出
    /// **新**组密钥：服务器残留的旧组密文解不开、按容错逐条跳过（不废
    /// 整轮），不回读旧数据。
    pub async fn bootstrap_group_if_empty(
        &self,
        device_id: Uuid,
        device_public: &[u8; 32],
    ) -> Result<bool> {
        if !self.group_keys().await?.is_empty() {
            return Ok(false);
        }
        let group = super::keys::GroupKey::generate()?;
        let envelope = super::envelope::seal_group_key(group.as_bytes(), device_public);
        self.put_group_key(device_id, &envelope).await?;
        Ok(true)
    }

    /// 为设备上传 group key 信封（授权动作）。信封必须已登记设备的公钥封出
    /// （服务器校验 80 字节 + 设备存在；挂幽灵设备 fail-closed）。
    pub async fn put_group_key(&self, device_id: Uuid, envelope: &[u8]) -> Result<()> {
        let resp = self
            .http
            .request(reqwest::Method::PUT, "/group-keys")
            .json(&WirePutGroupKey {
                device_id: device_id.to_string(),
                envelope: &B64.encode(envelope),
            })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync put group key failed: {e}")))?;
        SyncHttp::ensure_success(resp, "put group key").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_put() -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            kind: ItemKind::Credential,
            op: OpType::Put,
            lamport: 7,
            device_id: Uuid::new_v4(),
            timestamp: Some(
                DateTime::parse_from_rfc3339("2026-09-22T12:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            payload: Some(SyncPayload {
                ciphertext: vec![1, 2, 3, 4],
                wrapped_item_key: vec![5; 32],
            }),
        }
    }

    fn sample_delete() -> SyncOp {
        SyncOp {
            op: OpType::Delete,
            payload: None,
            ..sample_put()
        }
    }

    fn wire_to_op(wire: WireOpOut) -> Option<SyncOp> {
        // WireOpOut 与 WireOp 字段同形，经 JSON 往返保证测试与真实 wire 一致
        let json = serde_json::to_value(&wire).unwrap();
        let parsed: WireOp = serde_json::from_value(json).unwrap();
        op_from_wire(parsed)
    }

    #[test]
    fn wire_round_trip_preserves_put() {
        let op = sample_put();
        let back = wire_to_op(op_to_wire(&op)).unwrap();
        assert_eq!(back, op);
    }

    #[test]
    fn wire_round_trip_preserves_delete_tombstone() {
        let op = sample_delete();
        let back = wire_to_op(op_to_wire(&op)).unwrap();
        assert_eq!(back, op);
        assert!(back.is_tombstone());
    }

    #[test]
    fn unknown_kind_survives_wire_as_unknown() {
        let mut op = sample_put();
        op.kind = ItemKind::Unknown;
        let back = wire_to_op(op_to_wire(&op)).unwrap();
        assert_eq!(back.kind, ItemKind::Unknown);

        // 前向兼容主场景：未来客户端的新 kind 字符串 → Unknown，不跳过
        assert_eq!(kind_from_wire("totp_seed_v9"), ItemKind::Unknown);
    }

    #[test]
    fn corrupt_entries_are_skipped_not_fatal() {
        // 坏 UUID
        let mut wire = op_to_wire(&sample_put());
        wire.op_id = "not-a-uuid".to_string();
        assert!(op_from_wire(to_in(wire)).is_none());

        // 坏 base64 载荷
        let mut wire = op_to_wire(&sample_put());
        wire.payload.as_mut().unwrap().ciphertext = "!!!".to_string();
        assert!(op_from_wire(to_in(wire)).is_none());

        // put 无载荷 / delete 带载荷：形状矛盾
        let mut wire = op_to_wire(&sample_put());
        wire.payload = None;
        assert!(op_from_wire(to_in(wire)).is_none());
        let mut wire = op_to_wire(&sample_delete());
        wire.payload = Some(WirePayloadOut {
            ciphertext: "AAAA".to_string(),
            wrapped_item_key: "AAAA".to_string(),
        });
        assert!(op_from_wire(to_in(wire)).is_none());

        // 未知 op 类型字符串
        let mut wire = op_to_wire(&sample_put());
        wire.op = "merge".to_string();
        assert!(op_from_wire(to_in(wire)).is_none());
    }

    fn to_in(out: WireOpOut) -> WireOp {
        let json = serde_json::to_value(&out).unwrap();
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn bad_timestamp_degrades_to_none_not_skip() {
        let mut wire = op_to_wire(&sample_put());
        wire.timestamp = Some("yesterday-ish".to_string());
        let back = op_from_wire(to_in(wire)).unwrap();
        assert_eq!(back.timestamp, None);
    }
}
