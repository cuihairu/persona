//! 同步远端的 HTTP 客户端（feature `remote-auth`）：把
//! [`super::engine::SyncRemote`] 接到 persona-server 的 `/api/v1/sync/oplog`。
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

/// 对 persona-server `/api/v1/sync/oplog` 的同步远端。token 每请求携带
/// （静态令牌或 SRP 短期令牌——服务器同一 `require_bearer`）。
#[derive(Clone)]
pub struct HttpSyncRemote {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl HttpSyncRemote {
    /// `base_url` 形如 `http://127.0.0.1:8080`（尾部 `/` 容忍）。请求超时
    /// 60s：单批最多 500 条 KB 级密文，要覆盖慢速链路，但远小于备份链的
    /// 300s。
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
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

#[async_trait::async_trait]
impl SyncRemote for HttpSyncRemote {
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
        let request = PushRequestWire {
            ops: ops.iter().map(op_to_wire).collect(),
        };
        let resp = self
            .http
            .post(self.url("/oplog"))
            .bearer_auth(&self.token)
            .json(&request)
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync push request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "push").await?;
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
            .get(self.url("/oplog"))
            .bearer_auth(&self.token)
            .query(&[("limit", limit.to_string())]);
        if let Some(cursor) = since {
            builder = builder.query(&[("since", cursor)]);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync pull request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "pull").await?;
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
