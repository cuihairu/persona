//! oplog 同步远端：[`HttpSyncRemote`] 走 `/api/v1/sync/oplog` 推拉与
//! 快照传输（`SyncRemote` trait 实现）。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::sync::engine::SyncRemote;
use crate::sync::oplog::SyncOp;

use super::http::SyncHttp;
use super::wire::{
    op_from_wire, op_to_wire, PullResponseWire, PushRequestWire, PushResponseWire,
    StatusResponseWire, WirePutSnapshot, WirePutSnapshotResponse, WireSnapshot,
};
use crate::{PersonaError, Result};

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

    async fn head_seq(&self) -> Result<i64> {
        let resp = self
            .http
            .request(reqwest::Method::GET, "/status")
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync status request failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "status").await?;
        let body: StatusResponseWire = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync status response".to_string()))?;
        Ok(body.head_seq)
    }

    async fn put_library_snapshot(
        &self,
        seq: i64,
        device_id: &str,
        ciphertext: &[u8],
    ) -> Result<u64> {
        let resp = self
            .http
            .request(reqwest::Method::PUT, "/snapshot")
            .json(&WirePutSnapshot {
                seq,
                device_id,
                ciphertext: B64.encode(ciphertext),
            })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync snapshot upload request failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "snapshot upload").await?;
        let body: WirePutSnapshotResponse = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync snapshot upload response".to_string()))?;
        if body.seq != seq {
            return Err(PersonaError::Io(format!(
                "sync snapshot upload response seq mismatch: sent {seq}, server reports {}",
                body.seq
            ))
            .into());
        }
        Ok(body.pruned_ops)
    }

    async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
        let resp = self
            .http
            .request(reqwest::Method::GET, "/snapshot")
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync snapshot fetch request failed: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // 404 的两个成因——新服务器尚无快照（code=absent）、老服务器
            // 没有此路由（code=not_found）——客户端行为收敛：都退回全量
            // 重放。两者都真实（老服务器确实无快照可取），不谎报也不误报。
            return Ok(None);
        }
        let resp = SyncHttp::ensure_success(resp, "snapshot fetch").await?;
        let body: WireSnapshot = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync snapshot response".to_string()))?;
        let ciphertext = B64.decode(&body.ciphertext).map_err(|_| {
            PersonaError::Io("malformed snapshot ciphertext (bad base64)".to_string())
        })?;
        Ok(Some((body.seq, ciphertext)))
    }
}

// ---- 设备与 group key 信封管理（§6 设备生命周期，desktop/CLI 共用）----
