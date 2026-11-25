//! Oplog sync remote: [`HttpSyncRemote`] handles `/api/v1/sync/oplog` push/pull and
//! snapshot transfer (the `SyncRemote` trait implementation).

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

/// Sync remote against persona-server's `/api/v1/sync/oplog`. The token is sent with every request
/// (a static token or an SRP short-lived token — the server uses the same `require_bearer`).
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
            // else: per-entry corruption, skip it (the tolerance policy from the module docs)
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
            // Two causes of a 404 — a new server with no snapshot yet (code=absent), or an old server
            // without this route (code=not_found) — converge into one client behavior: fall back to a full
            // replay in both cases. Both are truthful (an old server really has no snapshot to fetch);
            // nothing is falsely claimed or misreported.
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

// ---- Device and group key envelope management (§6 device lifecycle, shared by desktop/CLI) ----
