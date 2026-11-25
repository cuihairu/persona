//! Device and group key envelope management plane: [`SyncAdminApi`] talks to `/devices` +
//! `/group-keys` (§6 device lifecycle); `SyncDevice`/`SyncGroupKeyEntry` are client-side
//! views of the server rows.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;

use super::http::SyncHttp;
use crate::{PersonaError, Result};

/// A registered device (client-side view of the server `sync_devices` row). `public_key` is already
/// base64-decoded — a bad value makes this layer error out rather than handing the caller a decoding problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDevice {
    pub id: Uuid,
    pub device_name: String,
    pub public_key: [u8; 32],
    pub created_at: String,
    /// The device owner's free-form remark (S4): only the device itself can write it; everyone can read it.
    pub remark: String,
}

/// A group key envelope entry (client-side view of the server `sync_group_keys` row).
/// Envelope bytes are kept verbatim (the input to `envelope::open_group_key`).
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
    /// The remark column was added later (migration 0011) — old servers do not send it, so serde default fills an empty string.
    #[serde(default)]
    remark: String,
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

#[derive(Debug, serde::Serialize)]
struct WirePutRemark<'a> {
    remark: &'a str,
}

/// The server also echoes device_name (always equal to the token's owning name, already known to the caller); not taken.
#[derive(Debug, serde::Deserialize)]
struct WireRemarkResponse {
    remark: String,
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

/// Management client for `/api/v1/sync/devices` + `/api/v1/sync/group-keys` —
/// register/list/revoke devices and exchange group key envelopes (DR-1/DR-3). The authorization flow is
/// assembled by the caller: unwrap the envelope only this device can open to get the group key → wrap a
/// new envelope with the new device's public key and upload it.
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

    /// Registers a device (public key + device name) and returns the server-assigned device_id.
    /// A duplicate name is 409 (a public key must not be silently replaced) — the error string includes the server's message.
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

    /// Lists all registered devices (including pending-authorization ones — devices whose envelope has not been uploaded).
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
                remark: wire.remark,
            });
        }
        Ok(devices)
    }

    /// Revokes a device (removes its registration and envelope; idempotent, 204). A known group key cannot be
    /// retroactively revoked (DR-3's honest boundary) — the notice text belongs to the caller.
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

    /// Sets **this device's** free-form remark (S4: token ownership is the device identity, with no cross-device
    /// path; the server locates the row by the token-owning device_name). An empty/whitespace-only string clears it.
    /// Returns the remark as normalized by the server (trimmed).
    pub async fn set_device_remark(&self, remark: &str) -> Result<String> {
        let resp = self
            .http
            .request(reqwest::Method::PUT, "/devices/remark")
            .json(&WirePutRemark { remark })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync set device remark failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "set device remark").await?;
        let body: WireRemarkResponse = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync remark response".to_string()))?;
        Ok(body.remark)
    }

    /// Fetches all device envelopes. The caller recognizes only the entry with its own device_id; an
    /// unauthorized device that fetches someone else's envelope cannot unwrap it anyway (fail-closed).
    pub async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>> {
        Ok(self.group_keys_with_epoch().await?.0)
    }

    /// [`Self::group_keys`] plus the group-wide rotation epoch (the baseline of the rotate-begin optimistic lock).
    /// When an old server has no epoch field, serde defaults to 0 — consistent with "never rotated"; if the
    /// server actually has a table, begin then naturally 409s and prompts a re-read, which is the safe direction.
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

    /// The rotation mutex point (E2EE_SYNC_DESIGN §11 open question 2): an epoch optimistic lock claim.
    /// Returns the new epoch after the claim; if another device rotated concurrently, a 409 →
    /// [`PersonaError::ConcurrentConflict`] (the caller aborts fail-closed — no envelopes written, no
    /// rewrapping — and can retry after re-reading the state).
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

    /// First-device bootstrap (creating a group from an empty one): when the server holds no group key
    /// envelopes at all, this device generates a group key, seals the single envelope with its own public key,
    /// and uploads it. A brand-new server has no "existing device" to authorize on its behalf — the token
    /// holder can already read all ciphertext anyway, so the first device forming the group does not enlarge
    /// the trust surface. Returns `true` = this device completed the bootstrap (i.e. is authorized);
    /// `false` = the group is non-empty and the existing flow (waiting for another device to authorize) applies.
    ///
    /// Known edge: two devices that each see an empty group before they can see each other will each form a
    /// group (concurrent bootstrap); each can only unwrap its own envelope, and the other's entries fail to
    /// open and are skipped under the tolerance policy — afterwards, leave from the duplicated side and redo
    /// the flow. Once every member leaves, the group returns to an empty state and the next joiner bootstraps
    /// a **new** group key: leftover old ciphertext on the server cannot be opened and is skipped entry by
    /// entry under the tolerance policy (without aborting the round); old data is never read back.
    pub async fn bootstrap_group_if_empty(
        &self,
        device_id: Uuid,
        device_public: &[u8; 32],
    ) -> Result<bool> {
        if !self.group_keys().await?.is_empty() {
            return Ok(false);
        }
        let group = crate::sync::keys::GroupKey::generate()?;
        let envelope = crate::sync::envelope::seal_group_key(group.as_bytes(), device_public)?;
        self.put_group_key(device_id, &envelope).await?;
        Ok(true)
    }

    /// Uploads a group key envelope for a device (an authorized action). The envelope must be sealed with the
    /// registered device's public key (the server validates 80 bytes + device existence; attaching to a ghost
    /// device fails closed).
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
