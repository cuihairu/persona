//! Cloud-drive transport (Phase 2): `CloudDriveRemote` implements [`SyncRemote`] against the local
//! cloud-drive sync directory (the local sync folder of iCloud Drive / Dropbox / Google Drive, where the
//! OS cloud agent handles cross-device distribution), and `CloudGroupKeyStore` implements [`GroupKeyStore`]
//! against the same directory (a device registry + one group key envelope file per device).
//!
//! **Transport red line** (`docs/STORAGE_AND_SYNC.md` §cloud drive): the cloud-drive directory holds
//! **encrypted artifacts** only — never a live `identities.db` (the SQLite WAL companion files would be
//! corrupted by bidirectional cloud sync). This module writes only instruction shards (oplog ciphertext
//! rows), snapshots (the group-key-encrypted whole package), and envelopes (X25519 sealed) — all ciphertext;
//! the vault snapshot is produced self-consistently as a single file by the host's `VACUUM INTO` (the same
//! source as the backup chain).
//!
//! **Semantic differences from the HTTP transport (honestly documented)**:
//! - **Oplog shards are physically compacted only up to a group-wide safe watermark.** After a snapshot
//!   upload, the server deletes `seq ≤ S` ops in the same transaction (compaction); the cloud drive has no
//!   cross-device transaction, so it rewrites each shard locally, dropping only the prefix every registered
//!   device has reported consumed (a device with no committed watermark blocks compaction — fail-closed).
//!   When no safe prefix exists `put_library_snapshot` returns 0 (shards unchanged).
//! - **The cursor is a per-shard row-count watermark** (`{"<device>": rows, …}`), not a global rank.
//!   A rank cursor would skip "late-arriving ops with a smaller lamport" (device B comes back offline and
//!   writes ops with lower lamport that land before an already-consumed rank) — the row-count watermark
//!   reads the full shard delta and then merges by `(lamport, device_id, op_id)`, never skipping.
//! - **pull ignores limit**: the cloud drive is a local file read, so it returns the entire shard delta (one
//!   page at a time); the engine's "stop only on an empty page" loop semantics naturally converge.
//!
//! **The cursor reuses the canonical format**: the watermark is encoded into the `op_id` slot of
//! `v1:{sum}:{map}` (`sum` = consumed row count, `map` = per-shard row-count JSON). `local_watermark`
//! reads only `sum` (consumed rows = deduplicated op count, since op_id is globally unique across shards),
//! and `SNAPSHOT_RESUME_OP_ID="0"` (the cursor written by the engine after installing a snapshot) decodes
//! to an empty map = a full read — the `sum` slot keeps its semantics, `decode_cursor` only validates that
//! `op_id` is non-empty, and the JSON inside the slot is not interpreted by any existing consumer (verified:
//! engine/tests only take `.0`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;

use super::admin::SyncGroupKeyEntry;
use super::group_key_store::GroupKeyStore;
use crate::sync::device::DeviceIdentity;
use crate::sync::engine::SyncRemote;
use crate::sync::oplog::SyncOp;
use crate::{PersonaError, Result};

/// Cloud-drive shard filename prefix/suffix (`dev-<device_id>.jsonl`).
const SHARD_PREFIX: &str = "dev-";
const SHARD_SUFFIX: &str = ".jsonl";
/// Snapshot filename prefix/suffix (`snapshot-<seq>-<device_id>.bin`).
const SNAPSHOT_PREFIX: &str = "snapshot-";
const SNAPSHOT_SUFFIX: &str = ".bin";
/// Envelope filename (`env-<device_id>.bin`).
const ENV_PREFIX: &str = "env-";
const ENV_SUFFIX: &str = ".bin";
/// Device registry filename.
const REGISTRY_FILE: &str = "registry.json";
/// Per-device committed pull watermark filename (`watermark-<device_id>.json`). Published by a device only
/// after its pull cycle has **persisted** the ops (the engine commits the cursor after landing ops), so a
/// watermark is a durable "I have consumed the first N rows of every shard" claim.
const WATERMARK_PREFIX: &str = "watermark-";
const WATERMARK_SUFFIX: &str = ".json";
/// Per-shard compaction base (`base-<device_id>.json`): the number of leading rows
/// physically removed from a shard. Cursor watermarks are expressed in **logical**
/// coordinates (original row numbers, never decreased), so a compaction can drop
/// physical rows without shifting any device's cursor — the base is subtracted
/// only when indexing the physical file.
const BASE_PREFIX: &str = "base-";
const BASE_SUFFIX: &str = ".json";

/// [`SyncRemote`] over a cloud-drive directory. `device_id` is this device (it decides which
/// shard push writes to). Every file operation is a local atomic write (temp + fsync + rename), so the
/// cloud sync agent never sees a half-written shard.
pub struct CloudDriveRemote {
    dir: PathBuf,
    device_id: Uuid,
}

impl CloudDriveRemote {
    pub fn new(dir: impl Into<PathBuf>, device_id: Uuid) -> Self {
        Self {
            dir: dir.into(),
            device_id,
        }
    }
}

/// [`GroupKeyStore`] over a cloud-drive directory: `registry.json` (device registry) +
/// `env-<device_id>.bin` (one group key envelope per device) + `env-<device_id>.meta.json`
/// (sealed_by/created_at metadata).
pub struct CloudGroupKeyStore {
    dir: PathBuf,
}

impl CloudGroupKeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

// ---------------------------------------------------------------------------
// Device registry + envelopes (GroupKeyStore)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct CloudRegistry {
    #[serde(default)]
    devices: Vec<CloudDevice>,
}

/// One record of the cloud-drive device registry (consumed by the host's device listing / for the
/// authorization target's public key).
///
/// `public_key` is the base64 X25519 public key — the authorizing device uses it to reseal the group key
/// envelope (same meaning as the server-side [`crate::sync::remote::SyncDevice::public_key`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CloudDevice {
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub remark: String,
}

async fn read_registry(dir: &Path) -> Result<CloudRegistry> {
    let path = dir.join(REGISTRY_FILE);
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CloudRegistry::default()),
        Err(e) => return Err(PersonaError::Io(format!("read sync registry failed: {e}")).into()),
    };
    let registry: CloudRegistry = serde_json::from_str(&text)
        .map_err(|e| PersonaError::Io(format!("malformed sync registry {REGISTRY_FILE}: {e}")))?;
    Ok(registry)
}

async fn write_registry(dir: &Path, registry: &CloudRegistry) -> Result<()> {
    let text = serde_json::to_vec_pretty(registry)
        .map_err(|e| PersonaError::Io(format!("encode sync registry failed: {e}")))?;
    atomic_write(dir, REGISTRY_FILE, &text).await
}

/// Atomic write: temp file in the same directory + fsync + rename (the cloud agent only ever sees complete files).
async fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| PersonaError::Io(format!("create cloud drive dir failed: {e}")))?;
    let tmp = dir.join(format!(".{name}.tmp-{}", Uuid::new_v4()));
    tokio::fs::write(&tmp, bytes)
        .await
        .map_err(|e| PersonaError::Io(format!("write temp file failed: {e}")))?;
    if let Ok(f) = tokio::fs::File::open(&tmp).await {
        let _ = f.sync_all().await;
    }
    tokio::fs::rename(&tmp, dir.join(name))
        .await
        .map_err(|e| PersonaError::Io(format!("rename temp file failed: {e}")))?;
    Ok(())
}

/// Reads a string field from the meta JSON (missing/corrupt meta returns the default).
async fn meta_string(dir: &Path, device_id: Uuid, field: &str, default: String) -> String {
    let path = dir.join(format!("{ENV_PREFIX}{device_id}.meta.json"));
    match tokio::fs::read_to_string(&path).await {
        Ok(text) => serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get(field).and_then(|x| x.as_str()).map(String::from))
            .unwrap_or(default),
        Err(_) => default,
    }
}

#[async_trait]
impl GroupKeyStore for CloudGroupKeyStore {
    async fn register_device(&self, identity: &DeviceIdentity) -> Result<()> {
        let mut registry = read_registry(&self.dir).await?;
        if registry
            .devices
            .iter()
            .any(|d| d.device_id == identity.device_id.to_string())
        {
            return Ok(()); // Idempotent: re-registering the same device has no side effects
        }
        if registry
            .devices
            .iter()
            .any(|d| d.device_name == identity.device_name)
        {
            return Err(PersonaError::InvalidInput(format!(
                "device name '{}' already registered in cloud sync group",
                identity.device_name
            ))
            .into());
        }
        registry.devices.push(CloudDevice {
            device_id: identity.device_id.to_string(),
            device_name: identity.device_name.clone(),
            public_key: B64.encode(identity.key_pair.public_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
            remark: String::new(),
        });
        write_registry(&self.dir, &registry).await
    }

    async fn put_group_key(&self, device_id: Uuid, envelope: &[u8]) -> Result<()> {
        let registry = read_registry(&self.dir).await?;
        if !registry
            .devices
            .iter()
            .any(|d| d.device_id == device_id.to_string())
        {
            return Err(PersonaError::NotFound(
                "device not registered in cloud sync group".to_string(),
            )
            .into());
        }
        atomic_write(
            &self.dir,
            &format!("{ENV_PREFIX}{device_id}{ENV_SUFFIX}"),
            envelope,
        )
        .await?;
        let meta = serde_json::json!({
            "sealed_by": "",
            "created_at": chrono::Utc::now().to_rfc3339(),
        });
        atomic_write(
            &self.dir,
            &format!("{ENV_PREFIX}{device_id}.meta.json"),
            meta.to_string().as_bytes(),
        )
        .await
    }

    async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>> {
        let registry = read_registry(&self.dir).await?;
        let mut keys = Vec::new();
        for device in &registry.devices {
            let device_id = Uuid::parse_str(&device.device_id).map_err(|_| {
                PersonaError::Io("malformed device_id in sync registry".to_string())
            })?;
            let env_path = self
                .dir
                .join(format!("{ENV_PREFIX}{device_id}{ENV_SUFFIX}"));
            // No envelope = pending authorization (registered but envelope not uploaded) -> skip, same semantics as the server.
            let Ok(envelope) = tokio::fs::read(&env_path).await else {
                continue;
            };
            keys.push(SyncGroupKeyEntry {
                device_id,
                envelope,
                sealed_by: meta_string(&self.dir, device_id, "sealed_by", String::new()).await,
                created_at: meta_string(
                    &self.dir,
                    device_id,
                    "created_at",
                    device.created_at.clone(),
                )
                .await,
            });
        }
        Ok(keys)
    }

    async fn bootstrap_group_if_empty(
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
}

impl CloudGroupKeyStore {
    /// Lists all devices in the cloud-drive registry (with public keys, used to fetch the target's public
    /// key when authorizing). A missing registry = an empty group.
    pub async fn list_devices(&self) -> Result<Vec<CloudDevice>> {
        Ok(read_registry(&self.dir).await?.devices)
    }

    /// Removes a device from the registry (revoke/leave). Best-effort deletion of that device's envelope and
    /// meta files (leftover files do not affect correctness: `group_keys` trusts the registry, and a removed
    /// device is no longer read). Returns whether the device was actually removed from the registry
    /// (false = was not in it, idempotent).
    pub async fn remove_device(&self, device_id: Uuid) -> Result<bool> {
        let mut registry = read_registry(&self.dir).await?;
        let before = registry.devices.len();
        registry
            .devices
            .retain(|d| d.device_id != device_id.to_string());
        if registry.devices.len() == before {
            return Ok(false);
        }
        write_registry(&self.dir, &registry).await?;
        // Envelope/meta deletion is best-effort: file system errors only warn (the registry no longer
        // contains the device, so orphaned files are mopped up by later GC or user cleanup).
        for name in [
            format!("{ENV_PREFIX}{device_id}{ENV_SUFFIX}"),
            format!("{ENV_PREFIX}{device_id}.meta.json"),
            watermark_name(device_id),
        ] {
            if let Err(e) = tokio::fs::remove_file(self.dir.join(&name)).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(error = %e, file = %name, "remove cloud envelope file failed");
                }
            }
        }
        Ok(true)
    }

    /// Writes a device remark (free text within the registry; the command layer guarantees itself that only
    /// the local device is written). Returns the normalized (trimmed) remark. A device missing from the
    /// registry → NotFound (fail-closed).
    pub async fn set_device_remark(&self, device_id: Uuid, remark: &str) -> Result<String> {
        let mut registry = read_registry(&self.dir).await?;
        let stored = remark.trim().to_string();
        let mut found = false;
        for device in &mut registry.devices {
            if device.device_id == device_id.to_string() {
                device.remark = stored.clone();
                found = true;
                break;
            }
        }
        if !found {
            return Err(PersonaError::NotFound(format!(
                "device {device_id} not in cloud sync registry"
            ))
            .into());
        }
        write_registry(&self.dir, &registry).await?;
        Ok(stored)
    }
}

// ---------------------------------------------------------------------------
// Instruction stream + snapshot (SyncRemote)
// ---------------------------------------------------------------------------

/// Lists all shards in the directory (`dev-*.jsonl`) and parses out the device_id.
async fn list_shards(dir: &Path) -> Result<Vec<(Uuid, PathBuf)>> {
    let mut out = Vec::new();
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| PersonaError::Io(format!("read cloud drive dir failed: {e}")))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| PersonaError::Io(format!("read cloud drive dir entry failed: {e}")))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name
            .strip_prefix(SHARD_PREFIX)
            .and_then(|r| r.strip_suffix(SHARD_SUFFIX))
        else {
            continue;
        };
        let Ok(device_id) = Uuid::parse_str(rest) else {
            continue; // dev- files from a different protocol (e.g. placed by hand) -> skip
        };
        out.push((device_id, entry.path()));
    }
    out.sort_by_key(|(id, _)| *id);
    Ok(out)
}

/// Reads all op lines of one shard. Bad lines are skipped (the same per-entry tolerance as HTTP pull: one
/// bad line does not void the batch or stall the cursor — the cursor advances by row count, and a bad line
/// counts as consumed too).
async fn read_shard_ops(path: &Path) -> Result<Vec<SyncOp>> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(PersonaError::Io(format!("read shard failed: {e}")).into());
        }
    };
    let mut ops = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<SyncOp>(line) {
            Ok(op) => ops.push(op),
            Err(e) => {
                tracing::warn!(error = %e, "malformed op line in cloud shard; skipped");
            }
        }
    }
    Ok(ops)
}

/// Lists snapshots in the directory (`snapshot-*.bin`), parses `(seq, device_id)`, ascending by seq.
async fn list_snapshots(dir: &Path) -> Result<Vec<(i64, Uuid, PathBuf)>> {
    let mut out = Vec::new();
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(PersonaError::Io(format!("read cloud drive dir failed: {e}")).into());
        }
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| PersonaError::Io(format!("read cloud drive dir entry failed: {e}")))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name
            .strip_prefix(SNAPSHOT_PREFIX)
            .and_then(|r| r.strip_suffix(SNAPSHOT_SUFFIX))
        else {
            continue;
        };
        // `snapshot-<seq>-<device_id>.bin` → rest = `<seq>-<device_id>`
        let Some((seq_str, dev_str)) = rest.split_once('-') else {
            continue;
        };
        let Ok(seq) = seq_str.parse::<i64>() else {
            continue;
        };
        let Ok(device_id) = Uuid::parse_str(dev_str) else {
            continue;
        };
        out.push((seq, device_id, entry.path()));
    }
    out.sort_by_key(|(seq, _, _)| *seq);
    Ok(out)
}

/// The per-shard row-count watermark table of the cursor (JSON `{"<device>": rows}` inside the op_id slot).
type Watermarks = HashMap<Uuid, u64>;

/// Decodes the watermark table from the cursor op_id slot. A slot of `"0"` (the snapshot-install sentinel) or an
/// unparseable one → an empty table = a full read (the safe side: never skip, prefer re-reading so the engine
/// can deduplicate by op_id).
fn decode_watermarks(op_id_slot: &str) -> Watermarks {
    if op_id_slot == "0" {
        return Watermarks::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(op_id_slot) else {
        return Watermarks::new();
    };
    let Some(map) = value.as_object() else {
        return Watermarks::new();
    };
    let mut out = Watermarks::new();
    for (key, v) in map {
        if let (Ok(id), Some(count)) = (Uuid::parse_str(key), v.as_u64()) {
            out.insert(id, count);
        }
    }
    out
}

fn encode_watermarks(watermarks: &Watermarks) -> String {
    let mut sorted: Vec<_> = watermarks.iter().collect();
    sorted.sort_by_key(|(id, _)| **id);
    let map: serde_json::Map<String, serde_json::Value> = sorted
        .iter()
        .map(|(id, count)| (id.to_string(), serde_json::Value::from(**count)))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// Merge sort key: `(lamport, device_id, op_id)` — isomorphic to the oplog LWW total order (op_id breaks
/// ties to guarantee determinism; op_id is globally unique across shards, so ties almost never happen).
fn merge_sort_key(op: &SyncOp) -> (u64, Uuid, Uuid) {
    (op.lamport, op.device_id, op.op_id)
}

// ---------------------------------------------------------------------------
// Per-device committed watermarks + shard-rewrite GC
// ---------------------------------------------------------------------------

/// One device's committed pull position, published into the cloud directory.
///
/// `watermarks` maps every shard to the number of its rows this device has
/// **consumed** (landed in the local oplog and recorded in the local cursor).
/// It is only ever written from a persisted cursor, never from an in-flight
/// page — otherwise a crash after the write but before the local commit would
/// have advertised rows as consumed that were in fact never stored.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CommittedWatermark {
    device_id: Uuid,
    watermarks: Watermarks,
}

fn watermark_name(device_id: Uuid) -> String {
    format!("{WATERMARK_PREFIX}{device_id}{WATERMARK_SUFFIX}")
}

fn base_name(device_id: Uuid) -> String {
    format!("{BASE_PREFIX}{device_id}{BASE_SUFFIX}")
}

/// Reads the compaction base of one shard (leading rows physically removed): 0
/// when no base file exists or it is unreadable.
async fn read_base(dir: &Path, device_id: Uuid) -> u64 {
    let path = dir.join(base_name(device_id));
    match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("dropped").and_then(|x| x.as_u64()))
            .unwrap_or(0),
        Err(_) => 0,
    }
}

async fn write_base(dir: &Path, device_id: Uuid, dropped: u64) -> Result<()> {
    let body = serde_json::json!({ "dropped": dropped }).to_string();
    atomic_write(dir, &base_name(device_id), body.as_bytes()).await
}

/// Writes this device's committed watermark file (atomic; the cloud agent only
/// ever sees a complete file).
async fn write_committed_watermark(dir: &Path, watermark: &CommittedWatermark) -> Result<()> {
    let text = serde_json::to_vec(watermark)
        .map_err(|e| PersonaError::Io(format!("encode pull watermark failed: {e}")))?;
    atomic_write(dir, &watermark_name(watermark.device_id), &text).await
}

/// Collects every committed watermark file in the directory. An unreadable or
/// malformed file is skipped: it merely keeps its device blocking compaction
/// (fail-closed), never advances it.
async fn committed_watermarks(dir: &Path) -> Result<Vec<CommittedWatermark>> {
    let mut out = Vec::new();
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => {
            return Err(PersonaError::Io(format!("read cloud drive dir failed: {e}")).into());
        }
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| PersonaError::Io(format!("read cloud drive dir entry failed: {e}")))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(id_text) = name
            .strip_prefix(WATERMARK_PREFIX)
            .and_then(|r| r.strip_suffix(WATERMARK_SUFFIX))
        else {
            continue;
        };
        let Ok(claimed_id) = Uuid::parse_str(id_text) else {
            continue;
        };
        let Ok(text) = tokio::fs::read_to_string(entry.path()).await else {
            continue;
        };
        // The filename is the identity: a file whose JSON claims a different
        // device must not be able to advance that device's boundary.
        if let Ok(w) = serde_json::from_str::<CommittedWatermark>(&text) {
            if w.device_id == claimed_id {
                out.push(w);
            }
        }
    }
    Ok(out)
}

/// The **safe logical watermark** of a shard: the highest logical row number
/// every registered device has committed as consumed — the compaction boundary.
///
/// `None` means "do not touch this shard" (fail-closed): no registered devices,
/// or some registered device has no committed watermark file (never pulled /
/// offline), or some device's count is at/below the current compaction base
/// (nothing new to drop).
fn safe_watermark(
    device_ids: &[Uuid],
    target: Uuid,
    committed: &[CommittedWatermark],
    base: u64,
) -> Option<u64> {
    if device_ids.is_empty() {
        return None;
    }
    let mut safe = u64::MAX;
    for device_id in device_ids {
        let w = committed.iter().find(|w| w.device_id == *device_id)?; // no file at all -> None
        let count = w.watermarks.get(&target).copied().unwrap_or(0);
        safe = safe.min(count);
    }
    if safe <= base {
        None
    } else {
        Some(safe)
    }
}

/// Shard-rewrite GC (§4): drop the rows below the safe watermark of every shard
/// by rewriting that shard locally (temp + fsync + rename). Cursor watermarks
/// stay in logical coordinates; the compaction base records what was physically
/// dropped, so no device's cursor is invalidated. Returns the number of rows
/// rewritten away.
async fn compact_shards(dir: &Path) -> Result<u64> {
    let device_ids: Vec<Uuid> = read_registry(dir)
        .await?
        .devices
        .iter()
        .filter_map(|d| d.device_id.parse::<Uuid>().ok())
        .collect();
    let shards = list_shards(dir).await?;
    let committed = committed_watermarks(dir).await?;
    let mut compacted = 0u64;
    for (device_id, path) in &shards {
        let base = read_base(dir, *device_id).await;
        let ops = read_shard_ops(path).await?;
        let Some(safe) = safe_watermark(&device_ids, *device_id, &committed, base) else {
            continue; // a device is offline / never pulled -> keep everything
        };
        let physical_safe = (safe - base) as usize;
        if physical_safe == 0 || physical_safe > ops.len() {
            continue; // nothing to drop (over-length means the cursor is already past the file)
        }
        let mut buf = Vec::new();
        for op in &ops[physical_safe..] {
            let line = serde_json::to_string(op)
                .map_err(|e| PersonaError::Io(format!("encode op line failed: {e}")))?;
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        atomic_write(dir, &shard_name(*device_id), &buf).await?;
        write_base(dir, *device_id, safe).await?;
        compacted += physical_safe as u64;
        tracing::info!(device = %device_id, dropped = physical_safe, kept = ops.len() - physical_safe, "compacted cloud shard");
    }
    Ok(compacted)
}

fn shard_name(device_id: Uuid) -> String {
    format!("{SHARD_PREFIX}{device_id}{SHARD_SUFFIX}")
}

impl CloudDriveRemote {
    /// Publishes this device's pull position into the cloud folder after the local
    /// cursor has been **persisted** (the engine commits it after landing ops).
    /// Called from `pull_ops` only after the cursor is computed; the file is
    /// atomic, so other devices never see a partial watermark.
    async fn publish_committed_watermark(&self, watermarks: &Watermarks) -> Result<()> {
        write_committed_watermark(
            &self.dir,
            &CommittedWatermark {
                device_id: self.device_id,
                watermarks: watermarks.clone(),
            },
        )
        .await
    }
}

#[async_trait]
impl SyncRemote for CloudDriveRemote {
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
        let path = self
            .dir
            .join(format!("{SHARD_PREFIX}{}{SHARD_SUFFIX}", self.device_id));
        // Read the existing shard to deduplicate (op_id idempotency: re-pushing the same op after a crash is not appended again).
        let existing = read_shard_ops(&path).await?;
        let mut known: HashMap<Uuid, ()> = existing.iter().map(|op| (op.op_id, ())).collect();
        let mut lines: Vec<String> = Vec::new();
        let mut accepted = 0u64;
        let mut duplicates = 0u64;
        for op in ops {
            if known.contains_key(&op.op_id) {
                duplicates += 1;
                continue;
            }
            known.insert(op.op_id, ());
            lines.push(
                serde_json::to_string(op)
                    .map_err(|e| PersonaError::Io(format!("encode op line failed: {e}")))?,
            );
            accepted += 1;
        }
        if !lines.is_empty() {
            // Append semantics: read the raw text (bad lines preserved verbatim), splice in the new lines,
            // and rename atomically. The cloud agent never sees a half-written shard.
            let raw = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            let mut final_buf = raw.into_bytes();
            for line in &lines {
                final_buf.extend_from_slice(line.as_bytes());
                final_buf.push(b'\n');
            }
            atomic_write(
                &self.dir,
                &format!("{SHARD_PREFIX}{}{SHARD_SUFFIX}", self.device_id),
                &final_buf,
            )
            .await?;
        }
        Ok((accepted, duplicates))
    }

    async fn pull_ops(
        &self,
        since: Option<&str>,
        _limit: u32,
    ) -> Result<(Vec<SyncOp>, Option<String>)> {
        // Watermark table: None / "0" / a corrupt slot -> a full read (the safe side).
        let watermarks = match since {
            Some(raw) => crate::sync::cursor::decode_cursor(raw)
                .map(|(_, slot)| decode_watermarks(&slot))
                .unwrap_or_default(),
            None => Watermarks::new(),
        };
        let shards = list_shards(&self.dir).await?;
        let mut new_ops: Vec<SyncOp> = Vec::new();
        let mut next = watermarks.clone();
        for (device_id, path) in &shards {
            let ops = read_shard_ops(path).await?;
            // Cursor watermarks are logical row numbers; the compaction base is
            // the number of leading rows physically gone. Subtracting gives the
            // index into the current file (saturating so an over-consumed cursor
            // never panics — it just reads nothing from that shard).
            let base = read_base(&self.dir, *device_id).await;
            let logical = watermarks.get(device_id).copied().unwrap_or(0);
            let start = logical.saturating_sub(base) as usize;
            if start < ops.len() {
                new_ops.extend(ops[start..].iter().cloned());
            }
            // Next logical position = base + current physical row count.
            next.insert(*device_id, base + ops.len() as u64);
        }
        if new_ops.is_empty() {
            // Publish even on an empty page: a device that just finished its
            // first full read has a non-empty *committed* map (decoded from
            // `since`) that other devices must be able to see, otherwise the
            // gc boundary stalls at that device's stale position forever.
            self.publish_committed_watermark(&watermarks).await?;
            return Ok((Vec::new(), None));
        }
        // Deterministic merge + op_id deduplication (a re-read safety net: the same op across pages/replays is kept once).
        new_ops.sort_by_key(merge_sort_key);
        let mut seen = std::collections::HashSet::new();
        new_ops.retain(|op| seen.insert(op.op_id));
        let total: u64 = next.values().sum();
        let cursor = crate::sync::cursor::encode_cursor(total as i64, &encode_watermarks(&next));
        // Publish the **previously committed** position, not `next`: the engine
        // persists the returned cursor only after it has landed the ops, so
        // advertising `next` here would over-report on a crash between this
        // write and that commit. Using `watermarks` (decoded from `since`, i.e.
        // this device's persisted cursor) gives a one-cycle lag: every row count
        // that becomes visible to other devices is already durable in this
        // device's oplog (fail-closed across crashes).
        self.publish_committed_watermark(&watermarks).await?;
        Ok((new_ops, Some(cursor)))
    }

    async fn head_seq(&self) -> Result<i64> {
        // The group's newest version = the total **logical** row count of all
        // shards (physical rows plus the compacted base of each shard). Using
        // logical counts keeps the version monotonic across compactions —
        // `local_watermark`/`behind` read this same coordinate space. op_id is
        // globally unique across shards, so this equals the deduplicated op
        // count.
        let shards = list_shards(&self.dir).await?;
        let mut total = 0i64;
        for (device_id, path) in &shards {
            let base = read_base(&self.dir, *device_id).await;
            total += (base as i64) + read_shard_ops(path).await?.len() as i64;
        }
        Ok(total)
    }

    async fn put_library_snapshot(
        &self,
        seq: i64,
        device_id: &str,
        ciphertext: &[u8],
    ) -> Result<u64> {
        // The filename is content-addressed by `(seq, device_id)`: different devices never write the same
        // file, and re-sending the same (seq, device) is idempotent (skipped, immutable — a snapshot file is
        // never modified once written).
        let name = format!("{SNAPSHOT_PREFIX}{seq}-{device_id}{SNAPSHOT_SUFFIX}");
        let mut pruned = 0;
        if !self.dir.join(&name).exists() {
            atomic_write(&self.dir, &name, ciphertext).await?;
            // Only the snapshot that actually introduces new coverage triggers GC.
            pruned = compact_shards(&self.dir).await?;
        }
        Ok(pruned)
    }

    async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
        // Take the snapshot with the largest seq (several devices writing concurrently each produce one → max-seq is the deterministic convergence point).
        let snapshots = list_snapshots(&self.dir).await?;
        let Some((seq, _device_id, path)) = snapshots.last() else {
            return Ok(None);
        };
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| PersonaError::Io(format!("read snapshot file failed: {e}")))?;
        Ok(Some((*seq, bytes)))
    }
}
