//! Sync session assembly (E2EE_SYNC_DESIGN phase 3b): strings together the
//! device identity, oplog engine, materialization layer, and existing data
//! inside a single "sync now" call by the host.
//!
//! Layering contract: protocol / cryptography / orchestration all live in
//! core; the host (desktop/CLI) only supplies parameters (device identity,
//! server url/token, travel gate) and persistence slots. The host never
//! touches [`SyncEngine`] / [`Materializer`] directly.
//!
//! Session lifecycle = a single `sync_now` call: `open` (unwraps the
//! envelope and assembles) -> `backfill_existing` (seeds existing data,
//! idempotent) -> `run_cycle` (pull -> materialize -> push) -> `capture`
//! (attaches [`OplogCapture`] to the service so later local writes enqueue
//! automatically). The session object can be discarded; engine state lives
//! entirely in the local database (local_lamport / cursor / pending op do
//! not travel with the instance). The travel gate is evaluated once by the
//! host before the call (a cycle is short and does not change mid-flight;
//! while travel is active the cycle side refuses on its own, see the engine
//! module).
//!
//!
//! Split (LAY-021): the session core (open/backfill/snapshot/run_cycle/
//! status/gc/capture) stays in this file; rewrap/rotate are in `rotate.rs`,
//! conflict resolution in `conflicts.rs`, and tests are grouped by domain in
//! `tests/`.
use std::sync::Arc;

use uuid::Uuid;

use super::capture::OplogCapture;
#[cfg(feature = "remote-auth")]
use super::device::DeviceIdentity;
use super::engine::{SyncEngine, SyncRemote};
use super::keys::{wrap_item_key_with_group, GroupKey};
use super::materialize::{MaterializeOutcome, Materializer};
use super::oplog::{item_view, ItemKind, OpType, SyncPayload};
use super::resolve::{self, ConflictEntry};
use super::snapshot::{LibrarySnapshotPayload, SyncItemSnapshot, UPLOAD_THRESHOLD_OPS};
use crate::crypto::encryption::EncryptionService;
use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::credential::CredentialData;
use crate::storage::sync_repository::SyncRepository;
use crate::storage::{CredentialRepository, Database};
use crate::PersonaError;
use crate::Result;

/// Summary of one `sync_now` (every field is a count, for host UI display).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncNowReport {
    /// Number of remote ops newly pulled and recorded.
    pub pulled: usize,
    /// Number of entries materialized into the master database (new rows or
    /// updates).
    pub materialized: usize,
    /// Number of conflict losers remaining in the oplog (nothing is lost;
    /// consumed by the resolution UI).
    pub conflicts: usize,
    /// Number of entries held pending because their identity has not synced
    /// yet (completed next round).
    pub pending_identity: usize,
    /// Number of local ops pushed out.
    pub pushed: usize,
    /// Number of existing credentials seeded into the oplog this time
    /// (usually nonzero only on the first sync).
    pub backfilled: u64,
}

/// One sync session. The host discards it after use; state lives in the
/// database.
pub struct SyncSession<R: SyncRemote> {
    engine: Arc<SyncEngine<R>>,
    sync_repo: SyncRepository,
    db: Database,
    group_key: GroupKey,
    device_id: Uuid,
}

/// Summary of one group key rotation. Rotation = swap envelopes + a full
/// rewrap (E2EE_SYNC_DESIGN DR-3 "safe rotation", the v1 answer to section
/// 11 open question 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncRotateReport {
    /// Number of credentials re-logged under the new group key (one put with
    /// a fresh lamport each).
    pub rewrapped: u64,
    /// Number of master-database credentials skipped because of legacy (no
    /// wrapped item key) or a decrypt failure -- after rotation these
    /// entries still carry only old-group ciphertext, invisible to devices
    /// that only have the new envelope.
    pub skipped: u64,
    /// Total number of ops pushed over the whole rotation (the initial queue
    /// drain + the rewrap batch).
    pub pushed: u64,
}

/// Summary of one oplog cleanup pass ([`SyncSession::gc_oplog`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Number of oplog rows pruned (consumed historical versions +
    /// tombstones past the retention window).
    pub removed_ops: u64,
}

/// The GC's default tombstone retention window: a master-position tombstone
/// is kept this long after ack before it is pruned, leaving replay headroom
/// for slow devices / cursor resets. chrono's Duration has no const
/// constructor, so this is a function.
pub fn default_tombstone_retention() -> chrono::Duration {
    chrono::Duration::try_days(30).expect("30 days always fits in chrono::Duration")
}

#[cfg(feature = "remote-auth")]
impl<R: SyncRemote> SyncSession<R> {
    /// Transport-independent assembly of the session: fetch all envelopes
    /// ([`GroupKeyStore`], the concrete transport is decided by the
    /// implementation) -> unwrap this device's share to get the group key ->
    /// build the engine ([`SyncRemote`]).
    /// A missing own envelope (not authorized) or one that cannot be unwrapped
    /// (fail-closed: the envelope is not wrapped for this private key / was
    /// tampered with) is always Err -- an unauthorized device gets no sync
    /// capability.
    ///
    /// The assembly logic shared by both transports lives here: the HTTP
    /// transport ([`Self::open`]) and the cloud-drive transport
    /// ([`Self::open_cloud`]) each just provide their own remote + key_store.
    pub async fn open_with<K: super::remote::GroupKeyStore>(
        db: &Database,
        identity: &DeviceIdentity,
        remote: R,
        key_store: K,
        travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self> {
        let keys = key_store.group_keys().await?;
        let own = keys
            .iter()
            .find(|k| k.device_id == identity.device_id)
            .ok_or_else(|| {
                PersonaError::NotFound(
                    "this device has no group key envelope yet (pending authorization)".to_string(),
                )
            })?;
        let group_bytes =
            super::envelope::open_group_key(&own.envelope, identity.key_pair.secret_bytes())
                .map_err(|e| {
                    PersonaError::CryptographicError(format!(
                        "failed to open own group key envelope: {e}"
                    ))
                })?;
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            remote,
            identity.device_id,
            travel_active,
        ));
        Ok(Self {
            engine,
            sync_repo: SyncRepository::new(db.clone()),
            db: db.clone(),
            group_key: GroupKey::from_bytes(group_bytes),
            device_id: identity.device_id,
        })
    }
}

#[cfg(feature = "remote-auth")]
impl SyncSession<super::remote::HttpSyncRemote> {
    /// Assemble an HTTP transport session: fetch all envelopes from the
    /// server and unwrap this device's share to get the group key.
    pub async fn open(
        db: &Database,
        identity: &DeviceIdentity,
        base_url: &str,
        token: &str,
        travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self> {
        let admin = super::remote::SyncAdminApi::new(base_url, token)?;
        Self::open_with(
            db,
            identity,
            super::remote::HttpSyncRemote::new(base_url, token)?,
            super::remote::HttpGroupKeyStore::new(admin),
            travel_active,
        )
        .await
    }
}

#[cfg(feature = "remote-auth")]
impl SyncSession<super::remote::CloudDriveRemote> {
    /// Assemble a cloud-drive transport session: the cloud-drive directory
    /// doubles as the transport and envelope exchange slot, no server needed.
    /// `cloud_dir` is this machine's cloud sync folder (iCloud Drive /
    /// Dropbox / Google Drive); the OS cloud agent handles cross-device
    /// distribution; a missing directory is created on first write.
    pub async fn open_cloud(
        db: &Database,
        identity: &DeviceIdentity,
        cloud_dir: impl Into<std::path::PathBuf>,
        travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self> {
        let dir = cloud_dir.into();
        Self::open_with(
            db,
            identity,
            super::remote::CloudDriveRemote::new(dir.clone(), identity.device_id),
            super::remote::CloudGroupKeyStore::new(dir),
            travel_active,
        )
        .await
    }
}

impl<R: SyncRemote> SyncSession<R> {
    /// Seed existing data: generate a put for each credential that exists in
    /// the master database but is absent from the oplog. Already queued
    /// entries are skipped based on the oplog's item set, so repeated calls
    /// are idempotent (usually only the first sync seeds nonzero entries).
    /// Legacy credentials (no wrapped_item_key) have no item key to recover;
    /// they are skipped with a warn (same semantics as the capture seam --
    /// edit once to upgrade the encryption form).
    pub async fn backfill_existing(&self, master: &EncryptionService) -> Result<u64> {
        let cred_repo = CredentialRepository::new(self.db.clone());
        let all = cred_repo.list_all().await?;
        let queued: std::collections::HashSet<Uuid> =
            self.sync_repo.item_ids().await?.into_iter().collect();
        let hierarchy = KeyHierarchy::new(master);
        let mut count: u64 = 0;
        for credential in all {
            if queued.contains(&credential.id) {
                continue;
            }
            let Some(wrapped) = credential.wrapped_item_key.as_ref() else {
                tracing::warn!(
                    credential_id = %credential.id,
                    "legacy credential without wrapped item key; sync backfill skipped"
                );
                continue;
            };
            // Failures skip the single entry (a bad row does not block the
            // whole batch), consistent with the capture seam's tolerance
            let item_key = match hierarchy.unwrap_item_key(wrapped) {
                Ok(item_key) => item_key,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "item key unwrap failed; backfill skipped");
                    continue;
                }
            };
            let plaintext = match hierarchy
                .decrypt_with_wrapped_key(wrapped, &credential.encrypted_data)
            {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "credential decrypt failed; backfill skipped");
                    continue;
                }
            };
            let data = match CredentialData::from_bytes(&plaintext) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "malformed credential data; backfill skipped");
                    continue;
                }
            };
            let sealed = match SyncItemSnapshot::from_credential(&credential, &data).seal(&item_key)
            {
                Ok(sealed) => sealed,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "snapshot seal failed; backfill skipped");
                    continue;
                }
            };
            let payload = SyncPayload {
                ciphertext: sealed,
                wrapped_item_key: wrap_item_key_with_group(&item_key, &self.group_key),
            };
            match self
                .engine
                .record_local_change(
                    credential.id,
                    ItemKind::Credential,
                    OpType::Put,
                    Some(payload),
                )
                .await
            {
                Ok(_) => count += 1,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "oplog record failed; backfill skipped");
                }
            }
        }
        Ok(count)
    }
    /// Pack this device's oplog view into a library snapshot plaintext (S2):
    /// for each item, take [`item_view`]'s primary position (put/tombstone)
    /// plus the unresolved conflict copies. Packing credential table rows
    /// would lose pending identity / conflict copies / tombstones; only
    /// carrying the oplog verbatim guarantees "snapshot bootstrap + post-point
    /// delta == full replay".
    pub async fn snapshot_payload(&self) -> Result<LibrarySnapshotPayload> {
        let mut ops = Vec::new();
        for item_id in self.sync_repo.item_ids().await? {
            let view = item_view(self.sync_repo.item_ops(item_id).await?);
            if let Some(primary) = view.primary {
                ops.push(primary);
            }
            ops.extend(view.conflicts);
        }
        Ok(LibrarySnapshotPayload {
            created_at: chrono::Utc::now().to_rfc3339(),
            ops,
        })
    }
    /// The install callback proper: unwrap with the group key (fail-closed)
    /// -> the fully-viewed ops enter the local oplog idempotently by op_id
    /// (record_remote_op, acked -- these positions are already compressed into
    /// the snapshot and must not be pushed again). The cursor does not move
    /// before installation; on failure nothing converges.
    #[allow(dead_code)]
    async fn install_snapshot_ops(&self, _seq: i64, sealed: Vec<u8>) -> Result<()> {
        let payload = LibrarySnapshotPayload::open(&sealed, &self.group_key)?;
        for op in &payload.ops {
            self.sync_repo.record_remote_op(op).await?;
        }
        Ok(())
    }
    /// Full cycle: pull (batch remote ops into the local oplog) ->
    /// materialize (materialize the oplog primary position into the master
    /// database) -> push (push local pending ops to the server).
    pub async fn run_cycle(&self, master: &EncryptionService) -> Result<SyncNowReport> {
        // bootstrap: when this device has never pulled (first run / new
        // device), try installing a library snapshot first -- on success the
        // cursor advances to the overwrite position and pull takes only
        // deltas; with no snapshot or on failure the cursor stays put and we
        // fall back to full replay (fail-closed, matching the engine
        // primitive's contract).
        if self.sync_repo.get_state().await?.last_pull_cursor.is_none() {
            if let Err(e) = self
                .engine
                .install_library_snapshot(|seq, sealed| self.install_snapshot_ops(seq, sealed))
                .await
            {
                // A failed install does not converge the cursor -- full
                // replay is the fallback, only logged.
                tracing::warn!(error = %e, "snapshot install failed; full replay");
            }
        }
        let pull = self.engine.pull_cycle().await?;
        let materialize = Materializer::new(self.db.clone())
            .materialize_all(master, &self.group_key, self.device_id)
            .await?;
        let push = self.engine.push_cycle().await?;
        // Opportunistically prune consumed oplog history (the client half of
        // section 11 open question 3); failure does not block sync -- growth
        // governance is not a precondition of sync correctness.
        if let Err(e) = self.gc_oplog(default_tombstone_retention()).await {
            tracing::warn!(error = %e, "oplog gc skipped");
        }
        // Snapshot trigger (S2): repack only when head - last snapshot
        // position > threshold. Failure is only logged and does not block --
        // the snapshot is an optimization layer; its absence just falls back
        // to full replay. Packing goes through the callback, which runs after
        // the engine converges (push/pull): the watermark and snapshot content
        // both read from the same post-convergence view, so an op pulled in
        // by convergence is not both pruned by the server and missing from
        // the snapshot.
        if let Ok(true) = self
            .engine
            .library_snapshot_needed(UPLOAD_THRESHOLD_OPS)
            .await
        {
            if let Err(e) = self
                .engine
                .upload_library_snapshot(|| async {
                    let payload = self.snapshot_payload().await?;
                    payload.seal(&self.group_key)
                })
                .await
            {
                tracing::warn!(error = %e, "snapshot upload skipped");
            }
        }
        Ok(SyncNowReport {
            pulled: pull.applied,
            materialized: materialize.written,
            // Number of entries pending resolution (computed fresh from the
            // oplog as the truth; 3b once misused
            // skipped_local_primary -- that was the "primary is a local op"
            // skip count).
            conflicts: self.conflict_item_count().await?,
            pending_identity: materialize.pending_identity.len(),
            pushed: push.pushed,
            backfilled: 0,
        })
    }
    /// Sync status snapshot (the data surface shown on the settings page in
    /// sync-group-mode section 2.5.5): the group's latest version number,
    /// this device's synced watermark, the number of entries behind, the
    /// number pending push, and the last sync time. Read-only and does not
    /// run a cycle -- "sync now" still goes through [`Self::run_cycle`].
    pub async fn status(&self) -> Result<super::engine::SyncStatusReport> {
        self.engine.sync_status().await
    }
    /// oplog growth governance (the client half of E2EE_SYNC_DESIGN section
    /// 11 open question 3).
    /// The local oplog is an append-only ciphertext log that grows without
    /// bound over long use; this method prunes only historical versions that
    /// "have no more consumers", per a conservative predicate:
    ///
    /// - **Protected set**: local ops in the push queue that are not yet
    ///   acked (the push window -- touching them loses changes); unresolved
    ///   conflict copies (the conflicts derived by `item_view` -- after a
    ///   resolution is adopted, the remaining versions win back the master
    ///   position with a larger lamport, so the losers drop out of the copy
    ///   set and the next GC round can prune them); the master-position put
    ///   (a live entry's view anchor, never pruned).
    /// - **Prunable set**: old versions that are acked and are neither the
    ///   master position nor a copy; and master-position tombstones that are
    ///   acked and older than `tombstone_retention` (the entry is already
    ///   deleted, leaving only replay headroom; a missing timestamp counts as
    ///   do not prune -- it cannot be proven old enough).
    ///
    /// If a pruned op is re-pulled because of a cursor reset, it is rebuilt by
    /// an idempotent upsert keyed on op_id and convergence is unaffected; the
    /// master database is never touched (GC only acts on the oplog).
    pub async fn gc_oplog(&self, tombstone_retention: chrono::Duration) -> Result<GcReport> {
        let pending = self.sync_repo.pending_op_ids().await?;
        let now = chrono::Utc::now();
        let mut to_remove = Vec::new();
        for item_id in self.sync_repo.item_ids().await? {
            let ops = self.sync_repo.item_ops(item_id).await?;
            let view = item_view(ops.clone());
            let Some(primary) = &view.primary else {
                continue;
            };
            for op in &ops {
                if pending.contains(&op.op_id) {
                    continue;
                }
                if op.op_id == primary.op_id {
                    // Master position: only a "tombstone past the retention
                    // window" is prunable.
                    if primary.is_tombstone() {
                        if let Some(ts) = primary.timestamp {
                            if now - ts > tombstone_retention {
                                to_remove.push(op.op_id);
                            }
                        }
                    }
                    continue;
                }
                if view.conflicts.iter().any(|c| c.op_id == op.op_id) {
                    continue;
                }
                to_remove.push(op.op_id);
            }
        }
        let removed = self.sync_repo.delete_ops(&to_remove).await?;
        if removed > 0 {
            tracing::info!(event = "oplog_gc", removed, "pruned consumed oplog history");
        }
        Ok(GcReport {
            removed_ops: removed,
        })
    }
    /// This session's capture seam (once attached to the service, the local
    /// write path automatically produces oplog put / tombstone entries). The
    /// capture stays valid after the session is dropped (it holds the engine
    /// Arc).
    pub fn capture(&self) -> Arc<OplogCapture<R>> {
        Arc::new(OplogCapture::new(
            self.engine.clone(),
            self.group_key.clone(),
        ))
    }
}

mod conflicts;
mod rotate;
#[cfg(test)]
mod tests;
