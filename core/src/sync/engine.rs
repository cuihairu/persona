//! Sync engine orchestration (E2EE_SYNC_DESIGN phase 2, batch 4): push/pull
//! cycles, Lamport clock maintenance, and the travel gate.
//!
//! The engine depends only on [`SyncRemote`] (the minimal interface of the
//! remote relay) and [`SyncRepository`]: HTTP details live in
//! [`super::remote`] (cfg remote-auth), and tests use an in-memory
//! implementation.
//!
//! **Travel gate** (design doc §8): while travel is active,
//! `push_cycle`/`pull_cycle` both stop — pushing the bulk deletions made on
//! enter would flood tombstones onto other devices and wreck their libraries,
//! and pulling could write an evicted identity back into the primary
//! database. `record_local_change` is **ungated** (ordinary local writes
//! queue up as usual during travel and are pushed with a later push cycle;
//! the travel enter's own bulk deletions go through travel.rs and bypass the
//! ordinary write capture point — keep this convention when wiring phase 3).
//!
//! **No coupling to the master password** (§4 key hierarchy): the engine
//! touches only oplog ciphertext and `(lamport, device_id)` along its whole
//! path, never master-password derivation material — changing the master
//! password does not affect sync state (local_lamport/cursor/oplog all live
//! in the database), so the host can rebuild the engine instance and resume.

use chrono::Utc;
use uuid::Uuid;

use crate::storage::sync_repository::SyncRepository;
use crate::sync::oplog::{ItemKind, OpType, SyncOp, SyncPayload};
use crate::{PersonaError, Result};

/// Page size of one pull round (aligned with the server's PULL_DEFAULT_LIMIT).
pub const PULL_PAGE: u32 = 200;

/// Sentinel op_id for the snapshot resume cursor (S2): an op_id is a UUID
/// string (hex alphabet), so lexicographically it is always greater than
/// `"0"`. The cursor `(snapshot seq, "0")` expresses "resume position =
/// snapshot coverage position" exactly through the server's composite
/// `(seq, op_id) >` comparison — rows with seq ≤ S have already been
/// compacted away by the snapshot upload, which is semantically a no-op; the
/// bonus is that the watermark (cursor decoded back to seq) reads the
/// snapshot position directly.
pub const SNAPSHOT_RESUME_OP_ID: &str = "0";

/// The minimal interface of the remote relay. Returned ops are already in
/// [`SyncOp`] form (wire parsing happens inside the implementation; unknown
/// kind → [`ItemKind::Unknown`], entry-level corruption → skip that entry).
#[async_trait::async_trait]
pub trait SyncRemote: Send + Sync {
    /// Push a batch of ops; the server is idempotent by op_id and returns
    /// (accepted, duplicates).
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)>;
    /// Pull one page of increments: returns (ops, next_cursor). `since`/
    /// next_cursor are server seq cursors, passed through verbatim to
    /// [`SyncRepository::set_last_pull_cursor`].
    async fn pull_ops(
        &self,
        since: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<SyncOp>, Option<String>)>;
    /// The group's current op sequence position (sync-group-mode §2.5.5
    /// "latest group version") — the maximum seq of the server oplog; 0 for
    /// an empty group.
    async fn head_seq(&self) -> Result<i64>;
    /// Upload a library-level snapshot (S2, E2EE_SYNC_DESIGN §5): the whole
    /// group key package ciphertext plus the coverage position seq. The
    /// server upserts a single snapshot and deletes ops with `seq ≤ S` in the
    /// same transaction, returning the number of ops compacted (display
    /// only). Failure must be reported as an error — the covered range may
    /// already be compacted, so silently dropping a snapshot is a real data
    /// hole: a fresh device with an empty library would have no source of
    /// truth to backfill from.
    async fn put_library_snapshot(
        &self,
        seq: i64,
        device_id: &str,
        ciphertext: &[u8],
    ) -> Result<u64>;
    /// Fetch the library-level snapshot: `Ok(None)` = no snapshot available
    /// on the server (a new server has not uploaded one yet, or an old server
    /// lacks the route); both causes converge to the same client behavior —
    /// fall back to full replay. Returns (coverage position seq, group key
    /// ciphertext).
    async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushCycleReport {
    pub pushed: usize,
    pub skipped_travel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullCycleReport {
    /// Number of remote ops newly persisted (after dedup).
    pub applied: usize,
    pub skipped_travel: bool,
}

pub struct SyncEngine<R: SyncRemote> {
    repo: SyncRepository,
    remote: R,
    /// This device's id (fixed at registration; local op device_ids and clock
    /// attribution both rely on it).
    device_id: Uuid,
    /// The travel gate (see module docs). Injected at construction; the host
    /// reads WorkspaceSettings.
    travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    pull_page: u32,
}

impl<R: SyncRemote> SyncEngine<R> {
    pub fn new(
        repo: SyncRepository,
        remote: R,
        device_id: Uuid,
        travel_active: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            repo,
            remote,
            device_id,
            travel_active,
            pull_page: PULL_PAGE,
        }
    }

    /// Local write capture (called by the service write path): lamport =
    /// local + 1, and the op enters the push queue. **Not travel-gated** (see
    /// module docs).
    pub async fn record_local_change(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        payload: Option<SyncPayload>,
    ) -> Result<SyncOp> {
        let lamport = self.repo.get_state().await?.local_lamport + 1;
        let sync_op = SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind,
            op,
            lamport,
            device_id: self.device_id,
            timestamp: Some(Utc::now()),
            payload,
        };
        // Bump the clock before queueing: a crash in between leaves a
        // "clock advanced but op lost" gap — harmless (lamport only needs a
        // total order, not continuity), while the reverse order could produce
        // a duplicate lamport (two ops with the same device and lamport is a
        // protocol violation).
        self.repo.bump_lamport(lamport).await?;
        self.repo.append_local_op(&sync_op).await?;
        Ok(sync_op)
    }

    /// Drain the local push queue (≤500 ops per batch, one batch per round; any
    /// remainder is pushed in the next round).
    pub async fn push_cycle(&self) -> Result<PushCycleReport> {
        if (self.travel_active)() {
            return Ok(PushCycleReport {
                pushed: 0,
                skipped_travel: true,
            });
        }
        let pending = self.repo.pending_ops(500).await?;
        if pending.is_empty() {
            return Ok(PushCycleReport {
                pushed: 0,
                skipped_travel: false,
            });
        }
        let (_accepted, _duplicates) = self.remote.push_ops(&pending).await?;
        // Mark everything acked: ops the server received are not pushed again;
        // if the server in fact never got them (a lost response misread as
        // success), INSERT OR IGNORE keeps the next round's re-push
        // idempotently safe.
        let ids: Vec<Uuid> = pending.iter().map(|op| op.op_id).collect();
        self.repo.mark_acked(&ids).await?;
        Ok(PushCycleReport {
            pushed: pending.len(),
            skipped_travel: false,
        })
    }

    /// Pull remote increments and land them in the local oplog (the view is
    /// derived from item_view on demand; persisting them does no LWW
    /// materialization). Advances the cursor and the clock (`max` semantics).
    pub async fn pull_cycle(&self) -> Result<PullCycleReport> {
        if (self.travel_active)() {
            return Ok(PullCycleReport {
                applied: 0,
                skipped_travel: true,
            });
        }
        let mut applied = 0usize;
        let mut max_lamport_seen = 0u64;
        loop {
            let since = self.repo.get_state().await?.last_pull_cursor;
            let (ops, next_cursor) = self
                .remote
                .pull_ops(since.as_deref(), self.pull_page)
                .await?;
            if ops.is_empty() {
                break;
            }
            let ids: Vec<Uuid> = ops.iter().map(|op| op.op_id).collect();
            let seen = self.repo.existing_op_ids(&ids).await?;
            for op in ops {
                max_lamport_seen = max_lamport_seen.max(op.lamport);
                if seen.contains(&op.op_id) {
                    continue; // replay/duplicate delivery (second line of defense behind storage-layer idempotency)
                }
                self.repo.record_remote_op(&op).await?;
                applied += 1;
            }
            match next_cursor {
                Some(cursor) => self.repo.set_last_pull_cursor(Some(&cursor)).await?,
                None => break, // last page reached
            }
        }
        if max_lamport_seen > 0 {
            self.repo.bump_lamport(max_lamport_seen).await?;
        }
        // A pull round that ran to completion (even with no new ops) = reconciled
        // with the group; record the last sync time.
        self.repo.mark_synced(Utc::now()).await?;
        Ok(PullCycleReport {
            applied,
            skipped_travel: false,
        })
    }

    /// Library-level snapshot upload primitive (S2, E2EE_SYNC_DESIGN §5): the
    /// caller (service layer, which holds the key layer) packs the whole
    /// library into group key ciphertext via the `pack` callback, while the
    /// engine owns convergence and coverage-position determination — first
    /// drain the local pending push queue (which gets seqs from the server),
    /// then drain remote increments, and upload with the "local synced
    /// watermark" as coverage position S. The push-before-pull cycle order
    /// guarantees that every op with seq ≤ S on the server has already been
    /// reflected into local state (pull pages in (seq, op_id) total order, so
    /// an empty page means the watermark is the head at that moment).
    ///
    /// **Packing must happen after convergence** (2026-11-13 codex deep
    /// review, Critical fix): the earlier signature had the caller call
    /// `snapshot_payload()` before uploading, so remote ops pulled in by the
    /// converging pull were absent from the already-packed ciphertext yet
    /// still inside the watermark, where the server's `seq ≤ S` trimming
    /// pruned them — increments outside the snapshot were deleted forever.
    /// Now the engine converges first, and the watermark and the pack both
    /// read the same consistent post-convergence view (watermark read first,
    /// pack immediately after; this task no longer advances the watermark
    /// after convergence), so the coverage range matches its content; `pack`
    /// must not call the engine's push/pull. On success, record
    /// `last_snapshot_seq` (the trigger threshold baseline).
    /// Returns (coverage position S, number of ops compacted on the server).
    pub async fn upload_library_snapshot<F>(&self, pack: F) -> Result<(i64, u64)>
    where
        F: AsyncFnOnce() -> Result<Vec<u8>>,
    {
        if (self.travel_active)() {
            return Err(PersonaError::InvalidInput(
                "library snapshot upload is blocked while travel mode is active".to_string(),
            )
            .into());
        }
        self.push_cycle().await?;
        self.pull_cycle().await?;
        let seq = self.repo.local_watermark().await?;
        let ciphertext = pack().await?;
        let pruned = self
            .remote
            .put_library_snapshot(seq, &self.device_id.to_string(), &ciphertext)
            .await?;
        self.repo.set_last_snapshot_seq(seq).await?;
        Ok((seq, pruned))
    }

    /// Library-level snapshot install primitive (first step of S2 bootstrap):
    /// fetch the server snapshot → hand the whole package ciphertext to the
    /// callback (the assembly layer holds the keys: unwrap with the group key
    /// and idempotently insert the view-sufficient set into the local oplog
    /// by op_id). Only after the callback succeeds does the pull cursor
    /// advance to the coverage position and record `last_snapshot_seq`, so
    /// later pulls take only increments. A callback failure or a missing
    /// server snapshot never moves the cursor, leaving the full-replay path
    /// as it was (fail-closed: the cursor moving first while install fails
    /// means the covered range is already compacted yet never installed
    /// locally, an unrecoverable data hole).
    ///
    /// While travel is active the whole step is skipped (installing writes
    /// remote data into the oplog and primary database, the same direction
    /// as pull, and must not happen during travel; after leaving travel the
    /// next bootstrap installs as usual, as the cursor was untouched).
    /// Returns `Some(coverage position seq)`; `None` when there is no
    /// snapshot or travel skipped it (both behave the same: they fall back
    /// to the full-replay path, and the cursor decides whether to try again
    /// next time).
    pub async fn install_library_snapshot<F>(&self, install: F) -> Result<Option<i64>>
    where
        F: AsyncFnOnce(i64, Vec<u8>) -> Result<()>,
    {
        if (self.travel_active)() {
            return Ok(None);
        }
        let Some((seq, ciphertext)) = self.remote.get_library_snapshot().await? else {
            return Ok(None);
        };
        install(seq, ciphertext).await?;
        self.repo
            .set_last_pull_cursor(Some(&crate::sync::cursor::encode_cursor(
                seq,
                SNAPSHOT_RESUME_OP_ID,
            )))
            .await?;
        self.repo.set_last_snapshot_seq(seq).await?;
        Ok(Some(seq))
    }

    /// Snapshot upload trigger check (E2EE_SYNC_DESIGN §5 "trigger timing"):
    /// repacking is only worthwhile when `head − last snapshot position >
    /// threshold` (to avoid frequent repacking). Always false during travel
    /// (no upload); a missing snapshot baseline counts as 0. Kept separate
    /// from [`Self::upload_library_snapshot`]: the trigger only means it is
    /// possible — the upload still has to pass the convergence cycle, so the
    /// caller asks after a push ack.
    pub async fn library_snapshot_needed(&self, threshold: i64) -> Result<bool> {
        if (self.travel_active)() {
            return Ok(false);
        }
        let head = self.remote.head_seq().await?;
        let last = self.repo.get_state().await?.last_snapshot_seq;
        Ok(head - last > threshold)
    }

    /// Sync status (sync-group-mode §2.5.5): latest group version, local
    /// synced watermark, lag count, pending push count and last sync time.
    /// Read-only; it touches no cycle state.
    pub async fn sync_status(&self) -> Result<SyncStatusReport> {
        let head_seq = self.remote.head_seq().await?;
        let local_watermark = self.repo.local_watermark().await?;
        let pending_push = self.repo.pending_count().await?;
        let last_sync_at = self.repo.get_state().await?.last_sync_at;
        Ok(SyncStatusReport {
            head_seq,
            local_watermark,
            behind: (head_seq - local_watermark).max(0),
            pending_push,
            last_sync_at,
        })
    }
}

/// Group sync watermark snapshot (the data plane for the settings page
/// status display).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatusReport {
    /// Latest group version (maximum server oplog seq; 0 for an empty group).
    pub head_seq: i64,
    /// Local synced watermark (the seq pulled so far; 0 if never pulled).
    pub local_watermark: i64,
    /// How many ops behind the group (head − local, floored at zero).
    pub behind: i64,
    /// Ops produced locally that have not yet been pushed to the group.
    pub pending_push: i64,
    /// Last successful sync cycle; None = never synced.
    pub last_sync_at: Option<chrono::DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PersonaError;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    /// In-memory remote: ops accumulate verbatim; pull ignores the cursor and
    /// returns everything (replays are caught by the engine's existing_op_ids
    /// dedup — the cursor semantics themselves are pinned by the server
    /// integration tests).
    struct MemorySyncRemote {
        state: Mutex<MemState>,
    }

    struct MemState {
        ops: Vec<SyncOp>,
        fail_push: bool,
        /// Library-level snapshot (S2): (coverage position, ciphertext); None =
        /// not uploaded yet.
        snapshot: Option<(i64, Vec<u8>)>,
    }

    impl MemorySyncRemote {
        fn new() -> Self {
            Self {
                state: Mutex::new(MemState {
                    ops: Vec::new(),
                    fail_push: false,
                    snapshot: None,
                }),
            }
        }

        fn add(&self, ops: Vec<SyncOp>) {
            self.state.lock().unwrap().ops.extend(ops);
        }
    }

    #[async_trait::async_trait]
    impl SyncRemote for MemorySyncRemote {
        async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
            let mut state = self.state.lock().unwrap();
            if state.fail_push {
                return Err(PersonaError::Io("push failed".to_string()).into());
            }
            let existing: HashSet<Uuid> = state.ops.iter().map(|op| op.op_id).collect();
            let mut accepted = 0u64;
            let mut duplicates = 0u64;
            for op in ops {
                if existing.contains(&op.op_id) {
                    duplicates += 1;
                } else {
                    accepted += 1;
                }
            }
            state.ops.extend(ops.iter().cloned());
            Ok((accepted, duplicates))
        }

        async fn pull_ops(
            &self,
            since: Option<&str>,
            limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            // Cursor semantics are isomorphic with the server's: the cursor position =
            // number of entries returned, and next points at the start of the
            // following page; reaching the last page returns None (otherwise
            // the engine's loop would never terminate).
            let state = self.state.lock().unwrap();
            let start = match since {
                Some(raw) => crate::sync::cursor::decode_cursor(raw)
                    .map(|(seq, _)| seq as usize)
                    .unwrap_or(0),
                None => 0,
            };
            let total = state.ops.len();
            let end = start.saturating_add(limit as usize).min(total);
            let page = state.ops[start.min(total)..end].to_vec();
            // Same semantics as the server: a non-empty page always returns the cursor
            // of its last row (null for an empty page, and the client loops
            // on "stop only at an empty page") — so the watermark can always
            // advance to the consumed position.
            let next = (end > start).then(|| {
                crate::sync::cursor::encode_cursor(
                    end as i64,
                    &state.ops[end - 1].op_id.to_string(),
                )
            });
            Ok((page, next))
        }

        async fn head_seq(&self) -> Result<i64> {
            // The in-memory remote's "server seq" = cumulative op count (head grows by
            // however many ops are pushed)
            Ok(self.state.lock().unwrap().ops.len() as i64)
        }

        async fn put_library_snapshot(
            &self,
            seq: i64,
            _device_id: &str,
            ciphertext: &[u8],
        ) -> Result<u64> {
            // Single-snapshot upsert; the return value bookkeeps "the number of ops to
            // be compacted". The in-memory remote stays append-only — the seq
            // semantics of real deletion (monotonic rowid, absolute cursors)
            // would fork if simulated with a vec, and the server side is
            // already pinned by integration tests
            // (snapshot_put_get_roundtrip_and_prunes_covered_ops).
            let mut state = self.state.lock().unwrap();
            let pruned = (seq as usize).min(state.ops.len());
            state.snapshot = Some((seq, ciphertext.to_vec()));
            Ok(pruned as u64)
        }

        async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
            Ok(self.state.lock().unwrap().snapshot.clone())
        }
    }

    /// The engine holds an Arc-shared in-memory remote (orphan rule allows: local
    /// trait for Arc<T>).
    #[async_trait::async_trait]
    impl<T: SyncRemote + ?Sized> SyncRemote for Arc<T> {
        async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
            self.as_ref().push_ops(ops).await
        }

        async fn pull_ops(
            &self,
            since: Option<&str>,
            limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            self.as_ref().pull_ops(since, limit).await
        }

        async fn head_seq(&self) -> Result<i64> {
            self.as_ref().head_seq().await
        }

        async fn put_library_snapshot(
            &self,
            seq: i64,
            device_id: &str,
            ciphertext: &[u8],
        ) -> Result<u64> {
            self.as_ref()
                .put_library_snapshot(seq, device_id, ciphertext)
                .await
        }

        async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
            self.as_ref().get_library_snapshot().await
        }
    }

    async fn fixture(travel: bool) -> (SyncEngine<Arc<MemorySyncRemote>>, Arc<MemorySyncRemote>) {
        let db = crate::storage::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let remote = Arc::new(MemorySyncRemote::new());
        let engine = SyncEngine::new(
            SyncRepository::new(db),
            remote.clone(),
            Uuid::new_v4(),
            Box::new(move || travel),
        );
        (engine, remote)
    }

    fn put_payload(tag: u8) -> Option<SyncPayload> {
        Some(SyncPayload {
            ciphertext: vec![tag; 8],
            wrapped_item_key: vec![tag; 32],
        })
    }

    fn remote_put(lamport: u64, tag: u8, kind: ItemKind) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            kind,
            op: OpType::Put,
            lamport,
            device_id: Uuid::new_v4(),
            timestamp: None,
            payload: put_payload(tag),
        }
    }

    #[tokio::test]
    async fn record_local_change_increments_clock_and_enqueues() {
        let (engine, _remote) = fixture(false).await;
        let device = engine.device_id;
        let item = Uuid::new_v4();

        let first = engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(1))
            .await
            .unwrap();
        let second = engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(2))
            .await
            .unwrap();

        assert_eq!((first.lamport, second.lamport), (1, 2));
        assert_eq!(first.device_id, device);
        let pending = engine.repo.pending_ops(100).await.unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 2);
    }

    #[tokio::test]
    async fn push_cycle_drains_queue_and_marks_acked() {
        let (engine, remote) = fixture(false).await;
        let item = Uuid::new_v4();
        for tag in 1..=3u8 {
            engine
                .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(tag))
                .await
                .unwrap();
        }
        let report = engine.push_cycle().await.unwrap();
        assert_eq!(report.pushed, 3);
        assert!(!report.skipped_travel);
        assert!(engine.repo.pending_ops(100).await.unwrap().is_empty());
        assert_eq!(remote.state.lock().unwrap().ops.len(), 3);

        // Push again: empty queue is a no-op
        let again = engine.push_cycle().await.unwrap();
        assert_eq!(again.pushed, 0);
    }

    #[tokio::test]
    async fn push_failure_keeps_queue_for_retry() {
        let (engine, remote) = fixture(false).await;
        let item = Uuid::new_v4();
        engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(1))
            .await
            .unwrap();

        remote.state.lock().unwrap().fail_push = true;
        assert!(engine.push_cycle().await.is_err());
        assert_eq!(engine.repo.pending_ops(100).await.unwrap().len(), 1);

        remote.state.lock().unwrap().fail_push = false;
        assert_eq!(engine.push_cycle().await.unwrap().pushed, 1);
        assert!(engine.repo.pending_ops(100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn travel_gate_stops_push_and_pull_both() {
        let (engine, remote) = fixture(true).await;
        let item = Uuid::new_v4();
        engine
            .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(1))
            .await
            .unwrap();

        let push = engine.push_cycle().await.unwrap();
        assert!(push.skipped_travel);
        assert_eq!(push.pushed, 0);
        assert_eq!(engine.repo.pending_ops(100).await.unwrap().len(), 1); // queue kept intact

        remote.add(vec![remote_put(9, 1, ItemKind::Credential)]);
        let pull = engine.pull_cycle().await.unwrap();
        assert!(pull.skipped_travel);
        assert_eq!(pull.applied, 0);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 1); // clock not advanced by the remote
    }

    #[tokio::test]
    async fn pull_lands_remote_ops_and_advances_clock() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(5, 1, ItemKind::Credential),
            remote_put(7, 2, ItemKind::Identity),
        ]);

        let report = engine.pull_cycle().await.unwrap();
        assert_eq!(report.applied, 2);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 7);

        // Replay the same remote: full dedup
        let replay = engine.pull_cycle().await.unwrap();
        assert_eq!(replay.applied, 0);
    }

    #[tokio::test]
    async fn pull_unknown_kind_still_lands_and_counts_for_clock() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![remote_put(4, 1, ItemKind::Unknown)]);

        let report = engine.pull_cycle().await.unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(engine.repo.get_state().await.unwrap().local_lamport, 4);
    }

    #[tokio::test]
    async fn local_write_after_pull_continues_from_max() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![remote_put(7, 1, ItemKind::Credential)]);
        engine.pull_cycle().await.unwrap();

        // After pulling remote lamport 7, the next local write must continue at 8
        // (clock = max)
        let op = engine
            .record_local_change(
                Uuid::new_v4(),
                ItemKind::Credential,
                OpType::Put,
                put_payload(1),
            )
            .await
            .unwrap();
        assert_eq!(op.lamport, 8);
    }

    // ---- sync_status (sync-group-mode §2.5.5 status display) ----

    #[tokio::test]
    async fn sync_status_tracks_head_watermark_pending_and_last_sync() {
        let (engine, remote) = fixture(false).await;

        // Initial: group head=0, local watermark 0, never synced
        let s = engine.sync_status().await.unwrap();
        assert_eq!(
            (s.head_seq, s.local_watermark, s.behind, s.pending_push),
            (0, 0, 0, 0)
        );
        assert_eq!(s.last_sync_at, None);

        // 5 ops appear in the group + 2 offline local writes: behind 5, pending 2
        remote.add(
            (1..=5)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );
        for _ in 0..2 {
            engine
                .record_local_change(
                    Uuid::new_v4(),
                    ItemKind::Credential,
                    OpType::Put,
                    put_payload(1),
                )
                .await
                .unwrap();
        }
        let before = engine.sync_status().await.unwrap();
        assert_eq!(
            (
                before.head_seq,
                before.local_watermark,
                before.behind,
                before.pending_push,
                before.last_sync_at.is_none()
            ),
            (5, 0, 5, 2, true)
        );

        // Pull done: watermark at 5, lag cleared, sync time recorded; pending push
        // is unaffected by pull
        engine.pull_cycle().await.unwrap();
        let after = engine.sync_status().await.unwrap();
        assert_eq!(after.local_watermark, 5);
        assert_eq!(after.behind, 0);
        assert_eq!(after.pending_push, 2);
        assert!(after.last_sync_at.is_some());

        // Push done: pending cleared; head is 5 before the 2 unpushed ops are
        // counted, and becomes 7 on the remote after they land
        engine.push_cycle().await.unwrap();
        let final_status = engine.sync_status().await.unwrap();
        assert_eq!(final_status.head_seq, 7, "推上的 2 条计入组流水位");
        assert_eq!(final_status.pending_push, 0);
        assert_eq!(final_status.behind, 2, "远端又被自己推进(自推自) → 还差拉");
    }

    #[tokio::test]
    async fn pull_again_never_loops_and_watermark_reaches_head() {
        // Large batch pulled across pages: the watermark must advance all the way to
        // head (position-based resumption)
        let (engine, remote) = fixture(false).await;
        remote.add(
            (1..=450)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );
        let report = engine.pull_cycle().await.unwrap();
        assert_eq!(report.applied, 450);
        let s = engine.sync_status().await.unwrap();
        assert_eq!((s.local_watermark, s.behind), (450, 0));
        // Once the cursor has advanced to the end, the next pull round is a single
        // empty-page round trip
        let again = engine.pull_cycle().await.unwrap();
        assert_eq!(again.applied, 0);
    }

    // ---- library-level snapshot primitives (S2, E2EE_SYNC_DESIGN §5) ----

    #[tokio::test]
    async fn upload_snapshot_converges_then_stamps_watermark() {
        // Coverage position semantics: drain the local queue first, then pull remote
        // increments; the watermark = the position the server has consumed
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(1, 1, ItemKind::Credential),
            remote_put(2, 2, ItemKind::Identity),
            remote_put(3, 3, ItemKind::Passkey),
        ]);
        let item = Uuid::new_v4();
        for tag in 1..=2u8 {
            engine
                .record_local_change(item, ItemKind::Credential, OpType::Put, put_payload(tag))
                .await
                .unwrap();
        }

        let (seq, pruned) = engine
            .upload_library_snapshot(|| async { Ok(vec![7u8; 5]) })
            .await
            .unwrap();
        assert_eq!(seq, 5, "远端 3 条 + 本机推上的 2 条 = 水位 5");
        assert_eq!(pruned, 5, "服务器压缩了覆盖区间内的全部 ops");
        assert_eq!(
            remote.state.lock().unwrap().snapshot,
            Some((5, vec![7u8; 5])),
            "单快照 upsert，密文与覆盖位点原样入库"
        );
        assert_eq!(
            remote.state.lock().unwrap().ops.len(),
            5,
            "内存远端 append-only（真删除由 server 集成测试锁定），只记账"
        );
        assert_eq!(
            engine.repo.get_state().await.unwrap().last_snapshot_seq,
            5,
            "上传成功记触发阈值基线"
        );

        // Continue pulling increments after the snapshot: the cursor's absolute
        // position (absolute seq) is unaffected by compaction
        remote.add(vec![remote_put(4, 4, ItemKind::Credential)]);
        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 1, "只拉到快照点之后的增量");
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 6);
    }

    #[tokio::test]
    async fn upload_snapshot_blocked_during_travel() {
        let (engine, remote) = fixture(true).await;
        let err = engine
            .upload_library_snapshot(|| async { Ok(vec![1u8; 4]) })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("travel"), "{err}");
        assert!(remote.state.lock().unwrap().snapshot.is_none());
    }

    #[tokio::test]
    async fn install_snapshot_advances_cursor_and_pulls_only_increment() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(1, 1, ItemKind::Credential),
            remote_put(2, 2, ItemKind::Identity),
            remote_put(3, 3, ItemKind::Credential),
        ]);
        remote.state.lock().unwrap().snapshot = Some((3, vec![9u8; 4]));

        let mut installed = None;
        let seq = engine
            .install_library_snapshot(async |s, bytes| {
                installed = Some((s, bytes));
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(seq, Some(3));
        assert_eq!(installed, Some((3, vec![9u8; 4])));
        assert_eq!(
            engine.repo.local_watermark().await.unwrap(),
            3,
            "游标直读快照位点"
        );
        assert_eq!(
            engine.repo.get_state().await.unwrap().last_snapshot_seq,
            3,
            "装包成功记触发阈值基线"
        );

        // Increments after the snapshot point are pulled as usual — starting from
        // the sentinel cursor (3, "0")
        remote.add(vec![remote_put(4, 4, ItemKind::Credential)]);
        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 1, "只拉 seq > 3 的增量，不重放已装快照");
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 4);
    }

    #[tokio::test]
    async fn install_without_snapshot_keeps_full_replay_path() {
        let (engine, remote) = fixture(false).await;
        remote.add(vec![remote_put(1, 1, ItemKind::Credential)]);

        let seq = engine
            .install_library_snapshot(async |_, _| panic!("无快照不得调用装包回调"))
            .await
            .unwrap();
        assert_eq!(seq, None);
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 0);

        // Full-replay path still works as before
        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 1);
    }

    #[tokio::test]
    async fn install_callback_failure_leaves_cursor_untouched() {
        // Main fail-closed scenario: an install failure leaves the cursor untouched —
        // although the covered range has already been compacted on the server,
        // the device still replays the remaining ops from zero (the shrunken
        // subset converges too), with no half-installed state left behind
        let (engine, remote) = fixture(false).await;
        remote.add(vec![
            remote_put(1, 1, ItemKind::Credential),
            remote_put(2, 2, ItemKind::Credential),
        ]);
        remote.state.lock().unwrap().snapshot = Some((2, vec![5u8; 4]));

        let err = engine
            .install_library_snapshot(async |_, _| {
                Err(PersonaError::CryptographicError("wrong group key".to_string()).into())
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("wrong group key"), "{err}");
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 0, "游标未动");

        let pull = engine.pull_cycle().await.unwrap();
        assert_eq!(pull.applied, 2, "剩余 ops 仍可全量重放");
    }

    #[tokio::test]
    async fn install_snapshot_skipped_during_travel() {
        // Install is skipped outright during travel (it writes remote data into the
        // oplog, the same gate as pull): the callback must not be called and
        // neither the cursor nor the watermark baseline may move — after
        // leaving travel, the next bootstrap will try again
        let (engine, remote) = fixture(true).await;
        remote.state.lock().unwrap().snapshot = Some((3, vec![1u8; 2]));
        let seq = engine
            .install_library_snapshot(async |_, _| panic!("travel 期间不得装包"))
            .await
            .unwrap();
        assert_eq!(seq, None);
        assert_eq!(engine.repo.local_watermark().await.unwrap(), 0);
        assert_eq!(engine.repo.get_state().await.unwrap().last_snapshot_seq, 0);
    }

    #[tokio::test]
    async fn library_snapshot_needed_tracks_threshold_and_travel() {
        let (engine, remote) = fixture(false).await;
        remote.add(
            (1..=5)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );

        // Never snapshotted (baseline 0): head 5 exceeds threshold 3 and triggers;
        // strictly greater — threshold 5 does not trigger
        assert!(engine.library_snapshot_needed(3).await.unwrap());
        assert!(!engine.library_snapshot_needed(5).await.unwrap());

        // After upload the baseline = watermark 5: head 5 − 5 = 0, so no threshold
        // triggers anymore
        engine
            .upload_library_snapshot(|| async { Ok(vec![1u8; 3]) })
            .await
            .unwrap();
        assert!(!engine.library_snapshot_needed(0).await.unwrap());

        // The group keeps advancing: head 8 − baseline 5 = 3 → exceeds 2 and
        // triggers, equal to 3 does not trigger
        remote.add(
            (6..=8)
                .map(|i| remote_put(i, 1, ItemKind::Credential))
                .collect(),
        );
        assert!(engine.library_snapshot_needed(2).await.unwrap());
        assert!(!engine.library_snapshot_needed(3).await.unwrap());

        // Travel active: never triggers (no upload)
        let (travel_engine, travel_remote) = fixture(true).await;
        travel_remote.add(vec![remote_put(1, 1, ItemKind::Credential)]);
        assert!(!travel_engine.library_snapshot_needed(0).await.unwrap());
    }
}
