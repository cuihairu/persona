//! Wire types for sync and pairing (device status / join / sync now / status /
//! rotate / conflicts / pairing outcomes).

use serde::Serialize;

/// Return of `sync_device_status`: this machine's device identity state
/// (purely local keyring, no unlock required).
#[derive(Debug, Clone, Serialize)]
pub struct SyncDeviceStatus {
    /// The keyring holds a parsable device identity.
    pub joined: bool,
    /// The keyring has a record that fails to parse (corrupted / hand-edited) —
    /// the UI prompts to re-join (leave can still clean up; server-side residue
    /// can be revoked from another device).
    pub corrupted: bool,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}

/// Return of `sync_join`: the registration outcome. `pending = true` means
/// registered but not yet authorized (no envelope for this device in
/// group-keys); authorization must be performed on another authorized device.
#[derive(Debug, Clone, Serialize)]
pub struct SyncJoinOutcome {
    pub device_id: String,
    pub device_name: String,
    pub pending: bool,
}

/// Single-row view of `sync_list_devices`: server registration row +
/// authorization status + this-device marker.
#[derive(Debug, Clone, Serialize)]
pub struct SyncDeviceView {
    pub id: String,
    pub device_name: String,
    pub created_at: String,
    /// Free-form remark from the device owner (S4: writable by that device
    /// only, readable by everyone).
    pub remark: String,
    /// group-keys holds an envelope for this device ("has envelope =
    /// authorized", fail-closed).
    pub authorized: bool,
    pub this_device: bool,
}

/// Return of `sync_now`: the counter summary of one sync round (fields mirror
/// core `SyncNowReport` one-to-one, for the UI to show "pulled N /
/// materialized N / conflicts N").
#[derive(Debug, Clone, Serialize)]
pub struct SyncNowReport {
    /// Remote ops newly pulled and persisted.
    pub pulled: usize,
    /// Entries materialized into the main db (new rows or updates).
    pub materialized: usize,
    /// Conflicting losers left in the oplog (no data loss, awaiting a ruling).
    pub conflicts: usize,
    /// Entries held back because identity is not yet synced (filled next round).
    pub pending_identity: usize,
    /// Local ops pushed out.
    pub pushed: usize,
    /// Pre-existing credentials backfilled into the oplog this round (usually
    /// nonzero only on the first sync).
    pub backfilled: u64,
}

impl From<persona_core::sync::runtime::SyncNowReport> for SyncNowReport {
    fn from(report: persona_core::sync::runtime::SyncNowReport) -> Self {
        Self {
            pulled: report.pulled,
            materialized: report.materialized,
            conflicts: report.conflicts,
            pending_identity: report.pending_identity,
            pushed: report.pushed,
            backfilled: report.backfilled,
        }
    }
}

/// Return of `sync_status_report`: a group sync watermark snapshot
/// (sync-group-mode §2.5.5 status display — group's latest version /
/// local synced watermark / behind by N / pending push N / last sync time).
/// Fields correspond to core `engine::SyncStatusReport`; `last_sync_at` is
/// RFC3339.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusInfo {
    pub head_seq: i64,
    pub local_watermark: i64,
    pub behind: i64,
    pub pending_push: i64,
    pub last_sync_at: Option<String>,
}

impl From<persona_core::sync::engine::SyncStatusReport> for SyncStatusInfo {
    fn from(report: persona_core::sync::engine::SyncStatusReport) -> Self {
        Self {
            head_seq: report.head_seq,
            local_watermark: report.local_watermark,
            behind: report.behind,
            pending_push: report.pending_push,
            last_sync_at: report.last_sync_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// Return of `sync_rotate`: the counter summary of a group key rotation
/// (fields mirror core `SyncRotateReport` one-to-one, for the UI to show
/// "rewrapped N / skipped N / pushed N").
#[derive(Debug, Clone, Serialize)]
pub struct SyncRotateReport {
    /// Credentials re-wrapped under the new group key.
    pub rewrapped: u64,
    /// Entries skipped due to legacy (no wrapped item key) / decryption
    /// failure — after rotation they still carry only the old group
    /// ciphertext, invisible to devices holding only the new envelope.
    pub skipped: u64,
    /// Total ops pushed over the whole rotation (pre-flush queue + rewrap
    /// batches).
    pub pushed: u64,
}

impl From<persona_core::sync::runtime::SyncRotateReport> for SyncRotateReport {
    fn from(report: persona_core::sync::runtime::SyncRotateReport) -> Self {
        Self {
            rewrapped: report.rewrapped,
            skipped: report.skipped,
            pushed: report.pushed,
        }
    }
}

/// Single-version view of `sync_conflicts_list`: the primary or a copy of a
/// conflicting item (fields mirror core `resolve::ConflictVersion`
/// one-to-one).
#[derive(Debug, Clone, Serialize)]
pub struct SyncConflictVersion {
    /// Op id to pass to `sync_conflict_resolve` when adopting.
    pub op_id: String,
    /// Device that produced this version (the frontend labels it as
    /// "this device / other device" from this).
    pub device_id: String,
    pub lamport: u64,
    /// Display only; not used for ruling ordering (LWW only looks at
    /// lamport + device).
    pub timestamp: Option<String>,
    /// Tombstone version: adopting = deleting the item; `snapshot` is then
    /// empty.
    pub deleted: bool,
    /// Decrypted snapshot of a put version (plaintext within the unlocked
    /// session, for frontend version comparison).
    pub snapshot: Option<persona_core::sync::snapshot::SyncItemSnapshot>,
}

/// One row of `sync_conflicts_list`: the conflict view of a single item
/// (primary + copies awaiting a ruling).
#[derive(Debug, Clone, Serialize)]
pub struct SyncConflictEntry {
    pub item_id: String,
    pub primary: SyncConflictVersion,
    pub copies: Vec<SyncConflictVersion>,
}

impl From<persona_core::sync::resolve::ConflictVersion> for SyncConflictVersion {
    fn from(version: persona_core::sync::resolve::ConflictVersion) -> Self {
        Self {
            op_id: version.op_id.to_string(),
            device_id: version.device_id.to_string(),
            lamport: version.lamport,
            timestamp: version.timestamp.map(|ts| ts.to_rfc3339()),
            deleted: version.deleted,
            snapshot: version.snapshot,
        }
    }
}

impl From<persona_core::sync::resolve::ConflictEntry> for SyncConflictEntry {
    fn from(entry: persona_core::sync::resolve::ConflictEntry) -> Self {
        Self {
            item_id: entry.item_id.to_string(),
            primary: entry.primary.into(),
            copies: entry.copies.into_iter().map(Into::into).collect(),
        }
    }
}

/// Return of `sync_group_pairing_create`: the code-display side (dynamic
/// code + invite link + relay session).
#[derive(Debug, Clone, Serialize)]
pub struct SyncPairingCreateOutcome {
    /// Dynamic code (9-digit Crockford base32; this is what gets verified
    /// by hand with the other party).
    pub code: String,
    /// Invite link `persona-pair-1.<b64url>` (handed to the guest via QR /
    /// clipboard).
    pub invite_link: String,
    /// Relay session id (the frontend no longer cares about it beyond using
    /// it to locate the session for poll/cancel).
    pub session_id: String,
    /// Remaining relay session validity (seconds; TTL 600, a new code must be
    /// generated after expiry).
    pub expires_in_secs: i64,
}

/// Return of `sync_group_pairing_poll`: the host-side waiting outcome.
#[derive(Debug, Clone, Serialize)]
pub struct SyncPairingPollOutcome {
    /// Pairing completed (group key delivered to the guest and stored in the
    /// local keyring).
    pub completed: bool,
    /// Host-side short fingerprint (6 digits; returned on completion, matching
    /// what the guest side displays).
    pub fingerprint: Option<String>,
}

/// Return of `sync_group_join_begin`: the guest code-entry side (before the
/// fingerprint-comparison gate).
#[derive(Debug, Clone, Serialize)]
pub struct SyncJoinBeginOutcome {
    /// Guest-side short fingerprint (6 digits; compared with the host display,
    /// confirm only if they match).
    pub fingerprint: String,
    /// Dynamic code from the invite link (should match the code the user
    /// typed in — an extra manual cross-check).
    pub code: String,
    /// Relay session id (used to locate the session for confirm/cancel).
    pub session_id: String,
}
