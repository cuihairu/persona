//! oplog entry structure and LWW conflict resolution (E2EE_SYNC_DESIGN DR-4 /
//! §5 / §7).
//!
//! Total order = `(lamport, device_id)`: the larger lamport wins; on a tie,
//! compare device_id lexicographically; both sides computing independently
//! must agree. Two versions of the same item with **equal lamport from
//! different devices** = a true conflict (the typical offline double-edit
//! shape) → keep both versions: the winner holds the primary position, the
//! loser goes into the conflict zone and waits for user adjudication (the
//! resolution UI is phase 3; this layer guarantees no data loss and no silent
//! overwrite).
//!
//! One deviation from the design doc: `conflict_of` is not a persisted
//! snapshot column; instead [`item_view`] **derives** it from the item's op
//! set (primary = the max in the total order; copies = the remaining versions
//! with a lamport equal to the primary but a different device)——the
//! append-only log needs no maintenance, the semantics are equivalent, and
//! there is no "copies dangling after the primary is overwritten" problem.
//!
//! Deletion = tombstone (a delete op with an empty payload), participating in
//! the same LWW, preventing an offline deletion from being revived by an old
//! version; the server only stores and forwards, making no win/loss
//! decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use uuid::Uuid;

/// The sync item type. Corresponds one-to-one with the kind strings of the
/// server wire layer (snake_case). `Unknown` is the forward-compatibility
/// fallback: a new kind introduced by a newer client can be stored and
/// participate in LWW after being pulled and persisted by an older build
/// (kind does not participate in adjudication); it is simply not
/// understood/rendered locally——when serialized back to the wire it is
/// written as "unknown" (not lossless, but an unknown kind never produces a
/// local write in the first place).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Credential,
    Identity,
    Passkey,
    #[serde(other)]
    Unknown,
}

/// The operation type: put = write/update; delete = tombstone (the payload
/// is always empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpType {
    Put,
    Delete,
}

/// The ciphertext payload of an oplog entry (§5): every byte is ciphertext,
/// unreadable to the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPayload {
    pub ciphertext: Vec<u8>,
    /// The per-item key wrapped by the group key (same origin as the local
    /// wrapped_item_key).
    pub wrapped_item_key: Vec<u8>,
}

/// One sync operation (§5 SyncOp). `timestamp` is display-only and
/// **participates in no ordering** (the clock trusts only the client Lamport
/// counter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOp {
    /// Idempotency dedup key (push replays / pull duplicate deliveries are
    /// ignored on this).
    pub op_id: Uuid,
    pub item_id: Uuid,
    pub kind: ItemKind,
    pub op: OpType,
    pub lamport: u64,
    pub device_id: Uuid,
    pub timestamp: Option<DateTime<Utc>>,
    /// None for delete (tombstone).
    pub payload: Option<SyncPayload>,
}

impl SyncOp {
    pub fn is_tombstone(&self) -> bool {
        self.op == OpType::Delete
    }
}

/// LWW total-order comparison (DR-4): lamport first, then device_id.
/// **op_id is not included**——two ops with the same (lamport, device_id)
/// should not coexist under the protocol (a single device's clock is
/// monotonic).
pub fn compare_ops(a: &SyncOp, b: &SyncOp) -> Ordering {
    a.lamport
        .cmp(&b.lamport)
        .then(a.device_id.cmp(&b.device_id))
}

/// True conflict: same item, equal lamport, from different devices (DR-4
/// definition).
pub fn is_true_conflict(a: &SyncOp, b: &SyncOp) -> bool {
    a.item_id == b.item_id && a.lamport == b.lamport && a.device_id != b.device_id
}

/// The LWW view of a single item: the primary position + the conflict copy
/// zone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemState {
    /// The current winner (put or tombstone).
    pub primary: Option<SyncOp>,
    /// The concurrent versions retired in a true conflict, waiting for user
    /// adjudication (phase 3 UI).
    pub conflicts: Vec<SyncOp>,
}

impl ItemState {
    /// Derive the view from all ops of the item (the method form of
    /// [`item_view`]).
    pub fn from_ops(ops: Vec<SyncOp>) -> Self {
        let mut state = Self::default();
        // Replay in a deterministic order, equivalent to applying one by one
        let mut ops = ops;
        ops.sort_by(|a, b| {
            b.lamport
                .cmp(&a.lamport)
                .then(b.device_id.cmp(&a.device_id))
                .then(b.op_id.cmp(&a.op_id))
        });
        for op in ops {
            apply_op(&mut state, op);
        }
        state
    }

    pub fn seen_op(&self, op_id: &Uuid) -> bool {
        self.primary.as_ref().is_some_and(|p| &p.op_id == op_id)
            || self.conflicts.iter().any(|c| &c.op_id == op_id)
    }
}

/// Derive the primary and conflict copies from a set of ops of the same item
/// (see the conflict_of deviation in the module docs).
pub fn item_view(ops: Vec<SyncOp>) -> ItemState {
    ItemState::from_ops(ops)
}

/// The result of a single apply step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// `incoming` becomes the new primary. `demoted` only appears when a true
    /// conflict's winner replaces it——the former primary that got demoted
    /// (this function has already pushed it into `conflicts`; it is returned
    /// here for the caller to observe/audit).
    Applied { demoted: Option<SyncOp> },
    /// `incoming` is a concurrent loser, demoted to a conflict copy.
    ConflictCopy,
    /// An old version, a replay (op_id already seen), or an out-of-bounds
    /// duplicate with the same (lamport, device_id).
    Ignored,
}

/// Apply one op to the item state (pure function; the single-step core of
/// [`apply_batch`]).
pub fn apply_op(state: &mut ItemState, incoming: SyncOp) -> StepOutcome {
    // Idempotency: op_id already in the primary or the copy zone → a
    // replay/duplicate delivery, ignore
    if state.seen_op(&incoming.op_id) {
        return StepOutcome::Ignored;
    }
    let Some(incumbent) = state.primary.clone() else {
        state.primary = Some(incoming);
        return StepOutcome::Applied { demoted: None };
    };
    match compare_ops(&incoming, &incumbent) {
        Ordering::Less => {
            if incoming.lamport == incumbent.lamport {
                // Concurrent loser (the true-conflict loser arriving late):
                // keep both versions
                state.conflicts.push(incoming);
                StepOutcome::ConflictCopy
            } else {
                // Strictly older version (including a late put against a
                // tombstone: prevents revival)
                StepOutcome::Ignored
            }
        }
        Ordering::Greater => {
            if incoming.lamport == incumbent.lamport {
                // True-conflict winner: the former primary is demoted into
                // the conflict zone (keep both versions)
                let demoted = state.primary.replace(incoming);
                state
                    .conflicts
                    .push(demoted.clone().expect("primary just replaced"));
                StepOutcome::Applied { demoted }
            } else {
                state.primary = Some(incoming);
                StepOutcome::Applied { demoted: None }
            }
        }
        Ordering::Equal => {
            // Same (lamport, device_id) but a different op_id: violates the
            // protocol invariant of per-device clock monotonicity. Defensively
            // ignore the later arrival; do not overwrite, do not crash.
            StepOutcome::Ignored
        }
    }
}

/// The summary of applying a batch of ops. `max_lamport` lets the caller
/// advance the local clock: `local = max(local, report.max_lamport)` (pull
/// clock advancement, DR-4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchReport {
    pub applied: usize,
    pub conflicts: usize,
    pub ignored: usize,
    pub max_lamport: u64,
}

/// Apply a batch of pulled ops (§7 operation order): first stable-sort them
/// **descending** by (lamport, device_id, op_id), then apply one by one via
/// [`apply_op`]. Out-of-order delivery / cross-batch disorder is naturally
/// tolerated——the final state depends only on the op set itself, not on the
/// arrival order.
pub fn apply_batch(items: &mut BTreeMap<Uuid, ItemState>, ops: Vec<SyncOp>) -> BatchReport {
    let mut ops = ops;
    ops.sort_by(|a, b| {
        b.lamport
            .cmp(&a.lamport)
            .then(b.device_id.cmp(&a.device_id))
            .then(b.op_id.cmp(&a.op_id))
    });
    let mut report = BatchReport::default();
    for op in ops {
        report.max_lamport = report.max_lamport.max(op.lamport);
        let state = items.entry(op.item_id).or_default();
        match apply_op(state, op) {
            StepOutcome::Applied { .. } => report.applied += 1,
            StepOutcome::ConflictCopy => report.conflicts += 1,
            StepOutcome::Ignored => report.ignored += 1,
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEM: Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000001");
    const DEVICE_A: Uuid = uuid::uuid!("00000000-0000-0000-0000-00000000000a");
    const DEVICE_B: Uuid = uuid::uuid!("00000000-0000-0000-0000-00000000000b");

    fn put(lamport: u64, device: Uuid, tag: u8) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: ITEM,
            kind: ItemKind::Credential,
            op: OpType::Put,
            lamport,
            device_id: device,
            timestamp: None,
            payload: Some(SyncPayload {
                ciphertext: vec![tag],
                wrapped_item_key: vec![tag],
            }),
        }
    }

    fn delete(lamport: u64, device: Uuid) -> SyncOp {
        SyncOp {
            op: OpType::Delete,
            payload: None,
            ..put(lamport, device, 0)
        }
    }

    // ---- compare_ops / is_true_conflict ----

    #[test]
    fn lamport_decides_regardless_of_device() {
        let low = put(1, DEVICE_B, 0);
        let high = put(2, DEVICE_A, 1);
        assert_eq!(compare_ops(&high, &low), Ordering::Greater);
        assert_eq!(compare_ops(&low, &high), Ordering::Less);
    }

    #[test]
    fn equal_lamport_falls_back_to_device_id() {
        let a = put(3, DEVICE_A, 0);
        let b = put(3, DEVICE_B, 1);
        assert_eq!(compare_ops(&b, &a), Ordering::Greater);
        assert!(is_true_conflict(&a, &b));
        assert!(!is_true_conflict(&a, &a)); // An op is not a conflict with itself
    }

    #[test]
    fn same_lamport_same_device_is_not_conflict() {
        let x = put(3, DEVICE_A, 0);
        let mut y = x.clone();
        y.op_id = Uuid::new_v4();
        assert!(!is_true_conflict(&x, &y));
        assert_eq!(compare_ops(&x, &y), Ordering::Equal);
    }

    // ---- apply_op ----

    #[test]
    fn first_op_takes_primary() {
        let mut state = ItemState::default();
        let op = put(1, DEVICE_A, 7);
        assert_eq!(
            apply_op(&mut state, op.clone()),
            StepOutcome::Applied { demoted: None }
        );
        assert_eq!(state.primary, Some(op));
        assert!(state.conflicts.is_empty());
    }

    #[test]
    fn newer_put_overwrites_primary_without_demote() {
        let mut state = ItemState::default();
        let old = put(1, DEVICE_A, 0);
        let new = put(2, DEVICE_A, 1);
        apply_op(&mut state, old);
        assert_eq!(
            apply_op(&mut state, new.clone()),
            StepOutcome::Applied { demoted: None }
        );
        assert_eq!(state.primary, Some(new));
    }

    #[test]
    fn stale_put_is_ignored() {
        let mut state = ItemState::default();
        apply_op(&mut state, put(5, DEVICE_A, 0));
        assert_eq!(
            apply_op(&mut state, put(4, DEVICE_B, 1)),
            StepOutcome::Ignored
        );
    }

    #[test]
    fn tombstone_prevents_revival_by_stale_put() {
        // An offline deletion being revived by an older version is exactly
        // the shape DR-4 explicitly guards against
        let mut state = ItemState::default();
        apply_op(&mut state, put(1, DEVICE_A, 0));
        apply_op(&mut state, delete(2, DEVICE_A));
        assert!(state.primary.as_ref().unwrap().is_tombstone());
        assert_eq!(
            apply_op(&mut state, put(1, DEVICE_B, 9)),
            StepOutcome::Ignored
        );
        assert!(state.primary.as_ref().unwrap().is_tombstone());
    }

    #[test]
    fn true_conflict_keeps_both_versions_regardless_of_arrival_order() {
        let a = put(3, DEVICE_A, 1);
        let b = put(3, DEVICE_B, 2);
        assert!(is_true_conflict(&a, &b));

        // A arrives first: B wins (device_id lexicographic), A is demoted
        let mut state1 = ItemState::default();
        apply_op(&mut state1, a.clone());
        assert_eq!(
            apply_op(&mut state1, b.clone()),
            StepOutcome::Applied {
                demoted: Some(a.clone())
            }
        );
        assert_eq!(state1.primary.as_ref().unwrap().device_id, DEVICE_B);
        assert_eq!(state1.conflicts, vec![a.clone()]);

        // B arrives first: A is demoted outright——both arrival orders reach
        // the same final state (convergence)
        let mut state2 = ItemState::default();
        apply_op(&mut state2, b.clone());
        assert_eq!(apply_op(&mut state2, a.clone()), StepOutcome::ConflictCopy);
        assert_eq!(state1, state2);
    }

    #[test]
    fn replayed_op_id_is_ignored_wherever_it_landed() {
        let op = put(1, DEVICE_A, 0);
        let mut state = ItemState::default();
        apply_op(&mut state, op.clone());
        assert_eq!(apply_op(&mut state, op.clone()), StepOutcome::Ignored);

        // Replaying an op_id from the copy zone is likewise ignored
        let loser = put(2, DEVICE_A, 5);
        let winner = put(2, DEVICE_B, 6);
        apply_op(&mut state, loser.clone());
        apply_op(&mut state, winner);
        assert_eq!(apply_op(&mut state, loser), StepOutcome::Ignored);
    }

    #[test]
    fn protocol_violation_same_key_different_op_id_is_ignored() {
        let x = put(3, DEVICE_A, 0);
        let mut y = x.clone();
        y.op_id = Uuid::new_v4();
        let mut state = ItemState::default();
        apply_op(&mut state, x);
        assert_eq!(apply_op(&mut state, y), StepOutcome::Ignored);
    }

    #[test]
    fn timestamp_never_participates_in_ordering() {
        let mut early = put(3, DEVICE_A, 0);
        early.timestamp = Some(DateTime::from_timestamp(0, 0).unwrap());
        let mut late = put(3, DEVICE_A, 1);
        late.timestamp = Some(DateTime::from_timestamp(999, 0).unwrap());
        late.op_id = Uuid::new_v4();
        let mut state = ItemState::default();
        apply_op(&mut state, early);
        // Same (lamport, device): the later arrival is ignored——wall-clock
        // recency has no bearing
        assert_eq!(apply_op(&mut state, late), StepOutcome::Ignored);
    }

    // ---- apply_batch / item_view ----

    #[test]
    fn batch_is_order_independent() {
        let ops = vec![
            put(1, DEVICE_A, 0),
            put(3, DEVICE_B, 1),
            put(2, DEVICE_A, 2),
        ];
        let mut forward = BTreeMap::new();
        let fwd = apply_batch(&mut forward, ops.clone());
        let mut shuffled = BTreeMap::new();
        let mut reversed = ops.clone();
        reversed.reverse();
        let rev = apply_batch(&mut shuffled, reversed);
        assert_eq!(forward, shuffled);
        // Only the maximum in the total order becomes the primary; the rest
        // are strictly older versions and are correctly ignored (the history
        // still lives in the local items table; the LWW view keeps only the
        // winner)
        assert_eq!(fwd.applied, 1);
        assert_eq!(fwd.ignored, 2);
        assert_eq!(fwd.max_lamport, 3);
        assert_eq!(rev.max_lamport, 3);
    }

    #[test]
    fn batch_replay_is_fully_ignored() {
        let ops = vec![put(1, DEVICE_A, 0), put(2, DEVICE_B, 1)];
        let mut items = BTreeMap::new();
        let first = apply_batch(&mut items, ops.clone());
        // lamport 2 is the primary, lamport 1 is a strictly older version →
        // only one op is applied
        assert_eq!(first.applied, 1);
        assert_eq!(first.max_lamport, 2);
        let replay = apply_batch(&mut items, ops);
        assert_eq!(
            (replay.applied, replay.conflicts, replay.ignored),
            (0, 0, 2)
        );
    }

    #[test]
    fn batch_conflict_keeps_both_and_reports_clock() {
        let a = put(3, DEVICE_A, 1);
        let b = put(3, DEVICE_B, 2);
        let mut items = BTreeMap::new();
        let report = apply_batch(&mut items, vec![a, b]);
        assert_eq!(report.applied, 1);
        assert_eq!(report.conflicts, 1);
        assert_eq!(report.max_lamport, 3);
        let view = items.get(&ITEM).unwrap();
        assert_eq!(view.primary.as_ref().unwrap().device_id, DEVICE_B);
        assert_eq!(view.conflicts.len(), 1);
    }

    #[test]
    fn item_view_derives_primary_and_conflicts_from_full_log() {
        let mut ops = vec![
            put(1, DEVICE_A, 0),
            put(2, DEVICE_A, 1), // Primary history
            put(3, DEVICE_B, 2), // Current primary
            put(3, DEVICE_A, 3), // True conflict with the primary → copy
        ];
        // Feed it deliberately out of order
        ops.swap(0, 3);
        let state = item_view(ops);
        assert_eq!(state.primary.as_ref().unwrap().lamport, 3);
        assert_eq!(state.conflicts.len(), 1);
        assert_eq!(state.conflicts[0].lamport, 3);
        assert_eq!(state.conflicts[0].device_id, DEVICE_A);
    }
}
