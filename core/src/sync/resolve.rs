//! Conflict-resolution data plane (E2EE_SYNC_DESIGN §7 / phase 3c)——turns
//! the oplog conflict zone into a form the host UI can consume.
//!
//! The layering matches the session assembly: types and pure logic
//! (decryption, validation) live in this module, while the
//! `list_conflicts` / `resolve_conflict` methods of
//! [`super::runtime::SyncSession`] hang off the runtime (they need access to
//! private session fields). Resolution semantics:
//!
//! - **Display**: each conflicting entry exposes comparable snapshots of the
//!   primary position and every copy (group key unwraps the item key → open
//!   the snapshot; tombstone versions are flagged `deleted`). A credential is
//!   an atomic whole (DR-4 ruling: field-level merging is rejected), so the
//!   UI only chooses between versions, never merges them.
//! - **Adopt**: the chosen copy is re-booked with a fresh local lamport (a
//!   put reuses the copy's payload bytes——the snapshot and the wrapped item
//!   key are both in the group domain, device-independent; a tombstone reuses
//!   the empty payload) and the main DB is written with its content. The new
//!   lamport is strictly greater than both sides of the conflict → LWW
//!   naturally wins back the primary position, and all other versions are
//!   retired out of the view (the oplog is append-only, no data is lost; the
//!   versions simply stop appearing in the resolution view).
//! - **Write order**: main DB first, then oplog. A main-DB write failure
//!   errors out with the oplog untouched, safe to retry (rewriting the main
//!   DB is idempotent); an oplog bookkeeping failure is retryable (the main
//!   DB already holds the target content; re-running idempotently adds the
//!   op)——neither direction can silently fork the main DB from the oplog.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::sync::keys::{unwrap_item_key_with_group, GroupKey};
use crate::sync::oplog::{item_view, ItemKind, SyncOp};
use crate::sync::snapshot::SyncItemSnapshot;

/// The displayable form of one version in a conflict.
#[derive(Debug, Clone)]
pub struct ConflictVersion {
    pub op_id: Uuid,
    pub device_id: Uuid,
    pub lamport: u64,
    pub timestamp: Option<DateTime<Utc>>,
    /// Tombstone version: no snapshot, `deleted == true` (adopting it = delete
    /// the entry).
    pub deleted: bool,
    /// The decrypted snapshot of a put version.
    pub snapshot: Option<SyncItemSnapshot>,
}

/// The conflict view of one entry: the primary position + pending copies.
#[derive(Debug, Clone)]
pub struct ConflictEntry {
    pub item_id: Uuid,
    pub primary: ConflictVersion,
    pub copies: Vec<ConflictVersion>,
}

/// Turn one op into a displayable version. Returns `None` when the put
/// snapshot cannot be opened (bad group envelope / bad ciphertext)——the
/// caller skips that entry (a corrupted copy cannot be adjudicated and stays
/// in the oplog); tombstones are always `Some`.
pub fn decrypt_version(op: &SyncOp, group: &GroupKey) -> Option<ConflictVersion> {
    let snapshot = match op.payload.as_ref() {
        None if op.is_tombstone() => None,
        None => return None, // put without payload: protocol invariant violated, not displayable
        Some(payload) => {
            let item_key = unwrap_item_key_with_group(&payload.wrapped_item_key, group).ok()?;
            Some(SyncItemSnapshot::open(&payload.ciphertext, &item_key).ok()?)
        }
    };
    Some(ConflictVersion {
        op_id: op.op_id,
        device_id: op.device_id,
        lamport: op.lamport,
        timestamp: op.timestamp,
        deleted: op.is_tombstone(),
        snapshot,
    })
}

/// Extract the conflicting entry from a set of ops; if any version cannot be
/// decrypted → `None` (skip the entry entirely). Conflicts on non-Credential
/// entries are out of scope for adjudication (neither capture nor
/// materialization supports them; a defensive arm).
pub fn conflict_entry(item_id: Uuid, ops: &[SyncOp], group: &GroupKey) -> Option<ConflictEntry> {
    let view = item_view(ops.to_vec());
    if view.conflicts.is_empty() {
        return None;
    }
    let primary_op = view.primary.as_ref()?;
    if primary_op.kind != ItemKind::Credential {
        return None;
    }
    let primary = decrypt_version(primary_op, group)?;
    let mut copies = Vec::with_capacity(view.conflicts.len());
    for op in &view.conflicts {
        if op.kind != ItemKind::Credential {
            return None;
        }
        copies.push(decrypt_version(op, group)?);
    }
    Some(ConflictEntry {
        item_id,
        primary,
        copies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::credential::{CredentialType, PasswordCredentialData, SecurityLevel};
    use crate::models::CredentialData;
    use crate::sync::keys::{wrap_item_key_with_group, GroupKey};
    use crate::sync::oplog::{ItemKind, OpType, SyncPayload};
    use chrono::Utc;

    fn group() -> GroupKey {
        GroupKey::generate().unwrap()
    }

    fn snapshot(name: &str) -> SyncItemSnapshot {
        SyncItemSnapshot {
            identity_id: Uuid::new_v4(),
            name: name.to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::Medium,
            url: None,
            username: None,
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: CredentialData::Password(PasswordCredentialData {
                password: format!("{name}-secret"),
                email: None,
                security_questions: vec![],
            }),
        }
    }

    fn put_op(
        item_id: Uuid,
        device_id: Uuid,
        lamport: u64,
        snap: &SyncItemSnapshot,
        g: &GroupKey,
    ) -> SyncOp {
        let item_key = crate::crypto::encryption::EncryptionService::generate_key();
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Credential,
            op: OpType::Put,
            lamport,
            device_id,
            timestamp: Some(Utc::now()),
            payload: Some(SyncPayload {
                ciphertext: snap.seal(&item_key).unwrap(),
                wrapped_item_key: wrap_item_key_with_group(&item_key, g),
            }),
        }
    }

    fn delete_op(item_id: Uuid, device_id: Uuid, lamport: u64) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Credential,
            op: OpType::Delete,
            lamport,
            device_id,
            timestamp: Some(Utc::now()),
            payload: None,
        }
    }

    #[test]
    fn decrypt_version_opens_snapshot_and_marks_tombstone() {
        let g = group();
        let item = Uuid::new_v4();
        let snap = snapshot("a");
        let put = put_op(item, Uuid::new_v4(), 3, &snap, &g);
        let version = decrypt_version(&put, &g).unwrap();
        assert!(!version.deleted);
        assert_eq!(version.snapshot.as_ref().unwrap().name, "a");

        let del = delete_op(item, Uuid::new_v4(), 4);
        let version = decrypt_version(&del, &g).unwrap();
        assert!(version.deleted);
        assert!(version.snapshot.is_none());
    }

    #[test]
    fn decrypt_version_rejects_broken_payload_and_payloadless_put() {
        let g = group();
        let item = Uuid::new_v4();
        // Bad ciphertext: unwrap succeeds but the snapshot fails to open
        let broken = SyncOp {
            payload: Some(SyncPayload {
                ciphertext: vec![7; 64],
                wrapped_item_key: wrap_item_key_with_group(
                    &crate::crypto::encryption::EncryptionService::generate_key(),
                    &g,
                ),
            }),
            ..put_op(item, Uuid::new_v4(), 1, &snapshot("x"), &g)
        };
        assert!(decrypt_version(&broken, &g).is_none());

        // put without payload: protocol invariant violated
        let payloadless = SyncOp {
            payload: None,
            ..put_op(item, Uuid::new_v4(), 1, &snapshot("x"), &g)
        };
        assert!(decrypt_version(&payloadless, &g).is_none());
    }

    #[test]
    fn conflict_entry_extracts_primary_and_copies_or_none() {
        let g = group();
        let item = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (winner, loser) = if a > b { (a, b) } else { (b, a) };
        let win_op = put_op(item, winner, 5, &snapshot("win"), &g);
        let lose_op = put_op(item, loser, 5, &snapshot("lose"), &g);

        // Real conflict (same lamport, different devices): primary + 1 copy
        let entry = conflict_entry(item, &[win_op.clone(), lose_op.clone()], &g).unwrap();
        assert_eq!(entry.primary.op_id, win_op.op_id);
        assert_eq!(entry.copies.len(), 1);
        assert_eq!(entry.copies[0].op_id, lose_op.op_id);

        // Single version (no conflict) → None
        let lone = put_op(item, Uuid::new_v4(), 1, &snapshot("lone"), &g);
        assert!(conflict_entry(item, &[lone], &g).is_none());

        // Any version corrupted → skip the entry entirely
        let broken = SyncOp {
            payload: Some(SyncPayload {
                ciphertext: vec![7; 64],
                wrapped_item_key: wrap_item_key_with_group(
                    &crate::crypto::encryption::EncryptionService::generate_key(),
                    &g,
                ),
            }),
            ..put_op(item, Uuid::new_v4(), 9, &snapshot("broken"), &g)
        };
        assert!(conflict_entry(item, &[win_op, lose_op, broken], &g).is_none());
    }

    #[test]
    fn conflict_entry_skips_non_credential_kinds() {
        let g = group();
        let item = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mk = |device: Uuid, lamport: u64, kind: ItemKind| SyncOp {
            op_id: Uuid::new_v4(),
            item_id: item,
            kind,
            op: OpType::Put,
            lamport,
            device_id: device,
            timestamp: None,
            payload: None,
        };
        // A put without payload cannot be decrypted anyway, but the kind check
        // runs first: non-Credential conflicts do not enter adjudication
        assert!(conflict_entry(
            item,
            &[mk(a, 5, ItemKind::Identity), mk(b, 5, ItemKind::Identity)],
            &g
        )
        .is_none());
    }
}
