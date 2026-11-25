use uuid::Uuid;

/// Materialization outcome for a single item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeOutcome {
    /// A remote put was written to the store (new row, or overwrite of an existing one).
    Written,
    /// A remote tombstone was applied (the local row was deleted, or it never existed).
    Tombstoned,
    /// The primary is a local op — the primary store is already the source of truth, nothing to materialize.
    SkippedLocalPrimary,
    /// The identity referenced by the snapshot is not available locally yet (Identity sync lands in a later
    /// batch) — deferred to the next round.
    SkippedPendingIdentity { identity_id: Uuid },
    /// Unsupported entry kind (Identity capture and materialization come in a later batch; unknown kinds).
    SkippedUnsupportedKind,
    /// The oplog holds no op for this item (defensive: the caller's enumeration raced with the query).
    NoPrimary,
}

/// Summary of one full materialization pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaterializeReport {
    pub written: usize,
    pub tombstoned: usize,
    pub skipped_local_primary: usize,
    pub skipped_unsupported_kind: usize,
    pub no_primary: usize,
    /// (item_id, identity_id): re-running after the identity syncs catches these up.
    pub pending_identity: Vec<(Uuid, Uuid)>,
}
