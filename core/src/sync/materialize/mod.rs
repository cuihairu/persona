//! Pull materialization layer (E2EE_SYNC_DESIGN §5/§7) — writes oplog primaries into the local primary store.
//!
//! Phase 2's `pull_cycle` only records remote ops into the local oplog table; this module adds the final
//! "write the primary store" step: for each item it derives the primary from the **op set** via [`item_view`]
//! (the final state depends only on the op set, not on arrival order), then persists it per §7:
//!
//! - Primary put: derive the item key from the group key → decrypt the snapshot ciphertext → rewrap the item
//!   key to the local primary key (primary passphrases are not synced across devices, so sync ciphertext
//!   stays decoupled from the primary passphrase) → write the credential row.
//! - Primary tombstone: delete the local row (there is no payload to decrypt).
//! - Primary is a **local** op: the primary store is already the source of truth (the write path writes it
//!   directly), so skip it.
//! - The loser of a real conflict is not materialized — the conflicting copy stays resident in the oplog
//!   ([`item_view`]'s `conflicts`) and is presented by phase 3's arbitration UI; "adopting" it produces a
//!   put with a newer lamport through the write path, which naturally wins the primary back.
//!
//! Idempotent and safe to re-run: an op that fails to materialize (e.g. the snapshot references an identity
//! that has not synced yet) **stays in the oplog** and is caught up automatically on the next round. A
//! missing identity is a normal state (syncing Identity entries lands in a later phase 3 batch), not an
//! error — report it honestly with [`MaterializeOutcome::SkippedPendingIdentity`]. Sync is a best-effort
//! side channel: a single item failure in this layer is only counted in the report and never aborts the pass.

mod materializer;
mod report;

pub use materializer::Materializer;
pub use report::{MaterializeOutcome, MaterializeReport};

#[cfg(test)]
mod tests;
