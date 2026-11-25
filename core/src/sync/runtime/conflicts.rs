//! `SyncSession` conflict resolution domain (split out by LAY-021):
//! `list_conflicts` / `conflict_item_count` / `resolve_conflict` (see
//! `super::resolve` for the predicate matrix).

use super::*;

impl<R: SyncRemote> SyncSession<R> {
    /// Conflict resolution view (phase 3c): all pending entries (master
    /// position + decrypted snapshots of the copies).
    /// An entry whose any version cannot be unwrapped (corrupt) is skipped
    /// wholesale -- it stays unresolvable but remains in the oplog, without
    /// blocking the display of the other entries.
    pub async fn list_conflicts(&self) -> Result<Vec<ConflictEntry>> {
        let mut entries = Vec::new();
        for item_id in self.sync_repo.item_ids().await? {
            let ops = self.sync_repo.item_ops(item_id).await?;
            if let Some(entry) = resolve::conflict_entry(item_id, &ops, &self.group_key) {
                entries.push(entry);
            }
        }
        entries.sort_by_key(|entry| entry.item_id);
        Ok(entries)
    }

    /// Number of currently pending conflict entries (the `conflicts` truth
    /// reported by run_cycle).
    pub async fn conflict_item_count(&self) -> Result<usize> {
        Ok(self.list_conflicts().await?.len())
    }

    /// Resolve: adopt one conflicting copy. The copy content is re-logged
    /// with a fresh local lamport (a put reuses the copy's payload bytes --
    /// the snapshot and wrapped item key are both in the group domain and
    /// device-independent; a tombstone reuses the empty payload), and the
    /// master database is written from it. The new lamport is strictly
    /// greater than both sides of the conflict, so LWW naturally wins back
    /// the master position and every other version is dropped from the
    /// resolution view (the oplog is append-only, so nothing is lost, they
    /// just stop appearing in the view).
    ///
    /// Write order = master database first, then oplog (see the
    /// [`crate::sync::resolve`] module docs): a master failure returns Err
    /// (the oplog is untouched, so retrying is safe); an oplog failure is
    /// retryable (rewriting the master is idempotent).
    /// If the identity referenced by the copy has not been synced yet, the
    /// master cannot be written -> Err and nothing is recorded (logging an
    /// op without writing the master = silent divergence; resolve again after
    /// the next sync completes the identity).
    pub async fn resolve_conflict(
        &self,
        master: &EncryptionService,
        item_id: Uuid,
        adopt_op_id: Uuid,
    ) -> Result<()> {
        let view = item_view(self.sync_repo.item_ops(item_id).await?);
        let Some(adopted) = view.conflicts.iter().find(|op| op.op_id == adopt_op_id) else {
            // A missing copy means it was already resolved (adopting any
            // version drops the rest from the view) or the op_id was
            // mistyped -- the caller gets the same message either way.
            return Err(PersonaError::NotFound(format!(
                "conflict copy {adopt_op_id} not found for item {item_id} (already resolved?)"
            ))
            .into());
        };
        if adopted.kind != ItemKind::Credential {
            return Err(PersonaError::InvalidInput(format!(
                "conflict resolution only supports credential entries, got {:?}",
                adopted.kind
            ))
            .into());
        }
        let (kind, op, payload) = (adopted.kind, adopted.op, adopted.payload.clone());

        // Master database first, then oplog.
        match op {
            OpType::Put => {
                let Some(payload) = payload.as_ref() else {
                    return Err(PersonaError::InvalidInput(
                        "cannot adopt a put copy without payload".to_string(),
                    )
                    .into());
                };
                let outcome = Materializer::new(self.db.clone())
                    .materialize_put(
                        &item_id,
                        &payload.ciphertext,
                        &payload.wrapped_item_key,
                        master,
                        &self.group_key,
                    )
                    .await?;
                if let MaterializeOutcome::SkippedPendingIdentity { identity_id } = outcome {
                    return Err(PersonaError::Validation(format!(
                        "adopted copy references identity {identity_id} that is not synced yet; \
                         resolve again after the next sync"
                    ))
                    .into());
                }
            }
            OpType::Delete => {
                Materializer::new(self.db.clone())
                    .materialize_delete(&item_id)
                    .await?;
            }
        }

        // Defensive clock advance before recording: guarantees the local
        // lamport of the new op is strictly greater than the adopted copy's.
        // In the normal flow, pull has already bumped the clock (record's
        // local+1 is large enough); when resolving directly without
        // run_cycle, the local clock may still sit at the copy's height, so
        // advance it to at least that value first. This happens after the
        // master write -- a failed pre-check (the Err arms above) has no
        // side effects.
        let local = self.sync_repo.get_state().await?.local_lamport;
        if local <= adopted.lamport {
            self.sync_repo.bump_lamport(adopted.lamport + 1).await?;
        }

        // Record to the oplog: the adopt op, carrying a fresh local lamport,
        // enters the push queue and goes out with the next cycle.
        self.engine
            .record_local_change(item_id, kind, op, payload)
            .await?;
        Ok(())
    }
}
