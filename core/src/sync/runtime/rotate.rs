//! `SyncSession` key rotation domain (split out by LAY-021): `rewrap_all`
//! for a full rewrap, `drain_push_queue` to drain the local queue, and
//! `rotate_group_key` for safe rotation (E2EE_SYNC_DESIGN DR-3, section 11
//! open question 2).

use super::*;

impl<R: SyncRemote> SyncSession<R> {
    /// Full rewrap: for every credential in the master database, re-seal the
    /// snapshot with the new group key and rewrap the item key, recording a
    /// put with a fresh lamport each (LWW makes it the master position).
    /// Same-shaped path as backfill but **without skipping already queued
    /// entries** -- rotation requires every existing credential to get a new
    /// ciphertext. Returns (rewrapped, skipped).
    pub async fn rewrap_all(
        &self,
        master: &EncryptionService,
        new_group: &GroupKey,
    ) -> Result<(u64, u64)> {
        let cred_repo = CredentialRepository::new(self.db.clone());
        let all = cred_repo.list_all().await?;
        let hierarchy = KeyHierarchy::new(master);
        let mut rewrapped: u64 = 0;
        let mut skipped: u64 = 0;
        for credential in all {
            let Some(wrapped) = credential.wrapped_item_key.as_ref() else {
                tracing::warn!(
                    credential_id = %credential.id,
                    "legacy credential without wrapped item key; rewrap skipped"
                );
                skipped += 1;
                continue;
            };
            // Failures skip the single entry (a bad row does not block the
            // whole batch), consistent with the capture seam's tolerance
            let item_key = match hierarchy.unwrap_item_key(wrapped) {
                Ok(item_key) => item_key,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "item key unwrap failed; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let plaintext = match hierarchy
                .decrypt_with_wrapped_key(wrapped, &credential.encrypted_data)
            {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "credential decrypt failed; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let data = match CredentialData::from_bytes(&plaintext) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "malformed credential data; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let sealed = match SyncItemSnapshot::from_credential(&credential, &data).seal(&item_key)
            {
                Ok(sealed) => sealed,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "snapshot seal failed; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let payload = SyncPayload {
                ciphertext: sealed,
                wrapped_item_key: wrap_item_key_with_group(&item_key, new_group),
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
                Ok(_) => rewrapped += 1,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "oplog record failed; rewrap skipped");
                    skipped += 1;
                }
            }
        }
        Ok((rewrapped, skipped))
    }

    /// Drain the local push queue (push_cycle handles at most 500 entries
    /// per round, looping until nothing more can be pushed). Returns the total
    /// number of entries pushed.
    #[cfg(feature = "remote-auth")]
    pub(super) async fn drain_push_queue(&self) -> Result<u64> {
        let mut total: u64 = 0;
        loop {
            let report = self.engine.push_cycle().await?;
            total += report.pushed as u64;
            if report.pushed == 0 {
                return Ok(total);
            }
        }
    }

    /// Group key rotation (DR-3 "safe rotation", the v1 that truly closes
    /// the loop on revoked devices):
    ///
    /// 1. Push all local pending entries first -- the old-group ciphertext
    ///    goes online before the key changes, so retained devices still
    ///    holding the old key can pull it in time;
    /// 2. Generate a new group key and re-seal + upload the envelope for
    ///    **every authorized device** (including this one) (put_group_key is
    ///    an idempotent upsert; revoked devices have no envelope and are
    ///    naturally skipped);
    /// 3. [`Self::rewrap_all`] for a full rewrap, then drain the queue.
    ///
    /// After the key change, devices need **zero client-side changes**:
    /// `SyncSession::open` unwraps this device's envelope on every open, so
    /// the next sync naturally picks up the new key; the rotator's current
    /// session keeps holding the old key (it is not written back) -- the
    /// host just discards it after use. Old-group ciphertexts remain in the
    /// server oplog; only devices with the new envelope cannot unwrap them
    /// and skip them per the existing tolerance -- the current state is
    /// fully restored by the rewrap ops.
    ///
    /// Honest boundaries (UI/docs must state them): (a) local changes on other
    /// devices that are **not yet pushed** within the window are still
    /// recorded under the old key, and the rotator and new devices cannot
    /// unwrap them and will skip them per tolerance -- before rotating, all
    /// retained devices should each complete one "sync now"; (b) unresolved
    /// conflict copies leave the resolution view once the rewrap op takes the
    /// master position (the master database current state is authoritative,
    /// and the append-only oplog raw records remain); (c) concurrent
    /// rotations are mutually excluded by an epoch optimistic lock
    /// (2026-09-24): after this device reads the baseline generation,
    /// `begin_group_rotation` CASes to grab it, and if another device already
    /// rotated ahead, [`PersonaError::ConcurrentConflict`] is returned to
    /// abort fail-closed -- at that point this device has written no envelope
    /// and rewrapped nothing, so resync and retry; if this device crashes
    /// after begin, the envelope family stays in a mixed state, and retrying
    /// simply reruns it (the idempotency surface is unchanged; the mixed-state
    /// self-healing semantics are locked in by the server real-TCP integration
    /// test `crashed_mid_rotation_retry_rewrites_envelopes_and_converges` --
    /// leftover envelopes are overwritten by the upsert and the whole group
    /// converges).
    #[cfg(feature = "remote-auth")]
    pub async fn rotate_group_key(
        &self,
        master: &EncryptionService,
        admin: &crate::sync::remote::SyncAdminApi,
    ) -> Result<SyncRotateReport> {
        // 1. Put the old-group ciphertext online first (the other retained
        // devices' old key is still valid at this point)
        let pushed_before = self.drain_push_queue().await?;

        // 2. The authorized device set = devices with an envelope; generate
        // a new key and re-seal + upload per device.
        //    Grab the rotation mutex (epoch CAS) before writing the envelope
        //    family: if the baseline read here has already been advanced by a
        //    concurrent rotator, 409/ConcurrentConflict aborts cleanly right
        //    here.
        let devices = admin.list_devices().await?;
        let (keys, epoch) = admin.group_keys_with_epoch().await?;
        let authorized: std::collections::HashSet<Uuid> =
            keys.iter().map(|k| k.device_id).collect();
        admin.begin_group_rotation(epoch).await?;
        let new_group = GroupKey::generate()?;
        for device in &devices {
            if !authorized.contains(&device.id) {
                continue;
            }
            let envelope =
                crate::sync::envelope::seal_group_key(new_group.as_bytes(), &device.public_key)?;
            admin.put_group_key(device.id, &envelope).await?;
        }

        // 3. Record the full rewrap, then drain the queue
        let (rewrapped, skipped) = self.rewrap_all(master, &new_group).await?;
        let pushed_after = self.drain_push_queue().await?;

        Ok(SyncRotateReport {
            rewrapped,
            skipped,
            pushed: pushed_before + pushed_after,
        })
    }
}
