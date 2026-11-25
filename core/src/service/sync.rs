use super::*;

impl PersonaService {
    /// Hand a single item-level write change to the sync capture seam (a zero-cost skip when not wired).
    ///
    /// Fault tolerance matches [`Self::record_credential_history`]: capture is a best-effort side
    /// channel (the trait method returns `()`, and the implementor logs on its own), so the service
    /// side performs no fallible preparation — the primary database is the source of truth.
    pub(crate) async fn capture_sync(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    ) {
        let capture = self.sync_capture.read().await.clone();
        if let Some(capture) = capture {
            capture
                .capture(item_id, kind, op, ciphertext, item_key)
                .await;
        }
    }

    /// Build the sync put payload for a metadata-level write change ([`Self::update_credential`] /
    /// restore): decrypt the current payload, assemble a full item snapshot, then seal it. Legacy
    /// rows (no per-item key) return `None` — they cannot yet share an item key with the sync
    /// envelope, so capture is skipped; the first [`Self::update_credential_data`] upgrades them,
    /// after which capture resumes.
    pub(crate) async fn sync_put_payload_for(
        &self,
        credential: &Credential,
    ) -> Option<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let data = self.decrypt_credential(credential).ok()?;
        let master_encryption = self.get_master_encryption_service().ok()?;
        let item_key = KeyHierarchy::new(master_encryption)
            .unwrap_item_key(credential.wrapped_item_key.as_ref()?)
            .ok()?;
        match SyncItemSnapshot::from_credential(credential, &data).seal(&item_key) {
            Ok(sealed) => Some((sealed, Zeroizing::new(item_key))),
            Err(e) => {
                tracing::warn!(
                    credential_id = %credential.id,
                    error = %e,
                    "sync snapshot seal failed; capture skipped"
                );
                None
            }
        }
    }

    /// Record a credential history row (created/updated/deleted/restored is distinguished by change_type).
    ///
    /// - An Updated change with no substantive field change is not recorded (the metadata
    ///   follow-up write right after CLI/desktop create produces no noise rows)
    /// - version takes the entity's current maximum version + 1
    /// - `reason` is optional (restore uses it to note the target version)
    /// - A recording failure only warns and does not block the primary operation (consistent with
    ///   log_audit's best-effort stance): the primary write is already committed, history is derived
    ///   data, and a history failure must not roll back a business fact
    pub(crate) async fn record_credential_history(
        &self,
        change_type: ChangeType,
        previous: Option<&Credential>,
        current: Option<&Credential>,
        reason: Option<String>,
    ) {
        let entity_id = match (current, previous) {
            (Some(c), _) => c.id,
            (None, Some(p)) => p.id,
            (None, None) => return,
        };

        let mut entry = ChangeHistory::new(EntityType::Credential, entity_id, change_type);
        if let Some(user) = self.current_user {
            entry = entry.with_user(user.to_string());
        }
        if let Some(reason) = reason {
            entry = entry.with_reason(reason);
        }

        match (previous, current) {
            (Some(old), Some(new)) => {
                let changes = Self::diff_credential_metadata(old, new);
                if changes.is_empty() {
                    return;
                }
                entry = entry.with_states(
                    Some(Self::credential_meta_snapshot(old)),
                    Some(Self::credential_meta_snapshot(new)),
                );
                for (field, old_value, new_value) in changes {
                    entry.add_field_change(field.to_string(), old_value, new_value);
                }
            }
            (None, Some(new)) => {
                entry = entry.with_states(None, Some(Self::credential_meta_snapshot(new)));
            }
            (Some(old), None) => {
                entry = entry.with_states(Some(Self::credential_meta_snapshot(old)), None);
            }
            (None, None) => return,
        }

        let version = self
            .change_history_repo
            .get_latest_version(EntityType::Credential, &entity_id)
            .await
            .unwrap_or(0)
            + 1;
        entry.version = version;

        if let Err(e) = self.change_history_repo.record(&entry).await {
            tracing::warn!("failed to record credential history: {}", e);
        }
    }
}
