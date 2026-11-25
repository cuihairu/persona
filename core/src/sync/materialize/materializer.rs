use uuid::Uuid;

use crate::crypto::encryption::EncryptionService;
use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::Credential;
use crate::storage::sync_repository::SyncRepository;
use crate::storage::{
    AuditLogRepository, CredentialRepository, IdentityRepository, PasskeyRepository, Repository,
};
use crate::sync::keys::unwrap_item_key_with_group;
use crate::sync::keys::GroupKey;
use crate::sync::oplog::{item_view, ItemKind, OpType};
use std::sync::Arc;

use crate::models::PasskeyItem;
use crate::sync::snapshot::{SyncItemSnapshot, SyncPasskeySnapshot};
use crate::{Database, Result};

use super::report::{MaterializeOutcome, MaterializeReport};

/// Materializer from the oplog into the primary store. Holds repository handles; the primary key and the group key are passed in per call
/// (the primary key lives and dies with the unlock session, while the group key belongs to the sync assembly layer only).
pub struct Materializer {
    pub(super) credential_repo: CredentialRepository,
    pub(super) identity_repo: IdentityRepository,
    pub(super) passkey_repo: PasskeyRepository,
    pub(super) sync_repo: SyncRepository,
    pub(super) audit_repo: AuditLogRepository,
}

impl Materializer {
    pub fn new(db: Database) -> Self {
        Self {
            credential_repo: CredentialRepository::new(db.clone()),
            identity_repo: IdentityRepository::new(db.clone()),
            passkey_repo: PasskeyRepository::new(Arc::new(db.clone())),
            sync_repo: SyncRepository::new(db.clone()),
            audit_repo: AuditLogRepository::new(db),
        }
    }

    /// Materializes every item in the oplog (idempotent, safe to re-run). `local_device_id` is used to
    /// recognize the "primary is a local op" skip case.
    pub async fn materialize_all(
        &self,
        master: &EncryptionService,
        group: &GroupKey,
        local_device_id: Uuid,
    ) -> Result<MaterializeReport> {
        let mut report = MaterializeReport::default();
        for item_id in self.sync_repo.item_ids().await? {
            match self
                .materialize_item(&item_id, master, group, local_device_id)
                .await
            {
                Ok(MaterializeOutcome::Written) => report.written += 1,
                Ok(MaterializeOutcome::Tombstoned) => report.tombstoned += 1,
                Ok(MaterializeOutcome::SkippedLocalPrimary) => report.skipped_local_primary += 1,
                Ok(MaterializeOutcome::SkippedUnsupportedKind) => {
                    report.skipped_unsupported_kind += 1
                }
                Ok(MaterializeOutcome::NoPrimary) => report.no_primary += 1,
                Ok(MaterializeOutcome::SkippedPendingIdentity { identity_id }) => {
                    report.pending_identity.push((item_id, identity_id));
                }
                Err(e) => {
                    // Best effort: a single item failure (e.g. a corrupt snapshot) does not abort the pass;
                    // the op stays in the oplog and can be re-run after investigation.
                    tracing::warn!(item_id = %item_id, error = %e, "materialize item failed; kept in oplog");
                }
            }
        }
        Ok(report)
    }

    /// Materializes the primary of a single item.
    pub async fn materialize_item(
        &self,
        item_id: &Uuid,
        master: &EncryptionService,
        group: &GroupKey,
        local_device_id: Uuid,
    ) -> Result<MaterializeOutcome> {
        let ops = self.sync_repo.item_ops(*item_id).await?;
        let state = item_view(ops);
        let Some(primary) = state.primary else {
            return Ok(MaterializeOutcome::NoPrimary);
        };
        if primary.device_id == local_device_id {
            return Ok(MaterializeOutcome::SkippedLocalPrimary);
        }
        match primary.kind {
            ItemKind::Credential => match primary.op {
                OpType::Delete => {
                    self.materialize_delete(item_id).await?;
                    Ok(MaterializeOutcome::Tombstoned)
                }
                OpType::Put => {
                    let Some(payload) = primary.payload else {
                        // Protocol invariant violation (a put always carries a payload): fail-closed, do not write.
                        tracing::warn!(item_id = %item_id, "remote put without payload; ignored");
                        return Ok(MaterializeOutcome::NoPrimary);
                    };
                    self.materialize_put(
                        item_id,
                        &payload.ciphertext,
                        &payload.wrapped_item_key,
                        master,
                        group,
                    )
                    .await
                }
            },
            ItemKind::Passkey => match primary.op {
                OpType::Delete => {
                    // The passkeys table has no inbound FK, so no reference cleanup is needed
                    self.passkey_repo.delete(item_id).await?;
                    Ok(MaterializeOutcome::Tombstoned)
                }
                OpType::Put => {
                    let Some(payload) = primary.payload else {
                        tracing::warn!(
                            item_id = %item_id,
                            "remote passkey put without payload; ignored"
                        );
                        return Ok(MaterializeOutcome::NoPrimary);
                    };
                    self.materialize_passkey_put(
                        item_id,
                        &payload.ciphertext,
                        &payload.wrapped_item_key,
                        master,
                        group,
                    )
                    .await
                }
            },
            // Identity capture and materialization land in a later batch; unknown kinds produce no local writes
            ItemKind::Identity | ItemKind::Unknown => {
                Ok(MaterializeOutcome::SkippedUnsupportedKind)
            }
        }
    }

    /// Materializes a tombstone primary: clears the `audit_logs` reference to the credential before deleting the row
    /// (the audit FK is NO ACTION; without detaching first, the delete is rejected with 787). Public for reuse by
    /// conflict arbitration: adopting a delete copy takes the same row-deletion path.
    pub async fn materialize_delete(&self, item_id: &Uuid) -> Result<()> {
        self.audit_repo.clear_credential_reference(item_id).await?;
        self.credential_repo.delete(item_id).await?;
        Ok(())
    }

    /// Materializes a put primary into the primary store (rewraps the item key to the local primary key). Public
    /// for reuse by conflict arbitration: adopting a put copy takes the same write path ([`super::resolve`]).
    pub async fn materialize_put(
        &self,
        item_id: &Uuid,
        ciphertext: &[u8],
        wrapped_item_key: &[u8],
        master: &EncryptionService,
        group: &GroupKey,
    ) -> Result<MaterializeOutcome> {
        let item_key = unwrap_item_key_with_group(wrapped_item_key, group)?;
        let snapshot = SyncItemSnapshot::open(ciphertext, &item_key)?;

        if self
            .identity_repo
            .find_by_id(&snapshot.identity_id)
            .await?
            .is_none()
        {
            return Ok(MaterializeOutcome::SkippedPendingIdentity {
                identity_id: snapshot.identity_id,
            });
        }

        // Rewrap: the same item key is now wrapped by the local primary key (the attachment invariant holds —
        // the item key is unchanged, so archived attachments remain decryptable).
        let hierarchy = KeyHierarchy::new(master);
        let wrapped_local = master.encrypt(&item_key).map_err(|e| {
            crate::PersonaError::CryptographicError(format!("failed to wrap item key: {e}"))
        })?;
        let encrypted_data =
            hierarchy.encrypt_with_item_key(&item_key, &snapshot.data.to_bytes()?)?;

        match self.credential_repo.find_by_id(item_id).await? {
            Some(mut row) => {
                row.identity_id = snapshot.identity_id;
                row.name = snapshot.name;
                row.credential_type = snapshot.credential_type;
                row.security_level = snapshot.security_level;
                row.url = snapshot.url;
                row.username = snapshot.username;
                row.notes = snapshot.notes;
                row.tags = snapshot.tags;
                row.metadata = snapshot.metadata;
                row.is_favorite = snapshot.is_favorite;
                row.is_active = snapshot.is_active;
                row.encrypted_data = encrypted_data;
                row.wrapped_item_key = Some(wrapped_local);
                row.touch();
                self.credential_repo.update(&row).await?;
            }
            None => {
                let mut credential = Credential::new(
                    snapshot.identity_id,
                    snapshot.name,
                    snapshot.credential_type,
                    snapshot.security_level,
                    encrypted_data,
                    Some(wrapped_local),
                );
                credential.id = *item_id;
                credential.url = snapshot.url;
                credential.username = snapshot.username;
                credential.notes = snapshot.notes;
                credential.tags = snapshot.tags;
                credential.metadata = snapshot.metadata;
                credential.is_favorite = snapshot.is_favorite;
                credential.is_active = snapshot.is_active;
                self.credential_repo.create(&credential).await?;
            }
        }
        Ok(MaterializeOutcome::Written)
    }

    /// Materializes a passkey put primary into the primary store. The private-key envelope is carried over
    /// as-is: the item key bytes are unchanged (unwrapped from the group envelope, then rewrapped to the
    /// local primary key), so the materialized row still decrypts the private key; the device-local usage
    /// state (`created_at`/`sign_count`/`last_used_at`) is preserved by [`PasskeyRepository::upsert_synced`]
    /// and is not carried by the remote.
    async fn materialize_passkey_put(
        &self,
        item_id: &Uuid,
        ciphertext: &[u8],
        wrapped_item_key: &[u8],
        master: &EncryptionService,
        group: &GroupKey,
    ) -> Result<MaterializeOutcome> {
        let item_key = unwrap_item_key_with_group(wrapped_item_key, group)?;
        let snapshot = SyncPasskeySnapshot::open(ciphertext, &item_key)?;

        if self
            .identity_repo
            .find_by_id(&snapshot.identity_id)
            .await?
            .is_none()
        {
            return Ok(MaterializeOutcome::SkippedPendingIdentity {
                identity_id: snapshot.identity_id,
            });
        }

        // Rewrap: the same item key is now wrapped by the local primary key (the private-key envelope invariant holds).
        let wrapped_local = master.encrypt(&item_key).map_err(|e| {
            crate::PersonaError::CryptographicError(format!("failed to wrap item key: {e}"))
        })?;

        let mut item = PasskeyItem::new(
            snapshot.identity_id,
            snapshot.rp_id,
            snapshot.user_handle,
            snapshot.credential_id,
            snapshot.encrypted_private_key,
            wrapped_local,
            snapshot.public_key_cose,
        );
        item.id = *item_id;
        item.rp_name = snapshot.rp_name;
        item.user_name = snapshot.user_name;
        item.user_display_name = snapshot.user_display_name;
        item.alg = snapshot.alg;
        item.uv_initialized = snapshot.uv_initialized;
        item.export_allowed = snapshot.export_allowed;
        item.tags = snapshot.tags;

        self.passkey_repo.upsert_synced(&item).await?;
        Ok(MaterializeOutcome::Written)
    }
}
