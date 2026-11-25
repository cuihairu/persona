use super::*;

impl PersonaService {
    /// Travel mode status. Ungated: neither the flag nor sidecar existence contains secrets
    /// (the lock screen also needs to be able to say "the data is not on this device").
    #[cfg(feature = "backup")]
    pub async fn travel_status(&self, db_path: &Path) -> Result<TravelStatus> {
        let workspaces = Repository::find_all(&self.workspace_repo).await?;
        let (active, entered_at) = workspaces
            .first()
            .map(|ws| {
                (
                    ws.settings.travel_mode,
                    ws.settings.travel_entered_at.clone(),
                )
            })
            .unwrap_or((false, None));
        let sidecar_exists = crate::travel::sidecar_path(db_path).exists();
        Ok(TravelStatus {
            active,
            entered_at,
            sidecar_exists,
            // The flag says travel mode is active, but the data container is gone (deleted by
            // hand/corrupted): the data is lost, so present it honestly rather than pretending
            // it is recoverable (see the crash-window table in the travel.rs module comments).
            inconsistent: active && !sidecar_exists,
        })
    }

    /// Mark/unmark an identity (on enter, its whole data pack moves off this device). A
    /// metadata-level editing operation, gated the same as update_identity (no sensitive
    /// re-auth — the gate for moving secrets sits at the enter step). Idempotent: marking the
    /// same state again simply succeeds.
    #[cfg(feature = "backup")]
    pub async fn set_travel_marked(&self, identity_id: &Uuid, marked: bool) -> Result<()> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let mut identity = self
            .identity_repo
            .find_by_id(identity_id)
            .await?
            .ok_or_else(|| PersonaError::IdentityNotFound(identity_id.to_string()))?;
        if identity.travel_marked == marked {
            return Ok(());
        }
        identity.travel_marked = marked;
        self.identity_repo.update(&identity).await?;
        self.log_audit(
            AuditAction::TravelMarkChanged,
            ResourceType::Identity,
            true,
            Some(*identity_id),
            None,
            None,
        )
        .await;
        Ok(())
    }

    /// Enter travel mode: all data of marked identities is packed and encrypted into the sidecar
    /// and then deleted from the primary database (true removal semantics, zero trace in the
    /// primary). Order is the security semantics: write the sidecar first, then touch the database.
    #[cfg(feature = "backup")]
    pub async fn enter_travel_mode(
        &self,
        db_path: &Path,
        passphrase: &str,
    ) -> Result<TravelCounts> {
        self.ensure_sensitive_operation_allowed().await?;

        if self.travel_mode_active().await? {
            return Err(PersonaError::TravelModeActive(
                "Travel mode is already active".to_string(),
            )
            .into());
        }

        let sidecar = crate::travel::sidecar_path(db_path);
        if sidecar.exists() {
            // Leftover from crash window 1 (sidecar written, transaction not committed): when the
            // database and disk disagree, do not overwrite automatically — let the user decide
            // whether to delete the leftover or run exit to restore directly.
            return Err(PersonaError::Validation(format!(
                "travel sidecar already exists at {}; remove the leftover file or run travel exit to restore",
                sidecar.display()
            ))
            .into());
        }

        let marked: Vec<String> =
            sqlx::query_as("SELECT id FROM identities WHERE travel_marked = 1")
                .fetch_all(self.db.pool())
                .await
                .map_err(|e| PersonaError::Database(e.to_string()))?
                .into_iter()
                .map(|(id,)| id)
                .collect();
        if marked.is_empty() {
            return Err(PersonaError::InvalidInput(
                "no identities are marked for travel mode".to_string(),
            )
            .into());
        }
        if passphrase.is_empty() {
            return Err(PersonaError::InvalidInput(
                "travel passphrase must not be empty".to_string(),
            )
            .into());
        }

        let attachments_root = self.attachment_manager.as_ref().map(|m| m.storage_root());
        let pack = crate::travel::build_pack(self.db.pool(), attachments_root, &marked).await?;
        let counts = TravelCounts::from_pack(&pack);

        let sealed = crate::travel::seal_pack(&pack, passphrase, None)?;
        crate::travel::write_sidecar_atomic(&sidecar, &sealed)?;

        if let Err(e) = crate::travel::apply_enter_tx(self.db.pool(), &pack).await {
            // Transaction failure (not a crash): reclaim the sidecar so the disk returns to the pre-enter state
            let _ = std::fs::remove_file(&sidecar);
            return Err(e.into());
        }

        // Transaction committed: blob file deletion is best-effort — failed items self-heal at
        // exit by overwriting the original storage_path, and do not block a successful enter.
        if let Some(root) = attachments_root {
            for failure in crate::travel::delete_blob_files(root, &pack.attachment_files) {
                tracing::warn!("travel enter: attachment file not removed: {failure}");
            }
        }

        self.log_audit(
            AuditAction::TravelModeEntered,
            ResourceType::Workspace,
            true,
            None,
            None,
            None,
        )
        .await;
        Ok(counts)
    }

    /// Exit travel mode: decrypt and unpack the sidecar, restore as-is (row ids and the encrypted
    /// form are byte-identical), then delete the sidecar once everything has landed. Any failure
    /// along the way leaves the sidecar in place, so the whole exit is retryable (row restore and
    /// file overwrite are both idempotent).
    #[cfg(feature = "backup")]
    pub async fn exit_travel_mode(&self, db_path: &Path, passphrase: &str) -> Result<TravelCounts> {
        self.ensure_sensitive_operation_allowed().await?;

        let sidecar = crate::travel::sidecar_path(db_path);
        let sealed = std::fs::read(&sidecar).map_err(|e| {
            PersonaError::NotFound(format!(
                "travel sidecar not found at {}: {e}",
                sidecar.display()
            ))
        })?;
        let pack = crate::travel::open_pack(&sealed, passphrase)?;

        crate::travel::apply_exit_tx(self.db.pool(), &pack).await?;

        // Rows restored: overwrite the blob files. A pack carrying attachments with no storage
        // location has nowhere to write the bytes — report a configuration error rather than
        // silently dropping data (rows are already inserted; attach storage and retry).
        if !pack.attachment_files.is_empty() {
            let root = self
                .attachment_manager
                .as_ref()
                .map(|m| m.storage_root())
                .ok_or_else(|| {
                    PersonaError::ConfigurationError(
                        "pack contains attachments but attachment storage is not initialized"
                            .to_string(),
                    )
                })?;
            crate::travel::write_blob_files(root, &pack.attachment_files)?;
        }

        if let Err(e) = std::fs::remove_file(&sidecar) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    "travel exit: failed to remove sidecar {}: {e}",
                    sidecar.display()
                );
            }
        }

        let counts = TravelCounts::from_pack(&pack);
        self.log_audit(
            AuditAction::TravelModeExited,
            ResourceType::Workspace,
            true,
            None,
            None,
            None,
        )
        .await;
        Ok(counts)
    }

    /// Re-wrap every stored item key (and re-encrypt legacy rows) under the
    /// new master key inside ONE transaction — any failure rolls the whole
    /// rotation back to the old password.
    ///
    /// Scope: `credentials` (wrapped + legacy rows) and `passkeys` (always
    /// wrapped). Crypto wallets use a dedicated wallet password; attachments
    /// are sealed under the owning credential's item key, which rotation
    /// leaves unchanged; change history stores plaintext JSON.
    pub(crate) async fn rewrap_all_item_keys(
        &self,
        old_enc: &EncryptionService,
        new_enc: &EncryptionService,
        user_auth: &UserAuth,
    ) -> Result<()> {
        let mut tx = self.db.pool().begin().await?;

        let rows = sqlx::query("SELECT id, encrypted_data, wrapped_item_key FROM credentials")
            .fetch_all(tx.as_mut())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        for row in rows {
            let id: String = row.get("id");
            let encrypted_data: Vec<u8> = row.get("encrypted_data");
            let wrapped: Option<Vec<u8>> = row.get("wrapped_item_key");
            match wrapped {
                Some(wrapped_key) => {
                    // Item key unchanged, ciphertext untouched — only the
                    // wrapping under the master key is replaced.
                    let rewrapped =
                        KeyHierarchy::rewrap_wrapped_key(&wrapped_key, old_enc, new_enc)?;
                    sqlx::query("UPDATE credentials SET wrapped_item_key = ? WHERE id = ?")
                        .bind(&rewrapped)
                        .bind(&id)
                        .execute(tx.as_mut())
                        .await
                        .map_err(|e| PersonaError::Database(e.to_string()))?;
                }
                None => {
                    // Legacy row: encrypted_data is sealed directly under the
                    // master key and must be re-encrypted.
                    let mut plaintext = old_enc.decrypt(&encrypted_data).map_err(|e| {
                        PersonaError::CryptographicError(format!(
                            "Failed to decrypt legacy credential during rotation: {e}"
                        ))
                    })?;
                    let reencrypted = new_enc.encrypt(&plaintext).map_err(|e| {
                        PersonaError::CryptographicError(format!(
                            "Failed to re-encrypt legacy credential during rotation: {e}"
                        ))
                    })?;
                    plaintext.zeroize();
                    sqlx::query("UPDATE credentials SET encrypted_data = ? WHERE id = ?")
                        .bind(&reencrypted)
                        .bind(&id)
                        .execute(tx.as_mut())
                        .await
                        .map_err(|e| PersonaError::Database(e.to_string()))?;
                }
            }
        }

        let rows = sqlx::query("SELECT id, wrapped_item_key FROM passkeys")
            .fetch_all(tx.as_mut())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        for row in rows {
            let id: String = row.get("id");
            let wrapped_key: Vec<u8> = row.get("wrapped_item_key");
            let rewrapped = KeyHierarchy::rewrap_wrapped_key(&wrapped_key, old_enc, new_enc)?;
            sqlx::query("UPDATE passkeys SET wrapped_item_key = ? WHERE id = ?")
                .bind(&rewrapped)
                .bind(&id)
                .execute(tx.as_mut())
                .await
                .map_err(|e| PersonaError::Database(e.to_string()))?;
        }

        // Persist the rotated auth record inside the same transaction.
        let enabled_factors = serde_json::to_string(&user_auth.enabled_factors)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize factors: {e}")))?;
        sqlx::query(
            r#"
            UPDATE user_auth SET
                master_password_hash = ?,
                enabled_factors = ?,
                failed_attempts = ?,
                locked_until = ?,
                last_auth = ?,
                password_change_required = ?,
                password_updated_at = ?,
                updated_at = ?,
                kdf_iterations = ?
            WHERE user_id = ?
            "#,
        )
        .bind(&user_auth.master_password_hash)
        .bind(&enabled_factors)
        .bind(user_auth.failed_attempts as i64)
        .bind(system_time_to_rfc3339_opt(user_auth.locked_until))
        .bind(system_time_to_rfc3339_opt(user_auth.last_auth))
        .bind(user_auth.password_change_required)
        .bind(system_time_to_rfc3339_opt(user_auth.password_updated_at))
        .bind(system_time_to_rfc3339_opt(Some(user_auth.updated_at)))
        .bind(user_auth.kdf_iterations as i64)
        .bind(user_auth.user_id.to_string())
        .execute(tx.as_mut())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        tx.commit().await.map_err(|e| {
            PersonaError::Database(format!("Failed to commit master password rotation: {e}"))
        })?;
        Ok(())
    }

    /// Resolve the per-item key used to seal credential-bound side data
    /// (attachment blobs, structured custom fields).
    ///
    /// Legacy rows (`wrapped_item_key` NULL, payload sealed directly with the
    /// master key) are upgraded in place first: master-password rotation
    /// re-encrypts legacy rows but never touches attachment blobs, so sealing
    /// an attachment with the master key would break it on rotation. After
    /// the upgrade the payload sits under a fresh item key and both the
    /// credential and its side data are rotation-safe.
    pub(crate) async fn credential_item_key_for_attachment(
        &self,
        credential_id: &Uuid,
    ) -> Result<[u8; 32]> {
        let mut credential = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;

        if credential.wrapped_item_key.is_none() {
            let master_encryption = self.get_master_encryption_service()?;
            let mut plaintext = master_encryption
                .decrypt(&credential.encrypted_data)
                .map_err(|e| {
                    PersonaError::CryptographicError(format!(
                        "Failed to decrypt legacy credential for item-key upgrade: {e}"
                    ))
                })?;
            let envelope =
                KeyHierarchy::new(master_encryption).encrypt_with_new_item_key(&plaintext)?;
            plaintext.zeroize();
            credential.encrypted_data = envelope.ciphertext;
            credential.wrapped_item_key = Some(envelope.wrapped_key);
            self.credential_repo.update(&credential).await?;
            tracing::info!(credential_id = %credential.id, "legacy credential upgraded to per-item key for side-data sealing");
        }

        let wrapped = credential.wrapped_item_key.as_ref().ok_or_else(|| {
            PersonaError::CryptographicError(
                "credential has no per-item key after upgrade".to_string(),
            )
        })?;
        let master_encryption = self.get_master_encryption_service()?;
        let key = KeyHierarchy::new(master_encryption)
            .unwrap_item_key(wrapped)
            .map_err(|e| {
                PersonaError::CryptographicError(format!(
                    "Failed to unwrap item key for side-data sealing: {e}"
                ))
            })?;
        Ok(key)
    }
}
