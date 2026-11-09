use super::*;

impl PersonaService {
    /// Attach a file to a credential
    ///
    /// Encrypted attachments are sealed under the owning credential's
    /// per-item key: the key survives master-password rotation untouched
    /// (rotation only re-wraps it), so the attachment stays decryptable.
    pub async fn attach_file<P: AsRef<Path>>(
        &mut self,
        credential_id: Uuid,
        file_path: P,
        encrypt: bool,
    ) -> Result<Uuid> {
        self.ensure_unlocked()?;

        let manager = self
            .attachment_manager
            .as_ref()
            .ok_or_else(|| PersonaError::Io("Attachment storage not initialized".to_string()))?;

        // Legacy rows (no wrapped key) are upgraded first — see
        // `credential_item_key_for_attachment`. Plaintext attachments skip
        // the key entirely and never trigger the upgrade.
        let mut item_key = if encrypt {
            Some(
                self.credential_item_key_for_attachment(&credential_id)
                    .await?,
            )
        } else {
            None
        };

        let attachment_id = manager
            .store(
                file_path,
                credential_id,
                encrypt,
                item_key.as_ref().map(|k| k.as_slice()),
            )
            .await?;

        if let Some(key) = item_key.as_mut() {
            key.zeroize();
        }

        // Log audit
        self.log_audit(
            AuditAction::CredentialUpdated,
            ResourceType::Credential,
            true,
            Some(credential_id),
            None,
            None,
        )
        .await;

        Ok(attachment_id)
    }

    /// Get all attachments for a credential
    pub async fn get_attachments(&self, credential_id: &Uuid) -> Result<Vec<Attachment>> {
        self.ensure_unlocked()?;

        let manager = self
            .attachment_manager
            .as_ref()
            .ok_or_else(|| PersonaError::Io("Attachment storage not initialized".to_string()))?;

        manager.list_for_credential(credential_id).await
    }

    /// Retrieve attachment content
    ///
    /// Encrypted attachments decrypt with the owning credential's per-item
    /// key — the same key that sealed them at attach time. Attachments
    /// created before this invariant held were sealed with a discarded
    /// random key and are reported as undecryptable.
    pub async fn retrieve_attachment(
        &self,
        attachment_id: &Uuid,
        decrypt: bool,
    ) -> Result<Vec<u8>> {
        self.ensure_unlocked()?;

        let manager = self
            .attachment_manager
            .as_ref()
            .ok_or_else(|| PersonaError::Io("Attachment storage not initialized".to_string()))?;

        let mut item_key = if decrypt {
            match manager.get(attachment_id).await? {
                Some(attachment) if attachment.is_encrypted => {
                    let credential = self
                        .credential_repo
                        .find_by_id(&attachment.credential_id)
                        .await?
                        .ok_or_else(|| {
                            PersonaError::InvalidInput(format!(
                                "credential {} not found for attachment",
                                attachment.credential_id
                            ))
                        })?;
                    let wrapped = credential.wrapped_item_key.as_ref().ok_or_else(|| {
                        PersonaError::CryptographicError(
                            "attachment predates item-key sealing and cannot be decrypted"
                                .to_string(),
                        )
                    })?;
                    let master_encryption = self.get_master_encryption_service()?;
                    Some(
                        KeyHierarchy::new(master_encryption)
                            .unwrap_item_key(wrapped)
                            .map_err(|e| {
                                PersonaError::CryptographicError(format!(
                                    "Failed to unwrap item key for attachment: {e}"
                                ))
                            })?,
                    )
                }
                // Plaintext attachment (or missing metadata): the blob layer
                // ignores the key when `is_encrypted` is false.
                _ => None,
            }
        } else {
            None
        };

        let content = manager
            .retrieve(
                attachment_id,
                decrypt,
                item_key.as_ref().map(|k| k.as_slice()),
            )
            .await?;

        if let Some(key) = item_key.as_mut() {
            key.zeroize();
        }
        Ok(content)
    }

    /// Save attachment content to a file
    pub async fn save_attachment<P: AsRef<Path>>(
        &self,
        attachment_id: &Uuid,
        output_path: P,
        decrypt: bool,
    ) -> Result<()> {
        let content = self.retrieve_attachment(attachment_id, decrypt).await?;

        use crate::storage::FileSystem;
        FileSystem::write(output_path, &content).await?;

        Ok(())
    }

    /// Delete an attachment
    pub async fn delete_attachment(&mut self, attachment_id: &Uuid) -> Result<()> {
        self.ensure_unlocked()?;

        let manager = self
            .attachment_manager
            .as_ref()
            .ok_or_else(|| PersonaError::Io("Attachment storage not initialized".to_string()))?;

        manager.delete(attachment_id).await?;

        // Log audit
        self.log_audit(
            AuditAction::CredentialUpdated,
            ResourceType::Credential,
            true,
            None,
            None,
            None,
        )
        .await;

        Ok(())
    }

    /// Get attachment storage statistics
    pub async fn get_attachment_stats(&self) -> Result<AttachmentStats> {
        let manager = self
            .attachment_manager
            .as_ref()
            .ok_or_else(|| PersonaError::Io("Attachment storage not initialized".to_string()))?;

        manager.get_stats().await
    }
}
