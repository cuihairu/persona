use super::*;

/// Assertion produced by a stored passkey, ready to hand to an RP.
#[derive(Debug, Clone)]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature_der: Vec<u8>,
}

/// A newly stored passkey plus the registration artifacts.
#[derive(Debug, Clone)]
pub struct PasskeyCreation {
    pub item: PasskeyItem,
    /// `none`-format attestation object from this registration ceremony.
    pub attestation_object: Vec<u8>,
}

impl PersonaService {
    /// Run a registration ceremony and store the new passkey.
    ///
    /// `client_data_json` must carry the RP's challenge; the private key is
    /// generated inside core, wrapped with a fresh item key, and never
    /// stored or returned in the clear.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn create_passkey(
        &self,
        identity_id: Uuid,
        rp_id: String,
        origin: &str,
        client_data_json: &[u8],
        user_handle: Option<Vec<u8>>,
        user_name: Option<String>,
        user_display_name: Option<String>,
        user_verification: bool,
    ) -> Result<PasskeyItem> {
        Ok(self
            .create_passkey_full(
                identity_id,
                rp_id,
                origin,
                client_data_json,
                user_handle,
                user_name,
                user_display_name,
                user_verification,
            )
            .await?
            .item)
    }

    /// Like [`Self::create_passkey`] but also returns the attestation object
    /// produced by this registration — the bridge forwards it to the page so
    /// the browser `PublicKeyCredential` carries the exact attested bytes.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_passkey_full(
        &self,
        identity_id: Uuid,
        rp_id: String,
        origin: &str,
        client_data_json: &[u8],
        user_handle: Option<Vec<u8>>,
        user_name: Option<String>,
        user_display_name: Option<String>,
        user_verification: bool,
    ) -> Result<PasskeyCreation> {
        self.ensure_unlocked()?;
        self.touch_activity();

        let registration = register_passkey(&rp_id, origin, client_data_json, user_verification)?;

        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);
        let scalar = registration.signing_key.to_bytes();
        // 同步捕获需要 item key 明文（包 group 信封）——与凭据同款 revealed 变体
        let (envelope, item_key) =
            hierarchy.encrypt_with_new_item_key_revealed(scalar.as_slice())?;

        let user_handle = match user_handle {
            Some(handle) => handle,
            None => random_bytes32().to_vec(),
        };
        let mut item = PasskeyItem::new(
            identity_id,
            rp_id,
            user_handle,
            registration.credential_id,
            envelope.ciphertext,
            envelope.wrapped_key,
            registration.public_key_cose,
        );
        item.user_name = user_name;
        item.user_display_name = user_display_name;
        item.uv_initialized = user_verification;

        let created = self.passkey_repo.create(&item).await?;
        self.log_audit(
            AuditAction::PasskeyCreated,
            ResourceType::Passkey,
            true,
            Some(created.id),
            Some(identity_id),
            None,
        )
        .await;
        // 同步载荷 = passkey 语义快照（不含设备本地使用态）密封——与凭据
        // 捕获同口径：密封失败只跳过捕获，不影响主库写入。
        match SyncPasskeySnapshot::from_item(&created).seal(&item_key) {
            Ok(sealed) => {
                self.capture_sync(
                    created.id,
                    ItemKind::Passkey,
                    OpType::Put,
                    Some(sealed),
                    Some(item_key),
                )
                .await;
            }
            Err(e) => tracing::warn!(
                passkey_id = %created.id,
                error = %e,
                "passkey sync snapshot seal failed; capture skipped"
            ),
        }
        Ok(PasskeyCreation {
            item: created,
            attestation_object: registration.attestation_object,
        })
    }

    /// List the passkeys of an identity (metadata only; no key material).
    pub async fn list_passkeys(&self, identity_id: &Uuid) -> Result<Vec<PasskeyItem>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        Ok(self.passkey_repo.find_by_identity(identity_id).await?)
    }

    /// List all passkeys registered for a relying party, across identities
    /// (metadata only; the bridge's selection UI data source).
    pub async fn list_passkeys_by_rp(&self, rp_id: &str) -> Result<Vec<PasskeyItem>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        Ok(self.passkey_repo.find_by_rp_id(rp_id).await?)
    }

    /// Fetch one passkey (metadata only) and audit the view.
    pub async fn get_passkey(&self, id: &Uuid) -> Result<Option<PasskeyItem>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let item = self.passkey_repo.find_by_id(id).await?;
        if let Some(passkey) = &item {
            self.log_audit(
                AuditAction::PasskeyViewed,
                ResourceType::Passkey,
                true,
                Some(passkey.id),
                Some(passkey.identity_id),
                None,
            )
            .await;
        }
        Ok(item)
    }

    /// Delete a passkey by ID.
    pub async fn delete_passkey(&self, id: &Uuid) -> Result<bool> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Fetch first so the audit entry keeps the identity context.
        let existing = self.passkey_repo.find_by_id(id).await?;
        let Some(existing) = existing else {
            return Ok(false);
        };
        let ok = self.passkey_repo.delete(id).await?;
        self.log_audit(
            AuditAction::PasskeyDeleted,
            ResourceType::Passkey,
            ok,
            Some(*id),
            Some(existing.identity_id),
            None,
        )
        .await;
        // 删除照实广播 tombstone（尽力而为旁路：无捕获装配时是 no-op）
        if ok {
            self.capture_sync(*id, ItemKind::Passkey, OpType::Delete, None, None)
                .await;
        }
        Ok(ok)
    }

    /// Produce a WebAuthn assertion for a stored passkey.
    ///
    /// Unseals the private key in memory, signs the ceremony, stamps usage
    /// time and audits the event. The key never leaves core.
    pub async fn passkey_assertion(
        &self,
        id: &Uuid,
        origin: &str,
        client_data_json: &[u8],
        user_verification: bool,
        via: &str,
    ) -> Result<PasskeyAssertion> {
        self.ensure_authorized(&AuthzResource::Vault, AuthzAction::Use)
            .await?;
        self.touch_activity();

        let passkey = self
            .passkey_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| PersonaError::NotFound("Passkey".to_string()))?;

        let signing_key = self.unseal_passkey_key(&passkey)?;
        let assertion = assert_passkey(
            &passkey.rp_id,
            origin,
            client_data_json,
            &signing_key,
            user_verification,
        )?;

        let mut updated = passkey.clone();
        updated.last_used_at = Some(chrono::Utc::now());
        self.passkey_repo.update(&updated).await?;

        self.log_audit_with_metadata(
            AuditAction::PasskeyAsserted,
            ResourceType::Passkey,
            true,
            Some(passkey.id),
            Some(passkey.identity_id),
            None,
            Some(("via", via.to_string())),
        )
        .await;
        self.update_sensitive_auto_lock_activity().await?;

        Ok(PasskeyAssertion {
            credential_id: passkey.credential_id,
            user_handle: passkey.user_handle,
            authenticator_data: assertion.authenticator_data,
            signature_der: assertion.signature_der,
        })
    }

    /// Verify a stored passkey end to end: sign a locally generated ceremony
    /// and check the assertion against the stored public key — the same
    /// verification an RP would run. No state is modified.
    pub async fn passkey_self_test(&self, id: &Uuid) -> Result<()> {
        self.ensure_authorized(&AuthzResource::Vault, AuthzAction::Use)
            .await?;
        self.touch_activity();

        let passkey = self
            .passkey_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| PersonaError::NotFound("Passkey".to_string()))?;

        let origin = format!("https://{}", passkey.rp_id);
        let client_data = self_test_client_data(&origin)?;
        let signing_key = self.unseal_passkey_key(&passkey)?;
        let assertion = assert_passkey(
            &passkey.rp_id,
            &origin,
            &client_data,
            &signing_key,
            passkey.uv_initialized,
        )?;
        verify_assertion(
            &passkey.public_key_cose,
            &passkey.rp_id,
            &client_data,
            &assertion.authenticator_data,
            &assertion.signature_der,
        )?;
        Ok(())
    }

    /// Export a passkey's private key scalar (P2 import/backup needs).
    ///
    /// Refused when the passkey is marked non-exportable; audited as a
    /// security-sensitive event.
    pub async fn export_passkey_private_key(&self, id: &Uuid) -> Result<Vec<u8>> {
        // Export 判 InteractionRequired：履约在调用边（CLI `--include-sensitive`
        // 的确认框/桌面导出对话框）；core 侧不重复弹窗，状态门禁照旧。
        self.ensure_authorized(&AuthzResource::Vault, AuthzAction::Export)
            .await?;
        self.touch_activity();

        let passkey = self
            .passkey_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| PersonaError::NotFound("Passkey".to_string()))?;
        if !passkey.export_allowed {
            return Err(PersonaError::InvalidInput(
                "Passkey export is disabled for this credential".to_string(),
            )
            .into());
        }

        let signing_key = self.unseal_passkey_key(&passkey)?;
        self.log_audit(
            AuditAction::PasskeyExported,
            ResourceType::Passkey,
            true,
            Some(passkey.id),
            Some(passkey.identity_id),
            None,
        )
        .await;
        self.update_sensitive_auto_lock_activity().await?;
        Ok(signing_key.to_bytes().to_vec())
    }

    /// Decrypt the wrapped private key scalar and rebuild the signing key.
    pub(crate) fn unseal_passkey_key(
        &self,
        passkey: &PasskeyItem,
    ) -> Result<p256::ecdsa::SigningKey> {
        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);
        let mut scalar = hierarchy
            .decrypt_with_wrapped_key(&passkey.wrapped_item_key, &passkey.encrypted_private_key)?;
        let key = p256::ecdsa::SigningKey::from_slice(&scalar).map_err(|e| {
            PersonaError::CryptographicError(format!("Invalid stored passkey key: {e}"))
        })?;
        scalar.fill(0);
        Ok(key)
    }
}
