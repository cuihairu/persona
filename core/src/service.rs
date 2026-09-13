use crate::{
    auth::{
        AuthResult, AuthService, AutoLockEvent, AutoLockManager, BiometricPlatform,
        BiometricPrompt, BiometricProvider, MasterKeyService, MockBiometricProvider,
        MockRemoteAuthProvider, RemoteAuthChallenge, RemoteAuthProvider, RemoteAuthResult, Session,
        UserAuth,
    },
    crypto::{
        assert_passkey, random_bytes32, register_passkey, self_test_client_data, verify_assertion,
        EncryptionService, KeyHierarchy, Sha256Hasher,
    },
    models::{
        Attachment, AttachmentStats, AuditAction, AuditLog, ChangeHistory, ChangeHistoryQuery,
        ChangeHistoryStats, Credential, CredentialData, CredentialType, EntityType, Identity,
        IdentityType, PasskeyItem, ResourceType, SecurityLevel,
    },
    password::{PasswordGenerator, PasswordGeneratorOptions},
    storage::{
        AttachmentManager, AttachmentRepository, AuditLogRepository, BlobStore,
        ChangeHistoryRepository, CredentialRepository, Database, IdentityRepository,
        PasskeyRepository, Repository, UserAuthRepository,
    },
    PersonaError, Result,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use uuid::Uuid;

/// High-level service for managing digital identities and credentials
pub struct PersonaService {
    auth_service: AuthService,
    master_key_service: MasterKeyService,
    identity_repo: IdentityRepository,
    credential_repo: CredentialRepository,
    passkey_repo: PasskeyRepository,
    user_auth_repo: UserAuthRepository,
    audit_repo: AuditLogRepository,
    change_history_repo: ChangeHistoryRepository,
    attachment_manager: Option<AttachmentManager>,
    /// AES-GCM service constructed from master key; used to wrap per-item keys
    master_encryption: Option<EncryptionService>,
    biometric_provider: Arc<dyn BiometricProvider>,
    remote_auth_provider: Arc<dyn RemoteAuthProvider>,
    auto_lock_timeout: Duration,
    last_activity: Mutex<Option<Instant>>,
    current_user: Option<Uuid>,
    /// Enhanced auto-lock manager
    auto_lock_manager: AutoLockManager,
    /// Current session ID for this service instance
    current_session_id: Arc<RwLock<Option<String>>>,
}

impl PersonaService {
    /// Create a new Persona service instance
    pub async fn new(db: Database) -> Result<Self> {
        let audit_repo = AuditLogRepository::new(db.clone());
        let auto_lock_manager =
            AutoLockManager::with_basic_config(crate::auth::AutoLockConfig::default())
                .with_audit_repo(audit_repo.clone());

        Ok(Self {
            auth_service: AuthService::new(),
            master_key_service: MasterKeyService::new(),
            identity_repo: IdentityRepository::new(db.clone()),
            credential_repo: CredentialRepository::new(db.clone()),
            passkey_repo: PasskeyRepository::new(Arc::new(db.clone())),
            user_auth_repo: UserAuthRepository::new(db.clone()),
            audit_repo,
            change_history_repo: ChangeHistoryRepository::new(db.clone()),
            attachment_manager: None,
            master_encryption: None,
            biometric_provider: Arc::new(MockBiometricProvider::default()),
            remote_auth_provider: Arc::new(MockRemoteAuthProvider),
            auto_lock_timeout: Duration::from_secs(300),
            last_activity: Mutex::new(None),
            current_user: None,
            auto_lock_manager,
            current_session_id: Arc::new(RwLock::new(None)),
        })
    }

    /// Initialize attachment storage
    pub async fn init_attachment_storage<P: AsRef<Path>>(
        &mut self,
        storage_path: P,
        db: Database,
    ) -> Result<()> {
        let blob_store = BlobStore::new(storage_path);
        let attachment_repo = AttachmentRepository::new(db);
        let manager = AttachmentManager::new(attachment_repo, blob_store);
        manager.init().await?;
        self.attachment_manager = Some(manager);
        Ok(())
    }

    /// Initialize the service with a master password
    pub fn unlock(&mut self, master_password: &str, salt: &[u8]) -> Result<()> {
        let encryption_service = self
            .master_key_service
            .create_encryption_service(master_password, salt);
        self.master_encryption = Some(encryption_service);
        *self.last_activity.lock().unwrap() = Some(std::time::Instant::now());

        // Session management will be handled in authenticate method
        // For direct unlock, we don't create a session

        Ok(())
    }

    /// Lock the service and clear encryption keys
    pub fn lock(&mut self) {
        self.master_encryption = None;
        *self.last_activity.lock().unwrap() = None;
        self.current_user = None;

        // Note: In async context, this should be handled differently
        // For now, we just clear the session ID
        // *self.current_session_id.write().await = None; // This requires async
    }

    /// Check if the service is unlocked
    pub fn is_unlocked(&self) -> bool {
        if let (Some(_), Some(last)) =
            (&self.master_encryption, *self.last_activity.lock().unwrap())
        {
            return last.elapsed() < self.auto_lock_timeout;
        }
        false
    }

    /// Authenticate user and unlock service
    pub async fn authenticate(
        &mut self,
        user_id: Uuid,
        password: &str,
        salt: &[u8],
    ) -> Result<AuthResult> {
        // For now, simplified authentication - in a real implementation,
        // you would load UserAuth from database
        let mut user_auth = UserAuth::new(user_id);
        let auth_result = self
            .auth_service
            .authenticate_password(&mut user_auth, password)?;

        if auth_result == AuthResult::Success {
            self.unlock(password, salt)?;
            self.current_user = Some(user_id);
            self.touch_activity();

            // Create and register session for auto-lock management
            let session = Session::new(user_id.to_string(), self.auto_lock_timeout);
            let session_id = session.id.clone();
            *self.current_session_id.write().await = Some(session_id.clone());

            // Add session to auto-lock manager
            self.auto_lock_manager
                .add_session(session)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            self.auto_lock_manager.set_current_user(user_id).await;
        }

        Ok(auth_result)
    }

    /// Replace the remote authentication provider (e.g., use the server implementation).
    pub fn set_remote_auth_provider(&mut self, provider: Arc<dyn RemoteAuthProvider>) {
        self.remote_auth_provider = provider;
    }

    /// Replace the biometric provider (desktop/mobile apps can inject real hooks).
    pub fn set_biometric_provider(&mut self, provider: Arc<dyn BiometricProvider>) {
        self.biometric_provider = provider;
    }

    /// Begin the SRP-like remote authentication handshake for a username.
    pub fn begin_remote_auth(&self, username: &str) -> Result<RemoteAuthChallenge> {
        self.remote_auth_provider.begin(username)
    }

    /// Finalize the remote authentication handshake, returning the remote result.
    pub fn finalize_remote_auth(
        &self,
        challenge: &RemoteAuthChallenge,
        client_proof: &str,
    ) -> Result<RemoteAuthResult> {
        self.remote_auth_provider.finalize(challenge, client_proof)
    }

    /// Check if a biometric unlock is possible on the active platform.
    pub fn biometric_available(&self, platform: Option<BiometricPlatform>) -> bool {
        self.biometric_provider.is_available(platform)
    }

    /// Attempt a biometric unlock flow (caller decides how to bind the result).
    pub fn authenticate_biometric(&self, prompt: &BiometricPrompt) -> Result<bool> {
        let result = self.biometric_provider.authenticate(prompt)?;
        Ok(result.verified)
    }

    /// Configure auto-lock timeout (seconds).
    pub fn set_auto_lock_timeout(&mut self, timeout: std::time::Duration) {
        self.auto_lock_timeout = timeout;
    }

    /// Reset inactivity timer; call this after sensitive operations to keep the session alive.
    pub fn touch_activity(&self) {
        *self.last_activity.lock().unwrap() = Some(std::time::Instant::now());
    }

    /// Configure auto-lock settings
    pub async fn configure_auto_lock(&mut self, config: crate::auth::AutoLockConfig) -> Result<()> {
        // This would require recreating the auto-lock manager with new config
        // For now, we'll just update the timeout
        self.auto_lock_timeout = Duration::from_secs(config.inactivity_timeout_secs);
        Ok(())
    }

    /// Register auto-lock event callback
    pub async fn register_auto_lock_callback(
        &self,
        callback: std::sync::Arc<dyn Fn(AutoLockEvent) + Send + Sync>,
    ) {
        self.auto_lock_manager.register_callback(callback).await;
    }

    /// Start background auto-lock monitoring
    pub async fn start_auto_lock_monitoring(&self) -> Result<()> {
        if let Some(user_id) = self.current_user {
            self.auto_lock_manager.set_current_user(user_id).await;
        }
        self.auto_lock_manager.start_background_monitoring().await;
        Ok(())
    }

    /// Stop background auto-lock monitoring
    pub async fn stop_auto_lock_monitoring(&self) {
        self.auto_lock_manager.stop_background_monitoring().await;
        self.auto_lock_manager.clear_current_user().await;
    }

    /// Force lock current session
    pub async fn force_lock_session(&self) -> Result<()> {
        let session_id_opt = {
            let current_session_id = self.current_session_id.read().await;
            current_session_id.clone()
        };

        if let Some(session_id) = session_id_opt {
            self.auto_lock_manager
                .lock_session(&session_id)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(())
    }

    /// Check if current session is auto-locked
    pub async fn is_session_locked(&self) -> bool {
        let session_id_opt = {
            let current_session_id = self.current_session_id.read().await;
            current_session_id.clone()
        };

        if let Some(session_id) = session_id_opt {
            !self.auto_lock_manager.is_session_valid(&session_id).await
        } else {
            // Legacy/bootstrapping flows can unlock the service without creating a session.
            // In that case we treat the service as "not auto-locked" and rely on the
            // in-memory `auto_lock_timeout` + `last_activity` checks.
            false
        }
    }

    /// Unlock current session after auto-lock
    pub async fn unlock_session(&self) -> Result<()> {
        let session_id_opt = {
            let current_session_id = self.current_session_id.read().await;
            current_session_id.clone()
        };

        if let Some(session_id) = session_id_opt {
            self.auto_lock_manager
                .unlock_session(&session_id)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(())
    }

    /// Get auto-lock statistics
    pub async fn get_auto_lock_statistics(&self) -> Result<crate::auth::AutoLockStatistics> {
        Ok(self.auto_lock_manager.get_statistics().await)
    }

    /// Get all sessions for current user
    pub async fn get_user_sessions(&self) -> Result<Vec<Session>> {
        if let Some(user_id) = self.current_user {
            let sessions = self
                .auto_lock_manager
                .get_user_sessions(&user_id.to_string())
                .await;
            Ok(sessions)
        } else {
            Ok(Vec::new())
        }
    }

    /// Update activity for auto-lock tracking
    async fn update_auto_lock_activity(&self) -> Result<()> {
        let session_id_opt = {
            let current_session_id = self.current_session_id.read().await;
            current_session_id.clone()
        };

        if let Some(session_id) = session_id_opt {
            self.auto_lock_manager
                .update_activity(&session_id)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(())
    }

    /// Update sensitive activity for auto-lock tracking
    async fn update_sensitive_auto_lock_activity(&self) -> Result<()> {
        let session_id_opt = {
            let current_session_id = self.current_session_id.read().await;
            current_session_id.clone()
        };

        if let Some(session_id) = session_id_opt {
            self.auto_lock_manager
                .update_sensitive_activity(&session_id)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(())
    }

    /// Enhanced ensure unlocked with auto-lock check
    async fn ensure_unlocked_with_auto_lock(&self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PersonaError::AuthenticationFailed("Service is locked".to_string()).into());
        }

        if self.is_session_locked().await {
            return Err(
                PersonaError::AuthenticationFailed("Session is auto-locked".to_string()).into(),
            );
        }

        Ok(())
    }

    /// Whether re-auth is required for a sensitive operation based on inactivity.
    pub async fn needs_reauth(&self) -> bool {
        let session_id_opt = {
            let current_session_id = self.current_session_id.read().await;
            current_session_id.clone()
        };

        if let Some(session_id) = session_id_opt {
            self.auto_lock_manager
                .requires_sensitive_auth(&session_id)
                .await
        } else {
            false
        }
    }

    /// Ensure sensitive operations can proceed without re-authentication.
    async fn ensure_sensitive_operation_allowed(&self) -> Result<()> {
        self.ensure_unlocked_with_auto_lock().await?;
        if self.needs_reauth().await {
            return Err(PersonaError::AuthenticationFailed(
                "Re-authentication required for sensitive operation".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// Create a new identity
    pub async fn create_identity(
        &self,
        name: String,
        identity_type: IdentityType,
    ) -> Result<Identity> {
        self.ensure_unlocked_with_auto_lock().await?;
        self.touch_activity();
        self.update_auto_lock_activity().await?;

        let identity = Identity::new(name, identity_type);
        let created = self.identity_repo.create(&identity).await?;
        self.log_audit(
            AuditAction::IdentityCreated,
            ResourceType::Identity,
            true,
            Some(created.id),
            None,
            None,
        )
        .await;
        Ok(created)
    }

    /// Create a new identity with all fields pre-populated.
    /// Use this when the caller already collected metadata such as email/phone/tags.
    pub async fn create_identity_full(&self, mut identity: Identity) -> Result<Identity> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Ensure timestamps are reasonable and updated on create
        identity.touch();
        let created = self.identity_repo.create(&identity).await?;
        self.log_audit(
            AuditAction::IdentityCreated,
            ResourceType::Identity,
            true,
            Some(created.id),
            None,
            None,
        )
        .await;
        Ok(created)
    }

    /// Get all identities
    pub async fn get_identities(&self) -> Result<Vec<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.identity_repo.find_all().await
    }

    /// Get identity by name
    pub async fn get_identity_by_name(&self, name: &str) -> Result<Option<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let res = self.identity_repo.find_by_name(name).await?;
        if let Some(ref ident) = res {
            self.log_audit(
                AuditAction::IdentityViewed,
                ResourceType::Identity,
                true,
                Some(ident.id),
                None,
                None,
            )
            .await;
        }
        Ok(res)
    }

    /// Get identity by ID
    pub async fn get_identity(&self, id: &Uuid) -> Result<Option<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let res = self.identity_repo.find_by_id(id).await?;
        if let Some(ref ident) = res {
            self.log_audit(
                AuditAction::IdentityViewed,
                ResourceType::Identity,
                true,
                Some(ident.id),
                None,
                None,
            )
            .await;
        }
        Ok(res)
    }

    /// Update an identity
    pub async fn update_identity(&self, identity: &Identity) -> Result<Identity> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let updated = self.identity_repo.update(identity).await?;
        self.log_audit(
            AuditAction::IdentityUpdated,
            ResourceType::Identity,
            true,
            Some(updated.id),
            None,
            None,
        )
        .await;
        Ok(updated)
    }

    /// Delete an identity
    pub async fn delete_identity(&self, id: &Uuid) -> Result<bool> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Audit logs reference identities via a strict FK; detach them first so the identity can
        // be deleted while preserving the audit trail.
        let _ = self.audit_repo.clear_identity_reference(id).await?;
        let ok = self.identity_repo.delete(id).await?;
        self.log_audit(
            AuditAction::IdentityDeleted,
            ResourceType::Identity,
            ok,
            Some(*id),
            None,
            None,
        )
        .await;
        Ok(ok)
    }

    /// Create a new credential
    pub async fn create_credential(
        &self,
        identity_id: Uuid,
        name: String,
        credential_type: CredentialType,
        security_level: SecurityLevel,
        credential_data: &CredentialData,
    ) -> Result<Credential> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);

        // Serialize and encrypt the credential data
        let plaintext = credential_data.to_bytes().map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to serialize credential data: {}", e))
        })?;

        let envelope = hierarchy.encrypt_with_new_item_key(&plaintext)?;

        let credential = Credential::new(
            identity_id,
            name,
            credential_type,
            security_level,
            envelope.ciphertext,
            Some(envelope.wrapped_key),
        );

        let created = self.credential_repo.create(&credential).await?;
        self.log_audit(
            AuditAction::CredentialCreated,
            ResourceType::Credential,
            true,
            Some(created.id),
            Some(identity_id),
            None,
        )
        .await;
        Ok(created)
    }

    /// Get credentials for an identity
    pub async fn get_credentials_for_identity(
        &self,
        identity_id: &Uuid,
    ) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_by_identity(identity_id).await
    }

    /// Get a specific credential by ID
    pub async fn get_credential(&self, id: &Uuid) -> Result<Option<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_by_id(id).await
    }

    /// Decrypt and get credential data
    pub async fn get_credential_data(
        &self,
        credential_id: &Uuid,
    ) -> Result<Option<CredentialData>> {
        self.ensure_sensitive_operation_allowed().await?;
        self.touch_activity();

        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);

        let credential = match self.credential_repo.find_by_id(credential_id).await? {
            Some(cred) => cred,
            None => return Ok(None),
        };

        // Mark as accessed
        let mut credential = credential;
        credential.mark_accessed();
        self.credential_repo.update(&credential).await?;

        // Decrypt the data
        let plaintext = match &credential.wrapped_item_key {
            Some(wrapped_key) => {
                hierarchy.decrypt_with_wrapped_key(wrapped_key, &credential.encrypted_data)?
            }
            None => master_encryption
                .decrypt(&credential.encrypted_data)
                .map_err(|e| {
                    PersonaError::CryptographicError(format!(
                        "Failed to decrypt legacy credential: {}",
                        e
                    ))
                })?,
        };

        let credential_data = CredentialData::from_bytes(&plaintext).map_err(|e| {
            PersonaError::CryptographicError(format!(
                "Failed to deserialize credential data: {}",
                e
            ))
        })?;
        self.log_audit(
            AuditAction::CredentialDecrypted,
            ResourceType::Credential,
            true,
            Some(credential.id),
            Some(credential.identity_id),
            None,
        )
        .await;

        self.update_sensitive_auto_lock_activity().await?;
        Ok(Some(credential_data))
    }

    /// Update a credential
    pub async fn update_credential(&self, credential: &Credential) -> Result<Credential> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let updated = self.credential_repo.update(credential).await?;
        self.log_audit(
            AuditAction::CredentialUpdated,
            ResourceType::Credential,
            true,
            Some(updated.id),
            Some(updated.identity_id),
            None,
        )
        .await;
        Ok(updated)
    }

    /// Delete a credential
    pub async fn delete_credential(&self, id: &Uuid) -> Result<bool> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Fetch the credential up-front so we can detach audit logs and keep useful context.
        let existing = self.credential_repo.find_by_id(id).await?;
        if existing.is_none() {
            return Ok(false);
        }
        let existing = existing.unwrap();

        let _ = self.audit_repo.clear_credential_reference(id).await?;
        let ok = self.credential_repo.delete(id).await?;
        self.log_audit(
            AuditAction::CredentialDeleted,
            ResourceType::Credential,
            ok,
            Some(*id),
            Some(existing.identity_id),
            None,
        )
        .await;
        Ok(ok)
    }

    // ------------------------------------------------------------------
    // Passkeys (WebAuthn software authenticator)
    // ------------------------------------------------------------------

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
        let envelope = hierarchy.encrypt_with_new_item_key(scalar.as_slice())?;

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
    ) -> Result<PasskeyAssertion> {
        self.ensure_sensitive_operation_allowed().await?;
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

        self.log_audit(
            AuditAction::PasskeyAsserted,
            ResourceType::Passkey,
            true,
            Some(passkey.id),
            Some(passkey.identity_id),
            None,
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
        self.ensure_sensitive_operation_allowed().await?;
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
        self.ensure_sensitive_operation_allowed().await?;
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
    fn unseal_passkey_key(&self, passkey: &PasskeyItem) -> Result<p256::ecdsa::SigningKey> {
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

    /// Search credentials by name
    pub async fn search_credentials(&self, query: &str) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.search_by_name(query).await
    }

    /// Get favorite credentials
    pub async fn get_favorite_credentials(&self) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_favorites().await
    }

    /// Get credentials by type
    pub async fn get_credentials_by_type(
        &self,
        credential_type: &CredentialType,
    ) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.find_by_type(credential_type).await
    }

    /// Get identities by type
    pub async fn get_identities_by_type(
        &self,
        identity_type: &IdentityType,
    ) -> Result<Vec<Identity>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.identity_repo.find_by_type(identity_type).await
    }

    /// Generate a strong password (legacy helper).
    pub fn generate_password(&self, length: usize, include_symbols: bool) -> String {
        let options = PasswordGeneratorOptions {
            length: length.max(4),
            include_symbols,
            ..Default::default()
        };

        PasswordGenerator::generate(&options).unwrap_or_else(|_| {
            // Fall back to a safe default if option validation fails for any reason.
            PasswordGenerator::generate(&PasswordGeneratorOptions {
                length: 12,
                include_symbols: false,
                ..PasswordGeneratorOptions::default()
            })
            .unwrap_or_else(|_| "persona-temp".to_string())
        })
    }

    /// Generate a password using advanced options.
    pub fn generate_password_with_options(
        &self,
        options: &PasswordGeneratorOptions,
    ) -> Result<String> {
        PasswordGenerator::generate(options)
    }

    /// Generate salt for master key derivation
    pub fn generate_salt(&self) -> [u8; 32] {
        self.master_key_service.generate_salt()
    }

    /// Hash data using SHA-256
    pub fn hash_data(&self, data: &[u8]) -> [u8; 32] {
        Sha256Hasher::hash(data)
    }

    /// Export identity data (for backup)
    pub async fn export_identity(&self, identity_id: &Uuid) -> Result<IdentityExport> {
        self.ensure_unlocked()?;

        let identity = self
            .identity_repo
            .find_by_id(identity_id)
            .await?
            .ok_or_else(|| PersonaError::IdentityNotFound(identity_id.to_string()))?;

        let credentials = self.credential_repo.find_by_identity(identity_id).await?;

        let export = IdentityExport {
            identity,
            credentials,
        };
        self.log_audit(
            AuditAction::BackupCreated,
            ResourceType::Identity,
            true,
            Some(*identity_id),
            None,
            None,
        )
        .await;
        Ok(export)
    }

    /// Get service statistics
    pub async fn get_statistics(&self) -> Result<PersonaStatistics> {
        self.ensure_unlocked()?;

        let identities = self.identity_repo.find_all().await?;
        let all_credentials = self.credential_repo.find_all().await?;

        let mut credential_types: HashMap<String, u32> = HashMap::new();
        let mut security_levels: HashMap<String, u32> = HashMap::new();

        for cred in &all_credentials {
            *credential_types
                .entry(cred.credential_type.to_string())
                .or_insert(0) += 1;
            *security_levels
                .entry(cred.security_level.to_string())
                .or_insert(0) += 1;
        }

        Ok(PersonaStatistics {
            total_identities: identities.len(),
            total_credentials: all_credentials.len(),
            active_credentials: all_credentials.iter().filter(|c| c.is_active).count(),
            favorite_credentials: all_credentials.iter().filter(|c| c.is_favorite).count(),
            credential_types,
            security_levels,
        })
    }

    /// Initialize first-time user with master password
    pub async fn initialize_user(&mut self, master_password: &str) -> Result<Uuid> {
        let user_id = Uuid::new_v4();
        let mut user_auth = UserAuth::new(user_id);
        // Set master password (this will generate and store salt inside the struct)
        user_auth.set_master_password(master_password)?;
        // Persist to DB
        self.user_auth_repo.create(&user_auth).await?;
        // Get the salt and unlock
        let salt = user_auth.get_master_key_salt()?;
        self.unlock(master_password, &salt)?;
        self.current_user = Some(user_id);
        self.log_audit(
            AuditAction::ConfigurationChanged,
            ResourceType::Configuration,
            true,
            None,
            None,
            None,
        )
        .await;
        Ok(user_id)
    }

    /// Check if any users exist in the database
    pub async fn has_users(&self) -> Result<bool> {
        self.user_auth_repo.has_any().await
    }

    /// Authenticate existing user
    pub async fn authenticate_user(&mut self, master_password: &str) -> Result<AuthResult> {
        // Load first user (single-user MVP)
        let mut user_auth = match self.user_auth_repo.get_first().await? {
            Some(ua) => ua,
            None => {
                // No user exists yet
                return Ok(AuthResult::InvalidCredentials);
            }
        };

        // Verify password
        let auth_result = self
            .auth_service
            .authenticate_password(&mut user_auth, master_password)?;
        // Persist updated auth state (failed attempts/lockout)
        self.user_auth_repo.update(&user_auth).await?;

        if auth_result == AuthResult::Success {
            // Unlock with stored salt
            let salt = user_auth.get_master_key_salt()?;
            self.unlock(master_password, &salt)?;
            self.current_user = Some(user_auth.user_id);
            self.log_audit(
                AuditAction::Login,
                ResourceType::User,
                true,
                None,
                None,
                None,
            )
            .await;
        } else {
            self.log_audit(
                AuditAction::LoginFailed,
                ResourceType::User,
                false,
                None,
                None,
                Some("invalid_credentials".to_string()),
            )
            .await;
        }

        Ok(auth_result)
    }

    // ===== Attachment Management =====

    /// Attach a file to a credential
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

        // For now, use a fixed key or generate one per attachment
        // In a real implementation, you'd use the master key hierarchy
        let encryption_key = if encrypt {
            Some(&EncryptionService::generate_key())
        } else {
            None
        };

        let attachment_id = manager
            .store(
                file_path,
                credential_id,
                encrypt,
                encryption_key.as_ref().map(|k| k.as_slice()),
            )
            .await?;

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

        // For now, use the same fixed key for decryption
        // In a real implementation, you'd retrieve the correct key from key hierarchy
        let decryption_key = if decrypt {
            Some(&EncryptionService::generate_key())
        } else {
            None
        };

        manager
            .retrieve(
                attachment_id,
                decrypt,
                decryption_key.as_ref().map(|k| k.as_slice()),
            )
            .await
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

    // ===== Change History / Versioning =====

    /// Get change history for an entity
    pub async fn get_entity_history(
        &self,
        entity_type: EntityType,
        entity_id: &Uuid,
    ) -> Result<Vec<ChangeHistory>> {
        self.change_history_repo
            .get_entity_history(entity_type, entity_id)
            .await
    }

    /// Get specific version of an entity
    pub async fn get_entity_version(
        &self,
        entity_type: EntityType,
        entity_id: &Uuid,
        version: u32,
    ) -> Result<Option<ChangeHistory>> {
        self.change_history_repo
            .get_version(entity_type, entity_id, version)
            .await
    }

    /// Query change history with filters
    pub async fn query_change_history(
        &self,
        query: &ChangeHistoryQuery,
    ) -> Result<Vec<ChangeHistory>> {
        self.change_history_repo.query(query).await
    }

    /// Get change history statistics
    pub async fn get_change_history_stats(&self) -> Result<ChangeHistoryStats> {
        self.change_history_repo.get_stats().await
    }

    /// Delete old change history (for cleanup/GDPR compliance)
    pub async fn cleanup_old_history(
        &self,
        before_date: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        self.change_history_repo
            .delete_before_date(before_date)
            .await
    }

    // Private helper methods

    fn ensure_unlocked(&self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PersonaError::AuthenticationFailed("Service is locked".to_string()).into());
        }
        Ok(())
    }

    fn get_master_encryption_service(&self) -> Result<&EncryptionService> {
        self.master_encryption.as_ref().ok_or_else(|| {
            PersonaError::AuthenticationFailed("Service is locked".to_string()).into()
        })
    }

    async fn log_audit(
        &self,
        action: AuditAction,
        resource_type: ResourceType,
        success: bool,
        identity_or_cred: Option<Uuid>,
        identity_id: Option<Uuid>,
        error: Option<String>,
    ) {
        let action_kind = action.clone();
        let mut log = AuditLog::new(action, resource_type, success)
            .with_user_id(self.current_user.map(|u| u.to_string()))
            .with_error_message(error);
        if let Some(id) = identity_or_cred {
            // Always store the raw resource identifier so deletion events can still be recorded
            // without violating foreign key constraints.
            log = log.with_resource_id(Some(id.to_string()));

            match action_kind {
                AuditAction::IdentityDeleted => {
                    // Identity no longer exists; don't set FK-backed fields.
                }
                AuditAction::PasskeyCreated
                | AuditAction::PasskeyViewed
                | AuditAction::PasskeyAsserted
                | AuditAction::PasskeyExported
                | AuditAction::PasskeyDeleted => {
                    // A passkey id is not a credential FK; resource_id carries
                    // the primary key, so just attach the identity context.
                    if let Some(identity_id_val) = identity_id {
                        log = log.with_identity_id(Some(identity_id_val));
                    }
                }
                AuditAction::CredentialDeleted => {
                    // Credential no longer exists; keep identity context if available.
                    if let Some(identity_id_val) = identity_id {
                        log = log.with_identity_id(Some(identity_id_val));
                    }
                }
                _ => {
                    // If identity_id provided, treat `id` as credential_id; else treat `id` as identity_id.
                    if let Some(identity_id_val) = identity_id {
                        log = log
                            .with_identity_id(Some(identity_id_val))
                            .with_credential_id(Some(id));
                    } else {
                        log = log.with_identity_id(Some(id));
                    }
                }
            }
        }
        let _ = self.audit_repo.create(&log).await;
    }
}

/// Export data structure for backup
#[derive(Debug)]
pub struct IdentityExport {
    pub identity: Identity,
    pub credentials: Vec<Credential>,
}

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

/// Service usage statistics
#[derive(Debug)]
pub struct PersonaStatistics {
    pub total_identities: usize,
    pub total_credentials: usize,
    pub active_credentials: usize,
    pub favorite_credentials: usize,
    pub credential_types: HashMap<String, u32>,
    pub security_levels: HashMap<String, u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CredentialData, PasswordCredentialData};
    use crate::storage::Database;

    #[tokio::test]
    async fn test_persona_service_basic_operations() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let mut service = PersonaService::new(db).await.unwrap();
        let salt = service.generate_salt();

        // Test unlock/lock
        assert!(!service.is_unlocked());
        service.unlock("test_password", &salt).unwrap();
        assert!(service.is_unlocked());

        // Create identity
        let identity = service
            .create_identity("Test Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // Create credential
        let password_data = CredentialData::Password(PasswordCredentialData {
            password: "secret123".to_string(),
            email: Some("test@example.com".to_string()),
            security_questions: vec![],
        });

        let credential = service
            .create_credential(
                identity.id,
                "Test Account".to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                &password_data,
            )
            .await
            .unwrap();

        // Retrieve and decrypt credential
        let retrieved_data = service.get_credential_data(&credential.id).await.unwrap();
        assert!(retrieved_data.is_some());

        if let Some(CredentialData::Password(pwd_data)) = retrieved_data {
            assert_eq!(pwd_data.password, "secret123");
            assert_eq!(pwd_data.email, Some("test@example.com".to_string()));
        } else {
            panic!("Expected password credential data");
        }
    }

    #[tokio::test]
    async fn test_passkey_lifecycle() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let mut service = PersonaService::new(db).await.unwrap();
        let salt = service.generate_salt();
        service.unlock("test_password", &salt).unwrap();

        let identity = service
            .create_identity("Passkey Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // registration through the service; client data mimics an RP challenge
        let create_client_data = br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
        let passkey = service
            .create_passkey(
                identity.id,
                "example.com".to_string(),
                "https://example.com",
                create_client_data,
                None,
                Some("alice@example.com".to_string()),
                Some("Alice".to_string()),
                true,
            )
            .await
            .unwrap();
        assert_eq!(passkey.rp_id, "example.com");
        assert_eq!(passkey.user_handle.len(), 32);
        assert_eq!(passkey.alg, -7);

        let listed = service.list_passkeys(&identity.id).await.unwrap();
        assert_eq!(listed.len(), 1);

        // self-test: sign locally, verify against the stored public key
        service.passkey_self_test(&passkey.id).await.unwrap();

        // assertion updates last_used_at and returns RP-ready artifacts
        let get_client_data =
            br#"{"type":"webauthn.get","challenge":"YXNzZXJ0aW9u","origin":"https://example.com"}"#;
        let assertion = service
            .passkey_assertion(&passkey.id, "https://example.com", get_client_data, true)
            .await
            .unwrap();
        assert_eq!(assertion.credential_id, passkey.credential_id);
        assert_eq!(assertion.user_handle, passkey.user_handle);

        let reloaded = service.get_passkey(&passkey.id).await.unwrap().unwrap();
        assert!(reloaded.last_used_at.is_some());

        assert!(service.delete_passkey(&passkey.id).await.unwrap());
        assert!(!service.delete_passkey(&passkey.id).await.unwrap());
        assert!(service.get_passkey(&passkey.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_passkey_error_paths_and_export() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let mut service = PersonaService::new(db.clone()).await.unwrap();
        let salt = service.generate_salt();
        service.unlock("test_password", &salt).unwrap();

        let identity = service
            .create_identity("Passkey Errors".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let create_client_data = br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
        let passkey = service
            .create_passkey(
                identity.id,
                "example.com".to_string(),
                "https://example.com",
                create_client_data,
                None,
                Some("alice@example.com".to_string()),
                Some("Alice".to_string()),
                true,
            )
            .await
            .unwrap();

        // ---- export: disabled flag, unknown id, then the happy path ----
        service
            .passkey_repo
            .update(&PasskeyItem {
                export_allowed: false,
                ..passkey.clone()
            })
            .await
            .unwrap();
        let err = service
            .export_passkey_private_key(&passkey.id)
            .await
            .expect_err("non-exportable passkey must be refused");
        assert!(err.to_string().contains("export is disabled"));

        let unknown = uuid::Uuid::new_v4();
        let err = service
            .export_passkey_private_key(&unknown)
            .await
            .expect_err("unknown passkey export must fail");
        assert!(err.to_string().contains("not found"));

        service
            .passkey_repo
            .update(&PasskeyItem {
                export_allowed: true,
                ..passkey.clone()
            })
            .await
            .unwrap();
        let exported = service
            .export_passkey_private_key(&passkey.id)
            .await
            .unwrap();
        assert_eq!(exported.len(), 32);
        // the exported scalar must match the stored key's public point
        let key = p256::ecdsa::SigningKey::from_slice(&exported).unwrap();
        let cose = crate::crypto::cose_public_key(&key.verifying_key()).unwrap();
        assert_eq!(cose, passkey.public_key_cose);

        // ---- assertion: origin must match the passkey's rp_id ----
        let get_client_data = br#"{"type":"webauthn.get","challenge":"YXNzZXJ0aW9u","origin":"https://evil.example"}"#;
        let err = service
            .passkey_assertion(&passkey.id, "https://evil.example", get_client_data, true)
            .await
            .expect_err("mismatched origin must be rejected");
        assert!(err.to_string().contains("does not match rp_id"));

        // ---- corrupted sealed key: unsealing must surface a crypto error ----
        // A validly-sealed envelope whose plaintext is not a valid P-256
        // scalar (zero) — AEAD decrypts fine, key reconstruction must fail.
        let hierarchy =
            crate::crypto::KeyHierarchy::new(service.get_master_encryption_service().unwrap());
        let envelope = hierarchy.encrypt_with_new_item_key(&[0u8; 32]).unwrap();
        sqlx::query(
            "UPDATE passkeys SET encrypted_private_key = ?, wrapped_item_key = ? WHERE id = ?",
        )
        .bind(&envelope.ciphertext)
        .bind(&envelope.wrapped_key)
        .bind(passkey.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
        let err = service
            .passkey_self_test(&passkey.id)
            .await
            .expect_err("corrupted sealed key must fail");
        assert!(err.to_string().contains("Invalid stored passkey key"));

        // ---- restore the sealed key, then break rp_id / public key ----
        sqlx::query(
            "UPDATE passkeys SET encrypted_private_key = ?, wrapped_item_key = ? WHERE id = ?",
        )
        .bind(&passkey.encrypted_private_key)
        .bind(&passkey.wrapped_item_key)
        .bind(passkey.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();

        // a rp_id that is not a hostname makes the self-test's own assertion fail
        sqlx::query("UPDATE passkeys SET rp_id = 'bad rp' WHERE id = ?")
            .bind(passkey.id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        let err = service
            .passkey_self_test(&passkey.id)
            .await
            .expect_err("invalid rp_id must fail the self-test");
        assert!(err.to_string().contains("rp_id"));

        // a public key from another key pair makes the final RP-check fail
        let foreign =
            crate::crypto::cose_public_key(&crate::crypto::generate_signing_key().verifying_key())
                .unwrap();
        sqlx::query("UPDATE passkeys SET rp_id = 'example.com', public_key_cose = ? WHERE id = ?")
            .bind(&foreign)
            .bind(passkey.id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        let err = service
            .passkey_self_test(&passkey.id)
            .await
            .expect_err("mismatched public key must fail the self-test");
        assert!(
            err.to_string().contains("signature invalid")
                || err.to_string().contains("Assertion signature invalid")
        );
    }
}
