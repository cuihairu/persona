use crate::{
    auth::{
        AuthResult, AuthService, AutoLockEvent, AutoLockManager, BiometricPlatform,
        BiometricPrompt, BiometricProvider, MasterKeyService, MockBiometricProvider,
        MockRemoteAuthProvider, RemoteAuthChallenge, RemoteAuthProvider, RemoteAuthResult, Session,
        UserAuth,
    },
    crypto::{EncryptionService, KeyHierarchy, Sha256Hasher},
    models::{
        Attachment, AttachmentStats, AuditAction, AuditLog, ChangeHistory, ChangeHistoryQuery,
        ChangeHistoryStats, ChangeType, Credential, CredentialData, SecurityLevel,
        CredentialType, EntityType, Identity, IdentityType, ResourceType,
    },
    storage::{
        AttachmentManager, AttachmentRepository, AuditLogRepository, BlobStore,
        ChangeHistoryRepository, CredentialRepository, Database, IdentityRepository, Repository,
        UserAuthRepository,
    },
    PersonaError, Result,
};
use std::{
    cell::Cell,
    collections::HashMap,
    path::Path,
    sync::Arc,
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
    user_auth_repo: UserAuthRepository,
    audit_repo: AuditLogRepository,
    change_history_repo: ChangeHistoryRepository,
    attachment_manager: Option<AttachmentManager>,
    /// AES-GCM service constructed from master key; used to wrap per-item keys
    master_encryption: Option<EncryptionService>,
    biometric_provider: Arc<dyn BiometricProvider>,
    remote_auth_provider: Arc<dyn RemoteAuthProvider>,
    auto_lock_timeout: Duration,
    last_activity: Cell<Option<Instant>>,
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
            user_auth_repo: UserAuthRepository::new(db.clone()),
            audit_repo,
            change_history_repo: ChangeHistoryRepository::new(db.clone()),
            attachment_manager: None,
            master_encryption: None,
            biometric_provider: Arc::new(MockBiometricProvider::default()),
            remote_auth_provider: Arc::new(MockRemoteAuthProvider),
            auto_lock_timeout: Duration::from_secs(300),
            last_activity: Cell::new(None),
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
        self.last_activity.set(Some(std::time::Instant::now()));

        // Session management will be handled in authenticate method
        // For direct unlock, we don't create a session

        Ok(())
    }

    /// Lock the service and clear encryption keys
    pub fn lock(&mut self) {
        self.master_encryption = None;
        self.last_activity.set(None);
        self.current_user = None;

        // Note: In async context, this should be handled differently
        // For now, we just clear the session ID
        // *self.current_session_id.write().await = None; // This requires async
    }

    /// Check if the service is unlocked
    pub fn is_unlocked(&self) -> bool {
        if let (Some(_), Some(last)) = (&self.master_encryption, self.last_activity.get()) {
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
            self.auto_lock_manager.add_session(session).await?;
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
        self.last_activity.set(Some(std::time::Instant::now()));
    }

    /// Enhanced auto-lock management methods

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
            self.auto_lock_manager.lock_session(&session_id).await?;
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
            true // No session = locked
        }
    }

    /// Unlock current session after auto-lock
    pub async fn unlock_session(&self) -> Result<()> {
        let session_id_opt = {
            let current_session_id = self.current_session_id.read().await;
            current_session_id.clone()
        };

        if let Some(session_id) = session_id_opt {
            self.auto_lock_manager.unlock_session(&session_id).await?;
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
            self.auto_lock_manager.update_activity(&session_id).await?;
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
                .await?;
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
    pub fn needs_reauth(&self) -> bool {
        !self.is_unlocked()
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
        self.ensure_unlocked_with_auto_lock().await?;
        self.touch_activity();
        self.update_sensitive_auto_lock_activity().await?;

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
        let ok = self.credential_repo.delete(id).await?;
        self.log_audit(
            AuditAction::CredentialDeleted,
            ResourceType::Credential,
            ok,
            Some(*id),
            None,
            None,
        )
        .await;
        Ok(ok)
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

    /// Generate a strong password
    pub fn generate_password(&self, length: usize, include_symbols: bool) -> String {
        use rand::{rngs::OsRng, Rng};

        let lowercase = "abcdefghijklmnopqrstuvwxyz";
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let numbers = "0123456789";
        let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        let mut charset = String::new();
        charset.push_str(lowercase);
        charset.push_str(uppercase);
        charset.push_str(numbers);

        if include_symbols {
            charset.push_str(symbols);
        }

        let charset_bytes = charset.as_bytes();
        let mut password = String::new();

        for _ in 0..length {
            let idx = OsRng.gen_range(0..charset_bytes.len());
            password.push(charset_bytes[idx] as char);
        }

        password
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

    /// Record a change in history (internal helper)
    async fn record_change(
        &self,
        entity_type: EntityType,
        entity_id: Uuid,
        change_type: ChangeType,
        previous: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
    ) -> Result<()> {
        let version = self
            .change_history_repo
            .get_latest_version(entity_type.clone(), &entity_id)
            .await?
            + 1;

        let mut history = ChangeHistory::new(entity_type, entity_id, change_type)
            .with_states(previous, new)
            .with_version(version);

        if let Some(ref user) = self.current_user {
            history = history.with_user(user.to_string());
        }

        self.change_history_repo.record(&history).await
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
        let mut log = AuditLog::new(action, resource_type, success)
            .with_user_id(self.current_user.map(|u| u.to_string()))
            .with_error_message(error);
        if let Some(id) = identity_or_cred {
            // If identity_id provided, treat id as credential_id; else treat id as identity_id
            if let Some(identity_id_val) = identity_id {
                log = log
                    .with_identity_id(Some(identity_id_val))
                    .with_credential_id(Some(id));
            } else {
                log = log.with_identity_id(Some(id));
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
}
