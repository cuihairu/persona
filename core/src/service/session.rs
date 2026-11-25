use super::*;

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
            favicon_repo: FaviconRepository::new(db.clone()),
            workspace_repo: WorkspaceRepository::new(db.clone()),
            db,
            attachment_manager: None,
            master_encryption: None,
            biometric_provider: Arc::new(MockBiometricProvider::default()),
            remote_auth_provider: Arc::new(MockRemoteAuthProvider),
            auto_lock_timeout: Duration::from_secs(300),
            last_activity: Mutex::new(None),
            current_user: None,
            auto_lock_manager,
            current_session_id: Arc::new(RwLock::new(None)),
            event_emitter: None,
            connect_audit_marks: Mutex::new(HashMap::new()),
            sync_capture: RwLock::new(None),
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

    /// Replace the remote authentication provider (e.g., use the server implementation).
    pub fn set_remote_auth_provider(&mut self, provider: Arc<dyn RemoteAuthProvider>) {
        self.remote_auth_provider = provider;
    }

    /// Replace the biometric provider (desktop/mobile apps can inject real hooks).
    pub fn set_biometric_provider(&mut self, provider: Arc<dyn BiometricProvider>) {
        self.biometric_provider = provider;
    }

    /// Inject/remove the audit event reporter (`None` turns reporting off). The caller owns the
    /// emitter's `start()`/`stop()` lifecycle; `log_audit` only enqueues synchronously and never
    /// blocks.
    ///
    /// Propagates to [`AutoLockManager`] as well — its SessionLocked/Unlocked audits go through
    /// the same reporting chain once written to the database; hosts only deal with the service
    /// and need no separate wiring.
    pub fn set_event_emitter(&mut self, emitter: Option<Emitter>) {
        self.event_emitter = emitter.clone();
        self.auto_lock_manager.set_event_emitter(emitter);
    }

    /// Inject the sync capture seam (E2EE_SYNC_DESIGN §5). Called by the assembly layer
    /// (host/integration tests) after unlock: the service hands item-level write changes to the
    /// implementor, which wraps the group envelope and records them in the oplog. `None` = sync
    /// not enabled, and the write path skips with zero cost.
    ///
    /// No `&mut` needed: the capture seam is a runtime-swappable runtime attachment, with a
    /// different lifecycle from [`Self::set_event_emitter`] (which only needs to be injected at
    /// construction time).
    pub async fn attach_sync_capture(&self, capture: Option<Arc<dyn SyncCapture>>) {
        *self.sync_capture.write().await = capture;
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

    /// Current inactivity auto-lock timeout in seconds.
    pub fn inactivity_timeout_secs(&self) -> u64 {
        self.auto_lock_timeout.as_secs()
    }

    /// Reset inactivity timer; call this after sensitive operations to keep the session alive.
    pub fn touch_activity(&self) {
        *self.last_activity.lock().unwrap() = Some(std::time::Instant::now());
    }

    /// Configure auto-lock settings
    pub async fn configure_auto_lock(&mut self, config: crate::auth::AutoLockConfig) -> Result<()> {
        self.auto_lock_timeout = Duration::from_secs(config.inactivity_timeout_secs);
        // Sync into the manager (including require_reauth_sensitive / sensitive_operation_timeout_secs):
        // the manager cannot be rebuilt — a rebuild would drop the sessions it manages, its
        // background tasks, and its callbacks. Previously only the timeout copy was updated, so
        // the command layer's sensitive-operation re-auth toggle never took effect.
        self.auto_lock_manager.update_base_config(config);
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
    pub(crate) async fn update_auto_lock_activity(&self) -> Result<()> {
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

    /// Sensitive-activity refresh on the Connect token surface (called per request by the
    /// connect-server auth middleware).
    ///
    /// A scoped token counts as re-auth: refreshes the sensitive and activity timers and lifts
    /// the sensitive timeout lock ([`AutoLockManager::refresh_sensitive`], no force-lock
    /// decision). A no-op when there is no session — an opportunistic refresh that changes no
    /// denial semantics. Without it, an unattended serve hits the `force_lock_sensitive` lock
    /// on its first ciphertext read 5 minutes after login, and the token surface has no
    /// re-auth entry point (observed as a 500).
    pub async fn mark_authorized_request(&self) -> Result<()> {
        let session_id = self.current_session_id.read().await.clone();
        let Some(session_id) = session_id else {
            return Ok(());
        };
        self.auto_lock_manager
            .refresh_sensitive(&session_id)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Update sensitive activity for auto-lock tracking
    pub(crate) async fn update_sensitive_auto_lock_activity(&self) -> Result<()> {
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
    pub(crate) async fn ensure_unlocked_with_auto_lock(&self) -> Result<()> {
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
    pub(crate) async fn ensure_sensitive_operation_allowed(&self) -> Result<()> {
        self.ensure_unlocked_with_auto_lock().await?;
        if self.needs_reauth().await {
            // Dedicated error variant: clients (desktop/CLI) use it to pop the re-auth flow,
            // distinguishing it from an ordinary authentication failure.
            return Err(PersonaError::ReauthRequired(
                "Re-authentication required for sensitive operation".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// Unified authorization entry point (local session data plane). Pure policy decisions go
    /// through [`authz::authorize`]: Denied fails immediately; Export's `InteractionRequired` is
    /// fulfilled at the call edge (CLI confirmation / desktop dialog), and core does not prompt
    /// again. Stateful gates then keep guarding session lock / auto-lock / sensitive re-auth as
    /// before — the mechanism layer is unchanged; only the decision vocabulary is unified.
    ///
    /// Admin-surface operations (token creation/revocation, travel mode enter/exit) keep their
    /// existing sensitive gate; no data-plane verbs are introduced (write verbs are not settled;
    /// see the authz module comments).
    pub(crate) async fn ensure_authorized(
        &self,
        resource: &AuthzResource,
        action: AuthzAction,
    ) -> Result<()> {
        let decision = authorize(
            &AuthzPrincipal::LocalSession,
            resource,
            action,
            &AuthzContext::LOCAL,
        );
        if let Some(err) = denied_error(&decision) {
            return Err(err.into());
        }
        self.ensure_sensitive_operation_allowed().await
    }

    pub(crate) fn ensure_unlocked(&self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PersonaError::AuthenticationFailed("Service is locked".to_string()).into());
        }
        Ok(())
    }

    /// Master key encryption service (needed by host orchestration such as sync_now: backfill/run_cycle
    /// must unwrap item keys). Errs while the vault is locked.
    pub fn get_master_encryption_service(&self) -> Result<&EncryptionService> {
        self.master_encryption.as_ref().ok_or_else(|| {
            PersonaError::AuthenticationFailed("Service is locked".to_string()).into()
        })
    }
}
