use super::*;

/// RFC3339 serialization for user_auth timestamps written via raw SQL
/// (mirrors the private helper in `storage::user_auth`).
pub(crate) fn system_time_to_rfc3339_opt(time: Option<SystemTime>) -> Option<String> {
    time.map(|t| {
        let datetime: chrono::DateTime<chrono::Utc> = t.into();
        datetime.to_rfc3339()
    })
}

impl PersonaService {
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

    /// Opt-in master-password expiry policy (`WorkspaceSettings
    /// .password_expiry_days`), evaluated lazily: at unlock the age of
    /// `password_updated_at` is compared, and on expiry `password_change_required` is set, after
    /// which `authenticate_password` returns `PasswordChangeRequired` per its existing semantics.
    ///
    /// Fail-open: a settings read failure only warns and is skipped — a policy read error must
    /// never lock the user out of unlocking; a missing timestamp is likewise skipped (migrations
    /// backfill it, so this is defensive).
    pub(crate) async fn enforce_password_expiry(&self, user_auth: &mut UserAuth) -> Result<()> {
        let Some(days) = self.load_password_expiry_days().await? else {
            return Ok(());
        };
        let Some(updated_at) = user_auth.password_updated_at else {
            return Ok(());
        };

        let age = SystemTime::now()
            .duration_since(updated_at)
            .unwrap_or_default();
        let expiry = Duration::from_secs(u64::from(days) * 86_400);
        if age >= expiry && !user_auth.password_change_required {
            user_auth.password_change_required = true;
            user_auth.updated_at = SystemTime::now();
            self.user_auth_repo.update(user_auth).await?;
        }
        Ok(())
    }

    /// Read the master-password expiry in days; returning None when there is no value or the read fails (fail-open).
    pub(crate) async fn load_password_expiry_days(&self) -> Result<Option<u32>> {
        match Repository::find_all(&self.workspace_repo).await {
            Ok(workspaces) => Ok(workspaces
                .first()
                .and_then(|ws| ws.settings.password_expiry_days)),
            Err(e) => {
                tracing::warn!(
                    "password expiry policy skipped: workspace settings unreadable: {e}"
                );
                Ok(None)
            }
        }
    }

    /// Whether travel mode is active. Consumers: the password-change block (changing the password
    /// during travel mode bricks the wrapped key in the sidecar; when settings cannot be read,
    /// refusing the change is preferred to taking the risk, fail-closed) and sampling the travel
    /// gate in sync_now. Reads only a settings boolean and does not depend on the travel module
    /// itself, so it carries no feature gate.
    pub async fn travel_mode_active(&self) -> Result<bool> {
        let workspaces = Repository::find_all(&self.workspace_repo).await?;
        Ok(workspaces
            .first()
            .map(|ws| ws.settings.travel_mode)
            .unwrap_or(false))
    }

    /// Derive the master encryption service for a verified password, lazily
    /// upgrading a legacy PBKDF2 iteration count along the way.
    ///
    /// Password verification is Argon2id over the password, so it is
    /// independent of the PBKDF2 count — only the derived *key* changes when
    /// the count moves. Because the iteration count is an input to derivation,
    /// upgrading changes the master key, so every item key wrapped by the old
    /// key must be re-wrapped (same transactional path as password rotation).
    /// Salt and password stay untouched.
    ///
    /// Travel mode defers the upgrade: the sidecar holds keys wrapped by the
    /// old master key, and this re-wrap only reaches the live vault (same
    /// limitation as `change_master_password`, which refuses outright). Unlock
    /// keeps working at the legacy count; the upgrade lands on the next
    /// unlock after travel mode exits.
    pub(crate) async fn derive_verified_master_key(
        &mut self,
        user_auth: &mut UserAuth,
        master_password: &str,
    ) -> Result<[u8; 32]> {
        let salt = user_auth.get_master_key_salt()?;
        if user_auth.kdf_iterations >= MASTER_KEY_PBKDF2_ITERATIONS {
            return Ok(self
                .master_key_service
                .derive_master_key(master_password, &salt));
        }
        #[cfg(feature = "backup")]
        if self.travel_mode_active().await? {
            return Ok(self.master_key_service.derive_master_key_with_iterations(
                master_password,
                &salt,
                user_auth.kdf_iterations,
            ));
        }
        let old_enc = self
            .master_key_service
            .create_encryption_service_with_iterations(
                master_password,
                &salt,
                user_auth.kdf_iterations,
            );
        let new_enc = self
            .master_key_service
            .create_encryption_service(master_password, &salt);
        // Advance the count *before* the rewrap so it commits in the same
        // transaction: a crash in between must never leave rewrapped rows tagged
        // with the old count — that would re-derive the old key on the next
        // unlock and fail to open the item keys.
        user_auth.kdf_iterations = MASTER_KEY_PBKDF2_ITERATIONS;
        self.rewrap_all_item_keys(&old_enc, &new_enc, user_auth)
            .await?;
        Ok(self
            .master_key_service
            .derive_master_key(master_password, &salt))
    }

    /// Authenticate an existing user with the master password.
    ///
    /// The single converged unlock entry: password verification via Argon2id,
    /// then master-key derivation through [`Self::derive_verified_master_key`],
    /// which also performs the lazy PBKDF2 iteration upgrade for legacy vaults.
    pub async fn authenticate_user(&mut self, master_password: &str) -> Result<AuthResult> {
        // Load first user (single-user MVP)
        let mut user_auth = match self.user_auth_repo.get_first().await? {
            Some(ua) => ua,
            None => {
                // No user exists yet
                return Ok(AuthResult::InvalidCredentials);
            }
        };

        // Opt-in expiry policy may flag rotation before the password check
        self.enforce_password_expiry(&mut user_auth).await?;

        // Verify password
        let auth_result = self
            .auth_service
            .authenticate_password(&mut user_auth, master_password)?;
        // Persist updated auth state (failed attempts/lockout)
        self.user_auth_repo.update(&user_auth).await?;

        if auth_result == AuthResult::Success {
            // Unlock with the stored salt, upgrading a legacy KDF iteration
            // count in place (see derive_verified_master_key).
            let master_key = self
                .derive_verified_master_key(&mut user_auth, master_password)
                .await?;
            self.unlock_with_master_key(&master_key)?;
            self.current_user = Some(user_auth.user_id);
            self.touch_activity();

            // Create and register a session for auto-lock management. Previously only the
            // low-level authenticate primitive created sessions, while every production login went
            // through this method — no session was ever established, so auto-lock monitoring and
            // the Locked event's forced lock were completely inert on the normal login path.
            let mut session = Session::new(user_auth.user_id.to_string(), self.auto_lock_timeout);
            // Login/re-auth is itself a sensitive verification: record sensitive activity. Otherwise,
            // once require_reauth_sensitive is on, a freshly logged-in user is gated on the very
            // first sensitive operation — and the sensitive timer can only be refreshed by a
            // successful sensitive operation, so this deadlocks.
            session.touch_sensitive();
            let session_id = session.id.clone();
            *self.current_session_id.write().await = Some(session_id.clone());
            self.auto_lock_manager
                .add_session(session)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            self.auto_lock_manager
                .set_current_user(user_auth.user_id)
                .await;

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

    /// Low-level primitive: establish the session encryption service directly from a master key
    /// (skipping password derivation).
    ///
    /// Consumer: hardware-bound biometric unlock (the `biometric_wrap` module recovers the master
    /// key and then takes this path). Production code must not use this as a bypass around
    /// password unlock — the caller is responsible for guaranteeing the key came from an
    /// authenticated source (hardware ceremony / password derivation).
    pub fn unlock_with_master_key(&mut self, master_key: &[u8; 32]) -> Result<()> {
        self.master_encryption = Some(crate::crypto::EncryptionService::new(master_key));
        *self.last_activity.lock().unwrap() = Some(std::time::Instant::now());
        Ok(())
    }

    /// Derive the current user's master key (for hardware-bound biometric enable to re-export the
    /// key and hand it to the wrapping layer right after the password was verified). A wrong
    /// password derives a wrong key — the caller must go through `authenticate_user` first.
    pub async fn derive_master_key_for_wrap(&self, master_password: &str) -> Result<[u8; 32]> {
        let Some(user_auth) = self.user_auth_repo.get_first().await? else {
            return Err(crate::PersonaError::NotFound("no user initialized".to_string()).into());
        };
        // Derive at the *stored* iteration count: vaults not yet lazily
        // upgraded still hold their item keys wrapped by the legacy count, so
        // a wrap produced at the floor would not match what unlock decrypts.
        Ok(self.master_key_service.derive_master_key_with_iterations(
            master_password,
            &user_auth.get_master_key_salt()?,
            user_auth.kdf_iterations,
        ))
    }

    /// Authenticate with a master key (the service-layer entry for hardware-bound biometric unlock).
    ///
    /// Semantically aligned with [`Self::authenticate_user`], except the "password verification"
    /// step becomes "the caller has already completed hardware authentication": a locked account
    /// is still refused (biometrics do not bypass the 5-failure lockout), the
    /// `password_change_required` forced-rotation flag still short-circuits, failed attempts are
    /// reset, a session is created + `touch_sensitive` is called, and Login is audited (details
    /// carry `source`; desktop passes "biometric-wrap").
    pub async fn authenticate_with_master_key(
        &mut self,
        master_key: &[u8; 32],
        source: &str,
    ) -> Result<AuthResult> {
        let Some(mut user_auth) = self.user_auth_repo.get_first().await? else {
            return Ok(AuthResult::InvalidCredentials);
        };

        // Expiry policy first, then the flag short-circuits: same order and semantics as authenticate_password
        self.enforce_password_expiry(&mut user_auth).await?;
        if user_auth.is_locked() {
            return Ok(AuthResult::AccountLocked);
        }
        if user_auth.password_change_required {
            return Ok(AuthResult::PasswordChangeRequired);
        }

        user_auth.reset_failed_attempts();
        self.user_auth_repo.update(&user_auth).await?;

        self.unlock_with_master_key(master_key)?;
        self.current_user = Some(user_auth.user_id);
        self.touch_activity();

        let mut session = Session::new(user_auth.user_id.to_string(), self.auto_lock_timeout);
        session.touch_sensitive();
        let session_id = session.id.clone();
        *self.current_session_id.write().await = Some(session_id.clone());
        self.auto_lock_manager
            .add_session(session)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        self.auto_lock_manager
            .set_current_user(user_auth.user_id)
            .await;

        self.log_audit_with_metadata(
            AuditAction::Login,
            ResourceType::User,
            true,
            None,
            None,
            None,
            Some(("via", source.to_string())),
        )
        .await;

        Ok(AuthResult::Success)
    }

    /// Change the workspace master password (rotation).
    ///
    /// Verifies `old_password` directly against the stored argon2 hash —
    /// deliberately NOT via [`Self::authenticate_user`], whose
    /// `password_change_required` short-circuit would reject the very
    /// password the forced-rotation flow just collected.
    ///
    /// All key-derivation CPU work (argon2 verify + PBKDF2 old/new master
    /// keys + argon2 hash of the new password) happens before the
    /// transaction; the transaction only re-wraps item keys, re-encrypts
    /// legacy rows and updates `user_auth`, so a crash mid-rotation rolls
    /// back to the old password entirely.
    pub async fn change_master_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Refuse a password change while travel mode is active: the wrapped_item_key of identities
        // removed into the sidecar is wrapped by the old master key, and a change only re-wraps the
        // live rows in the database -> the data bricks on restore.
        // PersonaService does not know the db path, so read the first workspaces row's settings
        // right now (consistent with the "first row is the truth" precedent of user_auth_repo.get_first()).
        #[cfg(feature = "backup")]
        if self.travel_mode_active().await? {
            return Err(PersonaError::TravelModeActive(
                "Exit travel mode before changing the master password".to_string(),
            )
            .into());
        }

        if new_password.is_empty() {
            return Err(PersonaError::AuthenticationFailed(
                "New master password must not be empty".to_string(),
            )
            .into());
        }
        if old_password == new_password {
            return Err(PersonaError::AuthenticationFailed(
                "New master password must differ from the current one".to_string(),
            )
            .into());
        }

        let mut user_auth = self.user_auth_repo.get_first().await?.ok_or_else(|| {
            PersonaError::AuthenticationFailed(
                "Workspace not initialized. Run `persona init` first.".to_string(),
            )
        })?;

        // Respect lockout: rotation must not become a lockout bypass oracle.
        if user_auth.is_locked() {
            return Err(PersonaError::AuthenticationFailed(
                "Account is locked due to too many failed attempts".to_string(),
            )
            .into());
        }

        // Verify the old password (argon2), bypassing the change-required
        // short-circuit on purpose.
        if !user_auth.verify_master_password(old_password)? {
            user_auth.add_failed_attempt();
            self.user_auth_repo.update(&user_auth).await?;
            return Err(PersonaError::AuthenticationFailed(
                "Invalid current master password".to_string(),
            )
            .into());
        }

        // Salt is stable across password changes by design. The old key is
        // derived at the *stored* iteration count — vaults that have not been
        // lazily upgraded yet still hold item keys wrapped by the legacy count.
        let salt = user_auth.get_master_key_salt()?;
        let old_enc = self
            .master_key_service
            .create_encryption_service_with_iterations(
                old_password,
                &salt,
                user_auth.kdf_iterations,
            );
        let new_enc = self
            .master_key_service
            .create_encryption_service(new_password, &salt);
        // Re-hashes, stamps password_updated_at, clears password_change_required.
        user_auth.set_master_password(new_password)?;
        user_auth.failed_attempts = 0;
        // Rotation re-wraps under a key derived at the current floor, so record
        // it — even for a vault that had never been lazily upgraded yet.
        user_auth.kdf_iterations = MASTER_KEY_PBKDF2_ITERATIONS;

        self.rewrap_all_item_keys(&old_enc, &new_enc, &user_auth)
            .await?;

        // Swap the in-memory master key only on the unlocked "change from
        // settings" path; on the locked/unlock-screen path master_encryption
        // is None and the host re-runs `authenticate_user` with the new
        // password, which unlocks + audits login properly.
        if self.master_encryption.is_some() {
            self.master_encryption = Some(new_enc);
        }

        self.log_audit(
            AuditAction::PasswordChange,
            ResourceType::User,
            true,
            None,
            None,
            None,
        )
        .await;
        Ok(())
    }
}
