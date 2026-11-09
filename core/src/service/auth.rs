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

    /// Opt-in master-password expiry policy（`WorkspaceSettings
    /// .password_expiry_days`），lazy 求值：解锁时对比
    /// `password_updated_at`，超期则置位 `password_change_required`，
    /// 随后 `authenticate_password` 按既有语义返回 `PasswordChangeRequired`。
    ///
    /// fail-open：设置读取失败只 warn 跳过，绝不因策略读取出错锁死解锁；
    /// 时间戳缺失同样跳过（迁移已回填，防御性兜底）。
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

    /// 读取主密码过期天数；读不到或读取失败一律返回 None（fail-open）。
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

    /// 旅行模式是否激活。消费方：改密拦截（旅行模式下改密会让 sidecar
    /// 里的 wrapped key 变砖，settings 读不出来时宁可拒绝改密也不冒险
    /// 放行，fail-closed）与 sync_now 的 travel 闸采样。只读 settings
    /// 布尔，不依赖 travel 模块本体，故不挂 feature 门控。
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

            // Create and register session for auto-lock management. 之前只有
            // 底层 authenticate 原语建 session，而生产登录全部走本方法——
            // session 从未建立，auto-lock 监控与 Locked 事件强制落锁对
            // 正常登录路径完全失效。
            let mut session = Session::new(user_auth.user_id.to_string(), self.auto_lock_timeout);
            // 登录/再认证本身就是一次敏感验证：记录敏感活动，否则打开
            // require_reauth_sensitive 后，刚登录的用户连第一个敏感操作都
            // 会被闸——而敏感计时器只能由成功的敏感操作刷新，形成死锁。
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

    /// 低层原语：直接用主密钥建立会话加密服务（跳过密码派生）。
    ///
    /// 消费方：硬件绑定的生物识别解锁（`biometric_wrap` 模块解出主密钥
    /// 后走此路径）。生产代码不要拿它当密码解锁的旁路——调用方必须
    /// 自己保证密钥来源经过了认证（硬件 ceremony / 密码派生）。
    pub fn unlock_with_master_key(&mut self, master_key: &[u8; 32]) -> Result<()> {
        self.master_encryption = Some(crate::crypto::EncryptionService::new(master_key));
        *self.last_activity.lock().unwrap() = Some(std::time::Instant::now());
        Ok(())
    }

    /// 派生当前用户的主密钥（供硬件绑定的 biometric enable 在密码刚
    /// 验证过后重导出密钥交给包裹层）。密码不对会派生出错误密钥——
    /// 调用方必须先走 `authenticate_user`。
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

    /// 用主密钥认证（硬件绑定生物识别解锁的服务层入口）。
    ///
    /// 与 [`Self::authenticate_user`] 语义对齐，只把"密码验证"一步换成
    /// "调用方已完成硬件认证"：锁户仍然拒绝（生物识别不越过 5 次失败
    /// 锁户）、`password_change_required` 强制改密旗标仍然短路、失败计数
    /// 复位、session 创建 + `touch_sensitive`、审计 Login（details 记
    /// `source`，桌面传 "biometric-wrap"）。
    pub async fn authenticate_with_master_key(
        &mut self,
        master_key: &[u8; 32],
        source: &str,
    ) -> Result<AuthResult> {
        let Some(mut user_auth) = self.user_auth_repo.get_first().await? else {
            return Ok(AuthResult::InvalidCredentials);
        };

        // 过期策略先行 + 旗标短路：与 authenticate_password 同序同语义
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
        // 旅行模式开启期间拒绝改密：sidecar 里被移除身份的 wrapped_item_key
        // 由旧主密钥包裹，改密只重包库内存活行 → 恢复后数据变砖。
        // PersonaService 不知道 db 路径，现读 workspaces 首行 settings
        //（与 user_auth_repo.get_first() 的"首行即真相"先例一致）。
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
