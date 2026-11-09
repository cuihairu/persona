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

    /// 注入/移除审计事件上报器（`None` 关闭上报）。调用方负责 emitter 的
    /// `start()`/`stop()` 生命周期；`log_audit` 只做同步入队，绝不阻塞。
    ///
    /// 同步传播给 [`AutoLockManager`]——它的 SessionLocked/Unlocked 审计
    /// 写库后走同一上报链；宿主只跟 service 打交道，无需单独接线。
    pub fn set_event_emitter(&mut self, emitter: Option<Emitter>) {
        self.event_emitter = emitter.clone();
        self.auto_lock_manager.set_event_emitter(emitter);
    }

    /// 注入同步捕获缝（E2EE_SYNC_DESIGN §5）。装配层（宿主/集成测试）在
    /// 解锁后调用：service 把条目级写变更交给实现方，由它包 group 信封并
    /// 记入 oplog。`None` = 未启用同步，写路径零开销跳过。
    ///
    /// 不需要 `&mut`：捕获缝是运行期可换的运行态附件，与
    /// [`Self::set_event_emitter`] 的生命周期不同（后者构造期注入即可）。
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
        // 同步进管理器（含 require_reauth_sensitive / sensitive_operation_timeout_secs）：
        // 管理器不能重建——重建会丢掉在管 session、后台任务与回调，所以
        // 之前只更新了超时副本，命令层的敏感操作再认证开关从未生效。
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

    /// Connect token 面的敏感活动刷新（connect-server 鉴权中间件每请求调用）。
    ///
    /// scoped token 即再认证：刷新敏感与活动计时、解除敏感超时锁
    /// （[`AutoLockManager::refresh_sensitive`]，无 force-lock 判定）。
    /// 无会话时为 no-op——机会性刷新，不改变任何拒绝语义。没有它，无人值守
    /// serve 在登录 5 分钟后的首个读密文请求会撞 `force_lock_sensitive` 锁
    /// 且 token 面无再认证入口（实测 500）。
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
            // 专用错误变体：客户端（桌面/CLI）据此弹出重新认证流程，
            // 与普通认证失败区分开。
            return Err(PersonaError::ReauthRequired(
                "Re-authentication required for sensitive operation".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// 统一授权入口（本地会话数据面）。纯策略裁决走 [`authz::authorize`]：
    /// Denied 立即失败；Export 的 `InteractionRequired` 由调用边履约
    /// （CLI 确认/桌面对话框），core 侧不重复弹窗。随后状态性门禁照旧
    /// 把守会话锁/自动锁/敏感重认证——机制层不变，只是判定词汇统一。
    ///
    /// 管理面操作（token 创建/吊销、旅行模式进出）保持既有敏感门禁，
    /// 不引入数据面动词（写动词未拍板，见 authz 模块注释）。
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

    /// 主密钥加密服务（sync_now 等宿主编排需要：backfill/run_cycle 要
    /// unwrap item key）。锁未解时 Err。
    pub fn get_master_encryption_service(&self) -> Result<&EncryptionService> {
        self.master_encryption.as_ref().ok_or_else(|| {
            PersonaError::AuthenticationFailed("Service is locked".to_string()).into()
        })
    }
}
