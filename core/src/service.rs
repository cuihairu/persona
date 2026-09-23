#[cfg(feature = "backup")]
use crate::travel::{TravelCounts, TravelStatus};
use crate::{
    auth::{
        AuthResult, AuthService, AutoLockEvent, AutoLockManager, BiometricPlatform,
        BiometricPrompt, BiometricProvider, MasterKeyService, MockBiometricProvider,
        MockRemoteAuthProvider, RemoteAuthChallenge, RemoteAuthProvider, RemoteAuthResult, Session,
        UserAuth,
    },
    breach::BreachChecker,
    connect::{ConnectItemType, ConnectTokenRow, ConnectTokenScope, ConnectVerb},
    crypto::{
        assert_passkey, random_bytes32, register_passkey, self_test_client_data, verify_assertion,
        EncryptionService, KeyHierarchy, Sha256Hasher,
    },
    events::Emitter,
    health::{HealthIssue, HealthIssueKind, HealthReport, HealthScanConfig},
    models::{
        Attachment, AttachmentStats, AuditAction, AuditLog, ChangeHistory, ChangeHistoryQuery,
        ChangeHistoryStats, ChangeType, Credential, CredentialData, CredentialType, EntityType,
        FaviconCacheEntry, Identity, IdentityType, PasskeyItem, ResourceType, SecurityLevel,
        MAX_HOSTS_PER_REQUEST,
    },
    password::{PasswordGenerator, PasswordGeneratorOptions},
    storage::{
        AttachmentManager, AttachmentRepository, AuditLogRepository, AuditLogStatistics, BlobStore,
        ChangeHistoryRepository, ConnectTokenRepository, CredentialRepository, Database,
        FaviconRepository, IdentityRepository, PasskeyRepository, Repository, UserAuthRepository,
        WorkspaceRepository, SECURITY_SENSITIVE_AUDIT_ACTIONS,
    },
    sync::capture::SyncCapture,
    sync::oplog::{ItemKind, OpType},
    sync::snapshot::SyncItemSnapshot,
    PersonaError, Result,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use sqlx::Row;

/// 审计日志查询条件。
///
/// 所有条件按 AND 组合：服务层先用最具选择性的数据库查询取数，
/// 再对剩余条件做内存过滤，`limit` 最后截断。
#[derive(Debug, Clone, Default)]
pub struct AuditLogQuery {
    pub user_id: Option<String>,
    pub identity_id: Option<Uuid>,
    pub action: Option<AuditAction>,
    pub failures_only: bool,
    pub security_sensitive_only: bool,
    pub time_range: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
    /// 最多返回条数（按时间降序取前 N 条）
    pub limit: Option<usize>,
}

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
    /// favicon 缓存仓储（非 feature 门控：只依赖 sqlx；抓取才要 `favicon`）
    favicon_repo: FaviconRepository,
    /// workspace 设置仓储（读取密码过期策略等全局配置）
    workspace_repo: WorkspaceRepository,
    /// 数据库句柄（改主密码等跨表事务需要直接开事务）
    db: Database,
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
    /// 可选审计事件上报器（`events::Emitter`；`set_event_emitter` 注入）
    event_emitter: Option<Emitter>,
    /// Connect token 审计/last_used 落库节流标记（key = token id 或指纹前缀，
    /// 值 = 窗口起点）。内存态、进程重启即清——语义是防刷屏/批量写，
    /// 不是访问限额（限额属宿主层 HTTP 面）。
    connect_audit_marks: Mutex<HashMap<String, Instant>>,
    /// 同步捕获缝（E2EE_SYNC_DESIGN §5）。`None` = 未启用同步，写路径
    /// 直接跳过（与 `attachment_manager` 同款可选组件模式）。
    sync_capture: RwLock<Option<Arc<dyn SyncCapture>>>,
}

/// RFC3339 serialization for user_auth timestamps written via raw SQL
/// (mirrors the private helper in `storage::user_auth`).
fn system_time_to_rfc3339_opt(time: Option<SystemTime>) -> Option<String> {
    time.map(|t| {
        let datetime: chrono::DateTime<chrono::Utc> = t.into();
        datetime.to_rfc3339()
    })
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
            // 专用错误变体：客户端（桌面/CLI）据此弹出重新认证流程，
            // 与普通认证失败区分开。
            return Err(PersonaError::ReauthRequired(
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

        let (envelope, item_key) = hierarchy.encrypt_with_new_item_key_revealed(&plaintext)?;

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
        self.record_credential_history(ChangeType::Created, None, Some(&created), None)
            .await;
        // 同步载荷 = 完整条目快照（元数据 + CredentialData）的密封——与
        // 主库 `encrypted_data` 同一把 item key、两份不同密文（见
        // `sync::snapshot` 模块文档）。密封失败只跳过捕获，不影响主库写入。
        match SyncItemSnapshot::from_credential(&created, credential_data).seal(&item_key) {
            Ok(sealed) => {
                self.capture_sync(
                    created.id,
                    ItemKind::Credential,
                    OpType::Put,
                    Some(sealed),
                    Some(item_key),
                )
                .await;
            }
            Err(e) => tracing::warn!(
                credential_id = %created.id,
                error = %e,
                "sync snapshot seal failed; capture skipped"
            ),
        }
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

    /// 按需抓取凭据 URL 对应站点的 favicon 并入缓存（`favicon` feature）。
    ///
    /// 唯一的外联触发点：由用户在详情面板点击 "Fetch icon" 经命令层调用，
    /// 绝不自动批量抓取。缓存按 host 命中即返，不重复外联。
    /// 不做 audit log——favicon 是公开数据，日志只记 host。
    #[cfg(feature = "favicon")]
    pub async fn fetch_favicon_for_credential(
        &self,
        credential_id: &Uuid,
        fetcher: &crate::favicon::FaviconFetcher,
    ) -> Result<FaviconCacheEntry> {
        use crate::favicon::extract_favicon_host;

        self.ensure_unlocked()?;
        self.touch_activity();

        let credential = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;

        let url = credential
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| PersonaError::InvalidInput("credential has no url".to_string()))?;

        let host = extract_favicon_host(url)?;

        // 缓存命中即返：缓存 miss 是抓取的必要条件
        if let Some(entry) = self.favicon_repo.get(&host).await? {
            return Ok(entry);
        }

        let blob = fetcher.fetch(&host).await?;
        self.favicon_repo
            .upsert(&host, &blob.mime_type, &blob.data)
            .await?;

        let entry =
            self.favicon_repo.get(&host).await?.ok_or_else(|| {
                PersonaError::Database("favicon upsert did not persist".to_string())
            })?;
        tracing::info!(host = %host, "favicon fetched and cached");
        Ok(entry)
    }

    /// 批量读取已缓存的 favicon（纯本地读，绝不外联）。
    ///
    /// hosts 大小写不敏感去重后逐 host 点查；只返回命中项，调用方以
    /// "缺席 = 无缓存"处理，本方法永远不会触发抓取。
    pub async fn get_cached_favicons(&self, hosts: &[String]) -> Result<Vec<FaviconCacheEntry>> {
        self.ensure_unlocked()?;
        self.touch_activity();

        if hosts.len() > MAX_HOSTS_PER_REQUEST {
            return Err(PersonaError::InvalidInput(format!(
                "too many hosts requested: {} > {MAX_HOSTS_PER_REQUEST}",
                hosts.len()
            ))
            .into());
        }

        let unique: Vec<String> = hosts
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        self.favicon_repo.get_many(&unique).await
    }

    /// Decrypt and get credential data
    pub async fn get_credential_data(
        &self,
        credential_id: &Uuid,
    ) -> Result<Option<CredentialData>> {
        self.ensure_sensitive_operation_allowed().await?;
        self.touch_activity();

        let credential = match self.credential_repo.find_by_id(credential_id).await? {
            Some(cred) => cred,
            None => return Ok(None),
        };

        // Mark as accessed
        let mut credential = credential;
        credential.mark_accessed();
        self.credential_repo.update(&credential).await?;

        let credential_data = self.decrypt_credential(&credential)?;
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

    /// Decrypt a credential's payload without side effects (no access-time
    /// update, no per-credential audit entry, no re-auth gate).
    ///
    /// The gated path is [`Self::get_credential_data`]; batch operations
    /// (health scan) use this one and record a single aggregate audit entry
    /// instead.
    fn decrypt_credential(&self, credential: &Credential) -> Result<CredentialData> {
        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);

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
        Ok(credential_data)
    }

    /// Run a Watchtower-style vault health scan (offline rules only).
    ///
    /// See [`Self::scan_health_with`] for the breach-check-enabled variant.
    pub async fn scan_health(&self, config: HealthScanConfig) -> Result<HealthReport> {
        self.scan_health_with(config, None).await
    }

    /// Run a Watchtower-style vault health scan.
    ///
    /// Decrypts every credential in memory, evaluates the offline rules
    /// (weak/reused secrets, expiries, staleness) and — when a
    /// [`BreachChecker`] is supplied — the breach rule. The checker works on
    /// SHA-1 digests only; plaintext secrets never reach it, and nothing
    /// leaves the call frame. A checker failure downgrades to a warning and
    /// the offline rules still report. One aggregate
    /// `SecurityScanPerformed` audit entry is written (`breach_status`:
    /// `skipped` / `completed` / `unavailable`).
    pub async fn scan_health_with(
        &self,
        config: HealthScanConfig,
        breach: Option<&dyn BreachChecker>,
    ) -> Result<HealthReport> {
        self.ensure_unlocked_with_auto_lock().await?;

        let credentials = self.credential_repo.find_all().await?;
        let now = chrono::Utc::now();

        // Secret material collected for the weak/reuse rules; dropped when
        // the scan frame ends.
        let mut secrets_by_password: HashMap<String, Vec<Uuid>> = HashMap::new();
        // credential_id → (name, type) so issues can be attributed later
        // without holding decrypted data.
        let mut secrets: HashMap<Uuid, (String, String, String)> = HashMap::new();
        // 2FA-available rule inputs: Password credentials carrying a site
        // URL, and the site keys already covered by TOTP-like credentials.
        let mut login_urls: Vec<(Uuid, String, String, String)> = Vec::new();
        let mut totp_sites: std::collections::HashSet<String> = std::collections::HashSet::new();

        let mut issues: Vec<HealthIssue> = Vec::new();
        let mut push_issue = |credential: &Credential, kind: HealthIssueKind| {
            issues.push(HealthIssue {
                credential_id: credential.id,
                credential_name: credential.name.clone(),
                credential_type: credential.credential_type.to_string(),
                severity: kind.severity(),
                detail: kind.detail(),
                kind,
            });
        };

        for credential in &credentials {
            if !credential.is_active {
                continue;
            }

            // Expiry rules (no decryption needed)
            let data = match self.decrypt_credential(credential) {
                Ok(data) => data,
                // A credential that fails to decrypt is reported but must
                // not abort the whole scan.
                Err(e) => {
                    tracing::warn!("health scan: failed to decrypt {}: {e}", credential.id);
                    continue;
                }
            };

            match &data {
                CredentialData::ApiKey(api) => {
                    if let Some(expires_at) = api.expires_at {
                        if let Some(kind) =
                            crate::health::check_expiry(expires_at, now, config.expiry_warning_days)
                        {
                            push_issue(credential, kind);
                        }
                    }
                }
                CredentialData::BankCard(card) => {
                    if let Some(kind) = crate::health::check_bank_card_expiry(
                        &card.expiry_date,
                        now,
                        config.expiry_warning_days,
                    ) {
                        push_issue(credential, kind);
                    }
                }
                CredentialData::SoftwareLicense(lic) => {
                    // `valid_until` is free text; unparseable values are
                    // skipped (data quality, not a security finding).
                    if let Some(valid_until) = &lic.valid_until {
                        if let Some(kind) = crate::health::check_text_expiry(
                            valid_until,
                            now,
                            config.expiry_warning_days,
                        ) {
                            push_issue(credential, kind);
                        }
                    }
                }
                _ => {}
            }

            // 2FA-available rule inputs: which logins have a site URL, and
            // which sites already have a TOTP-like credential.
            match &data {
                CredentialData::TwoFactor(_) | CredentialData::GameToken(_) => {
                    if let Some(site) = credential
                        .url
                        .as_deref()
                        .and_then(crate::health::normalize_site_key)
                    {
                        totp_sites.insert(site);
                    }
                }
                CredentialData::Password(_) => {
                    if let Some(url) = credential.url.as_deref() {
                        if crate::health::normalize_site_key(url).is_some() {
                            login_urls.push((
                                credential.id,
                                credential.name.clone(),
                                credential.credential_type.to_string(),
                                url.to_string(),
                            ));
                        }
                    }
                }
                _ => {}
            }

            // Staleness rule (metadata only)
            if let Some(kind) =
                crate::health::check_stale(credential.updated_at, now, config.stale_after_days)
            {
                push_issue(credential, kind);
            }

            // Secret strength + reuse rules
            let secret: Option<&str> = match &data {
                CredentialData::Password(p) => Some(p.password.as_str()),
                CredentialData::ServerConfig(s) => s.password.as_deref(),
                CredentialData::SshKey(k) => k.passphrase.as_deref(),
                _ => None,
            };
            if let Some(secret) = secret {
                let (score, _suggestions) = crate::health::evaluate_password_strength(secret);
                if score < config.min_password_score {
                    push_issue(credential, HealthIssueKind::WeakPassword { score });
                }
                secrets_by_password
                    .entry(secret.to_string())
                    .or_default()
                    .push(credential.id);
                secrets.insert(
                    credential.id,
                    (
                        credential.name.clone(),
                        credential.credential_type.to_string(),
                        String::new(),
                    ),
                );
            }
        }

        // 2FA-available rule (1Password Watchtower "2FA available"):
        // directory sites with no TOTP-like credential covering them.
        for (credential_id, name, credential_type, url) in &login_urls {
            if let Some(site) = crate::health::check_two_factor_available(url, &totp_sites) {
                let kind = HealthIssueKind::TwoFactorAvailable { site };
                issues.push(HealthIssue {
                    credential_id: *credential_id,
                    credential_name: name.clone(),
                    credential_type: credential_type.clone(),
                    severity: kind.severity(),
                    detail: kind.detail(),
                    kind,
                });
            }
        }

        // Reuse rule: one issue per credential in any shared group.
        for group in crate::health::find_reused_groups(&secrets_by_password) {
            let group_size = group.len();
            for credential_id in group {
                let (name, credential_type, _) = secrets[&credential_id].clone();
                let kind = HealthIssueKind::ReusedPassword { group_size };
                issues.push(HealthIssue {
                    credential_id,
                    credential_name: name,
                    credential_type,
                    severity: kind.severity(),
                    detail: kind.detail(),
                    kind,
                });
            }
        }

        // Breach rule: consult the corpus through SHA-1 digests only.
        // Failure is not fatal — the offline rules above already reported.
        let (breach_status, breach_checked): (&str, usize) = match breach {
            None => ("skipped", 0),
            Some(checker) => {
                // One digest per distinct secret; duplicate digests (hash
                // collisions) are harmless — the checker dedupes by prefix.
                let digest_of: HashMap<&String, String> = secrets_by_password
                    .keys()
                    .map(|secret| (secret, crate::breach::sha1_hex_upper(secret)))
                    .collect();
                let digests: Vec<String> = digest_of.values().cloned().collect();
                match checker.breach_counts(&digests).await {
                    Ok(counts) => {
                        for (secret, credential_ids) in &secrets_by_password {
                            let count = counts.get(&digest_of[secret]).copied().unwrap_or(0);
                            if count == 0 {
                                continue;
                            }
                            let kind = HealthIssueKind::BreachedPassword { count };
                            for credential_id in credential_ids {
                                let (name, credential_type, _) = secrets[credential_id].clone();
                                issues.push(HealthIssue {
                                    credential_id: *credential_id,
                                    credential_name: name,
                                    credential_type,
                                    severity: kind.severity(),
                                    detail: kind.detail(),
                                    kind: kind.clone(),
                                });
                            }
                        }
                        ("completed", digests.len())
                    }
                    Err(e) => {
                        tracing::warn!("health scan: breach check unavailable: {e}");
                        ("unavailable", 0)
                    }
                }
            }
        };

        let report = HealthReport::finalize(now, credentials.len(), issues);

        // One aggregate audit entry; the report itself is not persisted and
        // contains no secret material.
        let audit = AuditLog::new(
            AuditAction::SecurityScanPerformed,
            ResourceType::System,
            true,
        )
        .with_metadata(
            "total_credentials".to_string(),
            report.total_credentials.to_string(),
        )
        .with_metadata("issue_count".to_string(), report.issues.len().to_string())
        .with_metadata("breach_checked".to_string(), breach_checked.to_string())
        .with_metadata("breach_status".to_string(), breach_status.to_string());
        let _ = self.audit_repo.create(&audit).await;

        Ok(report)
    }

    /// Update a credential
    pub async fn update_credential(&self, credential: &Credential) -> Result<Credential> {
        self.ensure_unlocked()?;
        self.touch_activity();
        // Item history 需要变更前快照做字段级 diff
        let existing = self.credential_repo.find_by_id(&credential.id).await?;
        let updated = self.credential_repo.update(credential).await?;
        if let Some(old) = existing.as_ref() {
            self.record_credential_history(ChangeType::Updated, Some(old), Some(&updated), None)
                .await;
        }
        self.log_audit(
            AuditAction::CredentialUpdated,
            ResourceType::Credential,
            true,
            Some(updated.id),
            Some(updated.identity_id),
            None,
        )
        .await;
        // 元数据编辑同样进同步（快照含元数据全字段）；legacy 行由 helper
        // 判定跳过。
        if let Some((sealed, item_key)) = self.sync_put_payload_for(&updated).await {
            self.capture_sync(
                updated.id,
                ItemKind::Credential,
                OpType::Put,
                Some(sealed),
                Some(item_key),
            )
            .await;
        }
        Ok(updated)
    }

    /// Replace a credential's encrypted payload (edit secret data).
    ///
    /// Re-seals the new payload under the credential's **existing** item key —
    /// never a fresh one: attachments are sealed with that same key, so a new
    /// key would render them permanently undecryptable. The row's
    /// `wrapped_item_key` bytes are left untouched. Legacy rows (no wrapped
    /// key) are upgraded to a per-item key on edit, mirroring the attachment
    /// path. Gated like [`Self::get_credential_data`] (editing secret data is
    /// at least as sensitive as reading it) and recorded as an item-history
    /// `Updated` row plus an audit entry.
    pub async fn update_credential_data(
        &self,
        credential_id: &Uuid,
        credential_data: &CredentialData,
    ) -> Result<Credential> {
        self.ensure_sensitive_operation_allowed().await?;
        self.touch_activity();

        let mut credential = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;
        let existing = credential.clone();

        let plaintext = credential_data.to_bytes().map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to serialize credential data: {}", e))
        })?;
        let master_encryption = self.get_master_encryption_service()?;
        let hierarchy = KeyHierarchy::new(master_encryption);

        let (new_ciphertext, new_wrapped_key, sync_item_key) =
            match credential.wrapped_item_key.as_ref() {
                Some(wrapped) => {
                    // 复用原 item key 重封；wrapped key 字节不动（附件不变量）。
                    let item_key = hierarchy.unwrap_item_key(wrapped)?;
                    let ciphertext = hierarchy.encrypt_with_item_key(&item_key, &plaintext)?;
                    (ciphertext, None, Zeroizing::new(item_key))
                }
                None => {
                    // legacy 行（payload 直接用主密钥封存）：编辑时升级为 per-item
                    // key，与附件封存路径同一模式，改密轮换后不再依赖 legacy 解密。
                    let (envelope, item_key) =
                        hierarchy.encrypt_with_new_item_key_revealed(&plaintext)?;
                    (envelope.ciphertext, Some(envelope.wrapped_key), item_key)
                }
            };
        credential.encrypted_data = new_ciphertext;
        if let Some(wrapped) = new_wrapped_key {
            credential.wrapped_item_key = Some(wrapped);
            tracing::info!(credential_id = %credential.id, "legacy credential upgraded to per-item key on edit");
        }
        credential.touch();

        let updated = self.credential_repo.update(&credential).await?;
        self.record_credential_history(ChangeType::Updated, Some(&existing), Some(&updated), None)
            .await;
        // 同步载荷 = 完整条目快照的密封（与 create 同款；同一把 item key）。
        match SyncItemSnapshot::from_credential(&updated, credential_data).seal(&sync_item_key) {
            Ok(sealed) => {
                self.capture_sync(
                    updated.id,
                    ItemKind::Credential,
                    OpType::Put,
                    Some(sealed),
                    Some(sync_item_key),
                )
                .await;
            }
            Err(e) => tracing::warn!(
                credential_id = %updated.id,
                error = %e,
                "sync snapshot seal failed; capture skipped"
            ),
        }
        self.log_audit(
            AuditAction::CredentialUpdated,
            ResourceType::Credential,
            true,
            Some(updated.id),
            Some(updated.identity_id),
            None,
        )
        .await;
        self.update_sensitive_auto_lock_activity().await?;
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

        // Cascade-delete attachments: they are sealed under this credential's
        // item key, so orphaned blobs could never be decrypted again.
        if let Some(manager) = self.attachment_manager.as_ref() {
            let attachments = manager.list_for_credential(id).await?;
            for attachment in attachments {
                if let Err(e) = manager.delete(&attachment.id).await {
                    tracing::warn!(
                        attachment_id = %attachment.id,
                        error = %e,
                        "failed to delete attachment during credential deletion"
                    );
                }
            }
        }

        let ok = self.credential_repo.delete(id).await?;
        if ok {
            self.record_credential_history(ChangeType::Deleted, Some(&existing), None, None)
                .await;
            self.capture_sync(*id, ItemKind::Credential, OpType::Delete, None, None)
                .await;
        }
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

    /// Restore a credential's plaintext metadata to an earlier item-history version.
    ///
    /// Applies the `new_state` snapshot of `target_version` — the state after
    /// that version's change — over the live row's metadata fields (name, type,
    /// security level, username, url, notes, tags, favorite/active flags).
    ///
    /// The secret payload is **not** versioned: history snapshots are
    /// metadata-only by design (`encrypted_data` never enters a snapshot), so
    /// a restore never rolls back passwords or other `CredentialData` secrets —
    /// rotating a secret stays a forward-only action. Records a `Restored`
    /// item-history row (reason names the target version) plus an audit entry.
    /// Deletion rows carry no `new_state` and are not restorable.
    pub async fn restore_credential_version(
        &self,
        credential_id: &Uuid,
        target_version: u32,
    ) -> Result<Credential> {
        self.ensure_unlocked()?;
        self.touch_activity();
        let existing = self
            .credential_repo
            .find_by_id(credential_id)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!("credential {credential_id} not found"))
            })?;
        let row = self
            .change_history_repo
            .get_version(EntityType::Credential, credential_id, target_version)
            .await?
            .ok_or_else(|| {
                PersonaError::InvalidInput(format!(
                    "credential {credential_id} has no history version {target_version}"
                ))
            })?;
        let snapshot = row.new_state.as_ref().ok_or_else(|| {
            PersonaError::InvalidInput(format!(
                "history version {target_version} has no restorable state"
            ))
        })?;

        let mut restored = existing.clone();
        Self::apply_meta_snapshot(&mut restored, snapshot)?;
        restored.touch();
        let updated = self.credential_repo.update(&restored).await?;
        self.record_credential_history(
            ChangeType::Restored,
            Some(&existing),
            Some(&updated),
            Some(format!("restore to version {target_version}")),
        )
        .await;
        self.log_audit(
            AuditAction::CredentialRestored,
            ResourceType::Credential,
            true,
            Some(updated.id),
            Some(updated.identity_id),
            None,
        )
        .await;
        // 元数据回滚同样改变快照语义字段，进同步（同款 legacy 跳过）。
        if let Some((sealed, item_key)) = self.sync_put_payload_for(&updated).await {
            self.capture_sync(
                updated.id,
                ItemKind::Credential,
                OpType::Put,
                Some(sealed),
                Some(item_key),
            )
            .await;
        }
        Ok(updated)
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

    /// Search credentials by name / username / url
    pub async fn search_credentials(&self, query: &str) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.touch_activity();
        self.credential_repo.search_by_fields(query).await
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

    /// Query audit logs (descending by time). Requires the service to be unlocked.
    ///
    /// All conditions are AND-combined: the service layer first uses the most selective
    /// database query, then filters the remaining conditions in memory.
    pub async fn query_audit_logs(&self, query: AuditLogQuery) -> Result<Vec<AuditLog>> {
        self.ensure_unlocked_with_auto_lock().await?;

        let mut logs = if let Some(user_id) = query.user_id.clone() {
            self.audit_repo.find_by_user(&user_id).await?
        } else if let Some(identity_id) = query.identity_id {
            self.audit_repo.find_by_identity(&identity_id).await?
        } else if let Some(action) = query.action.clone() {
            self.audit_repo.find_by_action(&action).await?
        } else if query.failures_only {
            self.audit_repo.find_failures().await?
        } else if query.security_sensitive_only {
            self.audit_repo.find_security_sensitive().await?
        } else if let Some((start, end)) = query.time_range {
            self.audit_repo.find_by_time_range(start, end).await?
        } else {
            self.audit_repo.find_all().await?
        };

        logs.retain(|log| {
            query
                .user_id
                .as_ref()
                .is_none_or(|u| log.user_id.as_ref() == Some(u))
                && query
                    .identity_id
                    .is_none_or(|id| log.identity_id == Some(id))
                && query
                    .action
                    .as_ref()
                    .is_none_or(|a| log.action.to_string() == a.to_string())
                && (!query.failures_only || !log.success)
                && (!query.security_sensitive_only
                    || SECURITY_SENSITIVE_AUDIT_ACTIONS.contains(&log.action.to_string().as_str()))
        });

        if let Some((start, end)) = query.time_range {
            logs.retain(|log| log.timestamp >= start && log.timestamp <= end);
        }

        if let Some(limit) = query.limit {
            logs.truncate(limit);
        }

        Ok(logs)
    }

    /// Audit statistics (total count / failed operations / recent logins / active users)
    pub async fn audit_log_statistics(&self) -> Result<AuditLogStatistics> {
        self.ensure_unlocked_with_auto_lock().await?;
        self.audit_repo.get_statistics().await
    }

    /// Clean up audit logs older than the retention period, returning the number of deleted rows
    pub async fn cleanup_audit_logs(&self, retain_days: u32) -> Result<u64> {
        self.ensure_unlocked_with_auto_lock().await?;
        self.audit_repo.cleanup_old_logs(retain_days).await
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

    /// Opt-in master-password expiry policy（`WorkspaceSettings
    /// .password_expiry_days`），lazy 求值：解锁时对比
    /// `password_updated_at`，超期则置位 `password_change_required`，
    /// 随后 `authenticate_password` 按既有语义返回 `PasswordChangeRequired`。
    ///
    /// fail-open：设置读取失败只 warn 跳过，绝不因策略读取出错锁死解锁；
    /// 时间戳缺失同样跳过（迁移已回填，防御性兜底）。
    async fn enforce_password_expiry(&self, user_auth: &mut UserAuth) -> Result<()> {
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
    async fn load_password_expiry_days(&self) -> Result<Option<u32>> {
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

        // Opt-in expiry policy may flag rotation before the password check
        self.enforce_password_expiry(&mut user_auth).await?;

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

        // Salt is stable across password changes by design.
        let salt = user_auth.get_master_key_salt()?;
        let old_enc = self
            .master_key_service
            .create_encryption_service(old_password, &salt);
        let new_enc = self
            .master_key_service
            .create_encryption_service(new_password, &salt);
        // Re-hashes, stamps password_updated_at, clears password_change_required.
        user_auth.set_master_password(new_password)?;
        user_auth.failed_attempts = 0;

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

    // -----------------------------------------------------------------------
    // Connect 本机自动化端点（CONNECT_AUTOMATION_DESIGN 阶段 1）。框架无关：
    // HTTP 面（Host/Origin 三防线、限额、响应包络）在宿主层；本节提供
    // token 生命周期、每请求鉴权与数据面的 scope 过滤编排。token 明文只在
    // create 返回时出现一次，库里只有哈希 + 指纹；无效/吊销/越 scope 一律
    // None（404/403 同形由端点层落实，防探测）。
    // -----------------------------------------------------------------------

    /// Connect 审计与 last_used 落库节流窗口（同 key 每 60s 至多一次）。
    const CONNECT_THROTTLE: Duration = Duration::from_secs(60);

    /// 锁定门禁：Connect 数据面只在解锁会话内可用（DR-4；端点层把
    /// [`PersonaError::VaultLocked`] 映射为 503）。
    fn connect_gate(&self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PersonaError::VaultLocked(
                "connect endpoint requires an unlocked vault".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// 同 key 节流：窗口内已写过则 false，否则刷新窗口并放行。
    /// 内存态，进程重启即清——防刷屏/批量写，不是访问限额。
    fn connect_throttle_should_write(&self, key: &str) -> bool {
        let mut marks = self.connect_audit_marks.lock().unwrap();
        let now = Instant::now();
        match marks.get(key) {
            Some(t) if now.duration_since(*t) < Self::CONNECT_THROTTLE => false,
            _ => {
                marks.insert(key.to_string(), now);
                true
            }
        }
    }

    /// 创建 Connect token：返回 `(presented 明文, 库行)`——明文仅此一次
    /// 展示，调用方（桌面设置页/CLI）负责「关闭后无法再次查看」语义。
    /// 管理操作走敏感门禁（reauth）+ 解锁会话（DR-5）。
    pub async fn create_connect_token(
        &self,
        label: String,
        scope: ConnectTokenScope,
    ) -> Result<(String, ConnectTokenRow)> {
        self.ensure_sensitive_operation_allowed().await?;
        self.connect_gate()?;
        scope
            .validate()
            .map_err(|e| PersonaError::InvalidInput(format!("invalid connect scope: {e}")))
            .map_err(anyhow::Error::from)?;
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 128 {
            return Err(PersonaError::InvalidInput(
                "connect token label must be 1..=128 characters".to_string(),
            )
            .into());
        }

        let presented = crate::connect::generate_token();
        let hash = crate::connect::hash_token(&presented).ok_or_else(|| {
            PersonaError::CryptographicError("connect token hash failed".to_string())
        })?;
        let row = ConnectTokenRow {
            id: Uuid::new_v4(),
            label: label.to_string(),
            fingerprint: crate::connect::fingerprint_from_hash(&hash),
            hash,
            scope,
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
        };
        ConnectTokenRepository::new(self.db.clone())
            .insert(&row)
            .await?;

        self.log_audit(
            AuditAction::ConnectTokenCreated,
            ResourceType::Connect,
            true,
            Some(row.id),
            None,
            None,
        )
        .await;

        Ok((presented, row))
    }

    /// Token 管理列表（含已吊销，管理面展示吊销状态）。行含哈希——调用方
    /// 序列化时剥除（桌面/CLI 都只展示 label/指纹/scope/时间戳）。
    pub async fn list_connect_tokens(&self) -> Result<Vec<ConnectTokenRow>> {
        self.connect_gate()?;
        Ok(ConnectTokenRepository::new(self.db.clone())
            .list_all()
            .await?)
    }

    /// 吊销（幂等：重复吊销返回 false）。即时生效——鉴权每请求查表，
    /// 无缓存窗口（DR-2）。管理操作走敏感门禁（reauth）+ 解锁会话。
    pub async fn revoke_connect_token(&self, id: &Uuid) -> Result<bool> {
        self.ensure_sensitive_operation_allowed().await?;
        self.connect_gate()?;
        let revoked = ConnectTokenRepository::new(self.db.clone())
            .revoke(id, chrono::Utc::now())
            .await?;
        if revoked {
            self.log_audit(
                AuditAction::ConnectTokenRevoked,
                ResourceType::Connect,
                true,
                Some(*id),
                None,
                None,
            )
            .await;
        }
        Ok(revoked)
    }

    /// 每请求鉴权：呈现值 → SHA-256 → 查表 → 吊销判定。命中即节流落库
    /// `last_used_at` 并节流记审计（自动化轮询不刷屏）；未知/吊销 token
    /// 的尝试也节流记失败审计（指纹前缀做 key，可审计但不刷屏）。
    pub async fn connect_authenticate(&self, presented: &str) -> Result<Option<ConnectTokenRow>> {
        let Some(hash) = crate::connect::hash_token(presented) else {
            return Ok(None);
        };
        let repo = ConnectTokenRepository::new(self.db.clone());
        let Some(row) = repo.find_by_hash(&hash).await? else {
            let fp = crate::connect::fingerprint_from_hash(&hash);
            if self.connect_throttle_should_write(&format!("unknown:{fp}")) {
                self.log_audit(
                    AuditAction::ConnectTokenUsed,
                    ResourceType::Connect,
                    false,
                    None,
                    None,
                    Some(format!("unknown token {fp}")),
                )
                .await;
            }
            return Ok(None);
        };
        if row.revoked() {
            if self.connect_throttle_should_write(&format!("revoked:{}", row.id)) {
                self.log_audit(
                    AuditAction::ConnectTokenUsed,
                    ResourceType::Connect,
                    false,
                    Some(row.id),
                    None,
                    Some("revoked token".to_string()),
                )
                .await;
            }
            return Ok(None);
        }
        if self.connect_throttle_should_write(&format!("used:{}", row.id)) {
            repo.touch_last_used(&row.id, chrono::Utc::now()).await?;
            self.log_audit(
                AuditAction::ConnectTokenUsed,
                ResourceType::Connect,
                true,
                Some(row.id),
                None,
                None,
            )
            .await;
        }
        Ok(Some(row))
    }

    /// scope 内身份列表（id + 名称）。
    pub async fn connect_list_identities(
        &self,
        scope: &ConnectTokenScope,
    ) -> Result<Vec<Identity>> {
        self.connect_gate()?;
        if !scope.allows_verb(ConnectVerb::Read) {
            return Ok(vec![]);
        }
        let all = self.get_identities().await?;
        Ok(all
            .into_iter()
            .filter(|i| scope.allows_identity(&i.id))
            .collect())
    }

    /// scope 内条目元数据。`?identity=`/`?type=`/`?title=` 精确过滤；
    /// identity 参数越 scope 返回空列表（不报错，防探测）。
    pub async fn connect_list_items(
        &self,
        scope: &ConnectTokenScope,
        identity: Option<Uuid>,
        item_type: Option<ConnectItemType>,
        title: Option<String>,
    ) -> Result<Vec<Credential>> {
        self.connect_gate()?;
        if !scope.allows_verb(ConnectVerb::Read) {
            return Ok(vec![]);
        }
        if let Some(want) = &identity {
            if !scope.allows_identity(want) {
                return Ok(vec![]);
            }
        }
        let all = Repository::find_all(&self.credential_repo).await?;
        Ok(all
            .into_iter()
            .filter(|c| c.is_active)
            .filter(|c| identity.as_ref().is_none_or(|want| &c.identity_id == want))
            .filter(|c| scope.allows_identity(&c.identity_id))
            .filter(|c| scope.allows_credential_type(&c.credential_type))
            .filter(|c| {
                item_type.is_none_or(|want| {
                    ConnectItemType::from_credential_type(&c.credential_type) == Some(want)
                })
            })
            .filter(|c| title.as_ref().is_none_or(|t| &c.name == t))
            .collect())
    }

    /// 单条全字段（解密后）。scope 外/归档/不存在一律 `None`——端点层
    /// 统一映射 404（与 403 同形）。
    pub async fn connect_get_item_data(
        &self,
        scope: &ConnectTokenScope,
        id: &Uuid,
    ) -> Result<Option<(Credential, CredentialData)>> {
        self.connect_gate()?;
        if !scope.allows_verb(ConnectVerb::Read) {
            return Ok(None);
        }
        let Some(cred) = self.get_credential(id).await? else {
            return Ok(None);
        };
        if !cred.is_active
            || !scope.allows_identity(&cred.identity_id)
            || !scope.allows_credential_type(&cred.credential_type)
        {
            return Ok(None);
        }
        let Some(data) = self.get_credential_data(id).await? else {
            return Ok(None);
        };
        Ok(Some((cred, data)))
    }

    /// 当前 TOTP 码 + 剩余秒（复用 core RFC 6238 路径；scope 外/非
    /// TwoFactor 一律 `None`）。
    pub async fn connect_totp(
        &self,
        scope: &ConnectTokenScope,
        id: &Uuid,
    ) -> Result<Option<crate::crypto::totp::TotpCode>> {
        self.connect_gate()?;
        if !scope.allows_verb(ConnectVerb::Read) {
            return Ok(None);
        }
        let Some(cred) = self.get_credential(id).await? else {
            return Ok(None);
        };
        if !cred.is_active || !scope.allows_identity(&cred.identity_id) {
            return Ok(None);
        }
        if !scope.allows_credential_type(&CredentialType::TwoFactor) {
            return Ok(None);
        }
        let Some(data) = self.get_credential_data(id).await? else {
            return Ok(None);
        };
        let CredentialData::TwoFactor(tf) = data else {
            return Ok(None);
        };
        Ok(Some(crate::crypto::totp::totp_now(&tf)?))
    }

    // -----------------------------------------------------------------------
    // Travel Mode（旅行模式）。重量级逻辑（打包/加密/事务/文件 IO）在
    // crate::travel（cfg backup）；本节只做门禁、前置校验与审计编排。
    // sidecar 路径由调用方显式传 db_path——PersonaService 不知道库路径。
    // -----------------------------------------------------------------------

    /// 旅行模式状态。无门禁：旗标与 sidecar 存在性都不含秘密（锁屏界面
    /// 也要能提示"数据不在这台设备上"）。
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
            // 旗标说在旅行模式，但数据容器没了（被手删/损毁）：数据已丢，
            // 诚实呈现而非假装可恢复（见 travel.rs 模块注释崩溃窗口表）。
            inconsistent: active && !sidecar_exists,
        })
    }

    /// 标记/取消标记身份（enter 时随之整包移出本设备）。编辑元数据级
    /// 操作，与 update_identity 同门禁（不设敏感重认证——移动秘密的
    /// 门禁在 enter 这一步）。幂等：重复标记同一状态直接成功。
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

    /// 进入旅行模式：被标记身份全部数据打包加密进 sidecar 后从主库删除
    /// （真移除语义，主库零痕迹）。顺序即安全语义：先写 sidecar 再动库。
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
            // 崩溃窗口 1 的残留（sidecar 已写、事务未提交）：库与盘面
            // 不一致时不自动覆盖——由用户决定删残留还是直接 exit 恢复。
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
            // 事务失败（非崩溃）：回收 sidecar，盘面回到 enter 前状态
            let _ = std::fs::remove_file(&sidecar);
            return Err(e.into());
        }

        // 事务已提交：blob 文件删除 best-effort——失败项在 exit 时按
        // storage_path 原路径覆写自愈，不阻塞 enter 的成功。
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

    /// 退出旅行模式：sidecar 解密解包后原样恢复（行 id 与加密形态字节
    /// 不变），全部落地后删 sidecar。中途任何失败 sidecar 都保留，整条
    /// exit 可重试（恢复行与文件覆写均幂等）。
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

        // 行已恢复：blob 文件覆写。pack 带着附件却没有存储位就无法落
        // 字节——报配置错误而不是悄悄丢数据（行已插回，补上存储后重试）。
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
    async fn rewrap_all_item_keys(
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
                updated_at = ?
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
        .bind(user_auth.user_id.to_string())
        .execute(tx.as_mut())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        tx.commit().await.map_err(|e| {
            PersonaError::Database(format!("Failed to commit master password rotation: {e}"))
        })?;
        Ok(())
    }

    // ===== Attachment Management =====

    /// Resolve the per-item key an attachment should be sealed under.
    ///
    /// Legacy rows (`wrapped_item_key` NULL, payload sealed directly with the
    /// master key) are upgraded in place first: master-password rotation
    /// re-encrypts legacy rows but never touches attachment blobs, so sealing
    /// an attachment with the master key would break it on rotation. After
    /// the upgrade the payload sits under a fresh item key and both the
    /// credential and its attachments are rotation-safe.
    async fn credential_item_key_for_attachment(&self, credential_id: &Uuid) -> Result<[u8; 32]> {
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
            tracing::info!(credential_id = %credential.id, "legacy credential upgraded to per-item key for attachment sealing");
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
                    "Failed to unwrap item key for attachment sealing: {e}"
                ))
            })?;
        Ok(key)
    }

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

    /// Item history（1Password 对齐）：凭据变更快照，只含明文元数据字段。
    /// `encrypted_data` / `wrapped_item_key` 绝不进快照。
    fn credential_meta_snapshot(credential: &Credential) -> serde_json::Value {
        serde_json::json!({
            "name": credential.name,
            "credential_type": credential.credential_type.to_string(),
            "security_level": credential.security_level.to_string(),
            "username": credential.username,
            "url": credential.url,
            "notes": credential.notes,
            "tags": credential.tags,
            "is_favorite": credential.is_favorite,
            "is_active": credential.is_active,
        })
    }

    /// 把 [`Self::credential_meta_snapshot`] 写出的快照套回凭据元数据
    /// （restore-to-version 用）。整份校验通过后才落字段，坏快照不半套；
    /// 秘密字段（`encrypted_data` / `wrapped_item_key`）不在快照里，保持原样。
    fn apply_meta_snapshot(
        credential: &mut Credential,
        snapshot: &serde_json::Value,
    ) -> Result<()> {
        let obj = snapshot.as_object().ok_or_else(|| {
            PersonaError::InvalidInput("history snapshot is not an object".to_string())
        })?;
        let required_str = |key: &str| -> Result<String> {
            obj.get(key)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    PersonaError::InvalidInput(format!("history snapshot missing field {key}"))
                        .into()
                })
        };
        let optional_str = |key: &str| -> Option<String> {
            obj.get(key).and_then(|v| v.as_str()).map(str::to_string)
        };

        let name = required_str("name")?;
        let credential_type = required_str("credential_type")?
            .parse::<CredentialType>()
            .map_err(PersonaError::InvalidInput)?;
        let security_level = required_str("security_level")?
            .parse::<SecurityLevel>()
            .map_err(PersonaError::InvalidInput)?;
        let tags = match obj.get("tags") {
            Some(serde_json::Value::Array(items)) => {
                let mut tags = Vec::with_capacity(items.len());
                for item in items {
                    tags.push(item.as_str().map(str::to_string).ok_or_else(|| {
                        PersonaError::InvalidInput(
                            "history snapshot tag is not a string".to_string(),
                        )
                    })?);
                }
                tags
            }
            _ => {
                return Err(PersonaError::InvalidInput(
                    "history snapshot missing field tags".to_string(),
                )
                .into())
            }
        };
        let is_favorite = obj
            .get("is_favorite")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                PersonaError::InvalidInput("history snapshot missing field is_favorite".to_string())
            })?;
        let is_active = obj
            .get("is_active")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                PersonaError::InvalidInput("history snapshot missing field is_active".to_string())
            })?;

        credential.name = name;
        credential.credential_type = credential_type;
        credential.security_level = security_level;
        credential.username = optional_str("username");
        credential.url = optional_str("url");
        credential.notes = optional_str("notes");
        credential.tags = tags;
        credential.is_favorite = is_favorite;
        credential.is_active = is_active;
        Ok(())
    }

    /// 元数据字段级 diff；密文变化只记占位标记（历史里可见「密码已轮换」
    /// 这一事实，但永远看不到内容——与 1Password 的历史展示一致）。
    fn diff_credential_metadata(
        old: &Credential,
        new: &Credential,
    ) -> Vec<(&'static str, String, String)> {
        let mut changes = Vec::new();
        let mut push = |field: &'static str, o: String, n: String| {
            if o != n {
                changes.push((field, o, n));
            }
        };
        push("name", old.name.clone(), new.name.clone());
        push(
            "credential_type",
            old.credential_type.to_string(),
            new.credential_type.to_string(),
        );
        push(
            "security_level",
            old.security_level.to_string(),
            new.security_level.to_string(),
        );
        push(
            "username",
            old.username.clone().unwrap_or_default(),
            new.username.clone().unwrap_or_default(),
        );
        push(
            "url",
            old.url.clone().unwrap_or_default(),
            new.url.clone().unwrap_or_default(),
        );
        push(
            "notes",
            old.notes.clone().unwrap_or_default(),
            new.notes.clone().unwrap_or_default(),
        );
        push("tags", old.tags.join(","), new.tags.join(","));
        push(
            "is_favorite",
            old.is_favorite.to_string(),
            new.is_favorite.to_string(),
        );
        push(
            "is_active",
            old.is_active.to_string(),
            new.is_active.to_string(),
        );
        if old.encrypted_data != new.encrypted_data {
            changes.push((
                "encrypted_data",
                "<encrypted>".to_string(),
                "<encrypted>".to_string(),
            ));
        }
        changes
    }

    /// 把一次条目级写变更交给同步捕获缝（未装配即零开销跳过）。
    ///
    /// 容错语义与 [`Self::record_credential_history`] 一致：捕获是尽力而为
    /// 的旁路（trait 方法返回 `()`，实现方自行 log），service 侧不做任何
    /// 可失败的准备——主库才是第一事实源。
    async fn capture_sync(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    ) {
        let capture = self.sync_capture.read().await.clone();
        if let Some(capture) = capture {
            capture
                .capture(item_id, kind, op, ciphertext, item_key)
                .await;
        }
    }

    /// 为元数据级写变更（[`Self::update_credential`] / restore）构建同步
    /// put 载荷：解密现 payload 组装完整条目快照再密封。legacy 行（无
    /// per-item key）返回 `None`——它还不能与同步信封共享 item key，跳过
    /// 捕获；首次 [`Self::update_credential_data`] 会把它升级，此后恢复捕获。
    async fn sync_put_payload_for(
        &self,
        credential: &Credential,
    ) -> Option<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let data = self.decrypt_credential(credential).ok()?;
        let master_encryption = self.get_master_encryption_service().ok()?;
        let item_key = KeyHierarchy::new(master_encryption)
            .unwrap_item_key(credential.wrapped_item_key.as_ref()?)
            .ok()?;
        match SyncItemSnapshot::from_credential(credential, &data).seal(&item_key) {
            Ok(sealed) => Some((sealed, Zeroizing::new(item_key))),
            Err(e) => {
                tracing::warn!(
                    credential_id = %credential.id,
                    error = %e,
                    "sync snapshot seal failed; capture skipped"
                );
                None
            }
        }
    }

    /// 记一条凭据历史行（created/updated/deleted/restored 由 change_type 区分）。
    ///
    /// - Updated 且无实质字段变化时不记（CLI/桌面 create 后紧跟的元数据
    ///   补写不产生噪声行）
    /// - version 取该实体当前最大版本 +1
    /// - `reason` 可选（restore 用来标注目标版本）
    /// - 记录失败仅告警不阻断主操作（与 log_audit 的尽力而为一致）：
    ///   主写已提交，历史是派生数据，不能让历史失败回滚业务事实
    async fn record_credential_history(
        &self,
        change_type: ChangeType,
        previous: Option<&Credential>,
        current: Option<&Credential>,
        reason: Option<String>,
    ) {
        let entity_id = match (current, previous) {
            (Some(c), _) => c.id,
            (None, Some(p)) => p.id,
            (None, None) => return,
        };

        let mut entry = ChangeHistory::new(EntityType::Credential, entity_id, change_type);
        if let Some(user) = self.current_user {
            entry = entry.with_user(user.to_string());
        }
        if let Some(reason) = reason {
            entry = entry.with_reason(reason);
        }

        match (previous, current) {
            (Some(old), Some(new)) => {
                let changes = Self::diff_credential_metadata(old, new);
                if changes.is_empty() {
                    return;
                }
                entry = entry.with_states(
                    Some(Self::credential_meta_snapshot(old)),
                    Some(Self::credential_meta_snapshot(new)),
                );
                for (field, old_value, new_value) in changes {
                    entry.add_field_change(field.to_string(), old_value, new_value);
                }
            }
            (None, Some(new)) => {
                entry = entry.with_states(None, Some(Self::credential_meta_snapshot(new)));
            }
            (Some(old), None) => {
                entry = entry.with_states(Some(Self::credential_meta_snapshot(old)), None);
            }
            (None, None) => return,
        }

        let version = self
            .change_history_repo
            .get_latest_version(EntityType::Credential, &entity_id)
            .await
            .unwrap_or(0)
            + 1;
        entry.version = version;

        if let Err(e) = self.change_history_repo.record(&entry).await {
            tracing::warn!("failed to record credential history: {}", e);
        }
    }

    fn ensure_unlocked(&self) -> Result<()> {
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
                | AuditAction::PasskeyDeleted
                | AuditAction::ConnectTokenCreated
                | AuditAction::ConnectTokenRevoked
                | AuditAction::ConnectTokenUsed => {
                    // Passkey/Connect token id 均不是 credential/identity FK;
                    // resource_id 载主键,只附身份上下文。
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
        // 尽力而为的远端复制（见 events::Emitter）：本地审计库才是存证源
        if let Some(emitter) = &self.event_emitter {
            emitter.emit(&log);
        }
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

    // ----- Connect 本机自动化(阶段 1:token 生命周期/scope/锁定门禁)-----

    use crate::connect::{ConnectItemType, ConnectTokenScope, ConnectVerb};

    fn connect_read_scope() -> ConnectTokenScope {
        ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![ConnectVerb::Read],
        }
    }

    /// 已解锁服务 + 独立 Database 句柄(直接查表断言哈希存储用)。
    async fn connect_fixture() -> (PersonaService, Database) {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db.clone()).await.unwrap();
        let salt = service.generate_salt();
        service.unlock("test_password", &salt).unwrap();
        (service, db)
    }

    fn assert_vault_locked(err: anyhow::Error) {
        assert!(matches!(
            err.downcast_ref::<PersonaError>(),
            Some(PersonaError::VaultLocked(_))
        ));
    }

    #[tokio::test]
    async fn connect_token_requires_unlocked_vault() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let service = PersonaService::new(db).await.unwrap();
        assert!(!service.is_unlocked());

        // 锁定态管理面被拒:敏感门禁先于解锁门禁触发,按 SERVICE_LOCKED
        // 语义报认证失败(桌面据此回解锁屏);数据面的 VaultLocked/503
        // 语义由 connect_hides_archived_items_and_gates_when_locked 覆盖。
        let err = service
            .create_connect_token("t".into(), connect_read_scope())
            .await
            .unwrap_err();
        assert!(matches!(
            err.downcast_ref::<PersonaError>(),
            Some(PersonaError::AuthenticationFailed(_))
        ));
        assert_vault_locked_but_auth_gate_first_free(
            service.list_connect_tokens().await.unwrap_err(),
        );
    }

    /// list_connect_tokens 只挂解锁门禁(无 reauth):锁定即 VaultLocked。
    fn assert_vault_locked_but_auth_gate_first_free(err: anyhow::Error) {
        assert!(matches!(
            err.downcast_ref::<PersonaError>(),
            Some(PersonaError::VaultLocked(_))
        ));
    }

    #[tokio::test]
    async fn connect_token_lifecycle_hash_only_storage_and_revocation() {
        let (service, db) = connect_fixture().await;

        let (presented, row) = service
            .create_connect_token("  ci runner  ".into(), connect_read_scope())
            .await
            .unwrap();
        // 明文形态:前缀 + 32B base64url(43 字符),哈希/指纹与呈现值一致
        assert!(presented.starts_with("pconn_"));
        assert_eq!(presented.len(), "pconn_".len() + 43);
        assert_eq!(row.label, "ci runner");
        assert_eq!(row.hash, crate::connect::hash_token(&presented).unwrap());
        assert_eq!(
            row.fingerprint,
            crate::connect::fingerprint_from_hash(&row.hash)
        );
        assert!(row.last_used_at.is_none() && row.revoked_at.is_none());

        // 库里只有哈希(64 hex)与指纹,绝无呈现值明文
        let raw = sqlx::query("SELECT hash, fingerprint FROM connect_tokens")
            .fetch_all(db.pool())
            .await
            .unwrap();
        assert_eq!(raw.len(), 1);
        let stored_hash: String = raw[0].get("hash");
        assert_eq!(stored_hash, row.hash);
        assert_eq!(stored_hash.len(), 64);
        assert!(!stored_hash.contains("pconn_"));

        // 鉴权命中 + last_used 落库
        assert!(service
            .connect_authenticate(&presented)
            .await
            .unwrap()
            .is_some());
        let listed = service.list_connect_tokens().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].last_used_at.is_some());

        // 吊销即时生效;重复吊销幂等返回 false
        assert!(service.revoke_connect_token(&row.id).await.unwrap());
        assert!(!service.revoke_connect_token(&row.id).await.unwrap());
        assert!(service
            .connect_authenticate(&presented)
            .await
            .unwrap()
            .is_none());

        // 未知/畸形 token 一律 None(同形,防探测)
        assert!(service
            .connect_authenticate("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .unwrap()
            .is_none());
        assert!(service
            .connect_authenticate("garbage-without-prefix")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn connect_data_plane_filters_by_scope() {
        let (service, _db) = connect_fixture().await;
        let id_a = service
            .create_identity("A".into(), IdentityType::Personal)
            .await
            .unwrap();
        let id_b = service
            .create_identity("B".into(), IdentityType::Personal)
            .await
            .unwrap();

        let pwd = CredentialData::Password(PasswordCredentialData {
            password: "p1".into(),
            email: None,
            security_questions: vec![],
        });
        let card = CredentialData::BankCard(crate::models::credential::BankCardData {
            card_number: "4111 1111 1111 1111".into(),
            cardholder_name: "ALICE SMITH".into(),
            expiry_date: "12/29".into(),
            cvv: "123".into(),
            bank_name: "Example Bank".into(),
            card_type: "visa".into(),
        });
        let totp_data = CredentialData::TwoFactor(crate::models::credential::TwoFactorData {
            secret_key: "JBSWY3DPEHPK3PXP".into(),
            issuer: "Example".into(),
            account_name: "alice".into(),
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
        });

        let cred_a = service
            .create_credential(
                id_a.id,
                "A login".into(),
                CredentialType::Password,
                SecurityLevel::High,
                &pwd,
            )
            .await
            .unwrap();
        let cred_b = service
            .create_credential(
                id_b.id,
                "B card".into(),
                CredentialType::BankCard,
                SecurityLevel::High,
                &card,
            )
            .await
            .unwrap();
        let cred_totp = service
            .create_credential(
                id_a.id,
                "A totp".into(),
                CredentialType::TwoFactor,
                SecurityLevel::Medium,
                &totp_data,
            )
            .await
            .unwrap();

        // 全量 scope:全部身份/条目可见
        let all = connect_read_scope();
        assert_eq!(
            service.connect_list_identities(&all).await.unwrap().len(),
            2
        );
        assert_eq!(
            service
                .connect_list_items(&all, None, None, None)
                .await
                .unwrap()
                .len(),
            3
        );

        // identities 限定 [A]:B 的条目不可见;显式 identity=B 参数 → 空列表(防探测)
        let only_a = ConnectTokenScope {
            identities: vec![id_a.id],
            ..connect_read_scope()
        };
        assert_eq!(
            service
                .connect_list_identities(&only_a)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            service
                .connect_list_items(&only_a, None, None, None)
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(service
            .connect_list_items(&only_a, Some(id_b.id), None, None)
            .await
            .unwrap()
            .is_empty());

        // item_types 限定 Password:卡与 TOTP 不在列
        let pwd_only = ConnectTokenScope {
            item_types: vec![ConnectItemType::Password],
            ..connect_read_scope()
        };
        let items = service
            .connect_list_items(&pwd_only, None, None, None)
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, cred_a.id);

        // 单条读取:scope 外与不存在同形 None
        assert!(service
            .connect_get_item_data(&only_a, &cred_b.id)
            .await
            .unwrap()
            .is_none());
        assert!(service
            .connect_get_item_data(&all, &Uuid::new_v4())
            .await
            .unwrap()
            .is_none());
        let (cred, data) = service
            .connect_get_item_data(&all, &cred_a.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cred.id, cred_a.id);
        assert!(matches!(data, CredentialData::Password(_)));

        // TOTP:TwoFactor 项出码,密码项 None
        let code = service
            .connect_totp(&all, &cred_totp.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(service
            .connect_totp(&all, &cred_a.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn connect_hides_archived_items_and_gates_when_locked() {
        let (mut service, _db) = connect_fixture().await;
        let identity = service
            .create_identity("A".into(), IdentityType::Personal)
            .await
            .unwrap();
        let pwd = CredentialData::Password(PasswordCredentialData {
            password: "p1".into(),
            email: None,
            security_questions: vec![],
        });
        let cred = service
            .create_credential(
                identity.id,
                "login".into(),
                CredentialType::Password,
                SecurityLevel::High,
                &pwd,
            )
            .await
            .unwrap();
        let all = connect_read_scope();
        assert!(service
            .connect_get_item_data(&all, &cred.id)
            .await
            .unwrap()
            .is_some());

        // 归档后对 Connect 数据面不可见
        let mut archived = service.get_credential(&cred.id).await.unwrap().unwrap();
        archived.is_active = false;
        service.update_credential(&archived).await.unwrap();
        assert!(service
            .connect_get_item_data(&all, &cred.id)
            .await
            .unwrap()
            .is_none());
        let items = service
            .connect_list_items(&all, None, None, None)
            .await
            .unwrap();
        assert!(items.iter().all(|c| c.id != cred.id));

        // 锁定后数据面/管理面全部 503 语义(VaultLocked)
        service.lock();
        let err = service
            .connect_get_item_data(&all, &cred.id)
            .await
            .unwrap_err();
        assert_vault_locked(err);
        assert_vault_locked(
            service
                .connect_list_items(&all, None, None, None)
                .await
                .unwrap_err(),
        );
        // authenticate 本身无锁定门禁:DR-4 的 503 由宿主层在鉴权之前拦截,
        // core 层的 token 验证只读 connect_tokens 表(不涉解密)。
        assert!(service
            .connect_authenticate("pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .unwrap()
            .is_none());
    }

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
        let cose = crate::crypto::cose_public_key(key.verifying_key()).unwrap();
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
            crate::crypto::cose_public_key(crate::crypto::generate_signing_key().verifying_key())
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

    // ------------------------------------------------------------------
    // Helpers shared by the batches below
    // ------------------------------------------------------------------

    async fn unlocked_service() -> (Database, PersonaService) {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db.clone()).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        (db, service)
    }

    /// log_audit → emitter 挂钩：同步入队、None 解除后不再上报。
    #[tokio::test]
    async fn log_audit_feeds_event_emitter_until_detached() {
        use crate::events::testing::{eventually, FakeSink};
        use std::sync::Arc;

        let (_db, mut service) = unlocked_service().await;
        let sink = Arc::new(FakeSink::default());
        // batch_size=1：单条事件即触发 notify flush（默认 100 要等 interval）
        let emitter = crate::events::Emitter::with_config(
            sink.clone(),
            crate::events::EmitterConfig {
                batch_size: 1,
                ..Default::default()
            },
        );
        emitter.start();
        service.set_event_emitter(Some(emitter.clone()));

        service
            .log_audit(
                AuditAction::Login,
                ResourceType::User,
                true,
                None,
                None,
                None,
            )
            .await;
        eventually(|| sink.call_count() >= 1).await;
        assert_eq!(sink.batches()[0].len(), 1);
        assert_eq!(sink.batches()[0][0].action, "login");
        emitter.stop().await;

        // None 解除挂钩：后续审计只落本地库，不再上报
        service.set_event_emitter(None);
        service
            .log_audit(
                AuditAction::Login,
                ResourceType::User,
                true,
                None,
                None,
                None,
            )
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(sink.call_count(), 1);
    }

    /// `set_event_emitter` 传播到 auto_lock_manager：session 锁定审计
    /// 走同一上报链，`None` 时两处（service + manager）一起摘除。
    #[tokio::test]
    async fn set_event_emitter_propagates_to_auto_lock_manager() {
        use crate::events::testing::{eventually, FakeSink};
        use std::sync::Arc;

        let (_db, mut service) = unlocked_service().await;

        // 注册真 session 让 force_lock_session 触达 manager 的审计路径。
        let user_id = service.current_user.expect("initialized user");
        let session = Session::new(user_id.to_string(), Duration::from_secs(600));
        let session_id = session.id.clone();
        service
            .auto_lock_manager
            .add_session(session)
            .await
            .unwrap();
        *service.current_session_id.write().await = Some(session_id.clone());

        let sink = Arc::new(FakeSink::default());
        let emitter = crate::events::Emitter::with_config(
            sink.clone(),
            crate::events::EmitterConfig {
                batch_size: 1,
                ..Default::default()
            },
        );
        emitter.start();
        service.set_event_emitter(Some(emitter.clone()));

        service.force_lock_session().await.unwrap();
        eventually(|| sink.call_count() >= 1).await;
        assert_eq!(sink.batches()[0][0].action, "session_locked");
        assert_eq!(
            sink.batches()[0][0].session_id.as_deref(),
            Some(session_id.as_str())
        );

        // None 同步摘除 manager 侧：解锁/再锁只落本地库，不再上报
        service.set_event_emitter(None);
        service.unlock_session().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let count_after_detach = sink.call_count();
        service.force_lock_session().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(sink.call_count(), count_after_detach);
        emitter.stop().await;
    }

    async fn seed_credential(
        service: &PersonaService,
        identity_id: Uuid,
        name: &str,
        credential_type: CredentialType,
    ) -> Credential {
        let data = CredentialData::Password(PasswordCredentialData {
            password: "pw".to_string(),
            email: None,
            security_questions: vec![],
        });
        service
            .create_credential(
                identity_id,
                name.to_string(),
                credential_type,
                SecurityLevel::Medium,
                &data,
            )
            .await
            .unwrap()
    }

    // ------------------------------------------------------------------
    // Item history（1Password 对齐）：create/update/delete 自动记录
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn credential_history_records_created_updated_deleted() {
        let (_db, service) = unlocked_service().await;
        let identity = service
            .create_identity("History Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let mut cred =
            seed_credential(&service, identity.id, "Gmail", CredentialType::Password).await;

        // 创建 → created 行 v1（新快照有、旧快照无）
        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].change_type, ChangeType::Created);
        assert_eq!(history[0].version, 1);
        assert!(history[0].new_state.is_some());
        assert!(history[0].previous_state.is_none());

        // 元数据变化 → updated 行 v2，字段级 diff 记 username 与 url
        cred.username = Some("alice".to_string());
        cred.url = Some("https://mail.example.com".to_string());
        service.update_credential(&cred).await.unwrap();

        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].change_type, ChangeType::Updated);
        assert_eq!(history[0].version, 2);
        assert_eq!(history[0].changes_summary.len(), 2);
        let username_change = history[0].changes_summary.get("username").unwrap();
        assert_eq!(username_change.old_value, "");
        assert_eq!(username_change.new_value, "alice");

        // 无实质变化的重复 update → 不新增历史行
        service.update_credential(&cred).await.unwrap();
        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 2, "no-op update must not add history");

        // 密文变化（密码轮换）→ 只记占位 diff；内容绝不进历史
        cred.encrypted_data = vec![9u8; 8];
        service.update_credential(&cred).await.unwrap();
        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 3);
        let enc_change = history[0].changes_summary.get("encrypted_data").unwrap();
        assert_eq!(enc_change.old_value, "<encrypted>");
        assert_eq!(enc_change.new_value, "<encrypted>");
        let states = serde_json::to_string(&history[0].new_state).unwrap();
        assert!(!states.contains("encrypted_data"));

        // 删除 → deleted 行 v4（凭据行已删，历史仍在）
        service.delete_credential(&cred.id).await.unwrap();
        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].change_type, ChangeType::Deleted);
        assert_eq!(history[0].version, 4);
    }

    #[tokio::test]
    async fn restore_credential_version_reverts_metadata_and_keeps_secrets() {
        let (_db, service) = unlocked_service().await;
        let identity = service
            .create_identity("Restore Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let mut cred =
            seed_credential(&service, identity.id, "Gmail", CredentialType::Password).await;
        let original_ciphertext = cred.encrypted_data.clone();

        // v2：username/url
        cred.username = Some("alice".to_string());
        cred.url = Some("https://mail.example.com".to_string());
        service.update_credential(&cred).await.unwrap();

        // v3：rename
        cred.name = "Gmail Work".to_string();
        service.update_credential(&cred).await.unwrap();

        // 恢复到 v1（创建态）：元数据回滚，密文原样
        let restored = service
            .restore_credential_version(&cred.id, 1)
            .await
            .unwrap();
        assert_eq!(restored.name, "Gmail");
        assert_eq!(restored.username, None);
        assert_eq!(restored.url, None);
        assert_eq!(restored.tags, Vec::<String>::new());
        assert!(!restored.is_favorite);
        assert!(restored.is_active);
        assert_eq!(
            restored.encrypted_data, original_ciphertext,
            "metadata restore must never touch the secret payload"
        );

        // 历史多一行 restored，reason 标注目标版本
        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].change_type, ChangeType::Restored);
        assert_eq!(history[0].version, 4);
        assert_eq!(history[0].reason.as_deref(), Some("restore to version 1"));
        let name_change = history[0].changes_summary.get("name").unwrap();
        assert_eq!(name_change.old_value, "Gmail Work");
        assert_eq!(name_change.new_value, "Gmail");
        let username_change = history[0].changes_summary.get("username").unwrap();
        assert_eq!(username_change.old_value, "alice");
        assert_eq!(username_change.new_value, "");

        // 中间版本也可恢复：回到 v2（username=alice、name=Gmail）
        let restored = service
            .restore_credential_version(&cred.id, 2)
            .await
            .unwrap();
        assert_eq!(restored.name, "Gmail");
        assert_eq!(restored.username.as_deref(), Some("alice"));
        assert_eq!(restored.url.as_deref(), Some("https://mail.example.com"));

        // 恢复到当前状态 = 无实质变化 → 不记噪声历史行
        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 5);
        service
            .restore_credential_version(&cred.id, 2)
            .await
            .unwrap();
        let history = service
            .get_entity_history(EntityType::Credential, &cred.id)
            .await
            .unwrap();
        assert_eq!(history.len(), 5, "no-op restore must not add history");
    }

    #[tokio::test]
    async fn restore_credential_version_rejects_bad_targets() {
        let (_db, service) = unlocked_service().await;
        let identity = service
            .create_identity("Restore Errors".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let cred = seed_credential(&service, identity.id, "Temp", CredentialType::Password).await;

        let err = service
            .restore_credential_version(&cred.id, 99)
            .await
            .expect_err("unknown version must fail");
        assert!(err.to_string().contains("no history version 99"));

        let missing = Uuid::new_v4();
        let err = service
            .restore_credential_version(&missing, 1)
            .await
            .expect_err("unknown credential must fail");
        assert!(err.to_string().contains("not found"));

        // 删除后的条目不可恢复（行已不在；历史仍可查但不重建秘密外壳）
        service.delete_credential(&cred.id).await.unwrap();
        let err = service
            .restore_credential_version(&cred.id, 1)
            .await
            .expect_err("deleted credential must not restore");
        assert!(err.to_string().contains("not found"));
    }

    // ------------------------------------------------------------------
    // Locked service error paths
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_locked_service_rejects_operations() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();
        assert!(!service.is_unlocked());

        let id = Uuid::new_v4();
        for err in [
            service
                .create_identity("locked".to_string(), IdentityType::Personal)
                .await
                .unwrap_err()
                .to_string(),
            service.get_identities().await.unwrap_err().to_string(),
            service.get_identity(&id).await.unwrap_err().to_string(),
            service
                .get_credentials_for_identity(&id)
                .await
                .unwrap_err()
                .to_string(),
            service.get_credential(&id).await.unwrap_err().to_string(),
            service
                .delete_credential(&id)
                .await
                .unwrap_err()
                .to_string(),
            service.export_identity(&id).await.unwrap_err().to_string(),
            service.get_statistics().await.unwrap_err().to_string(),
            service
                .attach_file(id, "/tmp/x", false)
                .await
                .unwrap_err()
                .to_string(),
            service.get_attachments(&id).await.unwrap_err().to_string(),
        ] {
            assert!(
                err.contains("Service is locked"),
                "unexpected error: {}",
                err
            );
        }
    }

    #[tokio::test]
    async fn test_get_master_encryption_service_reports_locked() {
        // The public operations gate through ensure_unlocked first, so the
        // accessor's own locked branch is exercised directly (the same-module
        // legacy-decryption tests already poke the success side).
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();

        // A fresh service carries no encryption material at all.
        let err = service
            .get_master_encryption_service()
            .err()
            .expect("fresh service must be locked");
        assert!(err.to_string().contains("Service is locked"));

        // After a successful unlock, lock() drops the material again and the
        // same error surfaces.
        service.initialize_user("master-pin").await.unwrap();
        assert!(service.get_master_encryption_service().is_ok());
        service.lock();
        let err = service
            .get_master_encryption_service()
            .err()
            .expect("locked service must report locked");
        assert!(err.to_string().contains("Service is locked"));
    }

    // ------------------------------------------------------------------
    // User lifecycle / authentication
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_user_lifecycle_and_auth_paths() {
        // A fresh database has no users; authentication fails closed.
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db.clone()).await.unwrap();
        assert!(!service.has_users().await.unwrap());
        assert_eq!(
            service.authenticate_user("anything").await.unwrap(),
            AuthResult::InvalidCredentials
        );

        // Initialize the first user; the service unlocks automatically.
        let user_id = service.initialize_user("master-pin").await.unwrap();
        assert!(service.has_users().await.unwrap());
        assert!(service.is_unlocked());

        // Wrong password keeps the service usable but reports the failure.
        assert_eq!(
            service.authenticate_user("wrong").await.unwrap(),
            AuthResult::InvalidCredentials
        );
        // Correct password succeeds (and succeeds again on repeat login).
        assert_eq!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::Success
        );

        // Locking clears the in-memory key; ops are refused until re-unlock.
        service.lock();
        assert!(!service.is_unlocked());
        assert!(service.current_user.is_none());

        // Direct unlock with the stored salt restores access.
        let salt = service
            .user_auth_repo
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .get_master_key_salt()
            .unwrap();
        service.unlock("master-pin", &salt).unwrap();
        assert!(service.is_unlocked());
        assert_ne!(user_id, Uuid::new_v4());
    }

    #[tokio::test]
    async fn test_authenticate_user_locks_account_after_failures() {
        let (_db, mut service) = unlocked_service().await;

        for _ in 0..4 {
            assert_eq!(
                service.authenticate_user("wrong").await.unwrap(),
                AuthResult::InvalidCredentials
            );
        }
        // 5th failure triggers the account lockout.
        assert_eq!(
            service.authenticate_user("wrong").await.unwrap(),
            AuthResult::InvalidCredentials
        );
        assert_eq!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::AccountLocked
        );
    }

    #[tokio::test]
    async fn test_authenticate_memory_user_is_rejected_and_session_surface() {
        let (_db, mut service) = unlocked_service().await;

        // `authenticate` builds an in-memory UserAuth without a stored hash,
        // so no password can verify — the failure path must not panic.
        let salt = service.generate_salt();
        assert_eq!(
            service
                .authenticate(Uuid::new_v4(), "whatever", &salt)
                .await
                .unwrap(),
            AuthResult::InvalidCredentials
        );
    }

    // ------------------------------------------------------------------
    // Session / auto-lock surface
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_authenticated_user_start_monitoring_registers_current_user() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db.clone()).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        assert!(service.is_unlocked());
        // The full login path goes through authenticate_user; monitoring
        // started afterwards must propagate the current user into the
        // auto-lock manager.
        assert!(matches!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::Success
        ));
        service.start_auto_lock_monitoring().await.unwrap();
        service.stop_auto_lock_monitoring().await;
    }

    #[tokio::test]
    async fn test_sensitive_operation_gated_behind_reauth() {
        let (_db, mut service) = unlocked_service().await;
        let identity = service
            .create_identity("Reauth Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let cred = seed_credential(&service, identity.id, "Gated", CredentialType::Password).await;

        // Swap in a manager that demands re-authentication for sensitive
        // operations (the default config keeps this off).
        service.auto_lock_manager =
            AutoLockManager::with_basic_config(crate::auth::AutoLockConfig {
                require_reauth_sensitive: true,
                sensitive_operation_timeout_secs: 3600,
                ..Default::default()
            });
        let session = Session::new("reauth-user".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        service
            .auto_lock_manager
            .add_session(session)
            .await
            .unwrap();
        *service.current_session_id.write().await = Some(session_id.clone());

        // A freshly registered session has no sensitive-activity history, so
        // the gate must reject the read with the dedicated error variant.
        assert!(service.needs_reauth().await);
        let err = service.get_credential_data(&cred.id).await.unwrap_err();
        assert!(
            err.to_string().contains("Re-authentication required"),
            "unexpected error: {err}"
        );

        // Once sensitive activity is recorded, the same call goes through and
        // (via the success path) refreshes the sensitive timer again.
        service
            .auto_lock_manager
            .update_sensitive_activity(&session_id)
            .await
            .unwrap();
        assert!(!service.needs_reauth().await);
        let data = service
            .get_credential_data(&cred.id)
            .await
            .unwrap()
            .expect("credential exists");
        assert!(matches!(data, CredentialData::Password(_)));
    }

    /// 公开 API 的完整回路：configure_auto_lock 打开敏感闸门 → 登录
    /// （authenticate_user）记录敏感活动即放行 → 窗口过后被
    /// ReauthRequired 拦下 → 再认证恢复 → 关闭闸门同样恢复。
    /// 此前的测试只能换私有 manager 字段，公开路径下开关从未生效。
    #[tokio::test]
    async fn test_configure_auto_lock_gate_round_trip_via_public_api() {
        let (_db, mut service) = unlocked_service().await;
        let identity = service
            .create_identity("Gate Round Trip".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let cred = seed_credential(
            &service,
            identity.id,
            "Gated Three",
            CredentialType::Password,
        )
        .await;

        // 打开闸门，敏感窗口 1 秒。
        service
            .configure_auto_lock(crate::auth::AutoLockConfig {
                inactivity_timeout_secs: 900,
                absolute_timeout_secs: 0,
                require_reauth_sensitive: true,
                sensitive_operation_timeout_secs: 1,
            })
            .await
            .unwrap();

        // 生产登录路径建立 session，并把登录本身记为一次敏感验证——
        // 刚登录的用户应能直接做敏感操作（否则闸门无法自愈：计时器只能
        // 由成功的敏感操作刷新）。
        let auth = service.authenticate_user("master-pin").await.unwrap();
        assert!(matches!(auth, AuthResult::Success));
        assert!(!service.needs_reauth().await);
        assert!(service.get_credential_data(&cred.id).await.is_ok());

        // 窗口过后，同一操作被专用错误变体拦下。
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(service.needs_reauth().await);
        let err = service.get_credential_data(&cred.id).await.unwrap_err();
        assert!(
            err.to_string().contains("Re-authentication required"),
            "unexpected error: {err}"
        );

        // 再认证（同一登录路径）刷新敏感计时器，操作恢复放行。
        let auth = service.authenticate_user("master-pin").await.unwrap();
        assert!(matches!(auth, AuthResult::Success));
        assert!(!service.needs_reauth().await);

        // 关闭闸门后，即使窗口再次过期也放行。
        tokio::time::sleep(Duration::from_millis(1100)).await;
        service
            .configure_auto_lock(crate::auth::AutoLockConfig::default())
            .await
            .unwrap();
        assert!(!service.needs_reauth().await);
        assert!(service.get_credential_data(&cred.id).await.is_ok());
    }

    #[tokio::test]
    async fn test_session_auto_lock_surface() {
        let (_db, service) = unlocked_service().await;

        // Without a session (initialize_user does not create one) the
        // legacy checks keep the service usable.
        assert!(!service.is_session_locked().await);
        assert!(!service.needs_reauth().await);
        assert!(service.force_lock_session().await.is_ok());
        assert!(service.unlock_session().await.is_ok());
        assert!(service.get_user_sessions().await.unwrap().is_empty());
        let _stats = service.get_auto_lock_statistics().await.unwrap();

        // With a session id pointing at an unknown session, lock/unlock
        // surface the manager's errors and the service reports locked.
        *service.current_session_id.write().await = Some("ghost-session".to_string());
        assert!(service.is_session_locked().await);
        assert!(service.force_lock_session().await.is_err());
        assert!(service.unlock_session().await.is_err());
        // Default config does not require re-auth for sensitive ops.
        assert!(!service.needs_reauth().await);
        assert!(service.get_user_sessions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_auto_lock_configuration_and_monitoring() {
        let (_db, mut service) = unlocked_service().await;

        service
            .configure_auto_lock(crate::auth::AutoLockConfig::default())
            .await
            .unwrap();
        service.set_auto_lock_timeout(Duration::from_secs(60));
        service.touch_activity();
        service
            .register_auto_lock_callback(Arc::new(|_event| {}))
            .await;

        // Monitoring works with and without a current user.
        service.start_auto_lock_monitoring().await.unwrap();
        service.stop_auto_lock_monitoring().await;
        assert!(service.get_auto_lock_statistics().await.is_ok());
    }

    #[tokio::test]
    async fn test_auto_lock_timeout_configuration_semantics() {
        let (_db, mut service) = unlocked_service().await;

        // set_auto_lock_timeout and inactivity_timeout_secs round-trip.
        service.set_auto_lock_timeout(Duration::from_secs(90));
        assert_eq!(service.inactivity_timeout_secs(), 90);

        // configure_auto_lock propagates the configured inactivity timeout.
        service
            .configure_auto_lock(crate::auth::AutoLockConfig {
                inactivity_timeout_secs: 120,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(service.inactivity_timeout_secs(), 120);

        // touch_activity keeps the service unlocked inside the window ...
        service.set_auto_lock_timeout(Duration::from_secs(60));
        service.touch_activity();
        assert!(service.is_unlocked());

        // ... and a zero window is expired the moment it is touched.
        service.set_auto_lock_timeout(Duration::ZERO);
        service.touch_activity();
        assert!(!service.is_unlocked());
    }

    #[tokio::test]
    async fn test_monitoring_lifecycle_registers_user_and_sessions() {
        let (_db, service) = unlocked_service().await;
        let user_id = service.current_user.expect("initialized user");

        // A session registered on the manager is visible through the service.
        let session = Session::new(user_id.to_string(), Duration::from_secs(600));
        let session_id = session.id.clone();
        service
            .auto_lock_manager
            .add_session(session)
            .await
            .unwrap();
        *service.current_session_id.write().await = Some(session_id.clone());

        let sessions = service.get_user_sessions().await.unwrap();
        assert!(sessions.iter().any(|s| s.id == session_id));

        // Starting monitoring with a current user wires it into the manager;
        // stopping is idempotent and the session stays registered.
        service.start_auto_lock_monitoring().await.unwrap();
        service.stop_auto_lock_monitoring().await;
        service.stop_auto_lock_monitoring().await;

        let stats = service.get_auto_lock_statistics().await.unwrap();
        assert!(stats.total_sessions >= 1);
        assert!(service
            .get_user_sessions()
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == session_id));
    }

    // ------------------------------------------------------------------
    // Remote auth / biometric providers
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_remote_and_biometric_provider_surface() {
        let (_db, mut service) = unlocked_service().await;

        // Swap in providers explicitly (default no-op setters).
        service.set_remote_auth_provider(Arc::new(MockRemoteAuthProvider));
        service.set_biometric_provider(Arc::new(MockBiometricProvider::default()));

        let challenge = service.begin_remote_auth("alice").unwrap();
        let result = service
            .finalize_remote_auth(&challenge, "client-proof")
            .unwrap();
        assert_eq!(result.user_id, challenge.user_id);
        assert!(!result.session_key_fingerprint.is_empty());

        // Empty client proof is rejected.
        assert!(service.finalize_remote_auth(&challenge, "").is_err());

        // Biometrics: default mock is available and verifies.
        assert!(service.biometric_available(None));
        assert!(service.biometric_available(Some(BiometricPlatform::Unknown)));
        let prompt = BiometricPrompt {
            user_id: Uuid::new_v4(),
            reason: "unlock vault".to_string(),
            platform: None,
        };
        assert!(service.authenticate_biometric(&prompt).unwrap());

        // A failing provider surfaces the error.
        service.set_biometric_provider(Arc::new(MockBiometricProvider {
            force_fail: true,
            ..Default::default()
        }));
        assert!(service.authenticate_biometric(&prompt).is_err());
    }

    // ------------------------------------------------------------------
    // Attachments
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_attachment_lifecycle() {
        let (db, mut service) = unlocked_service().await;

        // Before initialization every attachment op reports the missing store.
        let err = service
            .get_attachment_stats()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Attachment storage not initialized"));

        let identity = service
            .create_identity("Attach Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credential =
            seed_credential(&service, identity.id, "with file", CredentialType::Password).await;

        let err = service
            .attach_file(credential.id, "/tmp/nope", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Attachment storage not initialized"));

        let dir = tempfile::tempdir().unwrap();
        service
            .init_attachment_storage(dir.path(), db)
            .await
            .unwrap();

        let file_path = dir.path().join("secret.txt");
        std::fs::write(&file_path, b"attachment-bytes").unwrap();

        let attachment_id = service
            .attach_file(credential.id, &file_path, false)
            .await
            .unwrap();

        let listed = service.get_attachments(&credential.id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, attachment_id);

        let content = service
            .retrieve_attachment(&attachment_id, false)
            .await
            .unwrap();
        assert_eq!(content, b"attachment-bytes");

        let out_path = dir.path().join("restored.txt");
        service
            .save_attachment(&attachment_id, &out_path, false)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), b"attachment-bytes");

        let stats = service.get_attachment_stats().await.unwrap();
        assert_eq!(stats.total_attachments, 1);

        service.delete_attachment(&attachment_id).await.unwrap();
        assert!(service
            .get_attachments(&credential.id)
            .await
            .unwrap()
            .is_empty());

        // Retrieving a deleted attachment surfaces the missing-file error.
        assert!(service
            .retrieve_attachment(&attachment_id, false)
            .await
            .is_err());
    }

    // ------------------------------------------------------------------
    // Export / statistics
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_export_identity_and_statistics() {
        let (_db, service) = unlocked_service().await;

        let identity = service
            .create_identity("Export Target".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let first =
            seed_credential(&service, identity.id, "GitHub", CredentialType::Password).await;
        seed_credential(&service, identity.id, "API", CredentialType::ApiKey).await;

        let mut favorite = first.clone();
        favorite.is_favorite = true;
        service.update_credential(&favorite).await.unwrap();

        let export = service.export_identity(&identity.id).await.unwrap();
        assert_eq!(export.identity.id, identity.id);
        assert_eq!(export.credentials.len(), 2);

        // Unknown identity -> IdentityNotFound.
        let err = service
            .export_identity(&Uuid::new_v4())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found"), "unexpected error: {}", err);

        let stats = service.get_statistics().await.unwrap();
        assert_eq!(stats.total_identities, 1);
        assert_eq!(stats.total_credentials, 2);
        assert_eq!(stats.active_credentials, 2);
        assert_eq!(stats.favorite_credentials, 1);
        assert_eq!(stats.credential_types.values().sum::<u32>(), 2);
        assert_eq!(stats.security_levels.values().sum::<u32>(), 2);
    }

    // ------------------------------------------------------------------
    // Change history
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_change_history_surface() {
        let (_db, service) = unlocked_service().await;

        let entity_id = Uuid::new_v4();
        service
            .change_history_repo
            .record(&ChangeHistory::new(
                EntityType::Identity,
                entity_id,
                crate::models::ChangeType::Created,
            ))
            .await
            .unwrap();

        let history = service
            .get_entity_history(EntityType::Identity, &entity_id)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);

        let version = service
            .get_entity_version(EntityType::Identity, &entity_id, 1)
            .await
            .unwrap();
        assert!(version.is_some());
        assert!(service
            .get_entity_version(EntityType::Identity, &entity_id, 99)
            .await
            .unwrap()
            .is_none());

        let queried = service
            .query_change_history(
                &ChangeHistoryQuery::new()
                    .entity_type(EntityType::Identity)
                    .entity_id(entity_id),
            )
            .await
            .unwrap();
        assert_eq!(queried.len(), 1);

        let stats = service.get_change_history_stats().await.unwrap();
        assert!(stats.total_changes >= 1);

        // A cutoff in the future removes everything recorded so far.
        let removed = service
            .cleanup_old_history(chrono::Utc::now() + chrono::Duration::days(1))
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(service
            .get_entity_history(EntityType::Identity, &entity_id)
            .await
            .unwrap()
            .is_empty());
    }

    // ------------------------------------------------------------------
    // Query helpers / password generation
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_query_helpers_and_password_generation() {
        let (_db, service) = unlocked_service().await;

        let identity = service
            .create_identity("Helper Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let cred = seed_credential(
            &service,
            identity.id,
            "GitHub token",
            CredentialType::Password,
        )
        .await;
        let mut fav = cred.clone();
        fav.is_favorite = true;
        fav.username = Some("octocat".to_string());
        service.update_credential(&fav).await.unwrap();
        seed_credential(&service, identity.id, "API key", CredentialType::ApiKey).await;

        assert_eq!(service.search_credentials("").await.unwrap().len(), 2);
        assert_eq!(service.search_credentials("GitHub").await.unwrap().len(), 1);
        // username / url 同样参与搜索（repository search_by_fields 链路）
        assert_eq!(
            service.search_credentials("octocat").await.unwrap().len(),
            1
        );
        assert_eq!(service.get_favorite_credentials().await.unwrap().len(), 1);
        assert_eq!(
            service
                .get_credentials_by_type(&CredentialType::Password)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            service
                .get_identities_by_type(&IdentityType::Personal)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(service
            .get_identity_by_name("no-such-identity")
            .await
            .unwrap()
            .is_none());
        assert!(service
            .list_passkeys_by_rp("example.com")
            .await
            .unwrap()
            .is_empty());
        assert!(service
            .get_credential(&Uuid::new_v4())
            .await
            .unwrap()
            .is_none());

        // Password helpers.
        let generated = service.generate_password(16, true);
        assert_eq!(generated.chars().count(), 16);
        // Lengths below the minimum are clamped to 4.
        assert_eq!(service.generate_password(2, false).chars().count(), 4);

        let options = PasswordGeneratorOptions {
            length: 20,
            include_symbols: false,
            ..Default::default()
        };
        assert_eq!(
            service
                .generate_password_with_options(&options)
                .unwrap()
                .chars()
                .count(),
            20
        );

        let hash = service.hash_data(b"persona");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, service.hash_data(b"persona"));
    }

    // ------------------------------------------------------------------
    // Identity / credential CRUD
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_identity_and_credential_crud() {
        let (_db, service) = unlocked_service().await;

        // create_identity_full stores the pre-populated identity.
        let mut identity = Identity::new("Full Identity".to_string(), IdentityType::Work);
        identity.email = Some("work@example.com".to_string());
        let created = service.create_identity_full(identity).await.unwrap();
        assert_eq!(created.email.as_deref(), Some("work@example.com"));

        // Rename and persist.
        let mut renamed = created.clone();
        renamed.name = "Renamed Identity".to_string();
        let updated = service.update_identity(&renamed).await.unwrap();
        assert_eq!(updated.name, "Renamed Identity");

        let fetched = service.get_identity(&created.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "Renamed Identity");

        // Credential lifecycle: not-found delete reports false, then a real delete.
        assert!(!service.delete_credential(&Uuid::new_v4()).await.unwrap());

        let identity2 = service
            .create_identity("Cred Owner".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credential = seed_credential(
            &service,
            identity2.id,
            "to delete",
            CredentialType::Password,
        )
        .await;

        let mut edited = credential.clone();
        edited.name = "renamed cred".to_string();
        service.update_credential(&edited).await.unwrap();
        assert_eq!(
            service
                .get_credential(&credential.id)
                .await
                .unwrap()
                .unwrap()
                .name,
            "renamed cred"
        );

        assert!(service.delete_credential(&credential.id).await.unwrap());
        assert!(!service.delete_credential(&credential.id).await.unwrap());

        // Deleting an identity with no leftover credentials succeeds.
        assert!(service.delete_identity(&identity2.id).await.unwrap());
        assert!(!service.delete_identity(&identity2.id).await.unwrap());
    }

    // ------------------------------------------------------------------
    // Credential decryption: legacy (master-key) format and error paths
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_credential_data_legacy_and_error_paths() {
        let (db, service) = unlocked_service().await;

        // Unknown id → Ok(None), never an error.
        assert!(service
            .get_credential_data(&Uuid::new_v4())
            .await
            .unwrap()
            .is_none());

        let identity = service
            .create_identity("Legacy Owner".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credentials = crate::storage::CredentialRepository::new(db.clone());

        let plaintext = CredentialData::Password(PasswordCredentialData {
            password: "legacy-secret".to_string(),
            email: None,
            security_questions: vec![],
        })
        .to_bytes()
        .unwrap();

        // Legacy format: sealed directly with the master key, no wrapped item key.
        let ciphertext = service
            .get_master_encryption_service()
            .unwrap()
            .encrypt(&plaintext)
            .unwrap();
        let legacy = Credential::new(
            identity.id,
            "Legacy".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            ciphertext,
            None,
        );
        credentials.create(&legacy).await.unwrap();

        let data = service
            .get_credential_data(&legacy.id)
            .await
            .unwrap()
            .expect("legacy credential must decrypt");
        match data {
            CredentialData::Password(pwd) => assert_eq!(pwd.password, "legacy-secret"),
            other => panic!("expected password credential data, got {:?}", other),
        }

        // The lookup stamps last_accessed via the repository update.
        let stored = credentials.find_by_id(&legacy.id).await.unwrap().unwrap();
        assert!(stored.last_accessed.is_some());

        // Legacy ciphertext that does not decrypt surfaces the legacy error.
        let broken = Credential::new(
            identity.id,
            "Broken Legacy".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            vec![7u8; 64],
            None,
        );
        credentials.create(&broken).await.unwrap();
        let err = service
            .get_credential_data(&broken.id)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Failed to decrypt legacy credential"),
            "unexpected error: {}",
            err
        );

        // A validly sealed envelope whose plaintext is not CredentialData
        // surfaces the deserialization error. Four zero bytes decode to the
        // Password variant and then run out of input for the payload.
        let hierarchy =
            crate::crypto::KeyHierarchy::new(service.get_master_encryption_service().unwrap());
        let envelope = hierarchy.encrypt_with_new_item_key(&[0u8; 4]).unwrap();
        let garbage = Credential::new(
            identity.id,
            "Garbage".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            envelope.ciphertext,
            Some(envelope.wrapped_key),
        );
        credentials.create(&garbage).await.unwrap();
        let err = service
            .get_credential_data(&garbage.id)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Failed to deserialize credential data"),
            "unexpected error: {}",
            err
        );
    }

    // ------------------------------------------------------------------
    // Attachments: encrypted storage through the service surface
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_attachment_encrypted_store_marks_and_scrambles_content() {
        let (db, mut service) = unlocked_service().await;

        let identity = service
            .create_identity("Encrypted Attach".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credential = seed_credential(
            &service,
            identity.id,
            "enc attach",
            CredentialType::Password,
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        service
            .init_attachment_storage(dir.path(), db)
            .await
            .unwrap();

        let file_path = dir.path().join("secret.bin");
        std::fs::write(&file_path, b"top-secret-bytes").unwrap();

        let attachment_id = service
            .attach_file(credential.id, &file_path, true)
            .await
            .unwrap();

        let listed = service.get_attachments(&credential.id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, attachment_id);
        assert!(listed[0].is_encrypted);

        // Without the decrypt flag the raw ciphertext comes back untouched.
        let raw = service
            .retrieve_attachment(&attachment_id, false)
            .await
            .unwrap();
        assert_ne!(raw, b"top-secret-bytes".to_vec());

        // The attachment is sealed under the credential's per-item key, so
        // decrypting through the service yields the original bytes.
        let plain = service
            .retrieve_attachment(&attachment_id, true)
            .await
            .unwrap();
        assert_eq!(plain, b"top-secret-bytes".to_vec());

        // Saving with decrypt=false still writes the stored bytes to disk.
        let out_path = dir.path().join("raw-copy.bin");
        service
            .save_attachment(&attachment_id, &out_path, false)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), raw);
    }

    /// 加密附件复用凭据 item key 的核心保障：改密（rewrap）后附件仍可解密。
    /// rotation 只重包 wrapped_item_key，item key 本身不变，blob 无需重写。
    #[tokio::test]
    async fn encrypted_attachment_survives_master_password_rotation() {
        let (db, mut service) = unlocked_service().await;

        let identity = service
            .create_identity("Rotation Attach".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credential = seed_credential(
            &service,
            identity.id,
            "rot attach",
            CredentialType::Password,
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        service
            .init_attachment_storage(dir.path(), db)
            .await
            .unwrap();

        let file_path = dir.path().join("doc.txt");
        std::fs::write(&file_path, b"survive-rotation-payload").unwrap();
        let attachment_id = service
            .attach_file(credential.id, &file_path, true)
            .await
            .unwrap();

        service
            .change_master_password("master-pin", "master-pin-2")
            .await
            .unwrap();

        let plain = service
            .retrieve_attachment(&attachment_id, true)
            .await
            .unwrap();
        assert_eq!(plain, b"survive-rotation-payload".to_vec());

        // 凭据本体同样可解（改密事务的既有承诺），防回归连带断言
        let data = service.get_credential_data(&credential.id).await.unwrap();
        assert!(data.is_some());
    }

    /// legacy 凭据（wrapped_item_key NULL）首次挂加密附件时升级为 per-item key：
    /// 升级后凭据 payload 仍可读、行获得 wrapped key、附件可解密往返。
    #[tokio::test]
    async fn attach_upgrades_legacy_credential_to_item_key() {
        let (db, mut service) = unlocked_service().await;

        let identity = service
            .create_identity("Legacy Attach".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // 手工构造 legacy 行：encrypted_data 直接用主密钥封、无 wrapped key
        let master = service.get_master_encryption_service().unwrap();
        let plaintext = CredentialData::Password(PasswordCredentialData {
            password: "legacy-pw".to_string(),
            email: None,
            security_questions: vec![],
        })
        .to_bytes()
        .unwrap();
        let sealed = master.encrypt(&plaintext).unwrap();
        let credential = Credential::new(
            identity.id,
            "legacy row".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            sealed,
            None,
        );
        let credentials = crate::storage::CredentialRepository::new(db.clone());
        credentials.create(&credential).await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        service
            .init_attachment_storage(dir.path(), db)
            .await
            .unwrap();

        let file_path = dir.path().join("legacy-attach.bin");
        std::fs::write(&file_path, b"legacy-attachment-bytes").unwrap();
        let attachment_id = service
            .attach_file(credential.id, &file_path, true)
            .await
            .unwrap();

        // 升级后：行有 wrapped key、凭据数据可解回原值、附件往返成功
        let upgraded = service
            .get_credential(&credential.id)
            .await
            .unwrap()
            .unwrap();
        assert!(upgraded.wrapped_item_key.is_some());

        let data = service
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .unwrap();
        match data {
            CredentialData::Password(p) => assert_eq!(p.password, "legacy-pw"),
            other => panic!("unexpected credential data: {other:?}"),
        }

        let plain = service
            .retrieve_attachment(&attachment_id, true)
            .await
            .unwrap();
        assert_eq!(plain, b"legacy-attachment-bytes".to_vec());
    }

    // ------------------------------------------------------------------
    // update_credential_data：编辑密文 payload（复用原 item key）
    // ------------------------------------------------------------------

    /// 编辑 payload 的核心不变量：wrapped_item_key 字节不动，新 payload 走
    /// 同一 item key 重封，已挂附件仍可解密，item history 落 Updated 行。
    #[tokio::test]
    async fn update_credential_data_reuses_item_key_and_keeps_attachments() {
        let (db, mut service) = unlocked_service().await;

        let identity = service
            .create_identity("Edit Owner".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credential = seed_credential(
            &service,
            identity.id,
            "edit target",
            CredentialType::Password,
        )
        .await;
        let wrapped_before = credential.wrapped_item_key.clone().unwrap();

        // 先挂一个加密附件（用当前 item key 封存）
        let dir = tempfile::tempdir().unwrap();
        service
            .init_attachment_storage(dir.path(), db.clone())
            .await
            .unwrap();
        let file_path = dir.path().join("edit-attach.bin");
        std::fs::write(&file_path, b"attachment-before-edit").unwrap();
        let attachment_id = service
            .attach_file(credential.id, &file_path, true)
            .await
            .unwrap();

        // 编辑 payload
        let edited = CredentialData::Password(PasswordCredentialData {
            password: "rotated-secret".to_string(),
            email: Some("edited@example.com".to_string()),
            security_questions: vec![],
        });
        let updated = service
            .update_credential_data(&credential.id, &edited)
            .await
            .unwrap();

        // wrapped key 字节不变（附件不变量的硬保障）
        assert_eq!(
            updated.wrapped_item_key.as_deref(),
            Some(&wrapped_before[..])
        );

        // 新 payload 读回逐字保留
        let data = service
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .unwrap();
        match data {
            CredentialData::Password(p) => {
                assert_eq!(p.password, "rotated-secret");
                assert_eq!(p.email.as_deref(), Some("edited@example.com"));
            }
            other => panic!("unexpected credential data: {other:?}"),
        }

        // 附件仍可解密（同一 item key）
        let plain = service
            .retrieve_attachment(&attachment_id, true)
            .await
            .unwrap();
        assert_eq!(plain, b"attachment-before-edit".to_vec());

        // item history 落 Updated 行（created + updated 至少两行）
        let history = service
            .get_entity_history(EntityType::Credential, &credential.id)
            .await
            .unwrap();
        assert!(history.iter().any(|e| e.change_type == ChangeType::Updated));
    }

    /// legacy 行（wrapped_item_key NULL）编辑 payload 时升级为 per-item key：
    /// 升级后新密文走 item key 解密、行获得 wrapped key。
    #[tokio::test]
    async fn update_credential_data_upgrades_legacy_row_to_item_key() {
        let (db, service) = unlocked_service().await;

        let identity = service
            .create_identity("Legacy Edit Owner".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // 手工构造 legacy 行（同 attach 升级测试的模式）
        let master = service.get_master_encryption_service().unwrap();
        let plaintext = CredentialData::Password(PasswordCredentialData {
            password: "legacy-pw".to_string(),
            email: None,
            security_questions: vec![],
        })
        .to_bytes()
        .unwrap();
        let sealed = master.encrypt(&plaintext).unwrap();
        let credential = Credential::new(
            identity.id,
            "legacy edit row".to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            sealed,
            None,
        );
        let credentials = crate::storage::CredentialRepository::new(db.clone());
        credentials.create(&credential).await.unwrap();

        let edited = CredentialData::Password(PasswordCredentialData {
            password: "edited-pw".to_string(),
            email: None,
            security_questions: vec![],
        });
        let updated = service
            .update_credential_data(&credential.id, &edited)
            .await
            .unwrap();
        assert!(updated.wrapped_item_key.is_some());

        // 新密文走 item key 路径解密（legacy 分支不再命中）
        let data = service
            .get_credential_data(&credential.id)
            .await
            .unwrap()
            .unwrap();
        match data {
            CredentialData::Password(p) => assert_eq!(p.password, "edited-pw"),
            other => panic!("unexpected credential data: {other:?}"),
        }
    }

    /// 编辑不存在的凭据报 InvalidInput（而非静默成功）。
    #[tokio::test]
    async fn update_credential_data_rejects_unknown_id() {
        let (_db, service) = unlocked_service().await;
        let err = service
            .update_credential_data(
                &Uuid::new_v4(),
                &CredentialData::Password(PasswordCredentialData {
                    password: "x".to_string(),
                    email: None,
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found"), "unexpected error: {err}");
    }

    /// 凭据删除级联清附件：blob 元数据随行消失，不留不可解密的孤儿。
    #[tokio::test]
    async fn delete_credential_cascades_attachments() {
        let (db, mut service) = unlocked_service().await;

        let identity = service
            .create_identity("Cascade Attach".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let credential = seed_credential(
            &service,
            identity.id,
            "cascade attach",
            CredentialType::Password,
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        service
            .init_attachment_storage(dir.path(), db)
            .await
            .unwrap();

        let file_path = dir.path().join("cascade.bin");
        std::fs::write(&file_path, b"cascade-bytes").unwrap();
        let attachment_id = service
            .attach_file(credential.id, &file_path, true)
            .await
            .unwrap();
        assert_eq!(
            service.get_attachments(&credential.id).await.unwrap().len(),
            1
        );

        assert!(service.delete_credential(&credential.id).await.unwrap());

        assert!(service
            .get_attachments(&credential.id)
            .await
            .unwrap()
            .is_empty());
        assert!(service
            .retrieve_attachment(&attachment_id, true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_get_user_sessions_without_current_user_is_empty() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let service = PersonaService::new(db).await.unwrap();
        assert!(service.get_user_sessions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_session_tracking_paths_with_injected_session() {
        let (_db, service) = unlocked_service().await;

        // An expired session registered with the auto-lock manager, injected
        // as the current session id, drives the auto-locked error branch.
        let expired = crate::auth::session::Session::new(
            service.current_user.unwrap().to_string(),
            std::time::Duration::from_secs(0),
        );
        let session_id = expired.id.clone();
        service
            .auto_lock_manager
            .add_session(expired)
            .await
            .unwrap();
        *service.current_session_id.write().await = Some(session_id.clone());

        assert!(service.is_session_locked().await);

        let err = service
            .create_identity("locked-work".to_string(), IdentityType::Personal)
            .await;
        let err_text = format!("{:#}", err.unwrap_err());
        assert!(err_text.contains("auto-locked") || err_text.contains("Session is auto-locked"));

        // Activity updates with a session registered do not error, and
        // needs_reauth consults the manager through the same branch.
        service.update_auto_lock_activity().await.unwrap();
        service.update_sensitive_auto_lock_activity().await.unwrap();
        let _ = service.needs_reauth().await;

        // A live session keeps the service usable and hits the Some(session)
        // arm again after replacing the injected id.
        let live = crate::auth::session::Session::new(
            "session-user".to_string(),
            std::time::Duration::from_secs(3600),
        );
        let live_id = live.id.clone();
        service.auto_lock_manager.add_session(live).await.unwrap();
        *service.current_session_id.write().await = Some(live_id);
        service.update_auto_lock_activity().await.unwrap();
        service.update_sensitive_auto_lock_activity().await.unwrap();
        assert!(!service.needs_reauth().await);
    }

    #[tokio::test]
    async fn test_get_identity_by_name_and_id_record_audit() {
        let (db, service) = unlocked_service().await;
        let created = service
            .create_identity("audited-identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        let by_name = service
            .get_identity_by_name("audited-identity")
            .await
            .unwrap()
            .expect("identity found by name");
        assert_eq!(by_name.id, created.id);

        let by_id = service
            .get_identity(&created.id)
            .await
            .unwrap()
            .expect("identity found by id");
        assert_eq!(by_id.id, created.id);

        let missing = service
            .get_identity_by_name("no-such-identity")
            .await
            .unwrap();
        assert!(missing.is_none());

        // Two IdentityViewed audit entries were recorded for the found reads.
        let repo = crate::storage::AuditLogRepository::new(db.clone());
        let logs = repo
            .find_by_action(&AuditAction::IdentityViewed)
            .await
            .unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_get_credentials_for_identity_lists_seed() {
        let (_db, service) = unlocked_service().await;
        let identity = service
            .create_identity("cred-listing".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        seed_credential(&service, identity.id, "listed", CredentialType::Password).await;

        let creds = service
            .get_credentials_for_identity(&identity.id)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].name, "listed");
    }

    #[tokio::test]
    async fn test_get_identities_surface_and_unknown_identity_returns_none() {
        let (_db, service) = unlocked_service().await;
        let created = service
            .create_identity("listed-surface".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // get_identities lists everything, including the fresh identity.
        let all = service.get_identities().await.unwrap();
        assert!(all.iter().any(|i| i.id == created.id));

        // A lookup by an unknown id yields None without an audit entry.
        assert!(service
            .get_identity(&Uuid::new_v4())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_create_passkey_full_preserves_supplied_user_handle() {
        let (_db, service) = unlocked_service().await;
        let identity = service
            .create_identity("handle-full".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        let client_data =
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
        let handle = vec![1u8, 2, 3, 4];
        let creation = service
            .create_passkey_full(
                identity.id,
                "example.com".to_string(),
                "https://example.com",
                client_data,
                Some(handle.clone()),
                Some("alice@example.com".to_string()),
                None,
                false,
            )
            .await
            .unwrap();

        // The caller-supplied handle is stored verbatim instead of a random one.
        assert_eq!(creation.item.user_handle, handle);
        assert_eq!(
            creation.item.user_name.as_deref(),
            Some("alice@example.com")
        );
        assert!(!creation.item.uv_initialized);
        assert!(!creation.attestation_object.is_empty());
    }
    #[tokio::test]
    async fn test_query_audit_log_filter_branches() {
        let (_db, service) = unlocked_service().await;
        // The real user (already `current_user`): audit rows carry an FK to
        // user_auth, so only an existing user id can label the logs.
        let user_id = service.current_user.expect("initialize_user set the user");

        let identity = service
            .create_identity("Filter Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // Curated rows so every branch has deterministic data: a failure, a
        // security-sensitive success, and a plain success.
        service
            .log_audit(
                AuditAction::CredentialCreated,
                ResourceType::Credential,
                false,
                None,
                Some(identity.id),
                Some("seed failure".to_string()),
            )
            .await;
        service
            .log_audit(
                AuditAction::CredentialDecrypted,
                ResourceType::Credential,
                true,
                None,
                Some(identity.id),
                None,
            )
            .await;

        // user_id filter: dedicated query + in-memory re-check.
        let mine = service
            .query_audit_logs(AuditLogQuery {
                user_id: Some(user_id.to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!mine.is_empty());
        let uid_str = user_id.to_string();
        assert!(mine
            .iter()
            .all(|l| l.user_id.as_deref() == Some(uid_str.as_str())));

        let foreign = service
            .query_audit_logs(AuditLogQuery {
                user_id: Some("no-such-user".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(foreign.is_empty());

        // failures_only: dedicated query + the success-negation re-check.
        let failures = service
            .query_audit_logs(AuditLogQuery {
                failures_only: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!failures.is_empty());
        assert!(failures.iter().all(|l| !l.success));

        // security_sensitive_only: only the sensitive-action rows survive.
        let sensitive = service
            .query_audit_logs(AuditLogQuery {
                security_sensitive_only: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!sensitive.is_empty());
        assert!(sensitive.iter().all(|l| {
            SECURITY_SENSITIVE_AUDIT_ACTIONS.contains(&l.action.to_string().as_str())
        }));

        // Combined filter: the user branch stays the primary query while the
        // failure condition is re-checked in memory.
        let my_failures = service
            .query_audit_logs(AuditLogQuery {
                user_id: Some(user_id.to_string()),
                failures_only: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!my_failures.is_empty());
        assert!(my_failures
            .iter()
            .all(|l| !l.success && l.user_id.as_deref() == Some(uid_str.as_str())));

        // time_range: a window covering "now" matches (the existing suite
        // only checks the empty future window).
        let now = chrono::Utc::now();
        let in_window = service
            .query_audit_logs(AuditLogQuery {
                time_range: Some((
                    now - chrono::Duration::hours(1),
                    now + chrono::Duration::hours(1),
                )),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!in_window.is_empty());
    }

    #[tokio::test]
    async fn test_audit_query_statistics_and_cleanup() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let mut service = PersonaService::new(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();

        let identity = service
            .create_identity("Audit Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // 全量查询：初始化 + 建身份至少各留一条，且按时间降序
        let all = service
            .query_audit_logs(AuditLogQuery::default())
            .await
            .unwrap();
        assert!(!all.is_empty());
        assert!(
            all.windows(2).all(|w| w[0].timestamp >= w[1].timestamp),
            "audit logs must be ordered by timestamp desc"
        );

        // 按 identity 过滤
        let by_identity = service
            .query_audit_logs(AuditLogQuery {
                identity_id: Some(identity.id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!by_identity.is_empty());
        assert!(by_identity
            .iter()
            .all(|l| l.identity_id == Some(identity.id)));
        assert!(by_identity
            .iter()
            .any(|l| l.action.to_string() == "identity_created"));

        // action 过滤（走 find_by_action 主查询 + 内存复核）
        let created = service
            .query_audit_logs(AuditLogQuery {
                action: Some(AuditAction::IdentityCreated),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(created
            .iter()
            .all(|l| l.action.to_string() == "identity_created"));

        // limit 截断
        let limited = service
            .query_audit_logs(AuditLogQuery {
                limit: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(limited.len(), 1);

        // 统计
        let stats = service.audit_log_statistics().await.unwrap();
        assert!(stats.total_logs > 0);

        // 时间窗口放在未来 → 空
        let now = chrono::Utc::now();
        let future = service
            .query_audit_logs(AuditLogQuery {
                time_range: Some((
                    now + chrono::Duration::hours(1),
                    now + chrono::Duration::hours(2),
                )),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(future.is_empty());

        // 清理保留 0 天 → 删光
        let deleted = service.cleanup_audit_logs(0).await.unwrap();
        assert!(deleted > 0);
        let after = service
            .query_audit_logs(AuditLogQuery::default())
            .await
            .unwrap();
        assert!(after.is_empty());
    }

    // ---- favicon（feature = "favicon"）：编排与缓存语义 ----

    // ------------------------------------------------------------------
    // Watchtower 扩展规则（1Password 对齐）：软件许可到期 + 2FA available
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn scan_health_flags_expiring_software_license() {
        let (_db, service) = unlocked_service().await;
        let identity = service
            .create_identity("Watchtower Licenses".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let make_license = |valid_until: Option<String>| {
            CredentialData::SoftwareLicense(crate::models::credential::SoftwareLicenseData {
                license_key: "LICENSE-1".to_string(),
                version: None,
                publisher: None,
                purchase_date: None,
                order_number: None,
                support_email: None,
                download_url: None,
                seats: None,
                valid_until,
            })
        };

        // 快到期（ISO 文本）与远未到期（点分文本）各一条；另留一条到期日
        // 不可解析的自由文本——必须静默跳过而不是报错。
        let soon = (chrono::Utc::now() + chrono::Duration::days(10))
            .format("%Y-%m-%d")
            .to_string();
        let far = (chrono::Utc::now() + chrono::Duration::days(400))
            .format("%d.%m.%Y")
            .to_string();
        service
            .create_credential(
                identity.id,
                "JetBrains".to_string(),
                CredentialType::SoftwareLicense,
                SecurityLevel::Medium,
                &make_license(Some(soon)),
            )
            .await
            .unwrap();
        service
            .create_credential(
                identity.id,
                "Perpetual Tool".to_string(),
                CredentialType::SoftwareLicense,
                SecurityLevel::Medium,
                &make_license(Some(far)),
            )
            .await
            .unwrap();
        service
            .create_credential(
                identity.id,
                "Lifetime Deal".to_string(),
                CredentialType::SoftwareLicense,
                SecurityLevel::Medium,
                &make_license(Some("lifetime".to_string())),
            )
            .await
            .unwrap();

        let report = service
            .scan_health(HealthScanConfig::default())
            .await
            .unwrap();
        let expiring: Vec<&HealthIssue> = report
            .issues
            .iter()
            .filter(|i| matches!(i.kind, HealthIssueKind::ExpiringSoon { .. }))
            .collect();
        assert_eq!(expiring.len(), 1, "only the soon license is flagged");
        assert_eq!(expiring[0].credential_name, "JetBrains");
    }

    #[tokio::test]
    async fn scan_health_flags_two_factor_available_until_covered() {
        let (_db, service) = unlocked_service().await;
        let identity = service
            .create_identity("Watchtower 2FA".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // GitHub 登录（目录站点、无 TOTP）→ 应提示；内部站点不在目录 → 不提示。
        let mut github =
            seed_credential(&service, identity.id, "GitHub", CredentialType::Password).await;
        github.url = Some("https://github.com".to_string());
        service.update_credential(&github).await.unwrap();
        let mut intranet =
            seed_credential(&service, identity.id, "Intranet", CredentialType::Password).await;
        intranet.url = Some("https://internal.corp.local".to_string());
        service.update_credential(&intranet).await.unwrap();

        let report = service
            .scan_health(HealthScanConfig::default())
            .await
            .unwrap();
        let two_fa: Vec<&HealthIssue> = report
            .issues
            .iter()
            .filter(|i| matches!(i.kind, HealthIssueKind::TwoFactorAvailable { .. }))
            .collect();
        assert_eq!(two_fa.len(), 1);
        assert_eq!(two_fa[0].credential_name, "GitHub");
        match &two_fa[0].kind {
            HealthIssueKind::TwoFactorAvailable { site } => assert_eq!(site, "github.com"),
            other => panic!("wrong kind: {other:?}"),
        }

        // 存进 GitHub 的 TOTP 后再扫：提示消失（同站覆盖）。
        service
            .create_credential(
                identity.id,
                "GitHub TOTP".to_string(),
                CredentialType::TwoFactor,
                SecurityLevel::High,
                &CredentialData::TwoFactor(crate::models::credential::TwoFactorData {
                    secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                    issuer: "GitHub".to_string(),
                    account_name: "alice".to_string(),
                    algorithm: "SHA1".to_string(),
                    digits: 6,
                    period: 30,
                }),
            )
            .await
            .unwrap();
        // create_credential 无 url 参数：历史测试同款 update 路径补 url
        let mut totp = service
            .get_credentials_for_identity(&identity.id)
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.name == "GitHub TOTP")
            .expect("seeded TOTP credential");
        totp.url = Some("https://github.com".to_string());
        service.update_credential(&totp).await.unwrap();

        let report = service
            .scan_health(HealthScanConfig::default())
            .await
            .unwrap();
        assert!(
            !report
                .issues
                .iter()
                .any(|i| matches!(i.kind, HealthIssueKind::TwoFactorAvailable { .. })),
            "covering TOTP must quiet the 2FA-available issue"
        );
    }

    // ------------------------------------------------------------------
    // Password expiry policy + master password rotation
    // ------------------------------------------------------------------

    use crate::models::Workspace;
    use crate::storage::UserAuthRepository;

    /// Seed (or update) the workspace row's password expiry policy.
    async fn set_password_expiry(db: &Database, days: Option<u32>) {
        let repo = crate::storage::WorkspaceRepository::new(db.clone());
        let created;
        let mut ws = match Repository::find_all(&repo)
            .await
            .unwrap()
            .into_iter()
            .next()
        {
            Some(ws) => {
                created = false;
                ws
            }
            None => {
                created = true;
                Workspace::new("/tmp/persona-test", "test".to_string())
            }
        };
        ws.settings.password_expiry_days = days;
        ws.touch();
        if created {
            Repository::create(&repo, &ws).await.unwrap();
        } else {
            Repository::update(&repo, &ws).await.unwrap();
        }
    }

    /// Backdate `password_updated_at` so the password looks N days old.
    async fn backdate_password_updated_at(db: &Database, days_ago: u64) {
        let old = (chrono::Utc::now() - chrono::Duration::days(days_ago as i64)).to_rfc3339();
        sqlx::query("UPDATE user_auth SET password_updated_at = ?")
            .bind(old)
            .execute(db.pool())
            .await
            .unwrap();
    }

    /// Seal `data` directly under the master key (legacy row shape) and
    /// clear the wrapped key, converting the row to the legacy layout.
    async fn convert_credential_to_legacy(
        db: &Database,
        service: &PersonaService,
        credential_id: &Uuid,
    ) {
        let data = service
            .get_credential_data(credential_id)
            .await
            .unwrap()
            .expect("seeded credential exists");
        let master = service.get_master_encryption_service().unwrap();
        let ciphertext = master.encrypt(&data.to_bytes().unwrap()).unwrap();
        sqlx::query(
            "UPDATE credentials SET encrypted_data = ?, wrapped_item_key = NULL WHERE id = ?",
        )
        .bind(&ciphertext)
        .bind(credential_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    }

    /// Opt-in policy flags rotation at unlock; flag persists for the UI.
    #[tokio::test]
    async fn password_expiry_policy_flags_rotation_on_unlock() {
        let (db, mut service) = unlocked_service().await;
        set_password_expiry(&db, Some(90)).await;
        backdate_password_updated_at(&db, 91).await;

        let result = service.authenticate_user("master-pin").await.unwrap();
        assert_eq!(result, AuthResult::PasswordChangeRequired);

        let ua = UserAuthRepository::new(db.clone())
            .get_first()
            .await
            .unwrap()
            .unwrap();
        assert!(ua.password_change_required);
    }

    /// Fresh password inside the window still unlocks; no policy unlocks too.
    #[tokio::test]
    async fn password_expiry_policy_untouched_when_inside_window_or_absent() {
        let (db, mut service) = unlocked_service().await;
        set_password_expiry(&db, Some(90)).await;
        // password_updated_at == now (initialize_user stamped it)
        assert_eq!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::Success
        );

        // No policy at all (regression: default None never flags).
        let (db2, mut service2) = unlocked_service().await;
        assert_eq!(
            service2.authenticate_user("master-pin").await.unwrap(),
            AuthResult::Success
        );
        let ua = UserAuthRepository::new(db2.clone())
            .get_first()
            .await
            .unwrap()
            .unwrap();
        assert!(!ua.password_change_required);
    }

    /// Fail-open: unreadable workspace settings must never block unlock.
    #[tokio::test]
    async fn password_expiry_policy_fails_open_on_settings_error() {
        let (db, mut service) = unlocked_service().await;
        set_password_expiry(&db, Some(90)).await;
        backdate_password_updated_at(&db, 91).await;
        sqlx::query("DROP TABLE workspaces")
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::Success
        );
    }

    /// Full rotation: flags wrapped + legacy + passkey rows, swaps the hash,
    /// keeps the salt, keeps data readable, writes the audit entry.
    #[tokio::test]
    async fn change_master_password_rotates_wrapped_legacy_and_passkey_rows() {
        let (db, mut service) = unlocked_service().await;
        let identity = service
            .create_identity("main".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let wrapped_cred =
            seed_credential(&service, identity.id, "wrapped", CredentialType::Password).await;
        let legacy_cred =
            seed_credential(&service, identity.id, "legacy", CredentialType::Password).await;
        convert_credential_to_legacy(&db, &service, &legacy_cred.id).await;

        // A passkey row sealed under the current master key.
        let master = service.get_master_encryption_service().unwrap();
        let hierarchy = KeyHierarchy::new(master);
        let envelope = hierarchy.encrypt_with_new_item_key(&[7u8; 32]).unwrap();
        sqlx::query(
            "INSERT INTO passkeys (id, identity_id, rp_id, user_handle, credential_id, \
             encrypted_private_key, wrapped_item_key, public_key_cose, created_at) \
             VALUES (?, ?, 'example.com', x'0102', x'0304', ?, ?, x'0506', ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(identity.id.to_string())
        .bind(&envelope.ciphertext)
        .bind(&envelope.wrapped_key)
        .bind(chrono::Utc::now().timestamp())
        .execute(db.pool())
        .await
        .unwrap();

        let salt_before = UserAuthRepository::new(db.clone())
            .get_first()
            .await
            .unwrap()
            .unwrap()
            .master_key_salt
            .clone();

        // Forced-rotation flow: policy flags → rotate from locked state →
        // old password rejected, new one unlocks, all rows readable.
        set_password_expiry(&db, Some(90)).await;
        backdate_password_updated_at(&db, 91).await;
        assert_eq!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::PasswordChangeRequired
        );
        service
            .change_master_password("master-pin", "new-master-pin")
            .await
            .unwrap();

        assert_eq!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::InvalidCredentials
        );
        assert_eq!(
            service.authenticate_user("new-master-pin").await.unwrap(),
            AuthResult::Success
        );

        // Wrapped + legacy credentials both decrypt under the new master.
        match service
            .get_credential_data(&wrapped_cred.id)
            .await
            .unwrap()
            .expect("row exists")
        {
            CredentialData::Password(p) => assert_eq!(p.password, "pw"),
            other => panic!("unexpected credential data: {other:?}"),
        }
        match service
            .get_credential_data(&legacy_cred.id)
            .await
            .unwrap()
            .expect("row exists")
        {
            CredentialData::Password(p) => assert_eq!(p.password, "pw"),
            other => panic!("unexpected credential data: {other:?}"),
        }

        // Passkey item key unwraps under the new master with unchanged payload.
        let (stored_wrapped, stored_ct): (Vec<u8>, Vec<u8>) =
            sqlx::query_as("SELECT wrapped_item_key, encrypted_private_key FROM passkeys")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let hierarchy = KeyHierarchy::new(service.get_master_encryption_service().unwrap());
        assert_eq!(
            hierarchy
                .decrypt_with_wrapped_key(&stored_wrapped, &stored_ct)
                .unwrap(),
            vec![7u8; 32]
        );

        // Salt stable, flag cleared, timestamp advanced, audit written.
        let ua = UserAuthRepository::new(db.clone())
            .get_first()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ua.master_key_salt, salt_before);
        assert!(!ua.password_change_required);
        assert!(ua.password_updated_at.is_some());
        let audit_count: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE action = 'password_change'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(audit_count, 1);
    }

    /// Wrong old password: error, attempt recorded, zero bytes touched.
    #[tokio::test]
    async fn change_master_password_rejects_wrong_old_password() {
        let (db, mut service) = unlocked_service().await;
        let identity = service
            .create_identity("main".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let cred = seed_credential(&service, identity.id, "c", CredentialType::Password).await;
        let before: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
                .bind(cred.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        let hash_before: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
            .fetch_one(db.pool())
            .await
            .unwrap();

        let err = service
            .change_master_password("wrong-pin", "new-master-pin")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid current master password"));

        let after: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
                .bind(cred.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        let hash_after: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(hash_before, hash_after);
        let ua = UserAuthRepository::new(db.clone())
            .get_first()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ua.failed_attempts, 1);
        assert!(!ua.password_change_required);
        let _ = cred;
    }

    /// A row that fails to unwrap under the old key aborts the whole
    /// rotation; the transaction rolls back leaving every byte untouched.
    #[tokio::test]
    async fn change_master_password_rolls_back_on_rewrap_failure() {
        let (db, mut service) = unlocked_service().await;
        let identity = service
            .create_identity("main".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let _cred = seed_credential(&service, identity.id, "c", CredentialType::Password).await;

        // Passkey whose wrapped key cannot be unwrapped under the old master.
        let master = service.get_master_encryption_service().unwrap();
        let envelope = KeyHierarchy::new(master)
            .encrypt_with_new_item_key(&[7u8; 32])
            .unwrap();
        sqlx::query(
            "INSERT INTO passkeys (id, identity_id, rp_id, user_handle, credential_id, \
             encrypted_private_key, wrapped_item_key, public_key_cose, created_at) \
             VALUES (?, ?, 'example.com', x'0102', x'0304', ?, ?, x'0506', ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(identity.id.to_string())
        .bind(&envelope.ciphertext)
        .bind(vec![0xABu8; 40])
        .bind(chrono::Utc::now().timestamp())
        .execute(db.pool())
        .await
        .unwrap();

        let before: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
                .bind(_cred.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        let hash_before: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
            .fetch_one(db.pool())
            .await
            .unwrap();

        let err = service
            .change_master_password("master-pin", "new-master-pin")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Failed to unwrap item key"));

        let after: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_item_key FROM credentials WHERE id = ?")
                .bind(_cred.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        let hash_after: String = sqlx::query_scalar("SELECT master_password_hash FROM user_auth")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(before, after, "rollback must restore every byte");
        assert_eq!(hash_before, hash_after, "rollback must keep the old hash");
    }

    /// Validation: empty and unchanged new passwords are rejected up front.
    #[tokio::test]
    async fn change_master_password_validates_new_password() {
        let (_db, mut service) = unlocked_service().await;
        let err = service
            .change_master_password("master-pin", "")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
        let err = service
            .change_master_password("master-pin", "master-pin")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("must differ"));
    }

    // ------------------------------------------------------------------
    // Travel Mode（旅行模式）集成：enter 真移除 → exit 原样恢复
    // ------------------------------------------------------------------

    /// travel 测试夹具：解锁服务 + workspaces 行（travel_status/enter/exit
    /// 读写 settings 需要；unlocked_service 不建行）+ sidecar 目录。
    async fn travel_fixture() -> (tempfile::TempDir, Database, PersonaService) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db.clone()).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let ws_repo = crate::storage::WorkspaceRepository::new(db.clone());
        if Repository::find_all(&ws_repo).await.unwrap().is_empty() {
            Repository::create(
                &ws_repo,
                &crate::models::Workspace::new(dir.path(), "test".to_string()),
            )
            .await
            .unwrap();
        }
        (dir, db, service)
    }

    #[tokio::test]
    async fn travel_round_trip_moves_secrets_out_and_back() {
        let (dir, db, mut service) = travel_fixture().await;
        let db_path = dir.path().join("identities.db");

        let work = service
            .create_identity("work".to_string(), IdentityType::Work)
            .await
            .unwrap();
        let personal = service
            .create_identity("personal".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let cred = seed_credential(&service, work.id, "GitHub", CredentialType::Password).await;
        service.set_travel_marked(&work.id, true).await.unwrap();

        // 附件（密封 blob 落盘）+ passkey + 钱包族（raw SQL 造行）
        let att_dir = tempfile::tempdir().unwrap();
        service
            .init_attachment_storage(att_dir.path(), db.clone())
            .await
            .unwrap();
        let src = att_dir.path().join("doc.txt");
        std::fs::write(&src, b"sealed attachment bytes").unwrap();
        let att = service.attach_file(cred.id, &src, false).await.unwrap();
        let passkey = service
            .create_passkey(
                work.id,
                "example.com".to_string(),
                "https://example.com",
                br#"{"type":"webauthn.create","origin":"https://example.com","challenge":"Y2hhbGxlbmdl"}"#,
                Some(vec![1, 2]),
                None,
                None,
                false,
            )
            .await
            .unwrap();
        let wallet_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO crypto_wallets (id, identity_id, name, network, wallet_type, \
             encrypted_private_key, watch_only, security_level, created_at, updated_at) \
             VALUES (?, ?, 'w', 'ethereum', 'hd', x'0102', 0, 'High', ?, ?)",
        )
        .bind(wallet_id.to_string())
        .bind(work.id.to_string())
        .bind(now)
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO wallet_addresses (id, wallet_id, address, address_type, \
             \"index\", used, metadata, created_at) VALUES (?, ?, '0xabc', 'receive', 0, 0, '{}', ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(wallet_id.to_string())
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();

        // workspace active 指针指向被移除身份（enter 清除、exit 还原）
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(work.id.to_string())
            .execute(db.pool())
            .await
            .unwrap();

        // enter 前基线：密封字节、历史行、带 FK 引用的审计行
        let (wrapped_before, enc_before): (Vec<u8>, Option<Vec<u8>>) =
            sqlx::query_as("SELECT wrapped_item_key, encrypted_data FROM credentials WHERE id = ?")
                .bind(cred.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        let history_before: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM change_history")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let audit_fk_before: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE identity_id = ?")
                .bind(work.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(
            audit_fk_before >= 1,
            "fixture must have FK-bearing audit rows"
        );

        let status = service.travel_status(&db_path).await.unwrap();
        assert!(!status.active && !status.sidecar_exists && !status.inconsistent);

        let counts = service
            .enter_travel_mode(&db_path, "travel-secret")
            .await
            .unwrap();
        assert!(counts.identities >= 1);
        assert!(counts.credentials >= 1);
        assert!(counts.attachments >= 1);
        assert!(counts.passkeys >= 1);
        assert!(counts.wallets >= 1);
        assert!(counts.history_rows >= 1);
        assert_eq!(counts.files, 1);

        // 主库零痕迹：被标记身份与其全部从属行消失，未标记身份完好
        assert!(service
            .identity_repo
            .find_by_id(&work.id)
            .await
            .unwrap()
            .is_none());
        assert!(service
            .identity_repo
            .find_by_id(&personal.id)
            .await
            .unwrap()
            .is_some());
        let wallet_left: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM crypto_wallets WHERE identity_id = ?")
                .bind(work.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(wallet_left, 0);

        let status = service.travel_status(&db_path).await.unwrap();
        assert!(status.active && status.sidecar_exists && !status.inconsistent);
        assert!(status.entered_at.is_some());

        // active 指针已清除
        let active: Option<String> =
            sqlx::query_scalar("SELECT active_identity_id FROM workspaces LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(active, None);

        // audit FK 剥离：引用列空了，审计行本身留下（resource_id 仍存证）
        let audit_fk_after: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE identity_id = ?")
                .bind(work.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(audit_fk_after, 0);
        let audit_kept: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM audit_logs WHERE resource_id = ?")
                .bind(work.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(audit_kept >= 1, "audit rows survive with resource_id only");

        // travel 期间改密被拒（sidecar 里 wrapped key 是旧主密钥包的）
        let err = service
            .change_master_password("master-pin", "rotated-pin")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Travel mode is active"), "{err}");

        // ---- exit：错口令 sidecar 保留，行仍缺失 ----
        let err = service
            .exit_travel_mode(&db_path, "wrong-passphrase")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("passphrase is wrong"), "{err}");
        assert!(crate::travel::sidecar_path(&db_path).exists());
        assert!(service
            .identity_repo
            .find_by_id(&work.id)
            .await
            .unwrap()
            .is_none());

        // ---- exit：对口令原样恢复 ----
        let counts = service
            .exit_travel_mode(&db_path, "travel-secret")
            .await
            .unwrap();
        assert_eq!(counts.identities, 1);

        // 行字节级相等（wrapped_item_key/encrypted_data 原样）
        let (wrapped_after, enc_after): (Vec<u8>, Option<Vec<u8>>) =
            sqlx::query_as("SELECT wrapped_item_key, encrypted_data FROM credentials WHERE id = ?")
                .bind(cred.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(wrapped_after, wrapped_before);
        assert_eq!(enc_after, enc_before);

        // 原主密码可解
        match service
            .get_credential_data(&cred.id)
            .await
            .unwrap()
            .expect("credential restored")
        {
            CredentialData::Password(p) => assert_eq!(p.password, "pw"),
            other => panic!("unexpected credential data: {other:?}"),
        }

        // 附件文件与行恢复：解密回原字节
        assert_eq!(
            service.retrieve_attachment(&att, false).await.unwrap(),
            b"sealed attachment bytes"
        );

        // passkey 与钱包族恢复
        assert!(service.get_passkey(&passkey.id).await.unwrap().is_some());
        let wallets_back: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM crypto_wallets WHERE identity_id = ?")
                .bind(work.id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(wallets_back, 1);
        let addresses_back: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM wallet_addresses WHERE wallet_id = ?")
                .bind(wallet_id.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(addresses_back, 1);

        // change_history 随行走了一遭，总数不变
        let history_after: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM change_history")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(history_after, history_before);

        // active 指针还原、sidecar 已删、旗标复位
        let active: Option<String> =
            sqlx::query_scalar("SELECT active_identity_id FROM workspaces LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(active.as_deref(), Some(work.id.to_string().as_str()));
        assert!(!crate::travel::sidecar_path(&db_path).exists());
        let status = service.travel_status(&db_path).await.unwrap();
        assert!(!status.active && status.entered_at.is_none() && !status.inconsistent);
    }

    #[tokio::test]
    async fn travel_enter_rejects_unready_states() {
        let (dir, _db, service) = travel_fixture().await;
        let db_path = dir.path().join("identities.db");
        let identity = service
            .create_identity("a".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // 无被标记身份
        let err = service.enter_travel_mode(&db_path, "pw").await.unwrap_err();
        assert!(
            err.to_string().contains("no identities are marked"),
            "{err}"
        );

        // 空口令
        service.set_travel_marked(&identity.id, true).await.unwrap();
        let err = service.enter_travel_mode(&db_path, "").await.unwrap_err();
        assert!(
            err.to_string().contains("passphrase must not be empty"),
            "{err}"
        );

        // sidecar 已存在（崩溃窗口 1 的残留）：拒绝且不覆盖
        std::fs::write(crate::travel::sidecar_path(&db_path), b"leftover").unwrap();
        let err = service.enter_travel_mode(&db_path, "pw").await.unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(
            std::fs::read(crate::travel::sidecar_path(&db_path)).unwrap(),
            b"leftover"
        );
        std::fs::remove_file(crate::travel::sidecar_path(&db_path)).unwrap();

        // 已激活
        service.enter_travel_mode(&db_path, "pw").await.unwrap();
        let err = service.enter_travel_mode(&db_path, "pw").await.unwrap_err();
        assert!(err.to_string().contains("Travel mode is active"), "{err}");
    }

    #[tokio::test]
    async fn travel_set_marked_is_idempotent_and_audited() {
        let (_dir, db, service) = travel_fixture().await;
        let identity = service
            .create_identity("m".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        service.set_travel_marked(&identity.id, true).await.unwrap();
        // 重复标记同一状态：幂等成功且不再写审计
        service.set_travel_marked(&identity.id, true).await.unwrap();
        let fetched = service
            .identity_repo
            .find_by_id(&identity.id)
            .await
            .unwrap()
            .unwrap();
        assert!(fetched.travel_marked);

        service
            .set_travel_marked(&identity.id, false)
            .await
            .unwrap();
        let fetched = service
            .identity_repo
            .find_by_id(&identity.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!fetched.travel_marked);

        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM audit_logs WHERE action = 'travel_mark_changed'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(audits, 2, "only actual flips are audited");

        let err = service
            .set_travel_marked(&Uuid::new_v4(), true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[tokio::test]
    async fn travel_mode_blocks_master_password_change_until_exit() {
        let (dir, _db, mut service) = travel_fixture().await;
        let db_path = dir.path().join("identities.db");

        // 未激活对照：改密正常走
        service
            .change_master_password("master-pin", "master-pin-2")
            .await
            .unwrap();
        service
            .change_master_password("master-pin-2", "master-pin")
            .await
            .unwrap();

        let identity = service
            .create_identity("t".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        service.set_travel_marked(&identity.id, true).await.unwrap();
        service.enter_travel_mode(&db_path, "pw").await.unwrap();

        let err = service
            .change_master_password("master-pin", "rotated")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Travel mode is active"), "{err}");

        service.exit_travel_mode(&db_path, "pw").await.unwrap();
        service
            .change_master_password("master-pin", "rotated")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn travel_status_reports_inconsistent_when_sidecar_removed() {
        let (dir, _db, service) = travel_fixture().await;
        let db_path = dir.path().join("identities.db");
        let identity = service
            .create_identity("t".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        service.set_travel_marked(&identity.id, true).await.unwrap();

        // 未激活时 sidecar 缺失是正常态
        let status = service.travel_status(&db_path).await.unwrap();
        assert!(!status.active && !status.sidecar_exists && !status.inconsistent);

        service.enter_travel_mode(&db_path, "pw").await.unwrap();
        std::fs::remove_file(crate::travel::sidecar_path(&db_path)).unwrap();
        let status = service.travel_status(&db_path).await.unwrap();
        assert!(
            status.active && !status.sidecar_exists && status.inconsistent,
            "flag says active but the only copy of the data is gone"
        );
    }

    /// favicon_cache 里仅被被移除凭据引用的 host 随 enter 清除；
    /// 仍被保留凭据（或同 host 多凭据）引用的 host 保留。
    #[cfg(feature = "favicon")]
    #[tokio::test]
    async fn travel_enter_prunes_favicon_hosts_only_when_unreferenced() {
        let (dir, db, service) = travel_fixture().await;
        let db_path = dir.path().join("identities.db");

        let marked_i = service
            .create_identity("rm".to_string(), IdentityType::Personal)
            .await
            .unwrap();
        let kept_i = service
            .create_identity("keep".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        let doomed =
            seed_credential(&service, marked_i.id, "doomed", CredentialType::Password).await;
        let mut doomed = doomed;
        doomed.url = Some("https://doomed.example.com/login".to_string());
        service.update_credential(&doomed).await.unwrap();
        // 被移除身份上的第二个凭据与保留凭据同 host：kept host 必须活下来
        let alt = seed_credential(&service, marked_i.id, "alt", CredentialType::Password).await;
        let mut alt = alt;
        alt.url = Some("https://kept.example.com/alt".to_string());
        service.update_credential(&alt).await.unwrap();
        let kept = seed_credential(&service, kept_i.id, "kept", CredentialType::Password).await;
        let mut kept = kept;
        kept.url = Some("https://kept.example.com/".to_string());
        service.update_credential(&kept).await.unwrap();

        for host in ["doomed.example.com", "kept.example.com"] {
            sqlx::query(
                "INSERT INTO favicon_cache (host, mime_type, data, created_at, updated_at) \
                 VALUES (?, 'image/png', x'89504e47', '2026-01-01', '2026-01-01')",
            )
            .bind(host)
            .execute(db.pool())
            .await
            .unwrap();
        }

        service.set_travel_marked(&marked_i.id, true).await.unwrap();
        service.enter_travel_mode(&db_path, "pw").await.unwrap();

        let doomed_left: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM favicon_cache WHERE host = 'doomed.example.com'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let kept_left: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM favicon_cache WHERE host = 'kept.example.com'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(doomed_left, 0, "unreferenced host must be pruned");
        assert_eq!(
            kept_left, 1,
            "host still referenced by kept credentials stays"
        );
    }

    #[cfg(all(test, feature = "favicon"))]
    mod favicon_tests {
        use super::*;
        use crate::favicon::FaviconFetcher;
        use std::sync::{Arc, Mutex};

        const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfake-icon";

        async fn unlocked_service() -> PersonaService {
            let db = Database::in_memory().await.unwrap();
            db.migrate().await.unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            let salt = service.generate_salt();
            service.unlock("test_password", &salt).unwrap();
            service
        }

        /// 恒 200 + PNG 的 fake favicon 源；返回注入用 base 与请求计数。
        async fn spawn_fake() -> (String, Arc<Mutex<usize>>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(Mutex::new(0usize));
            let counter = hits.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    let counter = counter.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 8192];
                        let _ = socket.read(&mut buf).await;
                        *counter.lock().unwrap() += 1;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            PNG.len()
                        );
                        let mut out = response.into_bytes();
                        out.extend_from_slice(PNG);
                        let _ = socket.write_all(&out).await;
                    });
                }
            });
            (format!("http://{addr}/"), hits)
        }

        async fn credential_with_url(
            service: &PersonaService,
            name: &str,
            url: Option<&str>,
        ) -> Credential {
            let identity = service
                .create_identity(format!("Identity for {name}"), IdentityType::Personal)
                .await
                .unwrap();
            let data = CredentialData::Password(PasswordCredentialData {
                password: "pw".to_string(),
                email: None,
                security_questions: vec![],
            });
            let mut credential = service
                .create_credential(
                    identity.id,
                    name.to_string(),
                    CredentialType::Password,
                    SecurityLevel::High,
                    &data,
                )
                .await
                .unwrap();
            credential.url = url.map(str::to_string);
            service.update_credential(&credential).await.unwrap()
        }

        #[tokio::test]
        async fn fetch_caches_and_serves_second_call_without_network() {
            let service = unlocked_service().await;
            let credential =
                credential_with_url(&service, "Site", Some("https://Example.COM/a")).await;
            let (base, hits) = spawn_fake().await;
            let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);

            let first = service
                .fetch_favicon_for_credential(&credential.id, &fetcher)
                .await
                .unwrap();
            assert_eq!(first.host, "example.com");
            assert_eq!(first.mime_type, "image/png");
            assert_eq!(first.data, PNG);
            assert_eq!(*hits.lock().unwrap(), 1);

            // 二次请求走缓存：host 归一后命中，不再外联
            let second = service
                .fetch_favicon_for_credential(&credential.id, &fetcher)
                .await
                .unwrap();
            assert_eq!(second.created_at, first.created_at);
            assert_eq!(*hits.lock().unwrap(), 1);
        }

        #[tokio::test]
        async fn fetch_shares_cache_across_credentials_of_same_host() {
            let service = unlocked_service().await;
            let a = credential_with_url(&service, "A", Some("https://a.com")).await;
            let b = credential_with_url(&service, "B", Some("a.com")).await; // 裸域名同 host
            let (base, hits) = spawn_fake().await;
            let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);

            service
                .fetch_favicon_for_credential(&a.id, &fetcher)
                .await
                .unwrap();
            let entry = service
                .fetch_favicon_for_credential(&b.id, &fetcher)
                .await
                .unwrap();

            assert_eq!(entry.host, "a.com");
            assert_eq!(*hits.lock().unwrap(), 1, "同 host 第二条凭据必须共享缓存");
        }

        #[tokio::test]
        async fn fetch_rejects_credential_without_url() {
            let service = unlocked_service().await;
            let credential = credential_with_url(&service, "NoUrl", None).await;
            let fetcher = FaviconFetcher::new().unwrap();

            let err = service
                .fetch_favicon_for_credential(&credential.id, &fetcher)
                .await
                .unwrap_err();
            assert!(
                err.downcast_ref::<PersonaError>()
                    .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
                "got: {err}"
            );
        }

        #[tokio::test]
        async fn fetch_rejects_unknown_credential() {
            let service = unlocked_service().await;
            let fetcher = FaviconFetcher::new().unwrap();

            let err = service
                .fetch_favicon_for_credential(&Uuid::new_v4(), &fetcher)
                .await
                .unwrap_err();
            assert!(
                err.downcast_ref::<PersonaError>()
                    .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
                "got: {err}"
            );
        }

        #[tokio::test]
        async fn fetch_rejects_non_https_url() {
            let service = unlocked_service().await;
            let credential =
                credential_with_url(&service, "Http", Some("http://example.com")).await;
            let (base, hits) = spawn_fake().await;
            let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);

            let err = service
                .fetch_favicon_for_credential(&credential.id, &fetcher)
                .await
                .unwrap_err();
            assert!(
                err.downcast_ref::<PersonaError>()
                    .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
                "got: {err}"
            );
            assert_eq!(*hits.lock().unwrap(), 0, "SSRF 拒绝后绝不外联");
        }

        #[tokio::test]
        async fn fetch_requires_unlock() {
            let db = Database::in_memory().await.unwrap();
            db.migrate().await.unwrap();
            let service = PersonaService::new(db).await.unwrap();
            let fetcher = FaviconFetcher::new().unwrap();

            let err = service
                .fetch_favicon_for_credential(&Uuid::new_v4(), &fetcher)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("Service is locked"), "got: {err}");
        }

        #[tokio::test]
        async fn get_cached_favicons_dedupes_and_returns_hits_only() {
            let service = unlocked_service().await;
            let credential = credential_with_url(&service, "Cached", Some("https://a.com")).await;
            let (base, hits) = spawn_fake().await;
            let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);
            service
                .fetch_favicon_for_credential(&credential.id, &fetcher)
                .await
                .unwrap();

            // 大小写/空白归一去重；b.com 未缓存不出现
            let entries = service
                .get_cached_favicons(&[
                    "A.COM".to_string(),
                    " a.com ".to_string(),
                    "b.com".to_string(),
                ])
                .await
                .unwrap();

            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].host, "a.com");
            assert_eq!(*hits.lock().unwrap(), 1, "批量读绝不外联");
        }

        #[tokio::test]
        async fn get_cached_favicons_enforces_limit() {
            let service = unlocked_service().await;
            let hosts: Vec<String> = (0..=MAX_HOSTS_PER_REQUEST)
                .map(|i| format!("h{i}.com"))
                .collect();
            let err = service.get_cached_favicons(&hosts).await.unwrap_err();
            assert!(
                err.downcast_ref::<PersonaError>()
                    .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
                "got: {err}"
            );
        }

        #[tokio::test]
        async fn get_cached_favicons_requires_unlock() {
            let db = Database::in_memory().await.unwrap();
            db.migrate().await.unwrap();
            let service = PersonaService::new(db).await.unwrap();

            let err = service
                .get_cached_favicons(&["a.com".to_string()])
                .await
                .unwrap_err();
            assert!(err.to_string().contains("Service is locked"), "got: {err}");
        }
    }
}
