#[cfg(feature = "backup")]
use crate::travel::{TravelCounts, TravelStatus};
use crate::{
    auth::{
        AuthResult, AuthService, AutoLockEvent, AutoLockManager, BiometricPlatform,
        BiometricPrompt, BiometricProvider, MasterKeyService, MockBiometricProvider,
        MockRemoteAuthProvider, RemoteAuthChallenge, RemoteAuthProvider, RemoteAuthResult, Session,
        UserAuth,
    },
    authz::{authorize, denied_error, AuthzAction, AuthzContext, AuthzPrincipal, AuthzResource},
    breach::BreachChecker,
    connect::{ConnectItemType, ConnectTokenRow, ConnectTokenScope},
    crypto::{
        assert_passkey, random_bytes32, register_passkey, self_test_client_data, verify_assertion,
        EncryptionService, KeyHierarchy, Sha256Hasher, MASTER_KEY_PBKDF2_ITERATIONS,
    },
    custom_fields::{decode_custom_fields, encode_custom_fields, CUSTOM_FIELDS_METADATA_KEY},
    events::Emitter,
    health::{HealthIssue, HealthIssueKind, HealthReport, HealthScanConfig},
    models::{
        Attachment, AttachmentStats, AuditAction, AuditLog, ChangeHistory, ChangeHistoryQuery,
        ChangeHistoryStats, ChangeType, Credential, CredentialData, CredentialType, CustomField,
        EntityType, FaviconCacheEntry, Identity, IdentityType, PasskeyItem, ResourceType,
        SecurityLevel, MAX_HOSTS_PER_REQUEST,
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
    sync::snapshot::{SyncItemSnapshot, SyncPasskeySnapshot},
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

mod attachments;
mod audit;
mod auth;
mod connect;
mod credentials;
mod health;
mod history;
mod identity;
mod misc;
mod passkey;
mod session;
mod sync;
mod travel;

pub use self::audit::*;
#[allow(unused_imports)]
pub(crate) use self::auth::*;
pub use self::misc::*;
pub use self::passkey::*;

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

#[cfg(test)]
mod tests;
