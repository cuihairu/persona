use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// 审计日志条目
/// 用于记录系统中的所有安全相关操作
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditLog {
    /// 唯一标识符
    pub id: Uuid,

    /// 用户ID (可选，某些系统操作可能没有用户)
    pub user_id: Option<String>,

    /// 身份ID (可选，操作涉及的身份)
    pub identity_id: Option<Uuid>,

    /// 凭据ID (可选，操作涉及的凭据)
    pub credential_id: Option<Uuid>,

    /// 会话ID (可选，操作发生的会话)
    pub session_id: Option<String>,

    /// 操作类型
    pub action: AuditAction,

    /// 资源类型
    pub resource_type: ResourceType,

    /// 资源ID (可选)
    pub resource_id: Option<String>,

    /// 客户端IP地址
    pub ip_address: Option<String>,

    /// 用户代理字符串
    pub user_agent: Option<String>,

    /// 操作是否成功
    pub success: bool,

    /// 错误消息 (仅在失败时)
    pub error_message: Option<String>,

    /// 额外的元数据
    pub metadata: HashMap<String, String>,

    /// 时间戳
    pub timestamp: DateTime<Utc>,
}

/// 审计操作类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // 认证相关
    Login,
    Logout,
    LoginFailed,
    SessionExpired,
    SessionLocked,
    SessionUnlocked,
    PasswordChange,
    MfaEnabled,
    MfaDisabled,

    // 身份管理
    IdentityCreated,
    IdentityUpdated,
    IdentityDeleted,
    IdentityViewed,
    IdentitySwitched,

    // 凭据管理
    CredentialCreated,
    CredentialUpdated,
    CredentialDeleted,
    CredentialViewed,
    CredentialDecrypted,
    CredentialExported,

    // 工作区管理
    WorkspaceCreated,
    WorkspaceUpdated,
    WorkspaceDeleted,
    WorkspaceEntered,
    WorkspaceLeft,

    // 系统操作
    DatabaseMigration,
    BackupCreated,
    BackupRestored,
    ConfigurationChanged,

    // 安全事件
    UnauthorizedAccess,
    BruteForceDetected,
    SuspiciousActivity,
    DataExfiltration,

    // 自定义操作
    Custom(String),
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action_str = match self {
            AuditAction::Login => "login",
            AuditAction::Logout => "logout",
            AuditAction::LoginFailed => "login_failed",
            AuditAction::SessionExpired => "session_expired",
            AuditAction::SessionLocked => "session_locked",
            AuditAction::SessionUnlocked => "session_unlocked",
            AuditAction::PasswordChange => "password_change",
            AuditAction::MfaEnabled => "mfa_enabled",
            AuditAction::MfaDisabled => "mfa_disabled",
            AuditAction::IdentityCreated => "identity_created",
            AuditAction::IdentityUpdated => "identity_updated",
            AuditAction::IdentityDeleted => "identity_deleted",
            AuditAction::IdentityViewed => "identity_viewed",
            AuditAction::IdentitySwitched => "identity_switched",
            AuditAction::CredentialCreated => "credential_created",
            AuditAction::CredentialUpdated => "credential_updated",
            AuditAction::CredentialDeleted => "credential_deleted",
            AuditAction::CredentialViewed => "credential_viewed",
            AuditAction::CredentialDecrypted => "credential_decrypted",
            AuditAction::CredentialExported => "credential_exported",
            AuditAction::WorkspaceCreated => "workspace_created",
            AuditAction::WorkspaceUpdated => "workspace_updated",
            AuditAction::WorkspaceDeleted => "workspace_deleted",
            AuditAction::WorkspaceEntered => "workspace_entered",
            AuditAction::WorkspaceLeft => "workspace_left",
            AuditAction::DatabaseMigration => "database_migration",
            AuditAction::BackupCreated => "backup_created",
            AuditAction::BackupRestored => "backup_restored",
            AuditAction::ConfigurationChanged => "configuration_changed",
            AuditAction::UnauthorizedAccess => "unauthorized_access",
            AuditAction::BruteForceDetected => "brute_force_detected",
            AuditAction::SuspiciousActivity => "suspicious_activity",
            AuditAction::DataExfiltration => "data_exfiltration",
            AuditAction::Custom(action) => action,
        };
        write!(f, "{}", action_str)
    }
}

impl std::str::FromStr for AuditAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "login" => Ok(AuditAction::Login),
            "logout" => Ok(AuditAction::Logout),
            "login_failed" => Ok(AuditAction::LoginFailed),
            "session_expired" => Ok(AuditAction::SessionExpired),
            "password_change" => Ok(AuditAction::PasswordChange),
            "mfa_enabled" => Ok(AuditAction::MfaEnabled),
            "mfa_disabled" => Ok(AuditAction::MfaDisabled),
            "identity_created" => Ok(AuditAction::IdentityCreated),
            "identity_updated" => Ok(AuditAction::IdentityUpdated),
            "identity_deleted" => Ok(AuditAction::IdentityDeleted),
            "identity_viewed" => Ok(AuditAction::IdentityViewed),
            "identity_switched" => Ok(AuditAction::IdentitySwitched),
            "credential_created" => Ok(AuditAction::CredentialCreated),
            "credential_updated" => Ok(AuditAction::CredentialUpdated),
            "credential_deleted" => Ok(AuditAction::CredentialDeleted),
            "credential_viewed" => Ok(AuditAction::CredentialViewed),
            "credential_decrypted" => Ok(AuditAction::CredentialDecrypted),
            "credential_exported" => Ok(AuditAction::CredentialExported),
            "workspace_created" => Ok(AuditAction::WorkspaceCreated),
            "workspace_updated" => Ok(AuditAction::WorkspaceUpdated),
            "workspace_deleted" => Ok(AuditAction::WorkspaceDeleted),
            "workspace_entered" => Ok(AuditAction::WorkspaceEntered),
            "workspace_left" => Ok(AuditAction::WorkspaceLeft),
            "database_migration" => Ok(AuditAction::DatabaseMigration),
            "backup_created" => Ok(AuditAction::BackupCreated),
            "backup_restored" => Ok(AuditAction::BackupRestored),
            "configuration_changed" => Ok(AuditAction::ConfigurationChanged),
            "unauthorized_access" => Ok(AuditAction::UnauthorizedAccess),
            "brute_force_detected" => Ok(AuditAction::BruteForceDetected),
            "suspicious_activity" => Ok(AuditAction::SuspiciousActivity),
            "data_exfiltration" => Ok(AuditAction::DataExfiltration),
            other => Ok(AuditAction::Custom(other.to_string())),
        }
    }
}

/// 资源类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    User,
    Identity,
    Credential,
    Workspace,
    Session,
    Configuration,
    Database,
    Backup,
    System,
    Unknown,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let resource_str = match self {
            ResourceType::User => "user",
            ResourceType::Identity => "identity",
            ResourceType::Credential => "credential",
            ResourceType::Workspace => "workspace",
            ResourceType::Session => "session",
            ResourceType::Configuration => "configuration",
            ResourceType::Database => "database",
            ResourceType::Backup => "backup",
            ResourceType::System => "system",
            ResourceType::Unknown => "unknown",
        };
        write!(f, "{}", resource_str)
    }
}

impl std::str::FromStr for ResourceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(ResourceType::User),
            "identity" => Ok(ResourceType::Identity),
            "credential" => Ok(ResourceType::Credential),
            "workspace" => Ok(ResourceType::Workspace),
            "session" => Ok(ResourceType::Session),
            "configuration" => Ok(ResourceType::Configuration),
            "database" => Ok(ResourceType::Database),
            "backup" => Ok(ResourceType::Backup),
            "system" => Ok(ResourceType::System),
            "unknown" => Ok(ResourceType::Unknown),
            _ => Err(format!("Unknown resource type: {}", s)),
        }
    }
}

impl AuditLog {
    /// 创建新的审计日志条目
    pub fn new(action: AuditAction, resource_type: ResourceType, success: bool) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: None,
            identity_id: None,
            credential_id: None,
            session_id: None,
            action,
            resource_type,
            resource_id: None,
            ip_address: None,
            user_agent: None,
            success,
            error_message: None,
            metadata: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    /// 构建器模式：设置用户ID
    pub fn with_user_id(mut self, user_id: Option<String>) -> Self {
        self.user_id = user_id;
        self
    }

    /// 构建器模式：设置身份ID
    pub fn with_identity_id(mut self, identity_id: Option<Uuid>) -> Self {
        self.identity_id = identity_id;
        self
    }

    /// 构建器模式：设置凭据ID
    pub fn with_credential_id(mut self, credential_id: Option<Uuid>) -> Self {
        self.credential_id = credential_id;
        self
    }

    /// 构建器模式：设置会话ID
    pub fn with_session_id(mut self, session_id: Option<String>) -> Self {
        self.session_id = session_id;
        self
    }

    /// 构建器模式：设置详细信息
    pub fn with_details(mut self, details: Option<String>) -> Self {
        self.error_message = details; // 使用error_message字段存储详细信息
        self
    }

    /// 构建器模式：设置资源ID
    pub fn with_resource_id(mut self, resource_id: Option<String>) -> Self {
        self.resource_id = resource_id;
        self
    }

    /// 构建器模式：设置IP地址
    pub fn with_ip_address(mut self, ip_address: Option<String>) -> Self {
        self.ip_address = ip_address;
        self
    }

    /// 构建器模式：设置用户代理
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// 构建器模式：设置错误消息
    pub fn with_error_message(mut self, error_message: Option<String>) -> Self {
        self.error_message = error_message;
        self
    }

    /// 构建器模式：添加元数据
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// 构建器模式：批量设置元数据
    pub fn with_metadata_map(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata.extend(metadata);
        self
    }

    /// 是否是安全敏感操作
    pub fn is_security_sensitive(&self) -> bool {
        matches!(
            self.action,
            AuditAction::Login
                | AuditAction::LoginFailed
                | AuditAction::PasswordChange
                | AuditAction::CredentialDecrypted
                | AuditAction::CredentialExported
                | AuditAction::UnauthorizedAccess
                | AuditAction::BruteForceDetected
                | AuditAction::SuspiciousActivity
                | AuditAction::DataExfiltration
        )
    }

    /// 是否是失败操作
    pub fn is_failure(&self) -> bool {
        !self.success
            || matches!(
                self.action,
                AuditAction::LoginFailed
                    | AuditAction::UnauthorizedAccess
                    | AuditAction::BruteForceDetected
                    | AuditAction::SuspiciousActivity
                    | AuditAction::DataExfiltration
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_creation() {
        let log = AuditLog::new(AuditAction::Login, ResourceType::User, true);

        assert_eq!(log.action, AuditAction::Login);
        assert_eq!(log.resource_type, ResourceType::User);
        assert!(log.success);
        assert!(log.metadata.is_empty());
    }

    #[test]
    fn test_audit_log_builder() {
        let user_id = "test_user".to_string();
        let identity_id = Uuid::new_v4();

        let log = AuditLog::new(
            AuditAction::CredentialDecrypted,
            ResourceType::Credential,
            true,
        )
        .with_user_id(Some(user_id.clone()))
        .with_identity_id(Some(identity_id))
        .with_metadata("client".to_string(), "desktop".to_string());

        assert_eq!(log.user_id, Some(user_id));
        assert_eq!(log.identity_id, Some(identity_id));
        assert_eq!(log.metadata.get("client"), Some(&"desktop".to_string()));
        assert!(log.is_security_sensitive());
    }

    #[test]
    fn test_audit_action_serialization() {
        let action = AuditAction::CredentialCreated;
        let serialized = action.to_string();
        let deserialized: AuditAction = serialized.parse().unwrap();

        assert_eq!(action, deserialized);
    }

    #[test]
    fn test_resource_type_serialization() {
        let resource_type = ResourceType::Credential;
        let serialized = resource_type.to_string();
        let deserialized: ResourceType = serialized.parse().unwrap();

        assert_eq!(resource_type, deserialized);
    }

    #[test]
    fn test_custom_action() {
        let custom_action = AuditAction::Custom("custom_operation".to_string());
        let serialized = custom_action.to_string();
        let deserialized: AuditAction = serialized.parse().unwrap();

        assert_eq!(custom_action, deserialized);
    }

    #[test]
    fn test_security_sensitive_detection() {
        let sensitive_log = AuditLog::new(
            AuditAction::CredentialDecrypted,
            ResourceType::Credential,
            true,
        );

        let non_sensitive_log =
            AuditLog::new(AuditAction::IdentityViewed, ResourceType::Identity, true);

        assert!(sensitive_log.is_security_sensitive());
        assert!(!non_sensitive_log.is_security_sensitive());
    }

    #[test]
    fn test_failure_detection() {
        let failed_log = AuditLog::new(AuditAction::LoginFailed, ResourceType::User, false);

        let success_log = AuditLog::new(AuditAction::Login, ResourceType::User, true);

        assert!(failed_log.is_failure());
        assert!(!success_log.is_failure());
    }
}
