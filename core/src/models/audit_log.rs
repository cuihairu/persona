use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Audit log entry
/// Records every security-relevant operation in the system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditLog {
    /// Unique identifier
    pub id: Uuid,

    /// User ID (optional; some system operations have no user)
    pub user_id: Option<String>,

    /// Identity ID (optional; the identity the operation touches)
    pub identity_id: Option<Uuid>,

    /// Credential ID (optional; the credential the operation touches)
    pub credential_id: Option<Uuid>,

    /// Session ID (optional; the session the operation happened in)
    pub session_id: Option<String>,

    /// Operation type
    pub action: AuditAction,

    /// Resource type
    pub resource_type: ResourceType,

    /// Resource ID (optional)
    pub resource_id: Option<String>,

    /// Client IP address
    pub ip_address: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Whether the operation succeeded
    pub success: bool,

    /// Error message (only on failure)
    pub error_message: Option<String>,

    /// Extra metadata
    pub metadata: HashMap<String, String>,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Audit operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication
    Login,
    Logout,
    LoginFailed,
    SessionExpired,
    SessionLocked,
    SessionUnlocked,
    PasswordChange,
    MfaEnabled,
    MfaDisabled,

    // Identity management
    IdentityCreated,
    IdentityUpdated,
    IdentityDeleted,
    IdentityViewed,
    IdentitySwitched,

    // Credential management
    CredentialCreated,
    CredentialUpdated,
    CredentialRestored,
    CredentialDeleted,
    CredentialViewed,
    CredentialDecrypted,
    CredentialExported,

    // Passkey (WebAuthn)
    PasskeyCreated,
    PasskeyViewed,
    PasskeyAsserted,
    PasskeyDeleted,
    PasskeyExported,

    // Workspace management
    WorkspaceCreated,
    WorkspaceUpdated,
    WorkspaceDeleted,
    WorkspaceEntered,
    WorkspaceLeft,

    // System operations
    DatabaseMigration,
    BackupCreated,
    BackupRestored,
    ConfigurationChanged,

    // Travel mode
    TravelModeEntered,
    TravelModeExited,
    TravelMarkChanged,

    // Connect automation endpoints (CONNECT_AUTOMATION_DESIGN; Used is rate
    // limited so it does not flood the log)
    ConnectTokenCreated,
    ConnectTokenRevoked,
    ConnectTokenUsed,

    // Security events
    SecurityScanPerformed,
    UnauthorizedAccess,
    BruteForceDetected,
    SuspiciousActivity,
    DataExfiltration,

    // Custom operations
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
            AuditAction::CredentialRestored => "credential_restored",
            AuditAction::CredentialDeleted => "credential_deleted",
            AuditAction::CredentialViewed => "credential_viewed",
            AuditAction::CredentialDecrypted => "credential_decrypted",
            AuditAction::CredentialExported => "credential_exported",
            AuditAction::PasskeyCreated => "passkey_created",
            AuditAction::PasskeyViewed => "passkey_viewed",
            AuditAction::PasskeyAsserted => "passkey_asserted",
            AuditAction::PasskeyDeleted => "passkey_deleted",
            AuditAction::PasskeyExported => "passkey_exported",
            AuditAction::WorkspaceCreated => "workspace_created",
            AuditAction::WorkspaceUpdated => "workspace_updated",
            AuditAction::WorkspaceDeleted => "workspace_deleted",
            AuditAction::WorkspaceEntered => "workspace_entered",
            AuditAction::WorkspaceLeft => "workspace_left",
            AuditAction::DatabaseMigration => "database_migration",
            AuditAction::BackupCreated => "backup_created",
            AuditAction::BackupRestored => "backup_restored",
            AuditAction::ConfigurationChanged => "configuration_changed",
            AuditAction::TravelModeEntered => "travel_mode_entered",
            AuditAction::TravelModeExited => "travel_mode_exited",
            AuditAction::TravelMarkChanged => "travel_mark_changed",
            AuditAction::ConnectTokenCreated => "connect_token_created",
            AuditAction::ConnectTokenRevoked => "connect_token_revoked",
            AuditAction::ConnectTokenUsed => "connect_token_used",
            AuditAction::SecurityScanPerformed => "security_scan_performed",
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
            "session_locked" => Ok(AuditAction::SessionLocked),
            "session_unlocked" => Ok(AuditAction::SessionUnlocked),
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
            "credential_restored" => Ok(AuditAction::CredentialRestored),
            "credential_deleted" => Ok(AuditAction::CredentialDeleted),
            "credential_viewed" => Ok(AuditAction::CredentialViewed),
            "credential_decrypted" => Ok(AuditAction::CredentialDecrypted),
            "credential_exported" => Ok(AuditAction::CredentialExported),
            "passkey_created" => Ok(AuditAction::PasskeyCreated),
            "passkey_viewed" => Ok(AuditAction::PasskeyViewed),
            "passkey_asserted" => Ok(AuditAction::PasskeyAsserted),
            "passkey_deleted" => Ok(AuditAction::PasskeyDeleted),
            "passkey_exported" => Ok(AuditAction::PasskeyExported),
            "workspace_created" => Ok(AuditAction::WorkspaceCreated),
            "workspace_updated" => Ok(AuditAction::WorkspaceUpdated),
            "workspace_deleted" => Ok(AuditAction::WorkspaceDeleted),
            "workspace_entered" => Ok(AuditAction::WorkspaceEntered),
            "workspace_left" => Ok(AuditAction::WorkspaceLeft),
            "database_migration" => Ok(AuditAction::DatabaseMigration),
            "backup_created" => Ok(AuditAction::BackupCreated),
            "backup_restored" => Ok(AuditAction::BackupRestored),
            "configuration_changed" => Ok(AuditAction::ConfigurationChanged),
            "travel_mode_entered" => Ok(AuditAction::TravelModeEntered),
            "travel_mode_exited" => Ok(AuditAction::TravelModeExited),
            "travel_mark_changed" => Ok(AuditAction::TravelMarkChanged),
            "connect_token_created" => Ok(AuditAction::ConnectTokenCreated),
            "connect_token_revoked" => Ok(AuditAction::ConnectTokenRevoked),
            "connect_token_used" => Ok(AuditAction::ConnectTokenUsed),
            "security_scan_performed" => Ok(AuditAction::SecurityScanPerformed),
            "unauthorized_access" => Ok(AuditAction::UnauthorizedAccess),
            "brute_force_detected" => Ok(AuditAction::BruteForceDetected),
            "suspicious_activity" => Ok(AuditAction::SuspiciousActivity),
            "data_exfiltration" => Ok(AuditAction::DataExfiltration),
            other => Ok(AuditAction::Custom(other.to_string())),
        }
    }
}

/// Resource type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    User,
    Identity,
    Credential,
    Passkey,
    Workspace,
    Session,
    Configuration,
    Database,
    Backup,
    System,
    /// Connect automation endpoints (token lifecycle and usage auditing)
    Connect,
    Unknown,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let resource_str = match self {
            ResourceType::User => "user",
            ResourceType::Identity => "identity",
            ResourceType::Credential => "credential",
            ResourceType::Passkey => "passkey",
            ResourceType::Workspace => "workspace",
            ResourceType::Session => "session",
            ResourceType::Configuration => "configuration",
            ResourceType::Database => "database",
            ResourceType::Backup => "backup",
            ResourceType::System => "system",
            ResourceType::Connect => "connect",
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
            "passkey" => Ok(ResourceType::Passkey),
            "workspace" => Ok(ResourceType::Workspace),
            "session" => Ok(ResourceType::Session),
            "configuration" => Ok(ResourceType::Configuration),
            "database" => Ok(ResourceType::Database),
            "backup" => Ok(ResourceType::Backup),
            "system" => Ok(ResourceType::System),
            "connect" => Ok(ResourceType::Connect),
            "unknown" => Ok(ResourceType::Unknown),
            _ => Err(format!("Unknown resource type: {}", s)),
        }
    }
}

impl AuditLog {
    /// Create a new audit log entry
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

    /// Builder pattern: set the user ID
    pub fn with_user_id(mut self, user_id: Option<String>) -> Self {
        self.user_id = user_id;
        self
    }

    /// Builder pattern: set the identity ID
    pub fn with_identity_id(mut self, identity_id: Option<Uuid>) -> Self {
        self.identity_id = identity_id;
        self
    }

    /// Builder pattern: set the credential ID
    pub fn with_credential_id(mut self, credential_id: Option<Uuid>) -> Self {
        self.credential_id = credential_id;
        self
    }

    /// Builder pattern: set the session ID
    pub fn with_session_id(mut self, session_id: Option<String>) -> Self {
        self.session_id = session_id;
        self
    }

    /// Builder pattern: set the details
    pub fn with_details(mut self, details: Option<String>) -> Self {
        self.error_message = details; // details are stored in the error_message field
        self
    }

    /// Builder pattern: set the resource ID
    pub fn with_resource_id(mut self, resource_id: Option<String>) -> Self {
        self.resource_id = resource_id;
        self
    }

    /// Builder pattern: set the IP address
    pub fn with_ip_address(mut self, ip_address: Option<String>) -> Self {
        self.ip_address = ip_address;
        self
    }

    /// Builder pattern: set the user agent
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Builder pattern: set the error message
    pub fn with_error_message(mut self, error_message: Option<String>) -> Self {
        self.error_message = error_message;
        self
    }

    /// Builder pattern: add one metadata entry
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Builder pattern: set metadata in bulk
    pub fn with_metadata_map(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata.extend(metadata);
        self
    }

    /// Whether this is a security-sensitive operation
    pub fn is_security_sensitive(&self) -> bool {
        matches!(
            self.action,
            AuditAction::Login
                | AuditAction::LoginFailed
                | AuditAction::PasswordChange
                | AuditAction::SecurityScanPerformed
                | AuditAction::CredentialDecrypted
                | AuditAction::CredentialExported
                | AuditAction::PasskeyAsserted
                | AuditAction::PasskeyExported
                | AuditAction::UnauthorizedAccess
                | AuditAction::BruteForceDetected
                | AuditAction::SuspiciousActivity
                | AuditAction::DataExfiltration
        )
    }

    /// Whether this is a failed operation
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

    /// `AuditAction::Display` and `FromStr` must agree on every named variant,
    /// and unknown strings must fall back to `Custom`.
    #[test]
    fn test_audit_action_display_roundtrip_all_variants() {
        let actions = vec![
            AuditAction::Login,
            AuditAction::Logout,
            AuditAction::LoginFailed,
            AuditAction::SessionExpired,
            AuditAction::SessionLocked,
            AuditAction::SessionUnlocked,
            AuditAction::PasswordChange,
            AuditAction::MfaEnabled,
            AuditAction::MfaDisabled,
            AuditAction::IdentityCreated,
            AuditAction::IdentityUpdated,
            AuditAction::IdentityDeleted,
            AuditAction::IdentityViewed,
            AuditAction::IdentitySwitched,
            AuditAction::CredentialCreated,
            AuditAction::CredentialUpdated,
            AuditAction::CredentialDeleted,
            AuditAction::CredentialViewed,
            AuditAction::CredentialDecrypted,
            AuditAction::CredentialExported,
            AuditAction::PasskeyCreated,
            AuditAction::PasskeyViewed,
            AuditAction::PasskeyAsserted,
            AuditAction::PasskeyDeleted,
            AuditAction::PasskeyExported,
            AuditAction::WorkspaceCreated,
            AuditAction::WorkspaceUpdated,
            AuditAction::WorkspaceDeleted,
            AuditAction::WorkspaceEntered,
            AuditAction::WorkspaceLeft,
            AuditAction::DatabaseMigration,
            AuditAction::BackupCreated,
            AuditAction::BackupRestored,
            AuditAction::ConfigurationChanged,
            AuditAction::UnauthorizedAccess,
            AuditAction::BruteForceDetected,
            AuditAction::SuspiciousActivity,
            AuditAction::DataExfiltration,
        ];

        for action in actions {
            let text = action.to_string();
            assert_eq!(text.parse::<AuditAction>().unwrap(), action);
        }

        // Variants without a dedicated FromStr arm parse back as Custom.
        assert_eq!(
            "totally_new".parse::<AuditAction>().unwrap(),
            AuditAction::Custom("totally_new".to_string())
        );
    }

    #[test]
    fn test_audit_action_serde_snake_case() {
        // Every variant serializes to its snake_case name and back.
        let actions = vec![
            AuditAction::Login,
            AuditAction::Logout,
            AuditAction::LoginFailed,
            AuditAction::SessionExpired,
            AuditAction::SessionLocked,
            AuditAction::SessionUnlocked,
            AuditAction::PasswordChange,
            AuditAction::MfaEnabled,
            AuditAction::MfaDisabled,
            AuditAction::IdentityCreated,
            AuditAction::IdentityUpdated,
            AuditAction::IdentityDeleted,
            AuditAction::IdentityViewed,
            AuditAction::IdentitySwitched,
            AuditAction::CredentialCreated,
            AuditAction::CredentialUpdated,
            AuditAction::CredentialDeleted,
            AuditAction::CredentialViewed,
            AuditAction::CredentialDecrypted,
            AuditAction::CredentialExported,
            AuditAction::PasskeyCreated,
            AuditAction::PasskeyViewed,
            AuditAction::PasskeyAsserted,
            AuditAction::PasskeyDeleted,
            AuditAction::PasskeyExported,
            AuditAction::WorkspaceCreated,
            AuditAction::WorkspaceUpdated,
            AuditAction::WorkspaceDeleted,
            AuditAction::WorkspaceEntered,
            AuditAction::WorkspaceLeft,
            AuditAction::DatabaseMigration,
            AuditAction::BackupCreated,
            AuditAction::BackupRestored,
            AuditAction::ConfigurationChanged,
            AuditAction::UnauthorizedAccess,
            AuditAction::BruteForceDetected,
            AuditAction::SuspiciousActivity,
            AuditAction::DataExfiltration,
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let decoded: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, action);
        }

        // rename_all also applies to the externally tagged Custom variant.
        let custom = AuditAction::Custom("my_op".to_string());
        assert_eq!(
            serde_json::to_string(&custom).unwrap(),
            "{\"custom\":\"my_op\"}"
        );
        let decoded: AuditAction = serde_json::from_str("{\"custom\":\"my_op\"}").unwrap();
        assert_eq!(decoded, custom);

        // Unknown variant names are rejected on deserialize.
        assert!(serde_json::from_str::<AuditAction>("\"does_not_exist\"").is_err());
    }

    #[test]
    fn test_resource_type_serde_snake_case() {
        let types = vec![
            ResourceType::User,
            ResourceType::Identity,
            ResourceType::Credential,
            ResourceType::Passkey,
            ResourceType::Workspace,
            ResourceType::Session,
            ResourceType::Configuration,
            ResourceType::Database,
            ResourceType::Backup,
            ResourceType::System,
            ResourceType::Unknown,
        ];
        for resource_type in types {
            let json = serde_json::to_string(&resource_type).unwrap();
            let decoded: ResourceType = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, resource_type);
        }

        assert!(serde_json::from_str::<ResourceType>("\"galaxy\"").is_err());
    }

    #[test]
    fn test_resource_type_display_and_parse() {
        let types = vec![
            ResourceType::User,
            ResourceType::Identity,
            ResourceType::Credential,
            ResourceType::Passkey,
            ResourceType::Workspace,
            ResourceType::Session,
            ResourceType::Configuration,
            ResourceType::Database,
            ResourceType::Backup,
            ResourceType::System,
            ResourceType::Unknown,
        ];

        for resource_type in types {
            let text = resource_type.to_string();
            assert_eq!(text.parse::<ResourceType>().unwrap(), resource_type);
        }

        let err = "gadget".parse::<ResourceType>().unwrap_err();
        assert_eq!(err, "Unknown resource type: gadget");
    }

    #[test]
    fn test_audit_log_serde_roundtrip() {
        let log = AuditLog::new(AuditAction::LoginFailed, ResourceType::Session, false)
            .with_user_id(Some("user-1".to_string()))
            .with_identity_id(Some(Uuid::new_v4()))
            .with_credential_id(Some(Uuid::new_v4()))
            .with_session_id(Some("session-1".to_string()))
            .with_resource_id(Some("res-1".to_string()))
            .with_ip_address(Some("127.0.0.1".to_string()))
            .with_user_agent(Some("persona-cli/0.1".to_string()))
            .with_error_message(Some("boom".to_string()))
            .with_details(Some("details".to_string()))
            .with_metadata("key".to_string(), "value".to_string())
            .with_metadata_map(HashMap::from([("extra".to_string(), "data".to_string())]));

        // with_details overwrites with_error_message's value.
        assert_eq!(log.error_message, Some("details".to_string()));
        assert_eq!(log.metadata.get("key"), Some(&"value".to_string()));
        assert_eq!(log.metadata.get("extra"), Some(&"data".to_string()));

        let json = serde_json::to_string(&log).unwrap();
        let decoded: AuditLog = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, log);
    }

    #[test]
    fn test_security_sensitive_covers_all_flagged_actions() {
        let sensitive = vec![
            AuditAction::Login,
            AuditAction::LoginFailed,
            AuditAction::PasswordChange,
            AuditAction::SecurityScanPerformed,
            AuditAction::CredentialDecrypted,
            AuditAction::CredentialExported,
            AuditAction::PasskeyAsserted,
            AuditAction::PasskeyExported,
            AuditAction::UnauthorizedAccess,
            AuditAction::BruteForceDetected,
            AuditAction::SuspiciousActivity,
            AuditAction::DataExfiltration,
        ];
        for action in sensitive {
            let log = AuditLog::new(action, ResourceType::System, true);
            assert!(
                log.is_security_sensitive(),
                "{} should be sensitive",
                log.action
            );
        }

        let not_sensitive = vec![
            AuditAction::Logout,
            AuditAction::IdentityViewed,
            AuditAction::CredentialViewed,
            AuditAction::WorkspaceEntered,
            AuditAction::BackupCreated,
        ];
        for action in not_sensitive {
            let log = AuditLog::new(action, ResourceType::System, true);
            assert!(
                !log.is_security_sensitive(),
                "{} should not be sensitive",
                log.action
            );
        }
    }

    #[test]
    fn test_is_failure_flags_security_actions_even_on_success() {
        let flagged = vec![
            AuditAction::LoginFailed,
            AuditAction::UnauthorizedAccess,
            AuditAction::BruteForceDetected,
            AuditAction::SuspiciousActivity,
            AuditAction::DataExfiltration,
        ];
        for action in flagged {
            let log = AuditLog::new(action, ResourceType::System, true);
            assert!(log.is_failure(), "{} should count as failure", log.action);
        }

        // Plain success and plain failure.
        let success = AuditLog::new(AuditAction::Login, ResourceType::User, true);
        assert!(!success.is_failure());
        let failure = AuditLog::new(AuditAction::Logout, ResourceType::User, false);
        assert!(failure.is_failure());
    }

    // The Connect variant (added with the Connect automation batch) also goes
    // through a Display/parse roundtrip.
    #[test]
    fn test_resource_type_connect_display_and_parse() {
        let text = ResourceType::Connect.to_string();
        assert_eq!(text.parse::<ResourceType>().unwrap(), ResourceType::Connect);
    }

    // The remaining with_* slots of the builder chain (the first builder test
    // only touched the user/identity/metadata slots) get values one by one.
    #[test]
    fn test_audit_log_builder_full_chain() {
        let credential_id = Uuid::new_v4();
        let mut extra = std::collections::HashMap::new();
        extra.insert("scope".to_string(), "export".to_string());

        let log = AuditLog::new(AuditAction::CredentialCreated, ResourceType::Backup, true)
            .with_credential_id(Some(credential_id))
            .with_session_id(Some("sess-1".to_string()))
            .with_error_message(Some("boom".to_string()))
            .with_details(Some("full vault".to_string()))
            .with_resource_id(Some("bkp-9".to_string()))
            .with_ip_address(Some("127.0.0.1".to_string()))
            .with_user_agent(Some("persona-test".to_string()))
            .with_metadata_map(extra);

        assert_eq!(log.credential_id, Some(credential_id));
        assert_eq!(log.session_id.as_deref(), Some("sess-1"));
        // with_details and with_error_message share the same storage slot; the
        // details at the end of the chain overwrites the former
        assert_eq!(log.error_message.as_deref(), Some("full vault"));
        assert_eq!(log.resource_id.as_deref(), Some("bkp-9"));
        assert_eq!(log.ip_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(log.user_agent.as_deref(), Some("persona-test"));
        assert_eq!(
            log.metadata.get("scope"),
            Some(&"export".to_string()),
            "with_metadata_map merges alongside single-key inserts"
        );
    }
}
