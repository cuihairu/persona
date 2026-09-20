use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Persona workspace configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// Unique workspace ID
    pub id: Uuid,

    /// Workspace root path
    pub path: PathBuf,

    /// Workspace name
    pub name: String,

    /// Current active identity ID
    pub active_identity_id: Option<Uuid>,

    /// Workspace settings
    pub settings: WorkspaceSettings,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// 高级功能开关（1Password 式默认关闭、用户 opt-in）。
///
/// 主航道功能（凭据/统计/Watchtower）恒开，不在此列。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FeatureFlags {
    /// SSH agent（浏览器/终端经 socket 取钥签名）
    pub ssh_agent: bool,
    /// 钱包面板
    pub wallet: bool,
    /// Passkey 管理与审批服务端
    pub passkeys: bool,
    /// 站点 favicon 按需抓取与展示（隐私红线：唯一外联入口是详情面板
    /// "Fetch icon" 按钮，开 = 显示按钮与缓存图标，关 = 无网络行为）
    pub fetch_favicons: bool,
}

/// 可选同步服务器（persona-server Events API）的客户端配置。
///
/// `server_token` 为上报用的共享 Bearer 令牌。desktop 宿主把它存 OS
/// keyring（键为 vault db_path），本结构在 vault settings JSON 里恒写
/// 空串占位；读到非空值即 keyring 批次之前的 legacy 数据，宿主首次
/// 运行时一次性迁移进 keyring（THREAT_MODEL 已登记）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConfig {
    /// 是否把本地审计事件上报到 persona-server
    pub enabled: bool,
    /// 服务器 base_url（形如 `http://127.0.0.1:3000`，可带反代前缀）
    pub server_url: String,
    /// 共享 Bearer 令牌；desktop 宿主恒写空串（真值在 OS keyring），
    /// CLI 不落盘（env-only）；提交空串 = 保留旧值
    pub server_token: String,
}

/// Workspace configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    /// Enable encryption for sensitive data
    pub encryption_enabled: bool,

    /// Auto-backup interval in hours (0 = disabled)
    pub auto_backup_hours: u32,

    /// Maximum number of backups to keep
    pub backup_retention_count: u32,

    /// Session timeout in seconds
    pub session_timeout_seconds: u32,

    /// Require confirmation for destructive operations
    pub require_confirmation: bool,

    /// Default identity type for new identities
    pub default_identity_type: String,

    /// 高级功能开关（旧 JSON 缺键时回退全关）
    #[serde(default)]
    pub features: FeatureFlags,

    /// 可选同步服务器配置（旧 JSON 缺键时为 None）
    #[serde(default)]
    pub sync: Option<SyncConfig>,

    /// 主密码有效期（天）；None = 不过期（默认，NIST 取向：仅在用户
    /// 显式选择后强制轮换）。Some(days) 且超期时，解锁返回
    /// `AuthResult::PasswordChangeRequired` 引导改密（旧 JSON 缺键时为 None）
    #[serde(default)]
    pub password_expiry_days: Option<u32>,

    /// 界面语言（"zh-CN" / "en"；None = 客户端默认基准语言 zh-CN）
    #[serde(default)]
    pub locale: Option<String>,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            encryption_enabled: true,
            auto_backup_hours: 24,
            backup_retention_count: 7,
            session_timeout_seconds: 3600,
            require_confirmation: true,
            default_identity_type: "personal".to_string(),
            features: FeatureFlags::default(),
            sync: None,
            password_expiry_days: None,
            locale: None,
        }
    }
}

impl Workspace {
    /// Create a new workspace
    pub fn new<P: Into<PathBuf>>(path: P, name: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4(),
            path: path.into(),
            name,
            active_identity_id: None,
            settings: WorkspaceSettings::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the last access timestamp
    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }

    /// Switch to a different identity
    pub fn switch_identity(&mut self, identity_id: Uuid) {
        self.active_identity_id = Some(identity_id);
        self.touch();
    }

    /// Clear the active identity
    pub fn clear_active_identity(&mut self) {
        self.active_identity_id = None;
        self.touch();
    }

    /// Get the database path for this workspace
    pub fn database_path(&self) -> PathBuf {
        self.path.join("identities.db")
    }

    /// Get the config path for this workspace
    pub fn config_path(&self) -> PathBuf {
        self.path.join("config.toml")
    }

    /// Get the backup directory path
    pub fn backup_path(&self) -> PathBuf {
        self.path.join("backups")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_new_defaults() {
        let ws = Workspace::new("/tmp/persona", "main".to_string());
        assert_eq!(ws.name, "main");
        assert_eq!(ws.path, PathBuf::from("/tmp/persona"));
        assert!(ws.active_identity_id.is_none());
        assert!(ws.settings.encryption_enabled);
        assert_eq!(ws.settings.auto_backup_hours, 24);
        assert_eq!(ws.settings.backup_retention_count, 7);
        assert_eq!(ws.settings.session_timeout_seconds, 3600);
        assert!(ws.settings.require_confirmation);
        assert_eq!(ws.settings.default_identity_type, "personal");
    }

    #[test]
    fn test_workspace_identity_switching() {
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        let id = Uuid::new_v4();

        ws.switch_identity(id);
        assert_eq!(ws.active_identity_id, Some(id));

        ws.clear_active_identity();
        assert!(ws.active_identity_id.is_none());
    }

    #[test]
    fn test_workspace_paths() {
        let ws = Workspace::new("/tmp/persona", "main".to_string());
        assert_eq!(
            ws.database_path(),
            PathBuf::from("/tmp/persona/identities.db")
        );
        assert_eq!(ws.config_path(), PathBuf::from("/tmp/persona/config.toml"));
        assert_eq!(ws.backup_path(), PathBuf::from("/tmp/persona/backups"));
    }

    #[test]
    fn test_workspace_touch_and_serde_round_trip() {
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        let id = Uuid::new_v4();
        ws.switch_identity(id);
        ws.settings.auto_backup_hours = 12;
        ws.touch();

        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, ws.id);
        assert_eq!(restored.active_identity_id, Some(id));
        assert_eq!(restored.settings.auto_backup_hours, 12);
    }

    #[test]
    fn test_feature_flags_default_all_off() {
        let flags = FeatureFlags::default();
        assert!(!flags.ssh_agent);
        assert!(!flags.wallet);
        assert!(!flags.passkeys);
        assert!(!flags.fetch_favicons);
        assert_eq!(
            flags,
            FeatureFlags {
                ssh_agent: false,
                wallet: false,
                passkeys: false,
                fetch_favicons: false
            }
        );
    }

    #[test]
    fn test_settings_without_features_key_falls_back_to_defaults() {
        // 旧版本持久化的 settings JSON 没有 features 键：反序列化应静默回退
        let legacy = r#"{
            "encryption_enabled": true,
            "auto_backup_hours": 24,
            "backup_retention_count": 7,
            "session_timeout_seconds": 3600,
            "require_confirmation": true,
            "default_identity_type": "personal"
        }"#;
        let settings: WorkspaceSettings = serde_json::from_str(legacy).unwrap();
        assert_eq!(settings.features, FeatureFlags::default());
        assert!(settings.sync.is_none());
    }

    #[test]
    fn test_sync_config_serde_round_trip() {
        let settings = WorkspaceSettings {
            sync: Some(SyncConfig {
                enabled: true,
                server_url: "http://127.0.0.1:3000".to_string(),
                server_token: "s3cret".to_string(),
            }),
            ..WorkspaceSettings::default()
        };

        let json = serde_json::to_string(&settings).unwrap();
        let restored: WorkspaceSettings = serde_json::from_str(&json).unwrap();
        let sync = restored.sync.unwrap();
        assert!(sync.enabled);
        assert_eq!(sync.server_url, "http://127.0.0.1:3000");
        assert_eq!(sync.server_token, "s3cret");
    }

    #[test]
    fn test_feature_flags_serde_round_trip() {
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        ws.settings.features = FeatureFlags {
            ssh_agent: true,
            wallet: false,
            passkeys: true,
            fetch_favicons: true,
        };

        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert!(restored.settings.features.ssh_agent);
        assert!(!restored.settings.features.wallet);
        assert!(restored.settings.features.passkeys);
        assert!(restored.settings.features.fetch_favicons);
    }
}
