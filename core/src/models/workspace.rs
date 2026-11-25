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

/// Advanced feature flags (1Password-style: off by default, user opt-in).
///
/// Mainline features (credentials/stats/Watchtower) are always on and not
/// listed here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FeatureFlags {
    /// SSH agent (browsers/terminals fetch keys over the socket to sign)
    pub ssh_agent: bool,
    /// Wallet panel
    pub wallet: bool,
    /// Passkey management and approval server
    pub passkeys: bool,
    /// On-demand fetching and display of site favicons (privacy red line: the
    /// only outbound entry point is the "Fetch icon" button in the detail
    /// panel; on = show the button and cached icons, off = no network behavior)
    pub fetch_favicons: bool,
}

/// Client configuration for the optional sync server (persona-server Events
/// API).
///
/// `server_token` is the shared Bearer token used for reporting. The desktop
/// host stores it in the OS keyring (keyed by the vault db_path); this struct
/// always writes an empty-string placeholder in the vault settings JSON. A
/// non-empty value read back is legacy data predating the keyring batch,
/// migrated into the keyring once on the host's first run (registered in
/// THREAT_MODEL).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Whether local audit events are reported to persona-server
    pub enabled: bool,
    /// Server base_url (e.g. `http://127.0.0.1:3000`; may carry a reverse
    /// proxy prefix)
    pub server_url: String,
    /// Shared Bearer token; the desktop host always writes an empty string
    /// (the real value lives in the OS keyring), the CLI never writes it to
    /// disk (env-only); submitting an empty string = keep the old value
    pub server_token: String,
    /// Local path of the sync folder for the cloud-drive transport (Phase 2;
    /// the local sync directory of iCloud Drive/Dropbox/Google Drive). Not a
    /// secret, so it is stored as a JSON field; None = no cloud-drive sync
    /// configured. Only meaningful when `sync_transport = cloud`.
    #[serde(default)]
    pub cloud_drive_dir: Option<String>,
    /// Which transport the sync command stream uses (Phase 2 cloud-drive +
    /// server dual rail, per the 2026-11-23 user directive "design them
    /// together"). Defaults to Server — existing behavior unchanged.
    #[serde(default)]
    pub sync_transport: SyncTransport,
}

/// Transport choice for the sync command stream (Phase 2 cloud-drive dual
/// rail). Defaults to Server (existing behavior); `cloud` = the command
/// stream is exchanged through files in the cloud-drive directory (same as
/// [`SyncConfig::cloud_drive_dir`]).
///
/// Independent of `settings.sync_methods` (the settings-page method switches):
/// `sync_methods` controls the availability of the settings-page entries
/// (cross-device/account), while `sync_transport` controls which transport the
/// engine uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncTransport {
    /// persona-server HTTP (the existing transport, default)
    #[default]
    Server,
    /// Cloud-drive directory file transport (Phase 2)
    Cloud,
}

/// Sync method switches (the settings page's "sync methods" section, each
/// independent; per the 2026-11-23 user directive "the settings page needs
/// the corresponding setting options, which sync methods are enabled").
///
/// **These are two separate semantics from `SyncConfig.enabled` (audit event
/// reporting); never merge them.** The derived state (whether the user is
/// actually grouped/joined) is a runtime keyring fact, not decided by these
/// fields — they only control whether the settings-page entries are available
/// (off = disable the entry: it does not leave the sync group, delete the
/// keyring or trigger any network activity).
///
/// Defaults: cross-device sync is **on** (the default sync method), account
/// sync is **off** (requires an explicit opt-in; see the explicit opt-in rule
/// in `docs/sync-group-mode.md` §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMethods {
    pub cross_device_sync: bool,
    pub account_sync: bool,
}

impl Default for SyncMethods {
    fn default() -> Self {
        Self {
            cross_device_sync: true,
            account_sync: false,
        }
    }
}

/// Account-domain binding (the account identity associated with this vault).
/// Non-sensitive identifiers are persisted: account_id is the unique login
/// identifier (persona-server has no username→account_id resolution endpoint, so
/// the login ritual is scoped by account_id); username/device_name are for
/// display only. The real token value is **never on disk** — desktop keeps it
/// in the OS keyring (ACCOUNT_SERVICE), under the same discipline as the sync
/// config's token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountBinding {
    pub account_id: String,
    pub username: String,
    /// Device name of the local SRP credential (the display slot in SRP
    /// identity and multi-device management)
    #[serde(default)]
    pub device_name: Option<String>,
}

/// Export record for a full-database encrypted backup (the S5 self-rescue
/// path; non-sensitive metadata).
///
/// The passphrase itself is **never written to disk** (same discipline as the
/// master password); only the time/destination/size are recorded, so that the
/// persistent "lose every device = lose the vault" warning (design doc §6.5)
/// can treat "a backup has been exported" as one piece of clearing evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupEvidence {
    /// Export time (RFC3339).
    pub exported_at: String,
    /// Destination type: "file" (local file) / "server" (server ciphertext
    /// vault, later batch).
    pub destination: String,
    /// Number of ciphertext bytes.
    pub size_bytes: u64,
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

    /// Advanced feature flags (all off when an old JSON lacks the key)
    #[serde(default)]
    pub features: FeatureFlags,

    /// Optional sync server configuration (None when an old JSON lacks the key)
    #[serde(default)]
    pub sync: Option<SyncConfig>,

    /// Sync method switches (cross-device sync on by default, account sync
    /// off by default; missing keys in old JSON fall back to the defaults).
    /// See [`SyncMethods`].
    #[serde(default)]
    pub sync_methods: SyncMethods,

    /// Master password lifetime (days); None = never expires (the default,
    /// NIST-aligned: rotation is enforced only after the user explicitly
    /// opts in). Some(days) past its term makes unlock return
    /// `AuthResult::PasswordChangeRequired` to walk the user through a change
    /// (None when an old JSON lacks the key)
    #[serde(default)]
    pub password_expiry_days: Option<u32>,

    /// UI language ("zh-CN" / "en"; None = the client's default baseline
    /// language zh-CN)
    #[serde(default)]
    pub locale: Option<String>,

    /// Travel mode in progress. Mutually true with the sidecar file's
    /// existence: the sidecar is the data authority, while this flag drives
    /// UI state, password-change interception and crash-recovery semantics
    /// (see the crash-window table in core/src/travel.rs's module comment;
    /// falls back to false when an old JSON lacks the key)
    #[serde(default)]
    pub travel_mode: bool,

    /// When travel mode was entered (RFC3339). Only for status display
    /// (reading it does not need the travel passphrase); written by enter,
    /// cleared by exit
    #[serde(default)]
    pub travel_entered_at: Option<String>,

    /// Whether Quick Access (an OS-level global-hotkey popup, modeled on
    /// 1Password Quick Access) is enabled. Off = the desktop registers no
    /// global hotkeys at all; the tray entry remains. Defaults to **off**
    /// (2026-09-28 user decision): global hotkeys preempt OS-level
    /// key combinations, and by the same rule as cloud backups we "don't turn
    /// it on proactively" — users who want it switch it on in settings and
    /// see the current combination and its conflict status. **Explicitly
    /// stored existing configuration is unaffected** (a stored true stays
    /// on); only old JSON missing the key / fresh installs fall back to off
    #[serde(default)]
    pub quick_access_enabled: bool,

    /// Accelerator string for the Quick Access global hotkey (tauri
    /// global-shortcut syntax, e.g. `"CommandOrControl+Shift+Space"`).
    /// None = the desktop picks the platform-default binding — core is a
    /// platform-agnostic layer and does not hardcode specific keys
    #[serde(default)]
    pub quick_access_hotkey: Option<String>,

    /// Global hotkey for the password generator (gap #9 leftover: summon the
    /// generator popup inside any OS-level application). The switch semantics
    /// match [`Self::quick_access_enabled`]: defaults to **off** (global
    /// hotkeys preempt OS key combinations, not turned on proactively),
    /// enabled explicitly in settings. Old JSON missing the key falls back
    /// to off
    #[serde(default)]
    pub generator_panel_enabled: bool,

    /// Accelerator string for the generator hotkey (same syntax as
    /// [`Self::quick_access_hotkey`]). None = the desktop picks the
    /// platform-default binding
    #[serde(default)]
    pub generator_panel_hotkey: Option<String>,

    /// Account-domain binding (None when an old JSON lacks the key = not
    /// bound to any account; privacy red line: account features are off by
    /// default, binding is done explicitly by the user in the settings page)
    #[serde(default)]
    pub account: Option<AccountBinding>,

    /// Self-rescue backup evidence (S5; None when an old JSON lacks the key =
    /// never exported on this machine). Only non-sensitive metadata is stored:
    /// time/destination/size. The backup passphrase is never written to disk
    /// (same discipline as the master password); the persistent "lose every
    /// device = lose the vault" warning (design doc §6.5) treats this field as
    /// one piece of clearing evidence for "a backup has been exported".
    #[serde(default)]
    pub backup: Option<BackupEvidence>,
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
            sync_methods: SyncMethods::default(),
            password_expiry_days: None,
            locale: None,
            travel_mode: false,
            travel_entered_at: None,
            quick_access_enabled: false,
            quick_access_hotkey: None,
            generator_panel_enabled: false,
            generator_panel_hotkey: None,
            account: None,
            backup: None,
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
        // Settings JSON persisted by older versions has no features key:
        // deserialization should fall back silently
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
        // The travel-mode fields (batch 013) also fall back on a missing key
        assert!(!settings.travel_mode);
        assert_eq!(settings.travel_entered_at, None);
        // Quick Access (batch 014; default off since 2026-09-28): a missing
        // enabled key falls back to false (global hotkeys preempt OS key
        // combinations, not turned on proactively), and a missing hotkey key
        // falls back to None = the desktop picks the platform-default binding
        assert!(!settings.quick_access_enabled);
        assert_eq!(settings.quick_access_hotkey, None);
        // A missing account-domain binding key falls back to unbound (M2 batch;
        // off-by-default red line)
        assert_eq!(settings.account, None);
        // A missing backup evidence key falls back to never-exported (S5 batch)
        assert_eq!(settings.backup, None);
        // Missing sync-method switch keys fall back to the defaults:
        // cross-device sync on (the default sync method), account sync off
        // (requires an explicit opt-in) (deliverable 4)
        assert_eq!(
            settings.sync_methods,
            SyncMethods {
                cross_device_sync: true,
                account_sync: false
            }
        );
    }

    #[test]
    fn test_sync_methods_round_trip_preserves_explicit_false() {
        // Explicitly stored switches are not overridden by defaults (explicit
        // false/true round-trip unchanged)
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        ws.settings.sync_methods = SyncMethods {
            cross_device_sync: false,
            account_sync: true,
        };
        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert!(!restored.settings.sync_methods.cross_device_sync);
        assert!(restored.settings.sync_methods.account_sync);
    }

    #[test]
    fn test_backup_evidence_round_trip() {
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        // Default: never exported on this machine
        assert_eq!(ws.settings.backup, None);

        ws.settings.backup = Some(BackupEvidence {
            exported_at: "2026-10-07T09:30:00Z".to_string(),
            destination: "file".to_string(),
            size_bytes: 20480,
        });
        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.settings.backup,
            Some(BackupEvidence {
                exported_at: "2026-10-07T09:30:00Z".to_string(),
                destination: "file".to_string(),
                size_bytes: 20480,
            })
        );
        // The bytes contain only metadata: the passphrase does not exist in
        // this struct, so it must not appear after a round-trip either
        assert!(!json.contains("passphrase"));
    }

    #[test]
    fn test_account_binding_round_trip_and_legacy_default() {
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        // Default: unbound (account features are off by default; binding is an
        // explicit action)
        assert_eq!(ws.settings.account, None);

        ws.settings.account = Some(AccountBinding {
            account_id: "acct-1".to_string(),
            username: "alice@example.com".to_string(),
            device_name: Some("laptop".to_string()),
        });
        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.settings.account,
            Some(AccountBinding {
                account_id: "acct-1".to_string(),
                username: "alice@example.com".to_string(),
                device_name: Some("laptop".to_string()),
            })
        );

        // A missing device_name key (old binding JSON) falls back to None
        let minimal = r#"{"account_id":"acct-1","username":"alice@example.com"}"#;
        let binding: AccountBinding = serde_json::from_str(minimal).unwrap();
        assert_eq!(binding.device_name, None);
    }

    #[test]
    fn test_quick_access_hotkey_round_trip() {
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        // Default: off (explicit switch lives in the settings page) + use the
        // platform-default binding
        assert!(!ws.settings.quick_access_enabled);
        assert!(ws.settings.quick_access_hotkey.is_none());

        // Explicitly stored existing config is respected: a stored true stays
        // on, upgrades never silently turn it off
        ws.settings.quick_access_enabled = true;
        ws.settings.quick_access_hotkey = Some("CommandOrControl+Shift+Space".to_string());
        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert!(restored.settings.quick_access_enabled);
        assert_eq!(
            restored.settings.quick_access_hotkey.as_deref(),
            Some("CommandOrControl+Shift+Space")
        );

        ws.settings.quick_access_enabled = false;
        ws.settings.quick_access_hotkey = Some("CommandOrControl+Shift+Space".to_string());
        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert!(!restored.settings.quick_access_enabled);
        assert_eq!(
            restored.settings.quick_access_hotkey.as_deref(),
            Some("CommandOrControl+Shift+Space")
        );
    }

    #[test]
    fn test_generator_panel_hotkey_round_trip() {
        let mut ws = Workspace::new("/tmp/persona", "main".to_string());
        // Default: off (same standard as Quick Access — hotkeys preempt OS
        // key combinations, not turned on proactively)
        assert!(!ws.settings.generator_panel_enabled);
        assert!(ws.settings.generator_panel_hotkey.is_none());

        ws.settings.generator_panel_enabled = true;
        ws.settings.generator_panel_hotkey = Some("CommandOrControl+Shift+G".to_string());
        let json = serde_json::to_string(&ws).unwrap();
        let restored: Workspace = serde_json::from_str(&json).unwrap();
        assert!(restored.settings.generator_panel_enabled);
        assert_eq!(
            restored.settings.generator_panel_hotkey.as_deref(),
            Some("CommandOrControl+Shift+G")
        );

        // Old JSON missing both keys falls back to the default off: serialize
        // the current defaults, then strip the generator keys to simulate
        // settings persisted before the fields existed
        let mut legacy = serde_json::to_value(WorkspaceSettings::default()).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("generator_panel_enabled");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("generator_panel_hotkey");
        let legacy_settings: WorkspaceSettings = serde_json::from_value(legacy).unwrap();
        assert!(!legacy_settings.generator_panel_enabled);
        assert!(legacy_settings.generator_panel_hotkey.is_none());
    }

    #[test]
    fn test_sync_config_serde_round_trip() {
        let settings = WorkspaceSettings {
            sync: Some(SyncConfig {
                enabled: true,
                server_url: "http://127.0.0.1:3000".to_string(),
                server_token: "s3cret".to_string(),
                cloud_drive_dir: None,
                sync_transport: SyncTransport::default(),
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
