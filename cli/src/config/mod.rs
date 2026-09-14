use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub workspace: WorkspaceConfig,
    pub security: SecurityConfig,
    pub backup: BackupConfig,
    pub sync: SyncConfig,
    pub ui: UiConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub path: PathBuf,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub encryption_enabled: bool,
    pub auto_lock_timeout: u64,
    pub require_biometric: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub enabled: bool,
    pub directory: PathBuf,
    pub auto_backup: bool,
    pub backup_interval: u64,
    pub max_backups: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub enabled: bool,
    pub server_url: String,
    pub auto_sync: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub color_enabled: bool,
    pub interactive: bool,
    pub default_output_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_enabled: bool,
    pub max_file_size: String,
    pub max_files: u32,
}

impl Default for CliConfig {
    fn default() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let workspace_path = home_dir.join(".persona");

        Self {
            workspace: WorkspaceConfig {
                path: workspace_path.clone(),
                version: "0.1.0".to_string(),
            },
            security: SecurityConfig {
                encryption_enabled: true,
                auto_lock_timeout: 300,
                require_biometric: false,
            },
            backup: BackupConfig {
                enabled: true,
                directory: workspace_path.join("backups"),
                auto_backup: true,
                backup_interval: 86400,
                max_backups: 30,
            },
            sync: SyncConfig {
                enabled: false,
                server_url: String::new(),
                auto_sync: false,
            },
            ui: UiConfig {
                color_enabled: true,
                interactive: true,
                default_output_format: "table".to_string(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_enabled: true,
                max_file_size: "10MB".to_string(),
                max_files: 5,
            },
        }
    }
}

impl CliConfig {
    /// Load configuration from file or create default
    pub fn load(config_override: Option<&Path>) -> Result<Self> {
        // If a config path is explicitly provided, be strict: missing file is an error.
        if let Some(p) = config_override {
            let mut cfg = Self::load_file(p)?;
            cfg.apply_env_overrides();
            return Ok(cfg);
        }

        let config_path = Self::get_config_path()?;
        let mut config = if config_path.exists() {
            Self::load_file(&config_path)?
        } else {
            debug!("Config file not found, using default configuration");
            Self::default()
        };

        // Override with environment variables
        config.apply_env_overrides();

        Ok(config)
    }

    /// Load configuration from a TOML file path (strict; no fallback).
    pub fn load_file(path: &Path) -> Result<Self> {
        debug!("Loading configuration from: {}", path.display());
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: CliConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        info!("Configuration loaded successfully");
        Ok(config)
    }

    /// Apply environment variable overrides
    pub(crate) fn apply_env_overrides(&mut self) {
        // Non-interactive mode
        if let Ok(val) = std::env::var("PERSONA_NON_INTERACTIVE") {
            if val == "1" || val.to_lowercase() == "true" {
                self.ui.interactive = false;
            }
        }

        // Workspace path
        if let Ok(path) = std::env::var("PERSONA_WORKSPACE_PATH") {
            self.workspace.path = PathBuf::from(path);
        }

        // Master password (for CI/automation)
        // Note: This is stored temporarily and should be cleared after use
        if std::env::var("PERSONA_MASTER_PASSWORD").is_ok() {
            debug!("Master password detected in environment");
        }

        // Encryption setting
        if let Ok(val) = std::env::var("PERSONA_ENCRYPTION_ENABLED") {
            if let Ok(enabled) = val.parse::<bool>() {
                self.security.encryption_enabled = enabled;
            }
        }

        // Output format
        if let Ok(format) = std::env::var("PERSONA_OUTPUT_FORMAT") {
            let valid_formats = ["table", "json", "yaml", "csv"];
            if valid_formats.contains(&format.as_str()) {
                self.ui.default_output_format = format;
            }
        }

        // Color output
        if let Ok(val) = std::env::var("PERSONA_NO_COLOR") {
            if val == "1" || val.to_lowercase() == "true" {
                self.ui.color_enabled = false;
            }
        }

        // Logging level
        if let Ok(level) = std::env::var("PERSONA_LOG_LEVEL") {
            let valid_levels = ["trace", "debug", "info", "warn", "error"];
            if valid_levels.contains(&level.as_str()) {
                self.logging.level = level;
            }
        }
    }

    /// Get the configuration file path
    pub fn get_config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .context("Failed to determine config directory")?;

        Ok(config_dir.join("persona").join("config.toml"))
    }

    /// Get database path
    pub fn get_database_path(&self) -> PathBuf {
        self.workspace.path.join("identities.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes every test that mutates process-global env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// The bridge tests also flip `PERSONA_MASTER_PASSWORD` from their own
    /// threads, so env-sensitive tests must take their lock in addition to
    /// ours to keep the process environment stable while they run.
    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK.lock().unwrap(),
            ENV_LOCK.lock().unwrap(),
        )
    }

    fn sample_toml() -> String {
        r#"
[workspace]
path = "/tmp/sample-workspace"
version = "9.9.9"

[security]
encryption_enabled = false
auto_lock_timeout = 42
require_biometric = true

[backup]
enabled = false
directory = "/tmp/sample-backups"
auto_backup = false
backup_interval = 60
max_backups = 3

[sync]
enabled = true
server_url = "https://sync.example.com"
auto_sync = true

[ui]
color_enabled = false
interactive = false
default_output_format = "json"

[logging]
level = "debug"
file_enabled = false
max_file_size = "1MB"
max_files = 2
"#
        .to_string()
    }

    /// Sets an env var, returning its previous value if it was set.
    fn set_var(key: &str, value: &str) -> Option<String> {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        previous
    }

    fn restore_var(key: &str, previous: Option<String>) {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn default_config_has_expected_values() {
        let config = CliConfig::default();

        assert_eq!(config.workspace.version, "0.1.0");
        assert!(config.workspace.path.ends_with(".persona"));
        assert!(config.security.encryption_enabled);
        assert_eq!(config.security.auto_lock_timeout, 300);
        assert!(!config.security.require_biometric);
        assert!(config.backup.enabled);
        assert!(config.backup.auto_backup);
        assert_eq!(config.backup.backup_interval, 86400);
        assert_eq!(config.backup.max_backups, 30);
        assert!(!config.sync.enabled);
        assert!(config.sync.server_url.is_empty());
        assert!(config.ui.color_enabled);
        assert!(config.ui.interactive);
        assert_eq!(config.ui.default_output_format, "table");
        assert_eq!(config.logging.level, "info");
        assert!(config.logging.file_enabled);
        assert_eq!(config.logging.max_file_size, "10MB");
        assert_eq!(config.logging.max_files, 5);

        // Backup directory lives inside the workspace directory.
        assert_eq!(
            Some(config.workspace.path.clone()),
            config.backup.directory.parent().map(|p| p.to_path_buf())
        );
    }

    #[test]
    fn get_database_path_lives_in_workspace() {
        let mut config = CliConfig::default();
        config.workspace.path = PathBuf::from("/data/ws");

        assert_eq!(
            config.get_database_path(),
            PathBuf::from("/data/ws/identities.db")
        );
    }

    #[test]
    fn load_file_reads_strict_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, sample_toml()).unwrap();

        let config = CliConfig::load_file(&path).unwrap();
        assert_eq!(config.workspace.version, "9.9.9");
        assert_eq!(
            config.workspace.path,
            PathBuf::from("/tmp/sample-workspace")
        );
        assert!(!config.security.encryption_enabled);
        assert_eq!(config.security.auto_lock_timeout, 42);
        assert_eq!(config.sync.server_url, "https://sync.example.com");
        assert_eq!(config.ui.default_output_format, "json");
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn load_file_errors_on_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.toml");

        let err = CliConfig::load_file(&path).unwrap_err();
        assert!(err.to_string().contains("Failed to read config file"));
    }

    #[test]
    fn load_file_errors_on_invalid_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("broken.toml");
        std::fs::write(&path, "not [valid toml").unwrap();

        let err = CliConfig::load_file(&path).unwrap_err();
        assert!(err.to_string().contains("Failed to parse config file"));
    }

    #[test]
    fn load_file_errors_on_schema_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[workspace]\npath = 12\n").unwrap();

        let err = CliConfig::load_file(&path).unwrap_err();
        assert!(err.to_string().contains("Failed to parse config file"));
    }

    #[test]
    fn load_with_override_requires_the_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("missing.toml");

        assert!(CliConfig::load(Some(&missing)).is_err());

        let path = dir.path().join("config.toml");
        std::fs::write(&path, sample_toml()).unwrap();
        let config = CliConfig::load(Some(&path)).unwrap();
        assert_eq!(config.workspace.version, "9.9.9");
    }

    #[test]
    // Skipped on Windows: `dirs::config_dir()` resolves through the Known
    // Folders API (SHGetKnownFolderPath), which ignores %APPDATA%, so the
    // platform config directory cannot be redirected into the temp dir and
    // the test would read the real user profile instead. The env-based
    // redirection below is honored on Linux ($XDG_CONFIG_HOME) and macOS
    // ($HOME), where the test runs normally.
    #[cfg_attr(
        windows,
        ignore = "dirs::config_dir() uses the Windows Known Folders API and cannot be redirected via %APPDATA%"
    )]
    fn load_without_override_uses_default_or_resolved_file() {
        let (_bridge_guard, _guard) = lock_process_env();

        // Point the platform config directory at a temp dir so the global
        // user config does not leak into the test.
        let dir = tempfile::TempDir::new().unwrap();
        let config_root = if cfg!(target_os = "macos") {
            dir.path().join("home")
        } else {
            dir.path().join("xdg-config")
        };
        std::fs::create_dir_all(config_root.join("persona")).unwrap();

        let mut saved = Vec::new();
        if cfg!(target_os = "macos") {
            let home = dir.path().join("home");
            saved.push(("HOME", set_var("HOME", home.to_str().unwrap())));
        } else {
            saved.push((
                "XDG_CONFIG_HOME",
                set_var("XDG_CONFIG_HOME", config_root.to_str().unwrap()),
            ));
            if let Ok(home) = std::env::var("HOME") {
                saved.push(("HOME", Some(home)));
            }
            std::env::set_var("HOME", dir.path());
        }

        // No config file at the resolved path -> built-in default.
        let config = CliConfig::load(None).unwrap();
        assert_eq!(config.workspace.version, "0.1.0");
        assert_eq!(config.ui.default_output_format, "table");

        // Once a config.toml exists there, load it instead.
        let config_path = config_root.join("persona").join("config.toml");
        std::fs::write(&config_path, sample_toml()).unwrap();
        let config = CliConfig::load(None).unwrap();
        assert_eq!(config.workspace.version, "9.9.9");

        for (key, previous) in saved {
            restore_var(key, previous);
        }
    }

    #[test]
    fn get_config_path_returns_ok() {
        let path = CliConfig::get_config_path().unwrap();
        assert!(path.to_string_lossy().contains("persona"));
        assert!(path.to_string_lossy().contains("persona"));
    }

    #[test]
    fn env_overrides_apply_valid_values() {
        let (_bridge_guard, _guard) = lock_process_env();

        let mut config = CliConfig::default();
        assert!(config.ui.interactive);
        assert!(config.ui.color_enabled);
        assert!(config.security.encryption_enabled);
        assert_eq!(config.ui.default_output_format, "table");
        assert_eq!(config.logging.level, "info");
        assert_ne!(config.workspace.path, PathBuf::from("/env/ws"));

        let saved = vec![
            (
                "PERSONA_NON_INTERACTIVE",
                set_var("PERSONA_NON_INTERACTIVE", "1"),
            ),
            (
                "PERSONA_WORKSPACE_PATH",
                set_var("PERSONA_WORKSPACE_PATH", "/env/ws"),
            ),
            (
                "PERSONA_MASTER_PASSWORD",
                set_var("PERSONA_MASTER_PASSWORD", "secret"),
            ),
            (
                "PERSONA_ENCRYPTION_ENABLED",
                set_var("PERSONA_ENCRYPTION_ENABLED", "false"),
            ),
            (
                "PERSONA_OUTPUT_FORMAT",
                set_var("PERSONA_OUTPUT_FORMAT", "yaml"),
            ),
            ("PERSONA_NO_COLOR", set_var("PERSONA_NO_COLOR", "true")),
            ("PERSONA_LOG_LEVEL", set_var("PERSONA_LOG_LEVEL", "trace")),
        ];

        config.apply_env_overrides();

        for (key, previous) in saved {
            restore_var(key, previous);
        }

        assert!(!config.ui.interactive);
        assert_eq!(config.workspace.path, PathBuf::from("/env/ws"));
        assert!(!config.security.encryption_enabled);
        assert_eq!(config.ui.default_output_format, "yaml");
        assert!(!config.ui.color_enabled);
        assert_eq!(config.logging.level, "trace");
    }

    #[test]
    fn env_overrides_ignore_invalid_values() {
        let (_bridge_guard, _guard) = lock_process_env();

        let mut config = CliConfig::default();

        let saved = vec![
            // Not "1"/"true": no effect.
            (
                "PERSONA_NON_INTERACTIVE",
                set_var("PERSONA_NON_INTERACTIVE", "nope"),
            ),
            // Not parseable as bool: no effect.
            (
                "PERSONA_ENCRYPTION_ENABLED",
                set_var("PERSONA_ENCRYPTION_ENABLED", "maybe"),
            ),
            // Invalid output format: no effect.
            (
                "PERSONA_OUTPUT_FORMAT",
                set_var("PERSONA_OUTPUT_FORMAT", "xml"),
            ),
            // "0" does not disable color.
            ("PERSONA_NO_COLOR", set_var("PERSONA_NO_COLOR", "0")),
            // Invalid log level: no effect.
            ("PERSONA_LOG_LEVEL", set_var("PERSONA_LOG_LEVEL", "verbose")),
        ];

        config.apply_env_overrides();

        for (key, previous) in saved {
            restore_var(key, previous);
        }

        assert!(config.ui.interactive);
        assert!(config.security.encryption_enabled);
        assert_eq!(config.ui.default_output_format, "table");
        assert!(config.ui.color_enabled);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn env_overrides_accept_word_forms() {
        let (_bridge_guard, _guard) = lock_process_env();

        let mut config = CliConfig::default();

        let saved = vec![
            (
                "PERSONA_NON_INTERACTIVE",
                set_var("PERSONA_NON_INTERACTIVE", "TRUE"),
            ),
            ("PERSONA_NO_COLOR", set_var("PERSONA_NO_COLOR", "True")),
            (
                "PERSONA_ENCRYPTION_ENABLED",
                set_var("PERSONA_ENCRYPTION_ENABLED", "true"),
            ),
            (
                "PERSONA_OUTPUT_FORMAT",
                set_var("PERSONA_OUTPUT_FORMAT", "csv"),
            ),
            ("PERSONA_LOG_LEVEL", set_var("PERSONA_LOG_LEVEL", "warn")),
        ];

        config.apply_env_overrides();

        for (key, previous) in saved {
            restore_var(key, previous);
        }

        assert!(!config.ui.interactive);
        assert!(!config.ui.color_enabled);
        assert!(config.security.encryption_enabled);
        assert_eq!(config.ui.default_output_format, "csv");
        assert_eq!(config.logging.level, "warn");
    }

    #[test]
    fn env_overrides_are_applied_by_load() {
        let (_bridge_guard, _guard) = lock_process_env();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, sample_toml()).unwrap();

        let previous = set_var("PERSONA_WORKSPACE_PATH", "/env/from-load/ws");
        let config = CliConfig::load(Some(&path)).unwrap();
        restore_var("PERSONA_WORKSPACE_PATH", previous);

        assert_eq!(config.workspace.path, PathBuf::from("/env/from-load/ws"));
    }

    #[test]
    fn config_serde_roundtrips_through_json() {
        let config = CliConfig::default();

        let json = serde_json::to_string(&config).unwrap();
        let decoded: CliConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.workspace.path, config.workspace.path);
        assert_eq!(decoded.workspace.version, config.workspace.version);
        assert_eq!(
            decoded.security.auto_lock_timeout,
            config.security.auto_lock_timeout
        );
        assert_eq!(decoded.backup.directory, config.backup.directory);
        assert_eq!(decoded.backup.max_backups, config.backup.max_backups);
        assert_eq!(
            decoded.ui.default_output_format,
            config.ui.default_output_format
        );
        assert_eq!(decoded.logging.max_file_size, config.logging.max_file_size);
        assert_eq!(decoded.logging.max_files, config.logging.max_files);
    }

    #[test]
    fn config_serializes_and_reparses_as_toml() {
        let config = CliConfig::default();

        // toml serialization exercises the Serialize side of every section,
        // matching what load_file does on the Deserialize side.
        let toml_text = toml::to_string(&config).unwrap();
        let decoded: CliConfig = toml::from_str(&toml_text).unwrap();

        assert_eq!(decoded.workspace.path, config.workspace.path);
        assert_eq!(decoded.backup.directory, config.backup.directory);
        assert_eq!(
            decoded.ui.default_output_format,
            config.ui.default_output_format
        );
    }
}
