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
