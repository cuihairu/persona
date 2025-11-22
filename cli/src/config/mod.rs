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
        let config_path = match config_override {
            Some(p) => p.to_path_buf(),
            None => Self::get_config_path()?,
        };

        if config_path.exists() {
            debug!("Loading configuration from: {}", config_path.display());
            let content = std::fs::read_to_string(&config_path).with_context(|| {
                format!("Failed to read config file: {}", config_path.display())
            })?;

            let config: CliConfig = toml::from_str(&content).with_context(|| {
                format!("Failed to parse config file: {}", config_path.display())
            })?;

            info!("Configuration loaded successfully");
            Ok(config)
        } else {
            debug!("Config file not found, using default configuration");
            Ok(Self::default())
        }
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path()?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize configuration")?;

        std::fs::write(&config_path, content)
            .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;

        info!("Configuration saved to: {}", config_path.display());
        Ok(())
    }

    /// Get the configuration file path
    pub fn get_config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .context("Failed to determine config directory")?;

        Ok(config_dir.join("persona").join("config.toml"))
    }

    /// Get workspace configuration file path
    pub fn get_workspace_config_path(&self) -> PathBuf {
        self.workspace.path.join("config.toml")
    }

    /// Load workspace-specific configuration
    pub fn load_workspace_config(&mut self) -> Result<()> {
        let workspace_config_path = self.get_workspace_config_path();

        if workspace_config_path.exists() {
            debug!(
                "Loading workspace configuration from: {}",
                workspace_config_path.display()
            );
            let content = std::fs::read_to_string(&workspace_config_path).with_context(|| {
                format!(
                    "Failed to read workspace config: {}",
                    workspace_config_path.display()
                )
            })?;

            let workspace_config: CliConfig = toml::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse workspace config: {}",
                    workspace_config_path.display()
                )
            })?;

            // Merge workspace config with global config
            self.merge_workspace_config(workspace_config);

            info!("Workspace configuration loaded and merged");
        }

        Ok(())
    }

    /// Merge workspace configuration with current configuration
    fn merge_workspace_config(&mut self, workspace_config: CliConfig) {
        // Update workspace-specific settings
        self.workspace = workspace_config.workspace;

        // Merge other settings (workspace config takes precedence)
        if workspace_config.security.encryption_enabled != self.security.encryption_enabled {
            self.security = workspace_config.security;
        }

        if workspace_config.backup.enabled != self.backup.enabled {
            self.backup = workspace_config.backup;
        }

        if workspace_config.sync.enabled != self.sync.enabled {
            self.sync = workspace_config.sync;
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate workspace path
        if !self.workspace.path.exists() {
            anyhow::bail!(
                "Workspace path does not exist: {}",
                self.workspace.path.display()
            );
        }

        // Validate backup directory
        if self.backup.enabled && !self.backup.directory.exists() {
            std::fs::create_dir_all(&self.backup.directory).with_context(|| {
                format!(
                    "Failed to create backup directory: {}",
                    self.backup.directory.display()
                )
            })?;
        }

        // Validate sync configuration
        if self.sync.enabled && self.sync.server_url.is_empty() {
            anyhow::bail!("Sync is enabled but server URL is not configured");
        }

        // Validate output format
        let valid_formats = ["table", "json", "yaml", "csv"];
        if !valid_formats.contains(&self.ui.default_output_format.as_str()) {
            anyhow::bail!(
                "Invalid default output format: {}",
                self.ui.default_output_format
            );
        }

        // Validate logging level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            anyhow::bail!("Invalid logging level: {}", self.logging.level);
        }

        Ok(())
    }

    /// Get database path
    pub fn get_database_path(&self) -> PathBuf {
        self.workspace.path.join("identities.db")
    }

    /// Get logs directory
    pub fn get_logs_directory(&self) -> PathBuf {
        self.workspace.path.join("logs")
    }

    /// Get exports directory
    pub fn get_exports_directory(&self) -> PathBuf {
        self.workspace.path.join("exports")
    }

    /// Get temp directory
    pub fn get_temp_directory(&self) -> PathBuf {
        self.workspace.path.join("temp")
    }

    /// Check if workspace is initialized
    pub fn is_workspace_initialized(&self) -> bool {
        self.workspace.path.exists()
            && self.get_database_path().exists()
            && self.get_workspace_config_path().exists()
    }
}
