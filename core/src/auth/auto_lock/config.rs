//! Auto-lock policy configuration: `EnhancedAutoLockConfig` and its serde defaults.

use serde::{Deserialize, Serialize};

use crate::auth::session::AutoLockConfig;

/// Enhanced auto-lock configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAutoLockConfig {
    /// Base auto-lock configuration
    #[serde(flatten)]
    pub base: AutoLockConfig,

    /// Warning time before lock (seconds)
    #[serde(default = "default_warning_time")]
    pub warning_time_secs: u64,

    /// Maximum number of concurrent sessions per user
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,

    /// Enable lock warnings
    #[serde(default)]
    pub enable_warnings: bool,

    /// Force lock on sensitive operations after timeout
    /// Secure by default: after sensitive operations (reveal, copying
    /// ciphertext, and so on), lock after the sensitive timeout; configs that
    /// never explicitly wrote `false` (serde default) are tightened along with
    /// this change.
    #[serde(default = "default_true")]
    pub force_lock_sensitive: bool,

    /// Activity grace period - small grace period for rapid operations
    #[serde(default = "default_grace_period")]
    pub activity_grace_period_secs: u64,

    /// Background check interval
    #[serde(default = "default_check_interval")]
    pub background_check_interval_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_warning_time() -> u64 {
    60
} // 1 minute warning
fn default_max_sessions() -> usize {
    5
}
fn default_grace_period() -> u64 {
    5
} // 5 seconds grace period
fn default_check_interval() -> u64 {
    30
} // Check every 30 seconds

impl Default for EnhancedAutoLockConfig {
    fn default() -> Self {
        Self {
            base: AutoLockConfig::default(),
            warning_time_secs: default_warning_time(),
            max_concurrent_sessions: default_max_sessions(),
            enable_warnings: true,
            force_lock_sensitive: true,
            activity_grace_period_secs: default_grace_period(),
            background_check_interval_secs: default_check_interval(),
        }
    }
}

impl From<AutoLockConfig> for EnhancedAutoLockConfig {
    fn from(base: AutoLockConfig) -> Self {
        Self {
            base,
            ..Default::default()
        }
    }
}
