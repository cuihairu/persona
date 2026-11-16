//! 自动锁定的策略配置：`EnhancedAutoLockConfig` 及其 serde 缺省值。

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
    /// 「默认安全」：敏感操作（reveal/复制密文等）过后按 sensitive timeout
    /// 强制上锁；旧配置未显式写 false 的（serde default）随之收紧。
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
