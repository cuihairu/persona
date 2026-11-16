//! 策略动作与严重级：`SecurityAction` 动作载荷、`AuthMethod`、通知与
//! 事件严重级枚举。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security actions to take when conditions are met
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecurityAction {
    /// Lock the session
    LockSession {
        /// Lock reason
        reason: String,

        /// Lock duration (None = indefinite)
        duration_secs: Option<u64>,
    },

    /// Extend session timeout
    ExtendTimeout {
        /// Additional time in seconds
        extension_secs: u64,

        /// Reason for extension
        reason: String,
    },

    /// Require re-authentication
    RequireReauth {
        /// Authentication method
        method: AuthMethod,

        /// Context message
        message: String,
    },

    /// Notify user or administrator
    Notify {
        /// Notification recipients
        recipients: Vec<String>,

        /// Notification message
        message: String,

        /// Notification severity
        severity: NotificationSeverity,
    },

    /// Log security event
    LogEvent {
        /// Event category
        category: String,

        /// Event details
        details: HashMap<String, serde_json::Value>,

        /// Event severity
        severity: EventSeverity,
    },

    /// Restrict functionality
    RestrictFunctionality {
        /// Restricted features
        restricted_features: Vec<String>,

        /// Restriction reason
        reason: String,
    },

    /// Execute custom action
    CustomAction {
        /// Action name
        name: String,

        /// Action parameters
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Authentication methods for re-authentication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Biometric,
    TwoFactor,
    SecurityKey,
    SmartCard,
    Custom(String),
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password => write!(f, "password"),
            AuthMethod::Biometric => write!(f, "biometric"),
            AuthMethod::TwoFactor => write!(f, "two_factor"),
            AuthMethod::SecurityKey => write!(f, "security_key"),
            AuthMethod::SmartCard => write!(f, "smart_card"),
            AuthMethod::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// Notification severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}
