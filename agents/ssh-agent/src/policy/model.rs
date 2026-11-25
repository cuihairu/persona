//! Policy configuration model: the `SigningPolicy` top level (global/key/
//! host three layers) and each layer's defaults.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy configuration for SSH key usage
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigningPolicy {
    /// Global settings
    pub global: GlobalPolicy,

    /// Per-key policies (key: credential_id)
    #[serde(default)]
    pub key_policies: HashMap<String, KeyPolicy>,

    /// Per-host policies (key: hostname pattern)
    #[serde(default)]
    pub host_policies: HashMap<String, HostPolicy>,
}

/// Global agent policy settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalPolicy {
    /// Require user confirmation for every signature
    #[serde(default)]
    pub require_confirm: bool,

    /// Minimum interval between signatures (milliseconds)
    #[serde(default)]
    pub min_interval_ms: u64,

    /// Enforce known_hosts checking
    #[serde(default)]
    pub enforce_known_hosts: bool,

    /// Prompt for confirmation on unknown hosts
    #[serde(default)]
    pub confirm_on_unknown_host: bool,

    /// Maximum signatures per hour (0 = unlimited)
    #[serde(default)]
    pub max_signatures_per_hour: u32,

    /// Deny all signatures (emergency lockdown)
    #[serde(default)]
    pub deny_all: bool,
}

/// Per-key policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Allow this key to be used
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Allowed hostnames (glob patterns, empty = all allowed)
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Denied hostnames (glob patterns, takes precedence over allowed)
    #[serde(default)]
    pub denied_hosts: Vec<String>,

    /// Require confirmation for this key
    #[serde(default)]
    pub require_confirm: bool,

    /// Require biometric authentication for this key
    #[serde(default)]
    pub require_biometric: bool,

    /// Maximum uses per day (0 = unlimited)
    #[serde(default)]
    pub max_uses_per_day: u32,

    /// Allowed time range (24h format, e.g., "09:00-17:00")
    #[serde(default)]
    pub allowed_time_range: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for KeyPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            require_confirm: false,
            require_biometric: false,
            max_uses_per_day: 0,
            allowed_time_range: None,
        }
    }
}

/// Per-host policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPolicy {
    /// Allow connections to this host
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Allowed keys for this host (credential IDs, empty = all allowed)
    #[serde(default)]
    pub allowed_keys: Vec<String>,

    /// Require confirmation for this host
    #[serde(default)]
    pub require_confirm: bool,

    /// Maximum connections per hour
    #[serde(default)]
    pub max_connections_per_hour: u32,
}

impl Default for HostPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_keys: Vec::new(),
            require_confirm: false,
            max_connections_per_hour: 0,
        }
    }
}
