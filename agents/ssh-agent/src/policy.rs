//! Policy management for SSH Agent
//!
//! Provides fine-grained control over SSH key usage:
//! - Per-host restrictions
//! - Per-key policies
//! - Time-based restrictions
//! - Usage counting and rate limiting

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Policy configuration for SSH key usage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
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

/// Runtime state for policy enforcement
pub struct PolicyEnforcer {
    policy: SigningPolicy,
    state: PolicyState,
}

#[derive(Debug, Default)]
struct PolicyState {
    last_sign: Option<Instant>,
    signature_timestamps: Vec<Instant>,
    key_usage: HashMap<Uuid, KeyUsageState>,
    host_usage: HashMap<String, HostUsageState>,
}

#[derive(Debug)]
struct KeyUsageState {
    daily_count: u32,
    last_reset: Instant,
    total_count: u64,
}

#[derive(Debug)]
struct HostUsageState {
    hourly_count: u32,
    last_reset: Instant,
    total_count: u64,
}

impl PolicyEnforcer {
    /// Create a new policy enforcer
    pub fn new(policy: SigningPolicy) -> Self {
        Self {
            policy,
            state: PolicyState::default(),
        }
    }

    /// Load policy from file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let policy: SigningPolicy = toml::from_str(&content)?;
        Ok(Self::new(policy))
    }

    /// Load policy from environment or use defaults
    pub fn from_env() -> Self {
        let policy_path = std::env::var("PERSONA_AGENT_POLICY_FILE")
            .ok()
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".persona").join("agent-policy.toml")));

        if let Some(path) = policy_path {
            if path.exists() {
                if let Ok(enforcer) = Self::from_file(&path) {
                    tracing::info!("Loaded policy from {}", path.display());
                    return enforcer;
                }
            }
        }

        // Build from environment variables (backward compatibility)
        let mut policy = SigningPolicy::default();

        policy.global.require_confirm = std::env::var("PERSONA_AGENT_REQUIRE_CONFIRM")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        policy.global.min_interval_ms = std::env::var("PERSONA_AGENT_MIN_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        policy.global.enforce_known_hosts = std::env::var("PERSONA_AGENT_ENFORCE_KNOWN_HOSTS")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        policy.global.confirm_on_unknown_host = std::env::var("PERSONA_AGENT_CONFIRM_ON_UNKNOWN")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self::new(policy)
    }

    /// Check if a signature request should be allowed
    pub fn check_signature(
        &mut self,
        credential_id: &Uuid,
        hostname: Option<&str>,
    ) -> Result<SignatureDecision> {
        // Global deny all check
        if self.policy.global.deny_all {
            return Ok(SignatureDecision::Denied {
                reason: "Agent is in lockdown mode".to_string(),
            });
        }

        // Rate limiting - global min interval
        if self.policy.global.min_interval_ms > 0 {
            if let Some(last) = self.state.last_sign {
                if last.elapsed() < Duration::from_millis(self.policy.global.min_interval_ms) {
                    return Ok(SignatureDecision::Denied {
                        reason: format!(
                            "Rate limit: {}ms interval required",
                            self.policy.global.min_interval_ms
                        ),
                    });
                }
            }
        }

        // Global hourly limit
        if self.policy.global.max_signatures_per_hour > 0 {
            self.cleanup_old_timestamps();
            if self.state.signature_timestamps.len()
                >= self.policy.global.max_signatures_per_hour as usize
            {
                return Ok(SignatureDecision::Denied {
                    reason: format!(
                        "Hourly limit exceeded: {} signatures per hour",
                        self.policy.global.max_signatures_per_hour
                    ),
                });
            }
        }

        // Check per-key policy
        let key_id = credential_id.to_string();
        if let Some(key_policy) = self.policy.key_policies.get(&key_id) {
            if !key_policy.enabled {
                return Ok(SignatureDecision::Denied {
                    reason: "Key is disabled".to_string(),
                });
            }

            // Check host restrictions for this key
            if let Some(hostname) = hostname {
                if !key_policy.denied_hosts.is_empty()
                    && self.matches_any_pattern(hostname, &key_policy.denied_hosts) {
                        return Ok(SignatureDecision::Denied {
                            reason: format!("Host '{}' is denied for this key", hostname),
                        });
                    }

                if !key_policy.allowed_hosts.is_empty()
                    && !self.matches_any_pattern(hostname, &key_policy.allowed_hosts) {
                        return Ok(SignatureDecision::Denied {
                            reason: format!(
                                "Host '{}' is not in allowed list for this key",
                                hostname
                            ),
                        });
                    }
            }

            // Check daily usage limit for key
            if key_policy.max_uses_per_day > 0 {
                let usage = self.state.key_usage.entry(*credential_id).or_default();
                usage.reset_if_needed();

                if usage.daily_count >= key_policy.max_uses_per_day {
                    return Ok(SignatureDecision::Denied {
                        reason: format!(
                            "Daily limit exceeded for key: {} uses per day",
                            key_policy.max_uses_per_day
                        ),
                    });
                }
            }

            // Check time range restrictions
            if let Some(ref time_range) = key_policy.allowed_time_range {
                if !self.is_within_time_range(time_range) {
                    return Ok(SignatureDecision::Denied {
                        reason: format!(
                            "Key usage not allowed at this time (allowed: {})",
                            time_range
                        ),
                    });
                }
            }
        }

        // Check per-host policy
        if let Some(hostname) = hostname {
            if let Some(host_policy) = self.find_host_policy(hostname) {
                if !host_policy.enabled {
                    return Ok(SignatureDecision::Denied {
                        reason: format!("Host '{}' is disabled", hostname),
                    });
                }

                // Check if key is allowed for this host
                if !host_policy.allowed_keys.is_empty()
                    && !host_policy.allowed_keys.contains(&key_id) {
                        return Ok(SignatureDecision::Denied {
                            reason: format!("Key not allowed for host '{}'", hostname),
                        });
                    }

                // Check hourly limit for host (extract values first to avoid borrow conflict)
                let max_connections = host_policy.max_connections_per_hour;
                let requires_confirm = host_policy.require_confirm;

                if max_connections > 0 {
                    let usage = self
                        .state
                        .host_usage
                        .entry(hostname.to_string())
                        .or_default();
                    usage.reset_if_needed();

                    if usage.hourly_count >= max_connections {
                        return Ok(SignatureDecision::Denied {
                            reason: format!(
                                "Hourly limit exceeded for host '{}': {} connections per hour",
                                hostname, max_connections
                            ),
                        });
                    }
                }

                // Determine if confirmation is required
                if requires_confirm {
                    return Ok(SignatureDecision::RequireConfirm {
                        reason: format!("Host '{}' requires confirmation", hostname),
                    });
                }
            }
        }

        // Check if global or key-specific authentication is required
        let key_requires_confirm = self
            .policy
            .key_policies
            .get(&key_id)
            .map(|p| p.require_confirm)
            .unwrap_or(false);

        let key_requires_biometric = self
            .policy
            .key_policies
            .get(&key_id)
            .map(|p| p.require_biometric)
            .unwrap_or(false);

        // Biometric takes precedence over confirmation
        if key_requires_biometric {
            return Ok(SignatureDecision::RequireBiometric {
                reason: "Biometric authentication required by policy".to_string(),
            });
        }

        if self.policy.global.require_confirm || key_requires_confirm {
            return Ok(SignatureDecision::RequireConfirm {
                reason: "Confirmation required by policy".to_string(),
            });
        }

        Ok(SignatureDecision::Allowed)
    }

    /// Record that a signature was performed
    pub fn record_signature(&mut self, credential_id: &Uuid, hostname: Option<&str>) {
        self.state.last_sign = Some(Instant::now());
        self.state.signature_timestamps.push(Instant::now());

        // Update key usage
        let usage = self.state.key_usage.entry(*credential_id).or_default();
        usage.daily_count += 1;
        usage.total_count += 1;

        // Update host usage
        if let Some(hostname) = hostname {
            let usage = self
                .state
                .host_usage
                .entry(hostname.to_string())
                .or_default();
            usage.hourly_count += 1;
            usage.total_count += 1;
        }
    }

    fn cleanup_old_timestamps(&mut self) {
        let one_hour_ago = Instant::now() - Duration::from_secs(3600);
        self.state
            .signature_timestamps
            .retain(|&t| t > one_hour_ago);
    }

    fn matches_any_pattern(&self, hostname: &str, patterns: &[String]) -> bool {
        patterns
            .iter()
            .any(|pattern| glob_match::glob_match(pattern, hostname))
    }

    fn find_host_policy(&self, hostname: &str) -> Option<&HostPolicy> {
        // Try exact match first
        if let Some(policy) = self.policy.host_policies.get(hostname) {
            return Some(policy);
        }

        // Try pattern match
        for (pattern, policy) in &self.policy.host_policies {
            if glob_match::glob_match(pattern, hostname) {
                return Some(policy);
            }
        }

        None
    }

    fn is_within_time_range(&self, time_range: &str) -> bool {
        // Parse time range like "09:00-17:00"
        let parts: Vec<&str> = time_range.split('-').collect();
        if parts.len() != 2 {
            return true; // Invalid format, allow by default
        }

        let now = chrono::Local::now().time();

        let start_time = chrono::NaiveTime::parse_from_str(parts[0], "%H:%M").ok();
        let end_time = chrono::NaiveTime::parse_from_str(parts[1], "%H:%M").ok();

        match (start_time, end_time) {
            (Some(start), Some(end)) => {
                if start <= end {
                    // Normal range: 09:00-17:00
                    now >= start && now <= end
                } else {
                    // Overnight range: 22:00-06:00
                    now >= start || now <= end
                }
            }
            _ => true, // Invalid times, allow by default
        }
    }
}

impl KeyUsageState {
    fn reset_if_needed(&mut self) {
        let now = Instant::now();
        if self.last_reset.elapsed() >= Duration::from_secs(86400) {
            // Reset daily counter
            self.daily_count = 0;
            self.last_reset = now;
        }
    }
}

impl HostUsageState {
    fn reset_if_needed(&mut self) {
        let now = Instant::now();
        if self.last_reset.elapsed() >= Duration::from_secs(3600) {
            // Reset hourly counter
            self.hourly_count = 0;
            self.last_reset = now;
        }
    }
}

impl Default for KeyUsageState {
    fn default() -> Self {
        Self {
            daily_count: 0,
            last_reset: Instant::now(),
            total_count: 0,
        }
    }
}

impl Default for HostUsageState {
    fn default() -> Self {
        Self {
            hourly_count: 0,
            last_reset: Instant::now(),
            total_count: 0,
        }
    }
}

/// Result of a signature policy check
#[derive(Debug, Clone)]
pub enum SignatureDecision {
    /// Signature is allowed
    Allowed,

    /// Signature requires user confirmation
    RequireConfirm { reason: String },

    /// Signature requires biometric authentication
    RequireBiometric { reason: String },

    /// Signature is denied
    Denied { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_allows() {
        let mut enforcer = PolicyEnforcer::new(SigningPolicy::default());
        let cred_id = Uuid::new_v4();

        let decision = enforcer
            .check_signature(&cred_id, Some("github.com"))
            .unwrap();
        assert!(matches!(decision, SignatureDecision::Allowed));
    }

    #[test]
    fn test_deny_all_lockdown() {
        let mut policy = SigningPolicy::default();
        policy.global.deny_all = true;

        let mut enforcer = PolicyEnforcer::new(policy);
        let cred_id = Uuid::new_v4();

        let decision = enforcer.check_signature(&cred_id, None).unwrap();
        assert!(matches!(decision, SignatureDecision::Denied { .. }));
    }

    #[test]
    fn test_rate_limiting() {
        let mut policy = SigningPolicy::default();
        policy.global.min_interval_ms = 1000;

        let mut enforcer = PolicyEnforcer::new(policy);
        let cred_id = Uuid::new_v4();

        // First signature should be allowed
        let decision = enforcer.check_signature(&cred_id, None).unwrap();
        assert!(matches!(decision, SignatureDecision::Allowed));
        enforcer.record_signature(&cred_id, None);

        // Immediate second signature should be denied
        let decision = enforcer.check_signature(&cred_id, None).unwrap();
        assert!(matches!(decision, SignatureDecision::Denied { .. }));
    }

    #[test]
    fn test_key_policy_host_restrictions() {
        let mut policy = SigningPolicy::default();
        let cred_id = Uuid::new_v4();

        let mut key_policy = KeyPolicy::default();
        key_policy.allowed_hosts = vec!["github.com".to_string(), "gitlab.com".to_string()];
        policy.key_policies.insert(cred_id.to_string(), key_policy);

        let mut enforcer = PolicyEnforcer::new(policy);

        // Allowed host
        let decision = enforcer
            .check_signature(&cred_id, Some("github.com"))
            .unwrap();
        assert!(matches!(decision, SignatureDecision::Allowed));

        // Denied host
        let decision = enforcer
            .check_signature(&cred_id, Some("evil.com"))
            .unwrap();
        assert!(matches!(decision, SignatureDecision::Denied { .. }));
    }

    #[test]
    fn test_glob_patterns() {
        let mut policy = SigningPolicy::default();
        let cred_id = Uuid::new_v4();

        let mut key_policy = KeyPolicy::default();
        key_policy.allowed_hosts = vec!["*.github.com".to_string()];
        policy.key_policies.insert(cred_id.to_string(), key_policy);

        let mut enforcer = PolicyEnforcer::new(policy);

        // Should match pattern
        let decision = enforcer
            .check_signature(&cred_id, Some("api.github.com"))
            .unwrap();
        assert!(matches!(decision, SignatureDecision::Allowed));

        // Should not match
        let decision = enforcer
            .check_signature(&cred_id, Some("github.io"))
            .unwrap();
        assert!(matches!(decision, SignatureDecision::Denied { .. }));
    }
}
