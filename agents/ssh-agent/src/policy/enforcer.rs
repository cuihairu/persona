//! Policy enforcer: `PolicyEnforcer` loading (TOML file / environment
//! variables), signature adjudication
//! (`check_signature`/`check_and_record_signature`/`rollback_signature`),
//! usage counting and rate-limit state machines
//! (`PolicyState`/`KeyUsageState`/`HostUsageState`), and the decision
//! representation `SignatureDecision`.

use crate::is_host_in_known_hosts;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::model::{HostPolicy, SigningPolicy};

/// Runtime state for policy enforcement
pub struct PolicyEnforcer {
    pub(super) policy: SigningPolicy,
    pub(super) state: PolicyState,
}

#[derive(Debug, Default)]
pub(super) struct PolicyState {
    pub(super) last_sign: Option<Instant>,
    pub(super) signature_timestamps: Vec<Instant>,
    pub(super) key_usage: HashMap<Uuid, KeyUsageState>,
    pub(super) host_usage: HashMap<String, HostUsageState>,
}

#[derive(Debug)]
pub(super) struct KeyUsageState {
    pub(super) daily_count: u32,
    pub(super) last_reset: Instant,
    pub(super) total_count: u64,
}

#[derive(Debug)]
pub(super) struct HostUsageState {
    pub(super) hourly_count: u32,
    pub(super) last_reset: Instant,
    pub(super) total_count: u64,
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

    /// Host-side override for the `PERSONA_AGENT_REQUIRE_CONFIRM` env var.
    /// Desktop apps run the agent in-process and inject policy through
    /// [`crate::AgentEnvOverrides`] instead of writing process-global
    /// environment state from a multi-threaded runtime.
    pub fn set_require_confirm(&mut self, value: bool) {
        self.policy.global.require_confirm = value;
    }

    /// Check if a signature request should be allowed
    pub fn check_signature(
        &mut self,
        credential_id: &Uuid,
        hostname: Option<&str>,
    ) -> Result<SignatureDecision> {
        let hostname = hostname.filter(|h| !h.is_empty());
        let is_known_host = hostname.map(is_host_in_known_hosts).unwrap_or(false);
        let mut unknown_host_confirmation: Option<String> = None;

        // Global deny all check
        if self.policy.global.deny_all {
            return Ok(SignatureDecision::Denied {
                reason: "Agent is in lockdown mode".to_string(),
            });
        }

        if self.policy.global.enforce_known_hosts {
            match (hostname, is_known_host) {
                (Some(_), true) => {}
                (Some(host), false) => {
                    return Ok(SignatureDecision::Denied {
                        reason: format!("Host {} is not trusted according to known_hosts", host),
                    });
                }
                (None, _) => {
                    return Ok(SignatureDecision::Denied {
                        reason: "Host must be provided when known_hosts enforcement is enabled"
                            .to_string(),
                    });
                }
            }
        }

        if self.policy.global.confirm_on_unknown_host {
            if let Some(host) = hostname {
                if !is_known_host {
                    unknown_host_confirmation =
                        Some(format!("Host {} is not present in known_hosts", host));
                }
            } else {
                unknown_host_confirmation =
                    Some("Host is unknown; confirmation required".to_string());
            }
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
                    && self.matches_any_pattern(hostname, &key_policy.denied_hosts)
                {
                    return Ok(SignatureDecision::Denied {
                        reason: format!("Host '{}' is denied for this key", hostname),
                    });
                }

                if !key_policy.allowed_hosts.is_empty()
                    && !self.matches_any_pattern(hostname, &key_policy.allowed_hosts)
                {
                    return Ok(SignatureDecision::Denied {
                        reason: format!("Host '{}' is not in allowed list for this key", hostname),
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
                    && !host_policy.allowed_keys.contains(&key_id)
                {
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

        let mut require_confirm = self.policy.global.require_confirm || key_requires_confirm;
        let mut confirm_reason = if self.policy.global.require_confirm || key_requires_confirm {
            Some("Confirmation required by policy".to_string())
        } else {
            None
        };

        if let Some(reason) = unknown_host_confirmation {
            require_confirm = true;
            confirm_reason = Some(reason);
        }

        // Biometric takes precedence over confirmation
        if key_requires_biometric {
            return Ok(SignatureDecision::RequireBiometric {
                reason: "Biometric authentication required by policy".to_string(),
            });
        }

        if require_confirm {
            return Ok(SignatureDecision::RequireConfirm {
                reason: confirm_reason
                    .unwrap_or_else(|| "Confirmation required by policy".to_string()),
            });
        }

        Ok(SignatureDecision::Allowed)
    }

    /// Atomically check and record a signature (fix for the check/record
    /// two-lock race): deciding and booking happen under the single policy
    /// lock the caller already holds, so concurrent requests can no longer
    /// all pass the limit check before any of them is recorded.
    ///
    /// Recording is optimistic: the caller may still have an approval/biometric
    /// UI gate ahead (it runs outside the lock). When that gate refuses, the
    /// caller must call [`Self::rollback_signature`] with the same
    /// `(credential_id, hostname)` so the tentatively booked signature does
    /// not consume budget.
    pub fn check_and_record_signature(
        &mut self,
        credential_id: &Uuid,
        hostname: Option<&str>,
    ) -> Result<SignatureDecision> {
        let decision = self.check_signature(credential_id, hostname)?;
        // A denied request never reaches signing, so it must not consume
        // budget; only decisions that may proceed are booked.
        if !matches!(decision, SignatureDecision::Denied { .. }) {
            self.record_signature(credential_id, hostname);
        }
        Ok(decision)
    }

    /// Roll back a signature recorded optimistically by
    /// [`Self::check_and_record_signature`] (user/biometric gate refused).
    pub fn rollback_signature(&mut self, credential_id: &Uuid, hostname: Option<&str>) {
        self.state.signature_timestamps.pop();
        // last_sign must reflect the newest remaining signature, otherwise a
        // rolled-back attempt would keep the min-interval gate armed.
        self.state.last_sign = self.state.signature_timestamps.last().copied();
        if let Some(usage) = self.state.key_usage.get_mut(credential_id) {
            usage.daily_count = usage.daily_count.saturating_sub(1);
            usage.total_count = usage.total_count.saturating_sub(1);
        }
        if let Some(hostname) = hostname {
            if let Some(usage) = self.state.host_usage.get_mut(hostname) {
                usage.hourly_count = usage.hourly_count.saturating_sub(1);
                usage.total_count = usage.total_count.saturating_sub(1);
            }
        }
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

    pub(super) fn is_within_time_range(&self, time_range: &str) -> bool {
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
    pub(super) fn reset_if_needed(&mut self) {
        let now = Instant::now();
        if self.last_reset.elapsed() >= Duration::from_secs(86400) {
            // Reset daily counter
            self.daily_count = 0;
            self.last_reset = now;
        }
    }
}

impl HostUsageState {
    pub(super) fn reset_if_needed(&mut self) {
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

impl SignatureDecision {
    /// Convert to the unified authorization decision vocabulary
    /// (architecture-correction batch 1): Denied maps one-to-one with the
    /// interaction-required variants. The policy logic itself is unchanged
    /// (host rules/rate limits/confirmation counting remain this module's
    /// mechanism-layer responsibility); only the outward decision
    /// representation is unified onto `persona_core::authz`.
    pub fn to_authz(&self) -> persona_core::authz::AuthzDecision {
        use persona_core::authz::AuthzDecision;
        match self {
            Self::Allowed => AuthzDecision::Allowed,
            Self::RequireConfirm { reason } | Self::RequireBiometric { reason } => {
                AuthzDecision::InteractionRequired {
                    reason: reason.clone(),
                }
            }
            Self::Denied { reason } => AuthzDecision::Denied {
                reason: reason.clone(),
            },
        }
    }
}
