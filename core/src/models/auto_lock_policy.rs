use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Auto-lock policy for different security levels and contexts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoLockPolicy {
    /// Policy unique identifier
    pub id: Uuid,

    /// Policy name
    pub name: String,

    /// Policy description
    pub description: Option<String>,

    /// Security level this policy applies to
    pub security_level: AutoLockSecurityLevel,

    /// Inactivity timeout in seconds
    pub inactivity_timeout_secs: u64,

    /// Absolute session timeout in seconds
    pub absolute_timeout_secs: u64,

    /// Sensitive operation timeout in seconds
    pub sensitive_operation_timeout_secs: u64,

    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: usize,

    /// Whether to enable lock warnings
    pub enable_warnings: bool,

    /// Warning time before lock in seconds
    pub warning_time_secs: u64,

    /// Force lock on sensitive operations after timeout
    pub force_lock_sensitive: bool,

    /// Activity grace period in seconds
    pub activity_grace_period_secs: u64,

    /// Background check interval in seconds
    pub background_check_interval_secs: u64,

    /// Policy metadata
    pub metadata: PolicyMetadata,

    /// Whether this policy is active
    pub is_active: bool,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Security levels for auto-lock policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Copy)]
#[serde(rename_all = "snake_case")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AutoLockSecurityLevel {
    /// Low security - longer timeouts, more lenient
    Low,
    /// Medium security - balanced approach
    Medium,
    /// High security - shorter timeouts, stricter
    High,
    /// Maximum security - very strict locking
    Maximum,
}

impl std::fmt::Display for AutoLockSecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoLockSecurityLevel::Low => write!(f, "Low"),
            AutoLockSecurityLevel::Medium => write!(f, "Medium"),
            AutoLockSecurityLevel::High => write!(f, "High"),
            AutoLockSecurityLevel::Maximum => write!(f, "Maximum"),
        }
    }
}

impl std::str::FromStr for AutoLockSecurityLevel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "maximum" => Ok(Self::Maximum),
            other => Err(format!("Invalid auto-lock security level: {}", other)),
        }
    }
}

impl Default for AutoLockSecurityLevel {
    fn default() -> Self {
        AutoLockSecurityLevel::Medium
    }
}

/// Policy metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct PolicyMetadata {
    /// Tags for policy categorization
    pub tags: Vec<String>,

    /// Custom key-value pairs
    pub custom_settings: HashMap<String, String>,

    /// Policy version
    pub version: u32,

    /// Owner user ID who created this policy
    pub owner_id: Option<Uuid>,

    /// Whether this is a system policy (cannot be deleted)
    pub is_system_policy: bool,
}

/// Auto-lock policy statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyStatistics {
    /// Number of active sessions using this policy
    pub active_sessions: usize,

    /// Number of users assigned to this policy
    pub assigned_users: usize,

    /// Average session duration (in seconds)
    pub avg_session_duration_secs: u64,

    /// Number of auto-lock events in the last 24 hours
    pub recent_lock_events: usize,

    /// Policy compliance score (0-100)
    pub compliance_score: u8,
}

impl AutoLockPolicy {
    /// Create a new auto-lock policy
    pub fn new(
        name: String,
        security_level: AutoLockSecurityLevel,
        inactivity_timeout_secs: u64,
    ) -> Self {
        let now = chrono::Utc::now();
        let id = Uuid::new_v4();

        // Set defaults based on security level
        let (absolute_timeout, sensitive_timeout, max_sessions, warnings_enabled, warning_time) =
            match security_level {
                AutoLockSecurityLevel::Low => (7200, 600, 10, true, 300),
                AutoLockSecurityLevel::Medium => (3600, 300, 5, true, 60),
                AutoLockSecurityLevel::High => (1800, 180, 3, true, 30),
                AutoLockSecurityLevel::Maximum => (900, 60, 1, false, 15),
            };

        Self {
            id,
            name,
            description: None,
            security_level,
            inactivity_timeout_secs,
            absolute_timeout_secs: absolute_timeout,
            sensitive_operation_timeout_secs: sensitive_timeout,
            max_concurrent_sessions: max_sessions,
            enable_warnings: warnings_enabled,
            warning_time_secs: warning_time,
            force_lock_sensitive: security_level != AutoLockSecurityLevel::Low,
            activity_grace_period_secs: 5,
            background_check_interval_secs: 30,
            metadata: PolicyMetadata::default(),
            is_active: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a policy with full custom configuration
    pub fn new_full(config: PolicyConfiguration) -> Self {
        let now = chrono::Utc::now();

        Self {
            id: Uuid::new_v4(),
            name: config.name,
            description: config.description,
            security_level: config.security_level,
            inactivity_timeout_secs: config.inactivity_timeout_secs,
            absolute_timeout_secs: config.absolute_timeout_secs,
            sensitive_operation_timeout_secs: config.sensitive_operation_timeout_secs,
            max_concurrent_sessions: config.max_concurrent_sessions,
            enable_warnings: config.enable_warnings,
            warning_time_secs: config.warning_time_secs,
            force_lock_sensitive: config.force_lock_sensitive,
            activity_grace_period_secs: config.activity_grace_period_secs,
            background_check_interval_secs: config.background_check_interval_secs,
            metadata: PolicyMetadata::default(),
            is_active: config.is_active,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the policy with new configuration
    pub fn update(&mut self, config: PolicyConfiguration) {
        self.name = config.name;
        self.description = config.description;
        self.security_level = config.security_level;
        self.inactivity_timeout_secs = config.inactivity_timeout_secs;
        self.absolute_timeout_secs = config.absolute_timeout_secs;
        self.sensitive_operation_timeout_secs = config.sensitive_operation_timeout_secs;
        self.max_concurrent_sessions = config.max_concurrent_sessions;
        self.enable_warnings = config.enable_warnings;
        self.warning_time_secs = config.warning_time_secs;
        self.force_lock_sensitive = config.force_lock_sensitive;
        self.activity_grace_period_secs = config.activity_grace_period_secs;
        self.background_check_interval_secs = config.background_check_interval_secs;
        self.is_active = config.is_active;
        self.updated_at = chrono::Utc::now();
    }

    /// Check if this policy is more strict than another
    pub fn is_more_strict_than(&self, other: &AutoLockPolicy) -> bool {
        // Compare security levels
        let level_order = match (self.security_level, other.security_level) {
            (AutoLockSecurityLevel::Maximum, _) => true,
            (_, AutoLockSecurityLevel::Maximum) => false,
            (
                AutoLockSecurityLevel::High,
                AutoLockSecurityLevel::Low | AutoLockSecurityLevel::Medium,
            ) => true,
            (AutoLockSecurityLevel::Medium, AutoLockSecurityLevel::Low) => true,
            (AutoLockSecurityLevel::Low, _) => false,
            _ => self.inactivity_timeout_secs < other.inactivity_timeout_secs,
        };

        level_order
            || (self.inactivity_timeout_secs < other.inactivity_timeout_secs
                && self.max_concurrent_sessions <= other.max_concurrent_sessions)
    }

    /// Calculate security score (0-100, higher is more secure)
    pub fn security_score(&self) -> u8 {
        let mut score = 50u8;

        // Inactivity timeout score (shorter = more secure)
        if self.inactivity_timeout_secs <= 300 {
            score += 20;
        } else if self.inactivity_timeout_secs <= 900 {
            score += 15;
        } else if self.inactivity_timeout_secs <= 1800 {
            score += 10;
        }

        // Sensitive operation timeout
        if self.sensitive_operation_timeout_secs <= 60 {
            score += 15;
        } else if self.sensitive_operation_timeout_secs <= 300 {
            score += 10;
        }

        // Force lock sensitive
        if self.force_lock_sensitive {
            score += 10;
        }

        // Warning system
        if self.enable_warnings {
            score += 5;
        }

        // Session limits
        if self.max_concurrent_sessions <= 2 {
            score += 10;
        } else if self.max_concurrent_sessions <= 5 {
            score += 5;
        }

        score.min(100)
    }

    /// Validate policy configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Policy name cannot be empty".to_string());
        }

        if self.inactivity_timeout_secs == 0 {
            return Err("Inactivity timeout must be greater than 0".to_string());
        }

        if self.sensitive_operation_timeout_secs == 0 {
            return Err("Sensitive operation timeout must be greater than 0".to_string());
        }

        if self.warning_time_secs >= self.inactivity_timeout_secs {
            return Err("Warning time must be less than inactivity timeout".to_string());
        }

        if self.max_concurrent_sessions == 0 {
            return Err("Max concurrent sessions must be at least 1".to_string());
        }

        if self.background_check_interval_secs == 0 {
            return Err("Background check interval must be greater than 0".to_string());
        }

        Ok(())
    }

    /// Get recommended settings for a given use case
    pub fn recommended_for_use_case(use_case: AutoLockUseCase) -> Self {
        match use_case {
            AutoLockUseCase::PersonalDevice => Self::new(
                "Personal Device".to_string(),
                AutoLockSecurityLevel::Medium,
                900, // 15 minutes
            ),
            AutoLockUseCase::CorporateDesktop => Self::new(
                "Corporate Desktop".to_string(),
                AutoLockSecurityLevel::High,
                600, // 10 minutes
            ),
            AutoLockUseCase::PublicKiosk => Self::new(
                "Public Kiosk".to_string(),
                AutoLockSecurityLevel::Maximum,
                300, // 5 minutes
            ),
            AutoLockUseCase::DeveloperEnvironment => Self::new(
                "Developer Environment".to_string(),
                AutoLockSecurityLevel::Low,
                1800, // 30 minutes
            ),
            AutoLockUseCase::HighSecurityFacility => Self::new(
                "High Security Facility".to_string(),
                AutoLockSecurityLevel::Maximum,
                120, // 2 minutes
            ),
        }
    }
}

/// Configuration for creating or updating a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfiguration {
    pub name: String,
    pub description: Option<String>,
    pub security_level: AutoLockSecurityLevel,
    pub inactivity_timeout_secs: u64,
    pub absolute_timeout_secs: u64,
    pub sensitive_operation_timeout_secs: u64,
    pub max_concurrent_sessions: usize,
    pub enable_warnings: bool,
    pub warning_time_secs: u64,
    pub force_lock_sensitive: bool,
    pub activity_grace_period_secs: u64,
    pub background_check_interval_secs: u64,
    pub is_active: bool,
}

/// Common use cases for auto-lock policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AutoLockUseCase {
    PersonalDevice,
    CorporateDesktop,
    PublicKiosk,
    DeveloperEnvironment,
    HighSecurityFacility,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy =
            AutoLockPolicy::new("Test Policy".to_string(), AutoLockSecurityLevel::High, 600);

        assert_eq!(policy.name, "Test Policy");
        assert_eq!(policy.security_level, AutoLockSecurityLevel::High);
        assert_eq!(policy.inactivity_timeout_secs, 600);
        assert!(policy.is_active);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_security_score() {
        let mut policy = AutoLockPolicy::new(
            "High Security".to_string(),
            AutoLockSecurityLevel::High,
            300,
        );

        let score = policy.security_score();
        assert!(score > 70); // Should be quite secure

        policy.force_lock_sensitive = true;
        policy.enable_warnings = true;
        policy.max_concurrent_sessions = 1;

        let new_score = policy.security_score();
        assert!(new_score > score); // Should be even more secure
    }

    #[test]
    fn test_policy_strictness() {
        let strict_policy =
            AutoLockPolicy::new("Strict".to_string(), AutoLockSecurityLevel::High, 300);

        let lenient_policy =
            AutoLockPolicy::new("Lenient".to_string(), AutoLockSecurityLevel::Low, 1800);

        assert!(strict_policy.is_more_strict_than(&lenient_policy));
        assert!(!lenient_policy.is_more_strict_than(&strict_policy));
    }

    #[test]
    fn test_recommended_policies() {
        let kiosk_policy = AutoLockPolicy::recommended_for_use_case(AutoLockUseCase::PublicKiosk);
        assert_eq!(kiosk_policy.security_level, AutoLockSecurityLevel::Maximum);
        assert_eq!(kiosk_policy.inactivity_timeout_secs, 300);

        let dev_policy =
            AutoLockPolicy::recommended_for_use_case(AutoLockUseCase::DeveloperEnvironment);
        assert_eq!(dev_policy.security_level, AutoLockSecurityLevel::Low);
        assert_eq!(dev_policy.inactivity_timeout_secs, 1800);
    }

    #[test]
    fn test_policy_validation() {
        let mut policy =
            AutoLockPolicy::new("Test".to_string(), AutoLockSecurityLevel::Medium, 600);

        assert!(policy.validate().is_ok());

        // Test invalid configurations
        policy.name = "".to_string();
        assert!(policy.validate().is_err());

        policy.name = "Test".to_string();
        policy.inactivity_timeout_secs = 0;
        assert!(policy.validate().is_err());

        policy.inactivity_timeout_secs = 600;
        policy.warning_time_secs = 700; // Greater than inactivity timeout
        assert!(policy.validate().is_err());
    }
}
