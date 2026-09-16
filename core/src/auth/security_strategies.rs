use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Advanced security strategies for auto-lock management
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityStrategy {
    /// Strategy identifier
    pub id: Uuid,

    /// Strategy name
    pub name: String,

    /// Strategy description
    pub description: Option<String>,

    /// Strategy category
    pub category: SecurityCategory,

    /// Risk level this strategy addresses
    pub risk_level: RiskLevel,

    /// Strategy configuration
    pub configuration: StrategyConfiguration,

    /// Conditions under which this strategy applies
    pub conditions: Vec<SecurityCondition>,

    /// Actions to take when strategy is triggered
    pub actions: Vec<SecurityAction>,

    /// Whether this strategy is enabled
    pub enabled: bool,

    /// Strategy priority (higher = more important)
    pub priority: u8,

    /// Strategy metadata
    pub metadata: StrategyMetadata,
}

/// Categories of security strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCategory {
    /// Time-based security (inactivity, timeouts)
    TimeBased,
    /// Location-based security
    LocationBased,
    /// Device-based security
    DeviceBased,
    /// Behavioral security (anomaly detection)
    Behavioral,
    /// Network security
    Network,
    /// Compliance and regulatory
    Compliance,
    /// Threat intelligence
    ThreatIntelligence,
    /// Custom user-defined strategies
    Custom,
}

/// Risk levels for security assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Critical = 5,
    High = 4,
    Medium = 3,
    Low = 2,
    Minimal = 1,
}

/// Configuration for security strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct StrategyConfiguration {
    /// Time-based settings
    pub time_settings: Option<TimeBasedSettings>,

    /// Location-based settings
    pub location_settings: Option<LocationBasedSettings>,

    /// Device-based settings
    pub device_settings: Option<DeviceBasedSettings>,

    /// Behavioral settings
    pub behavioral_settings: Option<BehavioralSettings>,

    /// Network settings
    pub network_settings: Option<NetworkSettings>,

    /// Custom key-value settings
    pub custom_settings: HashMap<String, serde_json::Value>,
}

/// Time-based security settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeBasedSettings {
    /// Inactivity timeout in seconds
    pub inactivity_timeout_secs: u64,

    /// Progressive lock intervals (escalating timeouts)
    pub progressive_timeouts: Vec<u64>,

    /// Time windows when stricter rules apply
    pub restricted_hours: Option<RestrictedHours>,

    /// Holiday/weekend policies
    pub holiday_policy: HolidayPolicy,

    /// Session duration limits
    pub max_session_duration_secs: Option<u64>,

    /// Daily usage limits
    pub daily_usage_limit_secs: Option<u64>,
}

/// Restricted hours configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RestrictedHours {
    /// Start hour (24-hour format)
    pub start_hour: u8,

    /// End hour (24-hour format)
    pub end_hour: u8,

    /// Days of week when restrictions apply (0=Sunday, 6=Saturday)
    pub days_of_week: Vec<u8>,

    /// Timezone for hour calculations
    pub timezone: String,
}

/// Holiday policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HolidayPolicy {
    /// Use stricter timeouts on holidays
    pub stricter_on_holidays: bool,

    /// Holiday timeout multiplier (e.g., 0.5 for half the normal timeout)
    pub holiday_timeout_multiplier: f64,

    /// List of holiday dates (YYYY-MM-DD format)
    pub holiday_dates: Vec<String>,

    /// Apply rules on weekends
    pub apply_on_weekends: bool,
}

/// Location-based security settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocationBasedSettings {
    /// Trusted locations (IP ranges, geofences)
    pub trusted_locations: Vec<TrustedLocation>,

    /// High-risk locations to block
    pub blocked_locations: Vec<String>,

    /// Require location verification
    pub require_location_verification: bool,

    /// Location-based timeout adjustments
    pub location_timeouts: HashMap<String, u64>,

    /// Geofencing enabled
    pub geofencing_enabled: bool,

    /// Maximum distance from trusted location (meters)
    pub max_distance_meters: Option<u64>,
}

/// Trusted location definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedLocation {
    /// Location name
    pub name: String,

    /// IP ranges (CIDR notation)
    pub ip_ranges: Vec<String>,

    /// Geographic coordinates (latitude, longitude)
    pub coordinates: Option<(f64, f64)>,

    /// Maximum radius in meters
    pub radius_meters: Option<u64>,

    /// Timeout multiplier for this location
    pub timeout_multiplier: Option<f64>,
}

/// Device-based security settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceBasedSettings {
    /// Trusted device identifiers
    pub trusted_devices: Vec<DeviceInfo>,

    /// Require device authentication
    pub require_device_auth: bool,

    /// Device fingerprinting enabled
    pub device_fingerprinting: bool,

    /// Maximum devices per user
    pub max_devices_per_user: usize,

    /// New device quarantine period (seconds)
    pub new_device_quarantine_secs: Option<u64>,

    /// Device-specific timeout adjustments
    pub device_timeouts: HashMap<String, u64>,
}

/// Device information for security tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceInfo {
    /// Device unique identifier
    pub device_id: String,

    /// Device type (desktop, mobile, tablet, etc.)
    pub device_type: String,

    /// Operating system
    pub os: String,

    /// Browser/application
    pub application: String,

    /// Device fingerprint hash
    pub fingerprint: Option<String>,

    /// Is this device trusted
    pub trusted: bool,

    /// Device registration timestamp
    pub registered_at: chrono::DateTime<chrono::Utc>,

    /// Last access timestamp
    pub last_access: Option<chrono::DateTime<chrono::Utc>>,
}

/// Behavioral security settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BehavioralSettings {
    /// Anomaly detection enabled
    pub anomaly_detection: bool,

    /// Typing pattern analysis
    pub typing_analysis: bool,

    /// Mouse movement pattern analysis
    pub mouse_pattern_analysis: bool,

    /// Access pattern analysis
    pub access_pattern_analysis: bool,

    /// Risk score threshold for action
    pub risk_score_threshold: f64,

    /// Learning period duration (days)
    pub learning_period_days: u32,

    /// Behavioral baseline update frequency
    pub baseline_update_frequency_hours: u32,
}

/// Network security settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkSettings {
    /// Trusted networks (IP ranges, SSIDs)
    pub trusted_networks: Vec<String>,

    /// Blocked networks
    pub blocked_networks: Vec<String>,

    /// Require VPN for sensitive operations
    pub require_vpn: bool,

    /// Network-based timeout adjustments
    pub network_timeouts: HashMap<String, u64>,

    /// Bandwidth-based security
    pub bandwidth_based_security: bool,

    /// Connection type restrictions
    pub connection_restrictions: ConnectionRestrictions,
}

/// Connection type restrictions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionRestrictions {
    /// Allow Wi-Fi connections
    pub allow_wifi: bool,

    /// Allow cellular connections
    pub allow_cellular: bool,

    /// Allow wired connections
    pub allow_wired: bool,

    /// Require encrypted connections
    pub require_encryption: bool,

    /// Block public Wi-Fi
    pub block_public_wifi: bool,
}

/// Security conditions that trigger strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecurityCondition {
    /// Time-based condition
    TimeCondition {
        /// Check time-based rules
        time_rule: TimeRule,
    },

    /// Location-based condition
    LocationCondition {
        /// Current location
        location: String,

        /// Trusted locations list
        trusted_locations: Vec<String>,
    },

    /// Device-based condition
    DeviceCondition {
        /// Device identifier
        device_id: String,

        /// Device trust status
        trusted: bool,

        /// Device type
        device_type: String,
    },

    /// Behavioral condition
    BehavioralCondition {
        /// Risk score
        risk_score: f64,

        /// Anomaly detected
        anomaly_detected: bool,

        /// Behavioral pattern deviation
        pattern_deviation: f64,
    },

    /// Network condition
    NetworkCondition {
        /// Network identifier
        network: String,

        /// Connection type
        connection_type: String,

        /// Is VPN connection
        is_vpn: bool,

        /// Is encrypted
        is_encrypted: bool,
    },

    /// Composite condition (AND/OR logic)
    CompositeCondition {
        /// Logical operator
        operator: LogicalOperator,

        /// Sub-conditions
        conditions: Vec<SecurityCondition>,
    },

    /// Custom condition
    CustomCondition {
        /// Condition name
        name: String,

        /// Custom parameters
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Time-based rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TimeRule {
    /// Current time is within restricted hours
    IsRestrictedHours,

    /// Is weekend
    IsWeekend,

    /// Is holiday
    IsHoliday,

    /// Session duration exceeds limit
    SessionDurationExceeds { limit_secs: u64 },

    /// Daily usage exceeds limit
    DailyUsageExceeds { limit_secs: u64 },

    /// Time since last activity exceeds threshold
    InactivityExceeds { threshold_secs: u64 },
}

/// Logical operators for composite conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

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

/// Strategy metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StrategyMetadata {
    /// Strategy version
    pub version: u32,

    /// Creation timestamp
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Last updated timestamp
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Strategy author
    pub author: Option<String>,

    /// Tags for categorization
    pub tags: Vec<String>,

    /// Compliance references
    pub compliance_references: Vec<String>,

    /// Strategy effectiveness score (0-100)
    pub effectiveness_score: Option<u8>,

    /// Number of times this strategy has been triggered
    pub trigger_count: u64,

    /// Last triggered timestamp
    pub last_triggered: Option<chrono::DateTime<chrono::Utc>>,

    /// Custom metadata
    pub custom: HashMap<String, serde_json::Value>,
}

impl SecurityStrategy {
    /// Create a new security strategy
    pub fn new(name: String, category: SecurityCategory, risk_level: RiskLevel) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            category,
            risk_level,
            configuration: StrategyConfiguration::default(),
            conditions: Vec::new(),
            actions: Vec::new(),
            enabled: true,
            priority: 50, // Default priority
            metadata: StrategyMetadata::default(),
        }
    }

    /// Add a condition to the strategy
    pub fn with_condition(mut self, condition: SecurityCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Add an action to the strategy
    pub fn with_action(mut self, action: SecurityAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Set strategy priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Enable/disable the strategy
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Check if strategy should be triggered
    pub fn should_trigger(&self, context: &SecurityContext) -> bool {
        if !self.enabled {
            return false;
        }

        // Evaluate all conditions (AND logic by default)
        self.conditions
            .iter()
            .all(|condition| self.evaluate_condition(condition, context))
    }

    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &SecurityCondition, context: &SecurityContext) -> bool {
        match condition {
            SecurityCondition::TimeCondition { time_rule } => {
                self.evaluate_time_rule(time_rule, context)
            }
            SecurityCondition::LocationCondition {
                trusted_locations, ..
            } => {
                // The condition's own `location` field is descriptive only;
                // triggering depends on the context's current location.
                trusted_locations.contains(&context.location)
            }
            SecurityCondition::DeviceCondition { trusted, .. } => *trusted,
            SecurityCondition::BehavioralCondition {
                risk_score,
                anomaly_detected,
                pattern_deviation,
            } => {
                // Threshold comes from the strategy's behavioral settings.
                let threshold = self
                    .configuration
                    .behavioral_settings
                    .as_ref()
                    .map(|s| s.risk_score_threshold)
                    .unwrap_or(0.5);
                *risk_score > threshold || *anomaly_detected || *pattern_deviation > threshold
            }
            SecurityCondition::NetworkCondition { is_encrypted, .. } => *is_encrypted,
            SecurityCondition::CompositeCondition {
                operator,
                conditions,
            } => match operator {
                LogicalOperator::And => conditions
                    .iter()
                    .all(|c| self.evaluate_condition(c, context)),
                LogicalOperator::Or => conditions
                    .iter()
                    .any(|c| self.evaluate_condition(c, context)),
                LogicalOperator::Not => {
                    if let Some(first) = conditions.first() {
                        !self.evaluate_condition(first, context)
                    } else {
                        true
                    }
                }
            },
            SecurityCondition::CustomCondition { .. } => {
                // Custom conditions would need external evaluation
                false
            }
        }
    }

    /// Evaluate time-based rules
    fn evaluate_time_rule(&self, rule: &TimeRule, context: &SecurityContext) -> bool {
        match rule {
            TimeRule::IsRestrictedHours => {
                // Implementation would check current time against restricted hours
                false // Placeholder
            }
            TimeRule::IsWeekend => {
                // Implementation would check if current day is weekend
                false // Placeholder
            }
            TimeRule::IsHoliday => {
                // Implementation would check if today is a holiday
                false // Placeholder
            }
            TimeRule::SessionDurationExceeds { limit_secs } => {
                context.session_duration_secs > *limit_secs
            }
            TimeRule::DailyUsageExceeds { limit_secs } => context.daily_usage_secs > *limit_secs,
            TimeRule::InactivityExceeds { threshold_secs } => {
                context.inactivity_duration_secs > *threshold_secs
            }
        }
    }

    /// Execute strategy actions
    pub fn execute_actions(&self, context: &mut SecurityContext) -> Vec<String> {
        let mut results = Vec::new();

        for action in &self.actions {
            let result = self.execute_action(action, context);
            results.push(result);
        }

        results
    }

    /// Execute a single action
    fn execute_action(&self, action: &SecurityAction, context: &mut SecurityContext) -> String {
        match action {
            SecurityAction::LockSession { reason, .. } => {
                context.session_locked = true;
                format!("Session locked: {}", reason)
            }
            SecurityAction::ExtendTimeout {
                extension_secs,
                reason,
            } => {
                context.session_timeout_extended_by = *extension_secs;
                format!("Timeout extended by {}s: {}", extension_secs, reason)
            }
            SecurityAction::RequireReauth { method, message } => {
                context.reauth_required = true;
                context.reauth_method = Some(method.clone());
                format!("Re-authentication required ({}): {}", method, message)
            }
            SecurityAction::Notify {
                message, severity, ..
            } => {
                context
                    .notifications
                    .push((message.clone(), severity.clone()));
                format!("Notification sent: {}", message)
            }
            SecurityAction::LogEvent {
                category,
                details,
                severity,
            } => {
                context
                    .security_events
                    .push((category.clone(), details.clone(), severity.clone()));
                format!("Security event logged: {}", category)
            }
            SecurityAction::RestrictFunctionality {
                restricted_features,
                reason,
            } => {
                context
                    .restricted_features
                    .extend(restricted_features.clone());
                format!(
                    "Functionality restricted: {} - {}",
                    reason,
                    restricted_features.join(", ")
                )
            }
            SecurityAction::CustomAction { name, .. } => {
                format!("Custom action executed: {}", name)
            }
        }
    }
}

/// Security context for evaluating strategies
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Current user ID
    pub user_id: String,

    /// Session ID
    pub session_id: String,

    /// Current location
    pub location: String,

    /// Device ID
    pub device_id: String,

    /// Network identifier
    pub network: String,

    /// Current time
    pub current_time: chrono::DateTime<chrono::Utc>,

    /// Session duration in seconds
    pub session_duration_secs: u64,

    /// Daily usage in seconds
    pub daily_usage_secs: u64,

    /// Inactivity duration in seconds
    pub inactivity_duration_secs: u64,

    /// Behavioral risk score
    pub risk_score: f64,

    /// Whether session is locked
    pub session_locked: bool,

    /// Session timeout extension
    pub session_timeout_extended_by: u64,

    /// Whether re-authentication is required
    pub reauth_required: bool,

    /// Required re-authentication method
    pub reauth_method: Option<AuthMethod>,

    /// Pending notifications
    pub notifications: Vec<(String, NotificationSeverity)>,

    /// Security events
    pub security_events: Vec<(String, HashMap<String, serde_json::Value>, EventSeverity)>,

    /// Restricted features
    pub restricted_features: Vec<String>,
}

impl Default for StrategyMetadata {
    fn default() -> Self {
        Self {
            version: 1,
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
            author: None,
            tags: Vec::new(),
            compliance_references: Vec::new(),
            effectiveness_score: None,
            trigger_count: 0,
            last_triggered: None,
            custom: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_strategy_creation() {
        let strategy = SecurityStrategy::new(
            "After Hours Lock".to_string(),
            SecurityCategory::TimeBased,
            RiskLevel::High,
        )
        .with_condition(SecurityCondition::TimeCondition {
            time_rule: TimeRule::IsRestrictedHours,
        })
        .with_action(SecurityAction::LockSession {
            reason: "Access outside business hours".to_string(),
            duration_secs: None,
        });

        assert_eq!(strategy.name, "After Hours Lock");
        assert_eq!(strategy.category, SecurityCategory::TimeBased);
        assert_eq!(strategy.risk_level, RiskLevel::High);
        assert_eq!(strategy.conditions.len(), 1);
        assert_eq!(strategy.actions.len(), 1);
    }

    #[test]
    fn test_composite_conditions() {
        let strategy = SecurityStrategy::new(
            "High Risk Location Lock".to_string(),
            SecurityCategory::LocationBased,
            RiskLevel::Critical,
        )
        .with_condition(SecurityCondition::CompositeCondition {
            operator: LogicalOperator::And,
            conditions: vec![
                SecurityCondition::LocationCondition {
                    location: "Unknown".to_string(),
                    trusted_locations: vec!["Office".to_string(), "Home".to_string()],
                },
                SecurityCondition::NetworkCondition {
                    network: "Public WiFi".to_string(),
                    connection_type: "WiFi".to_string(),
                    is_vpn: false,
                    is_encrypted: false,
                },
            ],
        });

        assert_eq!(strategy.conditions.len(), 1);
        if let SecurityCondition::CompositeCondition { conditions, .. } = &strategy.conditions[0] {
            assert_eq!(conditions.len(), 2);
        }
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::Minimal);
    }

    #[test]
    fn test_security_context() {
        let context = SecurityContext {
            user_id: "user123".to_string(),
            session_id: "session456".to_string(),
            location: "Office".to_string(),
            device_id: "device789".to_string(),
            network: "Corporate LAN".to_string(),
            current_time: chrono::Utc::now(),
            session_duration_secs: 3600,
            daily_usage_secs: 7200,
            inactivity_duration_secs: 300,
            risk_score: 0.2,
            session_locked: false,
            session_timeout_extended_by: 0,
            reauth_required: false,
            reauth_method: None,
            notifications: Vec::new(),
            security_events: Vec::new(),
            restricted_features: Vec::new(),
        };

        assert_eq!(context.user_id, "user123");
        assert_eq!(context.session_duration_secs, 3600);
        assert_eq!(context.risk_score, 0.2);
        assert!(!context.session_locked);
    }

    fn context_at(location: &str) -> SecurityContext {
        SecurityContext {
            user_id: "user123".to_string(),
            session_id: "session456".to_string(),
            location: location.to_string(),
            device_id: "device789".to_string(),
            network: "Corporate LAN".to_string(),
            current_time: chrono::Utc::now(),
            session_duration_secs: 3600,
            daily_usage_secs: 7200,
            inactivity_duration_secs: 300,
            risk_score: 0.2,
            session_locked: false,
            session_timeout_extended_by: 0,
            reauth_required: false,
            reauth_method: None,
            notifications: Vec::new(),
            security_events: Vec::new(),
            restricted_features: Vec::new(),
        }
    }

    fn triggers(condition: SecurityCondition, context: &SecurityContext) -> bool {
        SecurityStrategy::new(
            "probe".to_string(),
            SecurityCategory::Custom,
            RiskLevel::Low,
        )
        .with_condition(condition)
        .should_trigger(context)
    }

    #[test]
    fn test_time_rules_evaluate_against_context() {
        let context = context_at("Office");

        // Numeric rules compare against the context fields (strict >).
        assert!(triggers(
            SecurityCondition::TimeCondition {
                time_rule: TimeRule::SessionDurationExceeds { limit_secs: 1800 },
            },
            &context,
        ));
        assert!(!triggers(
            SecurityCondition::TimeCondition {
                time_rule: TimeRule::SessionDurationExceeds { limit_secs: 3600 },
            },
            &context,
        ));
        assert!(triggers(
            SecurityCondition::TimeCondition {
                time_rule: TimeRule::DailyUsageExceeds { limit_secs: 3600 },
            },
            &context,
        ));
        assert!(!triggers(
            SecurityCondition::TimeCondition {
                time_rule: TimeRule::DailyUsageExceeds { limit_secs: 7200 },
            },
            &context,
        ));
        assert!(triggers(
            SecurityCondition::TimeCondition {
                time_rule: TimeRule::InactivityExceeds {
                    threshold_secs: 120
                },
            },
            &context,
        ));
        assert!(!triggers(
            SecurityCondition::TimeCondition {
                time_rule: TimeRule::InactivityExceeds {
                    threshold_secs: 300
                },
            },
            &context,
        ));

        // Calendar rules are placeholders that never fire yet.
        for rule in [
            TimeRule::IsRestrictedHours,
            TimeRule::IsWeekend,
            TimeRule::IsHoliday,
        ] {
            assert!(
                !triggers(
                    SecurityCondition::TimeCondition { time_rule: rule },
                    &context,
                ),
                "placeholder rule must not trigger"
            );
        }
    }

    #[test]
    fn test_behavioral_condition_thresholds() {
        let context = context_at("Office");
        let behavioral =
            |risk: f64, anomaly: bool, deviation: f64| SecurityCondition::BehavioralCondition {
                risk_score: risk,
                anomaly_detected: anomaly,
                pattern_deviation: deviation,
            };

        // Default threshold is 0.5.
        assert!(triggers(behavioral(0.6, false, 0.0), &context));
        assert!(!triggers(behavioral(0.4, false, 0.4), &context));
        // An anomaly alone trips the condition regardless of score.
        assert!(triggers(behavioral(0.0, true, 0.0), &context));
        assert!(triggers(behavioral(0.0, false, 0.7), &context));

        // A configured threshold overrides the default.
        let mut strategy = SecurityStrategy::new(
            "Strict Behavior".to_string(),
            SecurityCategory::Behavioral,
            RiskLevel::High,
        )
        .with_condition(behavioral(0.6, false, 0.0));
        strategy.configuration.behavioral_settings = Some(BehavioralSettings {
            anomaly_detection: true,
            typing_analysis: false,
            mouse_pattern_analysis: false,
            access_pattern_analysis: true,
            risk_score_threshold: 0.9,
            learning_period_days: 14,
            baseline_update_frequency_hours: 24,
        });
        assert!(!strategy.should_trigger(&context));

        // ...but a detected anomaly still trips it.
        let mut strategy = strategy.clone();
        strategy.conditions = vec![behavioral(0.6, true, 0.0)];
        assert!(strategy.should_trigger(&context));
    }

    #[test]
    fn test_device_and_network_conditions() {
        let context = context_at("Office");

        assert!(triggers(
            SecurityCondition::DeviceCondition {
                device_id: "device789".to_string(),
                trusted: true,
                device_type: "laptop".to_string(),
            },
            &context,
        ));
        assert!(!triggers(
            SecurityCondition::DeviceCondition {
                device_id: "device789".to_string(),
                trusted: false,
                device_type: "laptop".to_string(),
            },
            &context,
        ));

        assert!(triggers(
            SecurityCondition::NetworkCondition {
                network: "Corporate LAN".to_string(),
                connection_type: "wired".to_string(),
                is_vpn: false,
                is_encrypted: true,
            },
            &context,
        ));
        assert!(!triggers(
            SecurityCondition::NetworkCondition {
                network: "Public WiFi".to_string(),
                connection_type: "wifi".to_string(),
                is_vpn: false,
                is_encrypted: false,
            },
            &context,
        ));
    }

    #[test]
    fn test_composite_or_not_and_custom_conditions() {
        let context = context_at("Office");
        // Matching depends on the context's location being trusted, so a
        // condition whose trust list excludes "Office" never fires.
        let office = SecurityCondition::LocationCondition {
            location: "Office".to_string(),
            trusted_locations: vec!["Office".to_string()],
        };
        let cafe = SecurityCondition::LocationCondition {
            location: "Cafe".to_string(),
            trusted_locations: vec!["Vault".to_string()],
        };

        // Or: at least one matching sub-condition.
        assert!(triggers(
            SecurityCondition::CompositeCondition {
                operator: LogicalOperator::Or,
                conditions: vec![cafe.clone(), office.clone()],
            },
            &context,
        ));
        assert!(!triggers(
            SecurityCondition::CompositeCondition {
                operator: LogicalOperator::Or,
                conditions: vec![cafe.clone()],
            },
            &context,
        ));

        // Not: negates the first sub-condition only.
        assert!(triggers(
            SecurityCondition::CompositeCondition {
                operator: LogicalOperator::Not,
                conditions: vec![cafe.clone()],
            },
            &context,
        ));
        assert!(!triggers(
            SecurityCondition::CompositeCondition {
                operator: LogicalOperator::Not,
                conditions: vec![office.clone()],
            },
            &context,
        ));
        // Not over an empty list is vacuously true.
        assert!(triggers(
            SecurityCondition::CompositeCondition {
                operator: LogicalOperator::Not,
                conditions: vec![],
            },
            &context,
        ));

        // Custom conditions need external evaluation and never fire.
        assert!(!triggers(
            SecurityCondition::CustomCondition {
                name: "external".to_string(),
                parameters: HashMap::new(),
            },
            &context,
        ));
    }

    #[test]
    fn test_disabled_strategy_and_priority_builder() {
        let context = context_at("Office");
        let always_matching = SecurityCondition::DeviceCondition {
            device_id: "device789".to_string(),
            trusted: true,
            device_type: "laptop".to_string(),
        };

        let strategy = SecurityStrategy::new(
            "Disabled".to_string(),
            SecurityCategory::Custom,
            RiskLevel::Low,
        )
        .with_condition(always_matching)
        .with_priority(80)
        .with_enabled(false);

        assert_eq!(strategy.priority, 80);
        assert!(!strategy.enabled);
        assert!(
            !strategy.should_trigger(&context),
            "disabled never triggers"
        );

        // Re-enabling lets the same condition fire again.
        let strategy = strategy.with_enabled(true);
        assert!(strategy.should_trigger(&context));
    }

    #[test]
    fn test_execute_all_action_kinds_mutates_context() {
        let strategy = SecurityStrategy::new(
            "Kitchen Sink".to_string(),
            SecurityCategory::Custom,
            RiskLevel::Medium,
        )
        .with_action(SecurityAction::LockSession {
            reason: "policy".to_string(),
            duration_secs: None,
        })
        .with_action(SecurityAction::ExtendTimeout {
            extension_secs: 300,
            reason: "long task".to_string(),
        })
        .with_action(SecurityAction::RequireReauth {
            method: AuthMethod::TwoFactor,
            message: "verify".to_string(),
        })
        .with_action(SecurityAction::Notify {
            recipients: vec!["admin".to_string()],
            message: "suspicious activity".to_string(),
            severity: NotificationSeverity::Warning,
        })
        .with_action(SecurityAction::LogEvent {
            category: "audit".to_string(),
            details: HashMap::new(),
            severity: EventSeverity::Low,
        })
        .with_action(SecurityAction::RestrictFunctionality {
            restricted_features: vec!["export".to_string(), "sharing".to_string()],
            reason: "least privilege".to_string(),
        })
        .with_action(SecurityAction::CustomAction {
            name: "rotate-keys".to_string(),
            parameters: HashMap::new(),
        });

        let mut context = context_at("Office");
        let results = strategy.execute_actions(&mut context);

        assert_eq!(results.len(), 7);
        assert_eq!(results[0], "Session locked: policy");
        assert_eq!(results[1], "Timeout extended by 300s: long task");
        assert_eq!(
            results[2],
            "Re-authentication required (two_factor): verify"
        );
        assert_eq!(results[3], "Notification sent: suspicious activity");
        assert_eq!(results[4], "Security event logged: audit");
        assert_eq!(
            results[5],
            "Functionality restricted: least privilege - export, sharing"
        );
        assert_eq!(results[6], "Custom action executed: rotate-keys");

        // Every action left its mark on the context.
        assert!(context.session_locked);
        assert_eq!(context.session_timeout_extended_by, 300);
        assert!(context.reauth_required);
        assert_eq!(context.reauth_method, Some(AuthMethod::TwoFactor));
        assert_eq!(context.notifications.len(), 1);
        assert_eq!(
            context.notifications[0],
            (
                "suspicious activity".to_string(),
                NotificationSeverity::Warning
            )
        );
        assert_eq!(context.security_events.len(), 1);
        assert_eq!(context.restricted_features, ["export", "sharing"]);
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(AuthMethod::Password.to_string(), "password");
        assert_eq!(AuthMethod::Biometric.to_string(), "biometric");
        assert_eq!(AuthMethod::TwoFactor.to_string(), "two_factor");
        assert_eq!(AuthMethod::SecurityKey.to_string(), "security_key");
        assert_eq!(AuthMethod::SmartCard.to_string(), "smart_card");
        assert_eq!(
            AuthMethod::Custom("yubikey-otp".to_string()).to_string(),
            "custom:yubikey-otp"
        );
    }
}
