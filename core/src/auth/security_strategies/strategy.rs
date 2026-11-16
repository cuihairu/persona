//! 安全策略与评估：`SecurityStrategy` 聚合条件与动作，`should_trigger`
//! 对 `SecurityContext` 求值，`execute_actions` 产生通知/事件/锁定副作用。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::actions::{AuthMethod, EventSeverity, NotificationSeverity, SecurityAction};
use super::conditions::{
    BehavioralSettings, DeviceBasedSettings, LocationBasedSettings, LogicalOperator,
    NetworkSettings, SecurityCondition, TimeBasedSettings, TimeRule,
};

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
