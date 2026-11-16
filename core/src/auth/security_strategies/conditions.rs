//! 策略条件模型：时间/位置/设备/行为/网络五类设置结构与
//! `SecurityCondition` 组合条件求值树。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
