//! Dashboard data models: metric aggregation (`DashboardMetrics`/
//! `PerformanceMetrics`), system health (`SystemHealth`/`HealthAlert`),
//! compliance statistics, notification settings (thresholds and quiet
//! hours), and the auto-lock event record `AutoLockEventRecord`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::auto_lock::{AutoLockEvent, LockReason};

/// Dashboard metrics for comprehensive monitoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardMetrics {
    /// Total number of active sessions
    pub active_sessions: usize,

    /// Number of locked sessions
    pub locked_sessions: usize,

    /// Number of sessions about to be locked (within warning period)
    pub expiring_soon: usize,

    /// Total users currently active
    pub active_users: usize,

    /// Security events in the last hour
    pub security_events_last_hour: u64,

    /// Security events in the last 24 hours
    pub security_events_last_day: u64,

    /// Average session duration
    pub avg_session_duration_secs: u64,

    /// Most common lock reasons
    pub common_lock_reasons: HashMap<LockReason, u64>,

    /// System health indicators
    pub system_health: SystemHealth,

    /// Performance metrics
    pub performance: PerformanceMetrics,

    /// Compliance statistics
    pub compliance: ComplianceStatistics,
}

/// System health indicators
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemHealth {
    /// Overall health score (0-100)
    pub health_score: u8,

    /// Auto-lock service status
    pub auto_lock_service_status: ServiceStatus,

    /// Database connection status
    pub database_status: ServiceStatus,

    /// Memory usage percentage
    pub memory_usage_percent: f64,

    /// CPU usage percentage
    pub cpu_usage_percent: f64,

    /// Last health check time
    pub last_check: chrono::DateTime<chrono::Utc>,

    /// Any active alerts
    pub alerts: Vec<HealthAlert>,
}

/// Service status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    #[default]
    Healthy,
    Warning,
    Critical,
    Unknown,
}

/// Health alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthAlert {
    /// Alert severity
    pub severity: AlertSeverity,

    /// Alert message
    pub message: String,

    /// Alert timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Suggested actions
    pub suggested_actions: Vec<String>,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Performance metrics for the dashboard
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Cache hit ratio
    pub cache_hit_ratio: f64,

    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,

    /// Request rate per second
    pub requests_per_second: f64,

    /// Error rate percentage
    pub error_rate_percent: f64,

    /// Memory usage in MB
    pub memory_usage_mb: f64,

    /// Background task performance
    pub background_task_performance: BackgroundTaskMetrics,
}

/// Background task performance metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackgroundTaskMetrics {
    /// Tasks completed successfully
    pub tasks_completed: u64,

    /// Tasks failed
    pub tasks_failed: u64,

    /// Average task duration in milliseconds
    pub avg_task_duration_ms: f64,

    /// Task queue size
    pub queue_size: usize,
}

/// Compliance statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceStatistics {
    /// Overall compliance score (0-100)
    pub compliance_score: u8,

    /// Number of compliant sessions
    pub compliant_sessions: usize,

    /// Number of non-compliant sessions
    pub non_compliant_sessions: usize,

    /// Most common compliance violations
    pub common_violations: HashMap<String, u64>,

    /// Policy effectiveness scores
    pub policy_effectiveness: HashMap<Uuid, u8>,

    /// Audit trail completeness
    pub audit_trail_complete: bool,
}

/// Notification settings for dashboard alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Enable desktop notifications
    pub desktop_notifications: bool,

    /// Enable email notifications
    pub email_notifications: bool,

    /// Enable webhook notifications
    pub webhook_notifications: bool,

    /// Notification thresholds
    pub thresholds: NotificationThresholds,

    /// Quiet hours configuration
    pub quiet_hours: Option<QuietHours>,
}

/// Notification thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationThresholds {
    /// Alert on high number of locked sessions
    pub locked_sessions_threshold: usize,

    /// Alert on low compliance score
    pub compliance_score_threshold: u8,

    /// Alert on performance degradation
    pub response_time_threshold_ms: u64,

    /// Alert on system health issues
    pub health_score_threshold: u8,
}

/// Quiet hours configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuietHours {
    /// Start hour (24-hour format)
    pub start_hour: u8,

    /// End hour (24-hour format)
    pub end_hour: u8,

    /// Days of week when quiet hours apply
    pub days_of_week: Vec<u8>,

    /// Allow critical alerts during quiet hours
    pub allow_critical_alerts: bool,
}

/// Recorded auto-lock event for dashboard display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoLockEventRecord {
    /// Event ID
    pub id: Uuid,

    /// Event type
    pub event_type: AutoLockEvent,

    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Session ID
    pub session_id: String,

    /// User ID
    pub user_id: String,

    /// Additional context
    pub context: HashMap<String, serde_json::Value>,

    /// Whether this event was acknowledged
    pub acknowledged: bool,

    /// Event resolution (if applicable)
    pub resolution: Option<String>,
}
