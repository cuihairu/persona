use super::{
    auto_lock::{AutoLockEvent, AutoLockManager, LockReason},
    cached_auto_lock::CachedAutoLockManager,
    security_strategies::{SecurityContext, SecurityStrategy},
};
use crate::models::auto_lock_policy::{AutoLockPolicy, PolicyStatistics};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Comprehensive auto-lock dashboard for monitoring and management
#[derive(Debug, Clone)]
pub struct AutoLockDashboard {
    session_manager: Arc<CachedAutoLockManager>,
    security_strategies: Arc<RwLock<Vec<SecurityStrategy>>>,
    active_events: Arc<RwLock<Vec<AutoLockEventRecord>>>,
    dashboard_metrics: Arc<RwLock<DashboardMetrics>>,
    notification_settings: Arc<RwLock<NotificationSettings>>,
}

/// Dashboard metrics for comprehensive monitoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardMetrics {
    /// Total number of active sessions
    pub active_sessions: usize,

    /// Number of locked sessions
    pub locked_sessions: usize,

    /// Number of sessions about to be locked (within warning period)
    expiring_soon: usize,

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord)]
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

/// Dashboard view configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardView {
    /// View ID
    pub id: Uuid,

    /// View name
    pub name: String,

    /// View description
    pub description: Option<String>,

    /// Components to display
    pub components: Vec<DashboardComponent>,

    /// Layout configuration
    pub layout: LayoutConfiguration,

    /// Filter settings
    pub filters: ViewFilters,

    /// Auto-refresh interval in seconds
    pub auto_refresh_interval_secs: u64,
}

/// Dashboard component types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DashboardComponent {
    /// Session overview table
    SessionOverview {
        /// Show only active sessions
        active_only: bool,

        /// Include locked sessions
        include_locked: bool,

        /// Maximum rows to display
        max_rows: Option<usize>,
    },

    /// Security metrics charts
    SecurityMetrics {
        /// Chart types to include
        chart_types: Vec<ChartType>,

        /// Time range for data
        time_range_hours: u64,
    },

    /// Policy effectiveness analysis
    PolicyEffectiveness {
        /// Include inactive policies
        include_inactive: bool,

        /// Sort by effectiveness score
        sort_by_effectiveness: bool,
    },

    /// Event timeline
    EventTimeline {
        /// Maximum events to display
        max_events: usize,

        /// Event types to include
        event_types: Vec<String>,

        /// Time range
        time_range_hours: u64,
    },

    /// System health dashboard
    SystemHealth {
        /// Include detailed metrics
        detailed: bool,

        /// Alert filtering
        alert_filter: Option<AlertSeverity>,
    },

    /// Custom component
    Custom {
        /// Component name
        name: String,

        /// Custom configuration
        configuration: HashMap<String, serde_json::Value>,
    },
}

/// Chart types for metrics display
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChartType {
    Line,
    Bar,
    Pie,
    Gauge,
    Heatmap,
}

/// Layout configuration for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutConfiguration {
    /// Layout type
    pub layout_type: LayoutType,

    /// Grid dimensions
    pub grid_size: (usize, usize),

    /// Component positions
    pub component_positions: HashMap<Uuid, (usize, usize, usize, usize)>, // component_id -> (row, col, rowspan, colspan)
}

/// Layout types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutType {
    Grid,
    Flex,
    Tabs,
    Accordion,
}

/// View filters for dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewFilters {
    /// Time range filter
    pub time_range: Option<TimeRangeFilter>,

    /// User filter
    pub users: Option<Vec<String>>,

    /// Security level filter
    pub security_levels: Option<Vec<String>>,

    /// Status filter
    pub status: Option<Vec<String>>,

    /// Custom filters
    pub custom: HashMap<String, serde_json::Value>,
}

/// Time range filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRangeFilter {
    /// Start time
    pub start: chrono::DateTime<chrono::Utc>,

    /// End time
    pub end: chrono::DateTime<chrono::Utc>,

    /// Relative time range (e.g., "last_24h", "last_week")
    pub relative: Option<String>,
}

impl AutoLockDashboard {
    /// Create a new auto-lock dashboard
    pub fn new(session_manager: Arc<CachedAutoLockManager>) -> Self {
        Self {
            session_manager,
            security_strategies: Arc::new(RwLock::new(Vec::new())),
            active_events: Arc::new(RwLock::new(Vec::new())),
            dashboard_metrics: Arc::new(RwLock::new(DashboardMetrics::default())),
            notification_settings: Arc::new(RwLock::new(NotificationSettings::default())),
        }
    }

    /// Initialize the dashboard
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // Initialize default security strategies
        self.initialize_default_strategies().await?;

        // Start background monitoring
        self.start_background_monitoring().await?;

        // Register event listeners
        self.register_event_listeners().await?;

        Ok(())
    }

    /// Get current dashboard metrics
    pub async fn get_metrics(&self) -> DashboardMetrics {
        // Update metrics from session manager
        let session_metrics = self.session_manager.get_performance_metrics().await;
        let mut dashboard_metrics = self.dashboard_metrics.read().await.clone();

        dashboard_metrics.performance = session_metrics;
        dashboard_metrics.active_sessions = session_metrics.active_sessions;

        // Update other metrics
        self.update_realtime_metrics(&mut dashboard_metrics).await;

        dashboard_metrics
    }

    /// Get active events
    pub async fn get_active_events(&self) -> Vec<AutoLockEventRecord> {
        let events = self.active_events.read().await;
        events.clone()
    }

    /// Get dashboard view
    pub async fn get_dashboard_view(&self, view_id: &Uuid) -> Option<DashboardView> {
        // This would typically load from a repository or configuration
        // For now, return a default view
        if *view_id == Uuid::new_v4() {
            Some(self.create_default_view())
        } else {
            None
        }
    }

    /// Add a security strategy
    pub async fn add_security_strategy(&self, strategy: SecurityStrategy) {
        let mut strategies = self.security_strategies.write().await;
        strategies.push(strategy);
    }

    /// Evaluate security strategies for a context
    pub async fn evaluate_security_strategies(
        &self,
        context: &SecurityContext,
    ) -> Vec<(SecurityStrategy, Vec<String>)> {
        let strategies = self.security_strategies.read().await;
        let mut results = Vec::new();

        for strategy in strategies.iter() {
            if strategy.should_trigger(context) {
                let mut context_clone = context.clone();
                let action_results = strategy.execute_actions(&mut context_clone);
                results.push((strategy.clone(), action_results));
            }
        }

        // Sort by risk level and priority
        results.sort_by(|(a, _), (b, _)| {
            b.risk_level.cmp(&a.risk_level)
                .then_with(|| b.priority.cmp(&a.priority))
        });

        results
    }

    /// Get notification settings
    pub async fn get_notification_settings(&self) -> NotificationSettings {
        self.notification_settings.read().await.clone()
    }

    /// Update notification settings
    pub async fn update_notification_settings(&self, settings: NotificationSettings) {
        let mut current_settings = self.notification_settings.write().await;
        *current_settings = settings;
    }

    /// Acknowledge an event
    pub async fn acknowledge_event(&self, event_id: &Uuid) -> bool {
        let mut events = self.active_events.write().await;
        if let Some(event) = events.iter_mut().find(|e| e.id == *event_id) {
            event.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Generate dashboard report
    pub async fn generate_report(&self, report_type: ReportType) -> DashboardReport {
        match report_type {
            ReportType::Summary => self.generate_summary_report().await,
            ReportType::Security => self.generate_security_report().await,
            ReportType::Performance => self.generate_performance_report().await,
            ReportType::Compliance => self.generate_compliance_report().await,
        }
    }

    // Private methods

    async fn initialize_default_strategies(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        use super::security_strategies::{
            AuthMethod, SecurityAction, SecurityCategory, SecurityCondition, SecurityContext, SecurityStrategy, TimeRule,
        };

        // Strategy: After-hours lock
        let after_hours_strategy = SecurityStrategy::new(
            "After Hours Security".to_string(),
            SecurityCategory::TimeBased,
            super::security_strategies::RiskLevel::High,
        )
        .with_condition(SecurityCondition::TimeCondition {
            time_rule: TimeRule::IsRestrictedHours,
        })
        .with_action(SecurityAction::LockSession {
            reason: "Access outside business hours".to_string(),
            duration_secs: None,
        });

        // Strategy: High-risk location lock
        let location_strategy = SecurityStrategy::new(
            "Untrusted Location Lock".to_string(),
            SecurityCategory::LocationBased,
            super::security_strategies::RiskLevel::Critical,
        )
        .with_action(SecurityAction::RequireReauth {
            method: AuthMethod::TwoFactor,
            message: "Authentication required for untrusted location".to_string(),
        });

        self.add_security_strategy(after_hours_strategy).await;
        self.add_security_strategy(location_strategy).await;

        Ok(())
    }

    async fn start_background_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // Start session manager background monitoring
        self.session_manager.start_background_monitoring().await?;

        // Start dashboard metrics collection
        self.start_metrics_collection().await;

        Ok(())
    }

    async fn register_event_listeners(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let events = self.active_events.clone();

        let listener = std::sync::Arc::new(move |event: AutoLockEvent| {
            let events_clone = events.clone();
            tokio::spawn(async move {
                let record = AutoLockEventRecord {
                    id: Uuid::new_v4(),
                    event_type: event,
                    timestamp: chrono::Utc::now(),
                    session_id: "unknown".to_string(), // Would be extracted from event
                    user_id: "unknown".to_string(),
                    context: HashMap::new(),
                    acknowledged: false,
                    resolution: None,
                };

                let mut events = events_clone.write().await;
                events.push(record);

                // Keep only last 1000 events
                if events.len() > 1000 {
                    events.drain(0..events.len() - 1000);
                }
            });
        });

        self.session_manager.register_callback(listener).await;
        Ok(())
    }

    async fn update_realtime_metrics(&self, metrics: &mut DashboardMetrics) {
        // Update expiring soon sessions
        // This would require access to session data to calculate

        // Update system health
        metrics.system_health = self.calculate_system_health().await;

        // Update compliance statistics
        metrics.compliance = self.calculate_compliance_stats().await;
    }

    async fn calculate_system_health(&self) -> SystemHealth {
        let performance_metrics = self.session_manager.get_performance_metrics().await;

        let health_score = if performance_metrics.cache_hit_ratio > 0.8
            && performance_metrics.avg_lookup_time_us < 1000.0 {
            90
        } else if performance_metrics.cache_hit_ratio > 0.6 {
            70
        } else {
            50
        };

        SystemHealth {
            health_score,
            auto_lock_service_status: ServiceStatus::Healthy,
            database_status: ServiceStatus::Healthy,
            memory_usage_percent: (performance_metrics.memory_usage_bytes as f64 / 1024.0 / 1024.0 / 1024.0 * 100.0).min(100.0),
            cpu_usage_percent: 0.0, // Would need system monitoring
            last_check: chrono::Utc::now(),
            alerts: vec![], // Would be populated based on thresholds
        }
    }

    async fn calculate_compliance_stats(&self) -> ComplianceStatistics {
        // This would analyze session data and policy compliance
        ComplianceStatistics::default()
    }

    fn create_default_view(&self) -> DashboardView {
        use super::security_strategies::{ChartType, DashboardComponent};
        use uuid::Uuid;

        DashboardView {
            id: Uuid::new_v4(),
            name: "Auto-Lock Overview".to_string(),
            description: Some("Comprehensive view of auto-lock system status and metrics".to_string()),
            components: vec![
                DashboardComponent::SessionOverview {
                    active_only: false,
                    include_locked: true,
                    max_rows: Some(50),
                },
                DashboardComponent::SecurityMetrics {
                    chart_types: vec![ChartType::Line, ChartType::Gauge],
                    time_range_hours: 24,
                },
                DashboardComponent::EventTimeline {
                    max_events: 100,
                    event_types: vec!["locked".to_string(), "unlocked".to_string()],
                    time_range_hours: 12,
                },
                DashboardComponent::SystemHealth {
                    detailed: true,
                    alert_filter: None,
                },
            ],
            layout: LayoutConfiguration {
                layout_type: super::security_strategies::LayoutType::Grid,
                grid_size: (2, 2),
                component_positions: HashMap::new(),
            },
            filters: ViewFilters {
                time_range: None,
                users: None,
                security_levels: None,
                status: None,
                custom: HashMap::new(),
            },
            auto_refresh_interval_secs: 30,
        }
    }

    async fn start_metrics_collection(&self) {
        let metrics = self.dashboard_metrics.clone();
        let session_manager = self.session_manager.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let performance_metrics = session_manager.get_performance_metrics().await;
                let mut dashboard_metrics = metrics.write().await;

                dashboard_metrics.performance = performance_metrics;
                dashboard_metrics.active_sessions = performance_metrics.active_sessions;
            }
        });
    }

    async fn generate_summary_report(&self) -> DashboardReport {
        let metrics = self.get_metrics().await;

        DashboardReport {
            title: "Auto-Lock System Summary".to_string(),
            generated_at: chrono::Utc::now(),
            report_type: ReportType::Summary,
            content: ReportContent::Summary {
                total_sessions: metrics.active_sessions + metrics.locked_sessions,
                active_sessions: metrics.active_sessions,
                locked_sessions: metrics.locked_sessions,
                health_score: metrics.system_health.health_score,
                compliance_score: metrics.compliance.compliance_score,
            },
        }
    }

    async fn generate_security_report(&self) -> DashboardReport {
        DashboardReport {
            title: "Security Analysis Report".to_string(),
            generated_at: chrono::Utc::now(),
            report_type: ReportType::Security,
            content: ReportContent::Security {
                security_events_last_hour: 0, // Would be calculated
                security_events_last_day: 0,
                common_lock_reasons: HashMap::new(),
                active_strategies: self.security_strategies.read().await.len(),
                security_incidents: 0,
            },
        }
    }

    async fn generate_performance_report(&self) -> DashboardReport {
        let metrics = self.get_metrics().await;

        DashboardReport {
            title: "Performance Report".to_string(),
            generated_at: chrono::Utc::now(),
            report_type: ReportType::Performance,
            content: ReportContent::Performance {
                cache_hit_ratio: metrics.performance.cache_hit_ratio,
                avg_response_time_ms: metrics.performance.avg_response_time_ms,
                requests_per_second: metrics.performance.requests_per_second,
                error_rate_percent: metrics.performance.error_rate_percent,
                memory_usage_mb: metrics.performance.memory_usage_mb,
            },
        }
    }

    async fn generate_compliance_report(&self) -> DashboardReport {
        let metrics = self.get_metrics().await;

        DashboardReport {
            title: "Compliance Report".to_string(),
            generated_at: chrono::Utc::now(),
            report_type: ReportType::Compliance,
            content: ReportContent::Compliance {
                compliance_score: metrics.compliance.compliance_score,
                compliant_sessions: metrics.compliance.compliant_sessions,
                non_compliant_sessions: metrics.compliance.non_compliant_sessions,
                common_violations: metrics.compliance.common_violations,
                audit_trail_complete: metrics.compliance.audit_trail_complete,
            },
        }
    }
}

/// Report types for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    Summary,
    Security,
    Performance,
    Compliance,
}

/// Dashboard report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardReport {
    pub title: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub report_type: ReportType,
    pub content: ReportContent,
}

/// Report content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReportContent {
    Summary {
        total_sessions: usize,
        active_sessions: usize,
        locked_sessions: usize,
        health_score: u8,
        compliance_score: u8,
    },
    Security {
        security_events_last_hour: u64,
        security_events_last_day: u64,
        common_lock_reasons: HashMap<LockReason, u64>,
        active_strategies: usize,
        security_incidents: u64,
    },
    Performance {
        cache_hit_ratio: f64,
        avg_response_time_ms: f64,
        requests_per_second: f64,
        error_rate_percent: f64,
        memory_usage_mb: f64,
    },
    Compliance {
        compliance_score: u8,
        compliant_sessions: usize,
        non_compliant_sessions: usize,
        common_violations: HashMap<String, u64>,
        audit_trail_complete: bool,
    },
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            desktop_notifications: true,
            email_notifications: false,
            webhook_notifications: false,
            thresholds: NotificationThresholds {
                locked_sessions_threshold: 10,
                compliance_score_threshold: 70,
                response_time_threshold_ms: 1000,
                health_score_threshold: 80,
            },
            quiet_hours: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dashboard_creation() {
        let session_manager = Arc::new(CachedAutoLockManager::new(
            crate::auth::EnhancedAutoLockConfig::default()
        ));

        let dashboard = AutoLockDashboard::new(session_manager);

        let metrics = dashboard.get_metrics().await;
        assert_eq!(metrics.active_sessions, 0); // No sessions initially

        let events = dashboard.get_active_events().await;
        assert!(events.is_empty()); // No events initially
    }

    #[tokio::test]
    async fn test_default_view() {
        let session_manager = Arc::new(CachedAutoLockManager::new(
            crate::auth::EnhancedAutoLockConfig::default()
        ));

        let dashboard = AutoLockDashboard::new(session_manager);
        let view = dashboard.create_default_view();

        assert_eq!(view.name, "Auto-Lock Overview");
        assert_eq!(view.components.len(), 4);
        assert_eq!(view.auto_refresh_interval_secs, 30);
    }

    #[tokio::test]
    async fn test_notification_settings() {
        let session_manager = Arc::new(CachedAutoLockManager::new(
            crate::auth::EnhancedAutoLockConfig::default()
        ));

        let dashboard = AutoLockDashboard::new(session_manager);

        let settings = dashboard.get_notification_settings().await;
        assert!(settings.desktop_notifications);
        assert!(!settings.email_notifications);

        // Update settings
        let new_settings = NotificationSettings {
            desktop_notifications: false,
            email_notifications: true,
            webhook_notifications: false,
            thresholds: settings.thresholds.clone(),
            quiet_hours: None,
        };

        dashboard.update_notification_settings(new_settings).await;

        let updated_settings = dashboard.get_notification_settings().await;
        assert!(!updated_settings.desktop_notifications);
        assert!(updated_settings.email_notifications);
    }
}