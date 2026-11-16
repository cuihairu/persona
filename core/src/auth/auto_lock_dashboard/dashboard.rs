//! 自动锁面板核心：`AutoLockDashboard` 会话监控、指标采集、健康/合规
//! 计算、事件监听与报表生成。

use crate::auth::auto_lock::AutoLockEvent;
use crate::auth::auto_lock_cached::{
    CachedAutoLockManager, PerformanceMetrics as ManagerPerformanceMetrics,
};
use crate::auth::security_strategies::{SecurityContext, SecurityStrategy};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::model::*;
use super::view::*;

/// Comprehensive auto-lock dashboard for monitoring and management
#[derive(Debug, Clone)]
pub struct AutoLockDashboard {
    session_manager: Arc<CachedAutoLockManager>,
    security_strategies: Arc<RwLock<Vec<SecurityStrategy>>>,
    active_events: Arc<RwLock<Vec<AutoLockEventRecord>>>,
    dashboard_metrics: Arc<RwLock<DashboardMetrics>>,
    notification_settings: Arc<RwLock<NotificationSettings>>,
}

/// Project the session manager's raw metrics onto the dashboard's view.
///
/// Fields the manager does not track yet (request rate, error rate) are
/// reported as zero rather than invented.
fn to_dashboard_performance(
    raw: &ManagerPerformanceMetrics,
    cache_hit_ratio: f64,
) -> PerformanceMetrics {
    PerformanceMetrics {
        cache_hit_ratio,
        avg_response_time_ms: raw.avg_lookup_time_us / 1000.0,
        requests_per_second: 0.0,
        error_rate_percent: 0.0,
        memory_usage_mb: raw.memory_usage_bytes as f64 / 1024.0 / 1024.0,
        background_task_performance: BackgroundTaskMetrics {
            tasks_completed: raw.background_checks_performed,
            tasks_failed: 0,
            avg_task_duration_ms: raw.background_check_time_us / 1000.0,
            queue_size: 0,
        },
    }
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
    pub async fn initialize(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
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

        dashboard_metrics.performance = to_dashboard_performance(
            &session_metrics,
            self.session_manager.cache_hit_ratio().await,
        );
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
    ///
    /// The nil UUID requests the default view; persisted custom views are not
    /// implemented yet, so any other id resolves to `None`.
    pub async fn get_dashboard_view(&self, view_id: &Uuid) -> Option<DashboardView> {
        if *view_id == Uuid::nil() {
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
            b.risk_level
                .cmp(&a.risk_level)
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

    pub(super) async fn initialize_default_strategies(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        use crate::auth::security_strategies::{
            AuthMethod, SecurityAction, SecurityCategory, SecurityCondition, TimeRule,
        };

        // Strategy: After-hours lock
        let after_hours_strategy = SecurityStrategy::new(
            "After Hours Security".to_string(),
            SecurityCategory::TimeBased,
            crate::auth::security_strategies::RiskLevel::High,
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
            crate::auth::security_strategies::RiskLevel::Critical,
        )
        .with_action(SecurityAction::RequireReauth {
            method: AuthMethod::TwoFactor,
            message: "Authentication required for untrusted location".to_string(),
        });

        self.add_security_strategy(after_hours_strategy).await;
        self.add_security_strategy(location_strategy).await;

        Ok(())
    }

    async fn start_background_monitoring(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // Start session manager background monitoring
        self.session_manager.start_background_monitoring().await?;

        // Start dashboard metrics collection
        self.start_metrics_collection().await;

        Ok(())
    }

    pub(super) async fn register_event_listeners(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
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
                    let excess = events.len() - 1000;
                    events.drain(0..excess);
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
        let cache_hit_ratio = self.session_manager.cache_hit_ratio().await;

        let health_score =
            if cache_hit_ratio > 0.8 && performance_metrics.avg_lookup_time_us < 1000.0 {
                90
            } else if cache_hit_ratio > 0.6 {
                70
            } else {
                50
            };

        SystemHealth {
            health_score,
            auto_lock_service_status: ServiceStatus::Healthy,
            database_status: ServiceStatus::Healthy,
            memory_usage_percent: (performance_metrics.memory_usage_bytes as f64
                / 1024.0
                / 1024.0
                / 1024.0
                * 100.0)
                .min(100.0),
            cpu_usage_percent: 0.0, // Would need system monitoring
            last_check: chrono::Utc::now(),
            alerts: vec![], // Would be populated based on thresholds
        }
    }

    async fn calculate_compliance_stats(&self) -> ComplianceStatistics {
        // This would analyze session data and policy compliance
        ComplianceStatistics::default()
    }

    pub(super) fn create_default_view(&self) -> DashboardView {
        DashboardView {
            id: Uuid::new_v4(),
            name: "Auto-Lock Overview".to_string(),
            description: Some(
                "Comprehensive view of auto-lock system status and metrics".to_string(),
            ),
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
                layout_type: LayoutType::Grid,
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

                let raw = session_manager.get_performance_metrics().await;
                let ratio = session_manager.cache_hit_ratio().await;
                let mut dashboard_metrics = metrics.write().await;

                dashboard_metrics.performance = to_dashboard_performance(&raw, ratio);
                dashboard_metrics.active_sessions = raw.active_sessions;
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
