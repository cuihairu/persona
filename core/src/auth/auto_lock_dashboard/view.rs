//! Dashboard views and reports: `DashboardView` layout (components,
//! charts, filters) and the four `DashboardReport` report payloads.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::auto_lock::LockReason;

use super::model::AlertSeverity;

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

/// Report types for dashboard
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
