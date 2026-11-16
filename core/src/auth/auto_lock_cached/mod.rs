use super::auto_lock::AutoLockEvent;
use super::{EnhancedAutoLockConfig, Session};
use crate::models::auto_lock_policy::AutoLockPolicy;
use crate::storage::AutoLockPolicyRepository;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;
/// A registered auto-lock event listener.
type EventCallback = Arc<dyn Fn(AutoLockEvent) + Send + Sync>;
/// Cached session information with performance optimizations
#[derive(Debug, Clone)]
struct CachedSessionInfo {
    session: Session,
    last_access: Instant,
    last_warning_time: Option<SystemTime>,
    warning_sent: bool,
    policy_id: Option<Uuid>,
    /// Cached compliance state to avoid repeated checks
    last_compliance_check: Option<Instant>,
    is_compliant: bool,
}
/// Performance-optimized auto-lock manager with caching
pub struct CachedAutoLockManager {
    config: EnhancedAutoLockConfig,
    sessions: Arc<RwLock<HashMap<String, CachedSessionInfo>>>,
    policy_cache: Arc<RwLock<HashMap<Uuid, (AutoLockPolicy, Instant)>>>,
    default_policy_cache: Arc<RwLock<Option<AutoLockPolicy>>>,
    // user_id -> (policy_id, cached_at)
    user_policy_cache: Arc<RwLock<HashMap<Uuid, (Uuid, Instant)>>>,
    callbacks: Arc<RwLock<Vec<EventCallback>>>,
    policy_repository: Option<Arc<AutoLockPolicyRepository>>,
    background_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,

    // Cache configuration
    cache_ttl: Duration,
    max_cache_size: usize,
}
impl std::fmt::Debug for CachedAutoLockManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAutoLockManager")
            .finish_non_exhaustive()
    }
}
/// Performance metrics for monitoring auto-lock manager performance
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total number of cache hits
    pub cache_hits: u64,

    /// Total number of cache misses
    pub cache_misses: u64,

    /// Average session lookup time in microseconds
    pub avg_lookup_time_us: f64,

    /// Number of active sessions
    pub active_sessions: usize,

    /// Memory usage in bytes (approximate)
    pub memory_usage_bytes: u64,

    /// Background task performance
    pub background_checks_performed: u64,
    pub background_check_time_us: f64,
}
/// Result of cache optimization operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheOptimizationResult {
    pub duration: Duration,
    pub removed_sessions: usize,
    pub removed_policies: usize,
    pub removed_user_policies: usize,
}
mod background;
mod lifecycle;
mod maintenance;
mod policy;
mod sessions;
#[cfg(test)]
mod tests;
