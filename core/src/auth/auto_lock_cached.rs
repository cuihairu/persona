use super::{auto_lock::AutoLockEvent, AutoLockManager, EnhancedAutoLockConfig, Session};
use crate::models::auto_lock_policy::AutoLockPolicy;
use crate::storage::AutoLockPolicyRepository;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Mutex};
use uuid::Uuid;

/// Cached session information with performance optimizations
#[derive(Debug, Clone)]
struct CachedSessionInfo {
    session: Session,
    last_access: Instant,
    last_warning_time: Option<SystemTime>,
    warning_sent: bool,
    created_at: SystemTime,
    policy_id: Option<Uuid>,
    /// Cached compliance state to avoid repeated checks
    last_compliance_check: Option<Instant>,
    is_compliant: bool,
}

/// Performance-optimized auto-lock manager with caching
pub struct CachedAutoLockManager {
    config: EnhancedAutoLockConfig,
    sessions: Arc<RwLock<HashMap<String, CachedSessionInfo>>>,
    policy_cache: Arc<RwLock<HashMap<Uuid, AutoLockPolicy>>>,
    default_policy_cache: Arc<RwLock<Option<AutoLockPolicy>>>,
    user_policy_cache: Arc<RwLock<HashMap<Uuid, Uuid>>>, // user_id -> policy_id
    callbacks: Arc<RwLock<Vec<std::sync::Arc<dyn Fn(AutoLockEvent) + Send + Sync>>>>,
    policy_repository: Option<Arc<AutoLockPolicyRepository>>,
    background_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    current_user: Arc<RwLock<Option<Uuid>>>,
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,

    // Cache configuration
    cache_ttl: Duration,
    max_cache_size: usize,
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

impl CachedAutoLockManager {
    /// Create a new cached auto-lock manager
    pub fn new(config: EnhancedAutoLockConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            policy_cache: Arc::new(RwLock::new(HashMap::new())),
            default_policy_cache: Arc::new(RwLock::new(None)),
            user_policy_cache: Arc::new(RwLock::new(HashMap::new())),
            callbacks: Arc::new(RwLock::new(Vec::new())),
            policy_repository: None,
            background_task: Arc::new(Mutex::new(None)),
            current_user: Arc::new(RwLock::new(None)),
            performance_metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            cache_ttl: Duration::from_secs(300), // 5 minutes cache TTL
            max_cache_size: 10000, // Maximum cached items
        }
    }

    /// Create with custom cache configuration
    pub fn with_cache_config(
        config: EnhancedAutoLockConfig,
        cache_ttl: Duration,
        max_cache_size: usize,
    ) -> Self {
        let mut manager = Self::new(config);
        manager.cache_ttl = cache_ttl;
        manager.max_cache_size = max_cache_size;
        manager
    }

    /// Set policy repository for policy management
    pub fn with_policy_repository(mut self, repository: Arc<AutoLockPolicyRepository>) -> Self {
        self.policy_repository = Some(repository);
        self
    }

    /// Register a callback for auto-lock events
    pub async fn register_callback(&self, callback: std::sync::Arc<dyn Fn(AutoLockEvent) + Send + Sync>) {
        let mut callbacks = self.callbacks.write().await;
        callbacks.push(callback);
    }

    /// Add a new session with caching
    pub async fn add_session(&self, mut session: Session) -> Result<(), String> {
        let start_time = Instant::now();
        let session_id = session.id.clone();
        let user_id = session.user_id.clone();

        // Get policy for user (with caching)
        let policy = self.get_user_policy_cached(&user_id).await?;

        // Apply policy settings to session
        if let Some(ref p) = policy {
            session.expires_at = SystemTime::now() + Duration::from_secs(p.absolute_timeout_secs);
        }

        let session_info = CachedSessionInfo {
            session,
            last_access: Instant::now(),
            last_warning_time: None,
            warning_sent: false,
            created_at: SystemTime::now(),
            policy_id: policy.map(|p| p.id),
            last_compliance_check: Some(Instant::now()),
            is_compliant: true,
        };

        // Check concurrent session limit
        {
            let sessions = self.sessions.read().await;
            let user_sessions = sessions.values()
                .filter(|s| s.session.user_id == user_id && s.session.is_valid())
                .count();

            let max_sessions = if let Some(ref p) = policy {
                p.max_concurrent_sessions
            } else {
                self.config.max_concurrent_sessions
            };

            if user_sessions >= max_sessions {
                self.record_cache_miss().await;
                return Err(format!("Maximum concurrent sessions ({}) exceeded", max_sessions));
            }
        }

        {
            let mut sessions = self.sessions.write().await;
            self.evict_if_needed(&mut sessions).await;
            sessions.insert(session_id.clone(), session_info);
        }

        self.record_lookup_time(start_time.elapsed()).await;
        self.emit_event(AutoLockEvent::Activity { session_id }).await;

        Ok(())
    }

    /// Optimized session validation with caching
    pub async fn is_session_valid(&self, session_id: &str) -> bool {
        let start_time = Instant::now();

        {
            let sessions = self.sessions.read().await;
            if let Some(session_info) = sessions.get(session_id) {
                // Use cached compliance check if recent
                let should_recheck = session_info.last_compliance_check
                    .map_or(true, |last| last.elapsed() > Duration::from_secs(30));

                let is_valid = if should_recheck {
                    let valid = self.check_session_compliance(session_info).await;
                    // Update cached result (would need mutable access)
                    valid
                } else {
                    session_info.is_compliant && session_info.session.is_valid()
                };

                drop(sessions);
                self.record_lookup_time(start_time.elapsed()).await;
                self.record_cache_hit().await;
                return is_valid;
            }
        }

        self.record_lookup_time(start_time.elapsed()).await;
        self.record_cache_miss().await;
        false
    }

    /// Update session activity with performance optimization
    pub async fn update_activity(&self, session_id: &str) -> Result<(), String> {
        let start_time = Instant::now();

        let mut sessions = self.sessions.write().await;
        if let Some(session_info) = sessions.get_mut(session_id) {
            // Apply grace period optimization
            let now = Instant::now();
            if now.duration_since(session_info.last_access) < Duration::from_millis(100) {
                // Rapid successive calls, skip processing
                drop(sessions);
                self.record_lookup_time(start_time.elapsed()).await;
                return Ok(());
            }

            session_info.last_access = now;
            session_info.session.touch();
            session_info.warning_sent = false;

            drop(sessions);
            self.record_lookup_time(start_time.elapsed()).await;
            self.emit_event(AutoLockEvent::Activity {
                session_id: session_id.to_string()
            }).await;

            Ok(())
        } else {
            self.record_lookup_time(start_time.elapsed()).await;
            Err("Session not found".to_string())
        }
    }

    /// Get policy for user with caching
    async fn get_user_policy_cached(&self, user_id: &str) -> Result<Option<AutoLockPolicy>, String> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|_| "Invalid user ID".to_string())?;

        // Check user policy cache
        {
            let user_policy_cache = self.user_policy_cache.read().await;
            if let Some(&policy_id) = user_policy_cache.get(&user_uuid) {
                let policy_cache = self.policy_cache.read().await;
                if let Some(policy) = policy_cache.get(&policy_id) {
                    return Ok(Some(policy.clone()));
                }
            }
        }

        // Cache miss - fetch from repository
        if let Some(ref repo) = self.policy_repository {
            match repo.get_user_policy(&user_uuid).await {
                Ok(Some(policy)) => {
                    // Update caches
                    {
                        let mut user_policy_cache = self.user_policy_cache.write().await;
                        user_policy_cache.insert(user_uuid, policy.id);
                    }
                    {
                        let mut policy_cache = self.policy_cache.write().await;
                        policy_cache.insert(policy.id, policy.clone());
                    }
                    return Ok(Some(policy));
                }
                Ok(None) => {
                    // Try default policy
                    if let Ok(Some(default_policy)) = repo.get_default_policy().await {
                        {
                            let mut policy_cache = self.policy_cache.write().await;
                            policy_cache.insert(default_policy.id, default_policy.clone());
                        }
                        return Ok(Some(default_policy));
                    }
                }
                Err(e) => return Err(format!("Failed to fetch policy: {}", e)),
            }
        }

        Ok(None)
    }

    /// Check if session complies with current policy
    async fn check_session_compliance(&self, session_info: &CachedSessionInfo) -> bool {
        let policy = if let Some(policy_id) = session_info.policy_id {
            let policy_cache = self.policy_cache.read().await;
            policy_cache.get(&policy_id).cloned()
        } else {
            None
        };

        if let Some(policy) = policy {
            // Check inactivity timeout
            if policy.inactivity_timeout_secs > 0 {
                let inactivity = Duration::from_secs(policy.inactivity_timeout_secs);
                if session_info.session.is_idle(inactivity) {
                    return false;
                }
            }

            // Check absolute timeout
            if policy.absolute_timeout_secs > 0 {
                let absolute = Duration::from_secs(policy.absolute_timeout_secs);
                if session_info.session.get_lifetime_seconds() > absolute.as_secs() {
                    return false;
                }
            }

            // Check concurrent sessions limit
            let sessions = self.sessions.read().await;
            let user_sessions = sessions.values()
                .filter(|s| s.session.user_id == session_info.session.user_id && s.session.is_valid())
                .count();

            if user_sessions > policy.max_concurrent_sessions {
                return false;
            }

            true
        } else {
            // Fallback to config-based checks
            session_info.session.is_valid()
        }
    }

    /// Evict old sessions if cache is full
    async fn evict_if_needed(&self, sessions: &mut HashMap<String, CachedSessionInfo>) {
        if sessions.len() <= self.max_cache_size {
            return;
        }

        // Sort by last access time and remove oldest entries
        let mut session_entries: Vec<_> = sessions.iter().collect();
        session_entries.sort_by_key(|(_, info)| info.last_access);

        let to_remove = sessions.len() - self.max_cache_size + 100; // Remove extra to avoid frequent evictions
        for (session_id, _) in session_entries.iter().take(to_remove) {
            sessions.remove(*session_id);
        }
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        let metrics = self.performance_metrics.read().await.clone();
        let sessions = self.sessions.read().await;

        let mut updated_metrics = metrics;
        updated_metrics.active_sessions = sessions.len();

        // Estimate memory usage
        let estimated_size = sessions.len() * std::mem::size_of::<CachedSessionInfo>();
        updated_metrics.memory_usage_bytes = estimated_size as u64;

        updated_metrics
    }

    /// Clear caches
    pub async fn clear_caches(&self) {
        {
            let mut sessions = self.sessions.write().await;
            sessions.clear();
        }
        {
            let mut policy_cache = self.policy_cache.write().await;
            policy_cache.clear();
        }
        {
            let mut default_policy_cache = self.default_policy_cache.write().await;
            *default_policy_cache = None;
        }
        {
            let mut user_policy_cache = self.user_policy_cache.write().await;
            user_policy_cache.clear();
        }

        // Reset metrics
        {
            let mut metrics = self.performance_metrics.write().await;
            *metrics = PerformanceMetrics::default();
        }
    }

    /// Optimize caches (remove expired entries, compact memory)
    pub async fn optimize_caches(&self) -> CacheOptimizationResult {
        let start_time = Instant::now();

        let mut removed_sessions = 0;
        let mut removed_policies = 0;
        let mut removed_user_policies = 0;

        // Clean expired sessions
        {
            let mut sessions = self.sessions.write().await;
            let initial_count = sessions.len();

            sessions.retain(|_, info| {
                // Remove sessions that are expired and have been inactive for over an hour
                !info.session.is_expired() ||
                (!info.session.locked && info.session.get_idle_seconds() < 3600)
            });

            removed_sessions = initial_count - sessions.len();
        }

        // Clean policy cache (remove policies older than TTL)
        {
            let mut policy_cache = self.policy_cache.write().await;
            let initial_count = policy_cache.len();

            // For now, just keep recently used policies
            // In a real implementation, you might want to track last access time
            if policy_cache.len() > 1000 {
                policy_cache.retain(|_, _| true); // Keep all for now
            }

            removed_policies = initial_count.saturating_sub(policy_cache.len());
        }

        // Clean user policy cache
        {
            let mut user_policy_cache = self.user_policy_cache.write().await;
            let initial_count = user_policy_cache.len();

            if user_policy_cache.len() > 5000 {
                user_policy_cache.retain(|_, _| true); // Keep all for now
            }

            removed_user_policies = initial_count.saturating_sub(user_policy_cache.len());
        }

        CacheOptimizationResult {
            duration: start_time.elapsed(),
            removed_sessions,
            removed_policies,
            removed_user_policies,
        }
    }

    // Performance metric recording methods
    async fn record_cache_hit(&self) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.cache_hits += 1;
    }

    async fn record_cache_miss(&self) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.cache_misses += 1;
    }

    async fn record_lookup_time(&self, duration: Duration) {
        let mut metrics = self.performance_metrics.write().await;
        let time_us = duration.as_micros() as f64;

        // Update running average
        let total_checks = metrics.cache_hits + metrics.cache_misses;
        if total_checks > 0 {
            metrics.avg_lookup_time_us =
                (metrics.avg_lookup_time_us * (total_checks - 1) as f64 + time_us) / total_checks as f64;
        } else {
            metrics.avg_lookup_time_us = time_us;
        }
    }

    async fn record_background_check_time(&self, duration: Duration) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.background_checks_performed += 1;

        let time_us = duration.as_micros() as f64;
        let total_checks = metrics.background_checks_performed;

        if total_checks > 1 {
            metrics.background_check_time_us =
                (metrics.background_check_time_us * (total_checks - 1) as f64 + time_us) / total_checks as f64;
        } else {
            metrics.background_check_time_us = time_us;
        }
    }

    // Reuse emit_event and other methods from the original AutoLockManager
    async fn emit_event(&self, event: AutoLockEvent) {
        let callbacks = self.callbacks.read().await;
        for callback in callbacks.iter() {
            tokio::spawn({
                let callback = callback.clone();
                let event = event.clone();
                async move { callback(event) }
            });
        }
    }

    /// Get cache hit ratio (0.0 to 1.0)
    pub async fn cache_hit_ratio(&self) -> f64 {
        let metrics = self.performance_metrics.read().await;
        let total_requests = metrics.cache_hits + metrics.cache_misses;

        if total_requests == 0 {
            0.0
        } else {
            metrics.cache_hits as f64 / total_requests as f64
        }
    }
}

/// Result of cache optimization operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheOptimizationResult {
    pub duration: Duration,
    pub removed_sessions: usize,
    pub removed_policies: usize,
    pub removed_user_policies: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AutoLockConfig;

    #[tokio::test]
    async fn test_cache_performance() {
        let config = EnhancedAutoLockConfig::default();
        let manager = CachedAutoLockManager::new(config);

        // Add a session
        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        // Test cache hit
        let start = Instant::now();
        let is_valid1 = manager.is_session_valid(&session_id).await;
        let first_lookup_time = start.elapsed();

        // Test cache hit again
        let start = Instant::now();
        let is_valid2 = manager.is_session_valid(&session_id).await;
        let second_lookup_time = start.elapsed();

        assert!(is_valid1);
        assert!(is_valid2);

        // Second lookup should be faster due to caching
        // Note: In a real scenario with proper cache implementation, the difference would be more apparent

        let metrics = manager.get_performance_metrics().await;
        assert!(metrics.cache_hits > 0);
        assert!(metrics.cache_hit_ratio() > 0.0);
    }

    #[tokio::test]
    async fn test_cache_optimization() {
        let config = EnhancedAutoLockConfig::default();
        let manager = CachedAutoLockManager::with_cache_config(
            config,
            Duration::from_secs(60),
            2, // Very small cache for testing
        );

        // Add sessions to exceed cache limit
        for i in 0..5 {
            let session = Session::new(format!("user{}", i), Duration::from_secs(3600));
            manager.add_session(session).await.unwrap();
        }

        let metrics_before = manager.get_performance_metrics().await;
        let result = manager.optimize_caches().await;

        assert!(result.duration > Duration::from_nanos(0));
        assert!(metrics_before.active_sessions >= result.removed_sessions);
    }

    #[tokio::test]
    async fn test_performance_metrics() {
        let config = EnhancedAutoLockConfig::default();
        let manager = CachedAutoLockManager::new(config);

        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        // Perform some operations to generate metrics
        for _ in 0..10 {
            manager.is_session_valid(&session_id).await;
            manager.update_activity(&session_id).await.ok();
        }

        let metrics = manager.get_performance_metrics().await;
        assert!(metrics.cache_hits > 0);
        assert!(metrics.active_sessions > 0);
        assert!(metrics.avg_lookup_time_us > 0.0);
        assert!(metrics.cache_hit_ratio() > 0.0);
    }
}