use super::auto_lock::{AutoLockEvent, LockReason};
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
    policy_cache: Arc<RwLock<HashMap<Uuid, AutoLockPolicy>>>,
    default_policy_cache: Arc<RwLock<Option<AutoLockPolicy>>>,
    user_policy_cache: Arc<RwLock<HashMap<Uuid, Uuid>>>, // user_id -> policy_id
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
            performance_metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            cache_ttl: Duration::from_secs(300), // 5 minutes cache TTL
            max_cache_size: 10000,               // Maximum cached items
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
    pub async fn register_callback(&self, callback: EventCallback) {
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
        let policy_id = policy.as_ref().map(|p| p.id);
        let max_sessions = policy
            .as_ref()
            .map(|p| p.max_concurrent_sessions)
            .unwrap_or(self.config.max_concurrent_sessions);

        // Apply policy settings to session
        if let Some(ref p) = policy {
            session.expires_at = SystemTime::now() + Duration::from_secs(p.absolute_timeout_secs);
        }

        let session_info = CachedSessionInfo {
            session,
            last_access: Instant::now(),
            last_warning_time: None,
            warning_sent: false,
            policy_id,
            last_compliance_check: Some(Instant::now()),
            is_compliant: true,
        };

        // Check concurrent session limit
        {
            let sessions = self.sessions.read().await;
            let user_sessions = sessions
                .values()
                .filter(|s| s.session.user_id == user_id && s.session.is_valid())
                .count();

            if user_sessions >= max_sessions {
                self.record_cache_miss().await;
                return Err(format!(
                    "Maximum concurrent sessions ({}) exceeded",
                    max_sessions
                ));
            }
        }

        {
            let mut sessions = self.sessions.write().await;
            self.evict_if_needed(&mut sessions).await;
            sessions.insert(session_id.clone(), session_info);
        }

        self.record_lookup_time(start_time.elapsed()).await;
        self.emit_event(AutoLockEvent::Activity { session_id })
            .await;

        Ok(())
    }

    /// Optimized session validation with caching
    pub async fn is_session_valid(&self, session_id: &str) -> bool {
        let start_time = Instant::now();

        {
            let sessions = self.sessions.read().await;
            if let Some(session_info) = sessions.get(session_id) {
                // Use cached compliance check if recent (honour the configured
                // cache TTL, capped at 30s so stale compliance never lingers).
                let recheck_window = self.cache_ttl.min(Duration::from_secs(30));
                let should_recheck = session_info
                    .last_compliance_check
                    .is_none_or(|last| last.elapsed() > recheck_window);

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
                session_id: session_id.to_string(),
            })
            .await;

            Ok(())
        } else {
            self.record_lookup_time(start_time.elapsed()).await;
            Err("Session not found".to_string())
        }
    }

    /// Get policy for user with caching
    async fn get_user_policy_cached(
        &self,
        user_id: &str,
    ) -> Result<Option<AutoLockPolicy>, String> {
        // A non-UUID user id has no policy footprint to look up; the caller
        // falls back to the config defaults.
        let Ok(user_uuid) = Uuid::parse_str(user_id) else {
            return Ok(None);
        };

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
                    // No user-specific policy: fall back to the (cached) default.
                    let cached_default = self.default_policy_cache.read().await.clone();
                    if let Some(policy) = cached_default {
                        return Ok(Some(policy));
                    }
                    if let Ok(Some(default_policy)) = repo.get_default_policy().await {
                        *self.default_policy_cache.write().await = Some(default_policy.clone());
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
            let user_sessions = sessions
                .values()
                .filter(|s| {
                    s.session.user_id == session_info.session.user_id && s.session.is_valid()
                })
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
        let to_remove = sessions.len() - self.max_cache_size + 100; // Remove extra to avoid frequent evictions
        let victim_ids: Vec<String> = {
            let mut session_entries: Vec<_> = sessions.iter().collect();
            session_entries.sort_by_key(|(_, info)| info.last_access);
            session_entries
                .iter()
                .take(to_remove)
                .map(|(id, _)| (*id).clone())
                .collect()
        };
        for session_id in victim_ids {
            sessions.remove(&session_id);
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

        // Clean expired sessions
        let removed_sessions = {
            let mut sessions = self.sessions.write().await;
            let initial_count = sessions.len();

            sessions.retain(|_, info| {
                // Remove sessions that are expired and have been inactive for over an hour
                !info.session.is_expired()
                    || (!info.session.locked && info.session.get_idle_seconds() < 3600)
            });

            initial_count - sessions.len()
        };

        // Clean policy cache (remove policies older than TTL)
        let removed_policies = {
            let mut policy_cache = self.policy_cache.write().await;
            let initial_count = policy_cache.len();

            // For now, just keep recently used policies
            // In a real implementation, you might want to track last access time
            if policy_cache.len() > 1000 {
                policy_cache.retain(|_, _| true); // Keep all for now
            }

            initial_count.saturating_sub(policy_cache.len())
        };

        // Clean user policy cache
        let removed_user_policies = {
            let mut user_policy_cache = self.user_policy_cache.write().await;
            let initial_count = user_policy_cache.len();

            if user_policy_cache.len() > 5000 {
                user_policy_cache.retain(|_, _| true); // Keep all for now
            }

            initial_count.saturating_sub(user_policy_cache.len())
        };

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
            metrics.avg_lookup_time_us = (metrics.avg_lookup_time_us * (total_checks - 1) as f64
                + time_us)
                / total_checks as f64;
        } else {
            metrics.avg_lookup_time_us = time_us;
        }
    }

    // Reuse emit_event and other methods from the original AutoLockManager
    async fn emit_event(&self, event: AutoLockEvent) {
        dispatch_event(&self.callbacks, event).await;
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

    /// Start the background monitoring loop using the configured interval.
    pub async fn start_background_monitoring(&self) -> Result<(), String> {
        let interval = Duration::from_secs(self.config.background_check_interval_secs.max(1));
        self.start_background_monitoring_with_interval(interval)
            .await
    }

    /// Start background monitoring with a custom check interval. Each pass
    /// emits a single `LockPending` warning for sessions approaching the
    /// inactivity deadline, then locks expired or idle sessions and reports
    /// `Locked` with the matching reason.
    pub async fn start_background_monitoring_with_interval(
        &self,
        interval: Duration,
    ) -> Result<(), String> {
        let mut task_slot = self.background_task.lock().await;
        if task_slot.is_some() {
            return Ok(()); // already running
        }

        let sessions = Arc::clone(&self.sessions);
        let callbacks = Arc::clone(&self.callbacks);
        let metrics = Arc::clone(&self.performance_metrics);
        let inactivity_timeout = Duration::from_secs(self.config.base.inactivity_timeout_secs);
        let warning_window = Duration::from_secs(self.config.warning_time_secs);
        let enable_warnings = self.config.enable_warnings;
        let interval = interval.max(Duration::from_millis(1));

        let handle = tokio::spawn(async move {
            loop {
                let start = Instant::now();

                let mut pending = Vec::new();
                let mut locked = Vec::new();
                {
                    let mut map = sessions.write().await;
                    for (id, info) in map.iter_mut() {
                        if !info.session.locked && info.session.is_expired() {
                            info.session.lock();
                            locked.push((id.clone(), LockReason::AbsoluteTimeout));
                            continue;
                        }
                        if inactivity_timeout.as_secs() > 0
                            && !info.session.locked
                            && info.session.is_idle(inactivity_timeout)
                        {
                            info.session.lock();
                            locked.push((id.clone(), LockReason::Inactivity));
                            continue;
                        }
                        if enable_warnings
                            && inactivity_timeout > warning_window
                            && !info.warning_sent
                            && info.session.is_idle(inactivity_timeout - warning_window)
                        {
                            info.warning_sent = true;
                            info.last_warning_time = Some(SystemTime::now());
                            let remaining = inactivity_timeout
                                .as_secs()
                                .saturating_sub(info.session.get_idle_seconds());
                            pending.push((id.clone(), remaining));
                        }
                    }
                }

                for (session_id, seconds_remaining) in pending {
                    dispatch_event(
                        &callbacks,
                        AutoLockEvent::LockPending {
                            session_id,
                            seconds_remaining,
                        },
                    )
                    .await;
                }
                for (session_id, reason) in locked {
                    dispatch_event(&callbacks, AutoLockEvent::Locked { session_id, reason }).await;
                }

                record_background_check(&metrics, start.elapsed()).await;

                tokio::time::sleep(interval).await;
            }
        });

        *task_slot = Some(handle);
        Ok(())
    }

    /// Stop the background monitoring loop (no-op when not running).
    pub async fn stop_background_monitoring(&self) {
        if let Some(handle) = self.background_task.lock().await.take() {
            handle.abort();
        }
    }
}

/// Fan an event out to every registered callback (each on its own task).
async fn dispatch_event(callbacks: &Arc<RwLock<Vec<EventCallback>>>, event: AutoLockEvent) {
    let callbacks = callbacks.read().await;
    for callback in callbacks.iter() {
        tokio::spawn({
            let callback = callback.clone();
            let event = event.clone();
            async move { callback(event) }
        });
    }
}

/// Record one background check's duration into the shared metrics.
async fn record_background_check(metrics: &Arc<RwLock<PerformanceMetrics>>, duration: Duration) {
    let mut metrics = metrics.write().await;
    metrics.background_checks_performed += 1;

    let time_us = duration.as_micros() as f64;
    let total_checks = metrics.background_checks_performed;

    if total_checks > 1 {
        metrics.background_check_time_us =
            (metrics.background_check_time_us * (total_checks - 1) as f64 + time_us)
                / total_checks as f64;
    } else {
        metrics.background_check_time_us = time_us;
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

    #[tokio::test]
    async fn test_cache_performance() {
        let config = EnhancedAutoLockConfig::default();
        let manager = CachedAutoLockManager::new(config);

        // Add a session
        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        // Test cache hit
        let is_valid1 = manager.is_session_valid(&session_id).await;

        // Test cache hit again
        let is_valid2 = manager.is_session_valid(&session_id).await;

        assert!(is_valid1);
        assert!(is_valid2);

        let metrics = manager.get_performance_metrics().await;
        assert!(metrics.cache_hits > 0);
        assert!(manager.cache_hit_ratio().await > 0.0);
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
        assert!(manager.cache_hit_ratio().await > 0.0);
    }

    #[tokio::test]
    async fn test_concurrent_session_limit_enforced() {
        let config = EnhancedAutoLockConfig {
            max_concurrent_sessions: 2,
            ..Default::default()
        };
        let manager = CachedAutoLockManager::new(config);

        for i in 0..2 {
            let session = Session::new("limited-user".to_string(), Duration::from_secs(3600));
            manager.add_session(session).await.unwrap();
            let _ = i;
        }

        // The third session for the same user exceeds the limit.
        let extra = Session::new("limited-user".to_string(), Duration::from_secs(3600));
        let err = manager.add_session(extra).await.unwrap_err();
        assert!(err.contains("Maximum concurrent sessions"), "got: {err}");

        // A different user is unaffected.
        let other = Session::new("other-user".to_string(), Duration::from_secs(3600));
        manager.add_session(other).await.unwrap();
    }

    #[tokio::test]
    async fn test_update_activity_and_unknown_session() {
        let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default());

        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        manager.update_activity(&session_id).await.unwrap();

        // Unknown session id surfaces a "not found" error, and validity is false.
        assert_eq!(
            manager
                .update_activity("no-such-session")
                .await
                .unwrap_err(),
            "Session not found"
        );
        assert!(!manager.is_session_valid("no-such-session").await);

        // Clearing caches wipes the session and resets the hit ratio.
        manager.clear_caches().await;
        assert!(!manager.is_session_valid(&session_id).await);
        assert_eq!(manager.cache_hit_ratio().await, 0.0);
    }

    #[tokio::test]
    async fn test_background_monitoring_locks_expired_sessions() {
        let config = EnhancedAutoLockConfig {
            base: crate::auth::AutoLockConfig {
                inactivity_timeout_secs: 3600, // must not trigger first
                ..Default::default()
            },
            enable_warnings: false,
            ..Default::default()
        };
        let manager = CachedAutoLockManager::new(config);

        // A zero-lifetime session is expired the moment it is added.
        let session = Session::new("user123".to_string(), Duration::from_secs(0));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        manager
            .register_callback(Arc::new(move |event| {
                let _ = tx.send(event);
            }))
            .await;

        manager
            .start_background_monitoring_with_interval(Duration::from_millis(10))
            .await
            .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a lock event must arrive")
            .expect("channel open");
        match event {
            AutoLockEvent::Locked {
                session_id: id,
                reason,
            } => {
                assert_eq!(id, session_id);
                assert_eq!(reason, LockReason::AbsoluteTimeout);
            }
            other => panic!("expected Locked, got {other:?}"),
        }

        // The monitor also stops cleanly, and starting twice is a no-op.
        manager
            .start_background_monitoring_with_interval(Duration::from_millis(10))
            .await
            .unwrap();
        manager.stop_background_monitoring().await;
        manager.stop_background_monitoring().await; // second stop is a no-op
    }

    #[tokio::test]
    async fn test_background_monitoring_warns_before_inactivity_lock() {
        let config = EnhancedAutoLockConfig {
            base: crate::auth::AutoLockConfig {
                inactivity_timeout_secs: 3,
                ..Default::default()
            },
            warning_time_secs: 2, // warn once idle passes 1s
            enable_warnings: true,
            ..Default::default()
        };
        let manager = CachedAutoLockManager::new(config);

        let session = Session::new("user456".to_string(), Duration::from_secs(3600));
        manager.add_session(session).await.unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        manager
            .register_callback(Arc::new(move |event| {
                let _ = tx.send(event);
            }))
            .await;

        manager
            .start_background_monitoring_with_interval(Duration::from_millis(50))
            .await
            .unwrap();

        // First event: the single warning while still inside the window.
        let first = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("warning must arrive")
            .expect("channel open");
        match first {
            AutoLockEvent::LockPending {
                session_id,
                seconds_remaining,
            } => {
                assert!(!session_id.is_empty());
                assert!(seconds_remaining <= 3, "got {seconds_remaining}");
            }
            other => panic!("expected LockPending, got {other:?}"),
        }

        // Then the lock once the full inactivity timeout elapses.
        let second = tokio::time::timeout(Duration::from_secs(4), rx.recv())
            .await
            .expect("lock must arrive")
            .expect("channel open");
        match second {
            AutoLockEvent::Locked { session_id, reason } => {
                assert!(!session_id.is_empty());
                assert_eq!(reason, LockReason::Inactivity);
            }
            other => panic!("expected Locked, got {other:?}"),
        }

        manager.stop_background_monitoring().await;

        // The background loop fed the check-time metrics.
        let metrics = manager.get_performance_metrics().await;
        assert!(metrics.background_checks_performed > 0);
        assert!(metrics.background_check_time_us >= 0.0);
    }

    use crate::models::auto_lock_policy::{AutoLockPolicy, AutoLockSecurityLevel};
    use crate::storage::Database;

    async fn policy_repository() -> Arc<AutoLockPolicyRepository> {
        let db = Database::in_memory().await.expect("in-memory database");
        db.migrate().await.expect("migrate");
        Arc::new(AutoLockPolicyRepository::new(Arc::new(db)))
    }

    #[tokio::test]
    async fn test_user_policy_from_repository_governs_sessions() {
        let repo = policy_repository().await;
        let user = Uuid::new_v4();
        let policy = repo
            .create(&AutoLockPolicy::new(
                "Strict".to_string(),
                AutoLockSecurityLevel::Maximum, // max_concurrent_sessions: 1
                3600,
            ))
            .await
            .unwrap();
        repo.assign_to_user(&policy.id, &user).await.unwrap();

        let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default())
            .with_policy_repository(repo);

        // The first add resolves the policy from the repository (and caches it).
        let s1 = Session::new(user.to_string(), Duration::from_secs(3600));
        manager.add_session(s1).await.unwrap();

        // The policy's single-session limit rejects the second add.
        let s2 = Session::new(user.to_string(), Duration::from_secs(3600));
        let err = manager.add_session(s2).await.unwrap_err();
        assert!(err.contains("Maximum concurrent sessions"), "got: {err}");
    }

    #[tokio::test]
    async fn test_default_policy_fallback_for_unassigned_users() {
        let repo = policy_repository().await;
        let default = repo
            .create(&AutoLockPolicy::new(
                "Company Default".to_string(),
                AutoLockSecurityLevel::Low, // max_concurrent_sessions: 10
                1800,
            ))
            .await
            .unwrap();
        repo.set_as_default(&default.id).await.unwrap();

        let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default())
            .with_policy_repository(repo);

        // Neither user has an assignment, so both resolve through the default
        // policy. Its limit is 10 — past the config default of 5 — proving the
        // policy (not the config) governs.
        for user in [Uuid::new_v4(), Uuid::new_v4()] {
            for _ in 0..6 {
                let session = Session::new(user.to_string(), Duration::from_secs(3600));
                manager.add_session(session).await.unwrap();
            }
        }

        // The 11th session for one user finally trips the default policy.
        let extra = Session::new(Uuid::new_v4().to_string(), Duration::from_secs(3600));
        manager.add_session(extra).await.unwrap(); // still fine for a third user

        let busy = Uuid::new_v4();
        for _ in 0..10 {
            let session = Session::new(busy.to_string(), Duration::from_secs(3600));
            manager.add_session(session).await.unwrap();
        }
        let one_too_many = Session::new(busy.to_string(), Duration::from_secs(3600));
        assert!(manager.add_session(one_too_many).await.is_err());
    }

    #[tokio::test]
    async fn test_compliance_recheck_enforces_policy_inactivity() {
        let repo = policy_repository().await;
        let user = Uuid::new_v4();
        let policy = repo
            .create(&AutoLockPolicy::new(
                "Idle Lock".to_string(),
                AutoLockSecurityLevel::Low, // absolute 7200: never trips here
                1,                          // inactivity timeout: 1 second
            ))
            .await
            .unwrap();
        repo.assign_to_user(&policy.id, &user).await.unwrap();

        // A zero cache TTL forces the compliance recheck on every validation.
        let manager = CachedAutoLockManager::with_cache_config(
            EnhancedAutoLockConfig::default(),
            Duration::from_secs(0),
            1000,
        )
        .with_policy_repository(repo);

        let session = Session::new(user.to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        // Fresh session: the policy check passes.
        assert!(manager.is_session_valid(&session_id).await);

        // Past the policy's inactivity timeout the recheck fails it.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!manager.is_session_valid(&session_id).await);
    }

    #[tokio::test]
    async fn test_update_activity_after_grace_period_touches_and_emits() {
        let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default());

        let session = Session::new("user123".to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        // The Debug rendering finishes non-exhaustively over the internal
        // RwLocks; it must still produce output.
        let rendered = format!("{:?}", manager);
        assert!(
            rendered.contains("CachedAutoLockManager"),
            "got: {rendered}"
        );

        // The callback is registered after the add, so only the real update
        // below (past the 100 ms grace window) reaches the channel.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        manager
            .register_callback(Arc::new(move |event| {
                let _ = tx.send(event);
            }))
            .await;

        tokio::time::sleep(Duration::from_millis(150)).await;
        manager.update_activity(&session_id).await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("activity event must arrive")
            .expect("channel open");
        match event {
            AutoLockEvent::Activity { session_id: id } => assert_eq!(id, session_id),
            other => panic!("expected Activity, got {other:?}"),
        }

        // An immediate follow-up lands inside the grace window: it succeeds
        // but skips the processing path, so no second event is emitted.
        manager.update_activity(&session_id).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "grace-window update must not emit"
        );
    }

    #[tokio::test]
    async fn test_uuid_user_without_repository_falls_back_to_session_validity() {
        // A UUID-shaped user on a repository-less manager resolves through
        // the no-policy tail instead of the non-UUID early return.
        let manager = CachedAutoLockManager::with_cache_config(
            EnhancedAutoLockConfig::default(),
            Duration::from_secs(0), // force the compliance recheck
            1000,
        );

        let session = Session::new(Uuid::new_v4().to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        // No policy governs the session, so the recheck falls back to plain
        // session validity.
        assert!(manager.is_session_valid(&session_id).await);
    }

    #[tokio::test]
    async fn test_policy_repository_error_surfaces() {
        let db = Database::in_memory().await.expect("in-memory database");
        db.migrate().await.expect("migrate");
        let pool = db.pool().clone();
        let repo = Arc::new(AutoLockPolicyRepository::new(Arc::new(db)));

        let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default())
            .with_policy_repository(repo);

        // Closing the underlying pool makes the policy lookup fail; the
        // error must surface instead of being swallowed into a default.
        pool.close().await;
        let session = Session::new(Uuid::new_v4().to_string(), Duration::from_secs(3600));
        let err = manager.add_session(session).await.unwrap_err();
        assert!(err.contains("Failed to fetch policy"), "got: {err}");
    }

    #[tokio::test]
    async fn test_compliance_recheck_enforces_policy_absolute_timeout() {
        let repo = policy_repository().await;
        let user = Uuid::new_v4();
        let mut policy = AutoLockPolicy::new(
            "Flash".to_string(),
            AutoLockSecurityLevel::Low,
            3600, // inactivity: never trips within the test's lifetime
        );
        // A one-second lifetime so only the absolute-timeout check can fail.
        policy.absolute_timeout_secs = 1;
        let policy = repo.create(&policy).await.unwrap();
        repo.assign_to_user(&policy.id, &user).await.unwrap();

        let manager = CachedAutoLockManager::with_cache_config(
            EnhancedAutoLockConfig::default(),
            Duration::from_secs(0), // force the compliance recheck
            1000,
        )
        .with_policy_repository(repo);

        let session = Session::new(user.to_string(), Duration::from_secs(3600));
        let session_id = session.id.clone();
        manager.add_session(session).await.unwrap();

        // Fresh session: the lifetime check passes.
        assert!(manager.is_session_valid(&session_id).await);

        // Past the one-second absolute timeout the recheck fails it (the
        // lifetime is measured in whole seconds, so wait past two).
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(!manager.is_session_valid(&session_id).await);
    }

    #[tokio::test]
    async fn test_optimize_caches_keeps_expired_but_idle_sessions() {
        let manager = CachedAutoLockManager::new(EnhancedAutoLockConfig::default());

        // One long-lived session plus one that is expired the moment it is
        // added (but unlocked and recently active): the optimizer's retain
        // clause must evaluate the expired branch and still keep it.
        let live = Session::new("live-user".to_string(), Duration::from_secs(3600));
        manager.add_session(live).await.unwrap();
        let expired = Session::new("gone-user".to_string(), Duration::from_secs(0));
        manager.add_session(expired).await.unwrap();

        let result = manager.optimize_caches().await;
        assert_eq!(
            result.removed_sessions, 0,
            "expired-but-idle session is kept"
        );
    }
}
