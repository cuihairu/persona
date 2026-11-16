use super::background::dispatch_event;
use super::{
    CacheOptimizationResult, CachedAutoLockManager, CachedSessionInfo, PerformanceMetrics,
};
use crate::auth::auto_lock::AutoLockEvent;
use std::collections::HashMap;
use std::time::{Duration, Instant};

impl CachedAutoLockManager {
    /// Evict old sessions if cache is full
    pub(super) async fn evict_if_needed(&self, sessions: &mut HashMap<String, CachedSessionInfo>) {
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
            let now = Instant::now();

            policy_cache
                .retain(|_, (_, cached_at)| now.duration_since(*cached_at) < self.cache_ttl);

            initial_count.saturating_sub(policy_cache.len())
        };

        // Clean user policy cache
        let removed_user_policies = {
            let mut user_policy_cache = self.user_policy_cache.write().await;
            let initial_count = user_policy_cache.len();
            let now = Instant::now();

            user_policy_cache
                .retain(|_, (_, cached_at)| now.duration_since(*cached_at) < self.cache_ttl);

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
    pub(super) async fn record_cache_hit(&self) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.cache_hits += 1;
    }

    pub(super) async fn record_cache_miss(&self) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.cache_misses += 1;
    }

    pub(super) async fn record_lookup_time(&self, duration: Duration) {
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
    pub(super) async fn emit_event(&self, event: AutoLockEvent) {
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
}
