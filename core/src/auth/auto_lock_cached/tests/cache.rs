use crate::auth::auto_lock_cached::CachedAutoLockManager;
use crate::auth::{EnhancedAutoLockConfig, Session};
use crate::models::auto_lock_policy::AutoLockPolicy;
use std::time::{Duration, Instant};
use uuid::Uuid;

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
    assert!(
        metrics.avg_lookup_time_us >= 0.0,
        "lookup time should be non-negative"
    );
    assert!(manager.cache_hit_ratio().await >= 0.0);
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

/// Real TTL eviction of the policy caches (audit batch 2 #8): the placeholder
/// `retain(|_, _| true)` never removed anything, so entries only ever grew.
/// With timestamps in place, expired entries (> cache_ttl) are evicted and
/// counted in removed_*, while fresh entries are kept.
#[tokio::test]
async fn optimize_caches_evicts_expired_policy_entries() {
    let config = EnhancedAutoLockConfig::default();
    let manager = CachedAutoLockManager::new(config);
    let ttl = manager.cache_ttl;

    let stale = Instant::now() - ttl - Duration::from_secs(1);
    let fresh = Instant::now();
    let old_policy = AutoLockPolicy::new(
        "stale".to_string(),
        crate::models::auto_lock_policy::AutoLockSecurityLevel::Medium,
        300,
    );
    let old_id = old_policy.id;
    let fresh_policy = AutoLockPolicy::new(
        "fresh".to_string(),
        crate::models::auto_lock_policy::AutoLockSecurityLevel::Medium,
        300,
    );

    {
        let mut policy_cache = manager.policy_cache.write().await;
        policy_cache.insert(old_id, (old_policy, stale));
        policy_cache.insert(fresh_policy.id, (fresh_policy.clone(), fresh));
        let mut user_policy_cache = manager.user_policy_cache.write().await;
        user_policy_cache.insert(old_id, (old_id, stale));
        user_policy_cache.insert(Uuid::new_v4(), (fresh_policy.id, fresh));
    }

    let result = manager.optimize_caches().await;
    assert_eq!(result.removed_policies, 1, "过期策略条目必须逐出");
    assert_eq!(result.removed_user_policies, 1, "过期用户映射必须逐出");

    let policy_cache = manager.policy_cache.read().await;
    assert_eq!(policy_cache.len(), 1, "新鲜策略条目保留");
    assert!(policy_cache.contains_key(&fresh_policy.id));
    let user_policy_cache = manager.user_policy_cache.read().await;
    assert_eq!(user_policy_cache.len(), 1);
}
