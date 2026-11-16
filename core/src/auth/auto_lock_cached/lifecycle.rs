use super::{CachedAutoLockManager, EventCallback, PerformanceMetrics};
use crate::auth::EnhancedAutoLockConfig;
use crate::storage::AutoLockPolicyRepository;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

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
}
