use super::{CachedAutoLockManager, CachedSessionInfo};
use crate::models::auto_lock_policy::AutoLockPolicy;
use std::time::{Duration, Instant};
use uuid::Uuid;

impl CachedAutoLockManager {
    /// Get policy for user with caching
    pub(super) async fn get_user_policy_cached(
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
            let now = Instant::now();
            let user_policy_cache = self.user_policy_cache.read().await;
            if let Some(&(policy_id, cached_at)) = user_policy_cache.get(&user_uuid) {
                if now.duration_since(cached_at) < self.cache_ttl {
                    let policy_cache = self.policy_cache.read().await;
                    if let Some((policy, _)) = policy_cache.get(&policy_id) {
                        return Ok(Some(policy.clone()));
                    }
                }
            }
        }

        // Cache miss - fetch from repository
        if let Some(ref repo) = self.policy_repository {
            match repo.get_user_policy(&user_uuid).await {
                Ok(Some(policy)) => {
                    // Update caches
                    let now = Instant::now();
                    {
                        let mut user_policy_cache = self.user_policy_cache.write().await;
                        user_policy_cache.insert(user_uuid, (policy.id, now));
                    }
                    {
                        let mut policy_cache = self.policy_cache.write().await;
                        policy_cache.insert(policy.id, (policy.clone(), now));
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
                            policy_cache.insert(
                                default_policy.id,
                                (default_policy.clone(), Instant::now()),
                            );
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
    pub(super) async fn check_session_compliance(&self, session_info: &CachedSessionInfo) -> bool {
        let policy = if let Some(policy_id) = session_info.policy_id {
            let policy_cache = self.policy_cache.read().await;
            policy_cache
                .get(&policy_id)
                .map(|(policy, _)| policy.clone())
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
}
