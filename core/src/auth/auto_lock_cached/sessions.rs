use super::{CachedAutoLockManager, CachedSessionInfo};
use crate::auth::auto_lock::AutoLockEvent;
use crate::auth::session::saturating_add;
use crate::auth::Session;
use std::time::{Duration, Instant, SystemTime};

impl CachedAutoLockManager {
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
            // 策略里的 absolute_timeout_secs 来自库/配置（u64 无上界），
            // 裸加溢出即 panic——与 Session::new 同一饱和口径。
            session.expires_at = saturating_add(
                SystemTime::now(),
                Duration::from_secs(p.absolute_timeout_secs),
            );
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
}
