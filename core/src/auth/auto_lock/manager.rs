//! 管理器运行时核：构造、接线（审计/事件/回调）、运行期配置更新、
//! 用户上下文、统计与过期清理。

use std::collections::HashMap;
use std::sync::{Arc, RwLock as SyncRwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::auth::session::AutoLockConfig;
use crate::events::Emitter;
use crate::storage::AuditLogRepository;

use super::config::EnhancedAutoLockConfig;
use super::events::AutoLockCallback;
use super::AutoLockManager;

impl AutoLockManager {
    /// Create a new auto-lock manager
    pub fn new(config: EnhancedAutoLockConfig) -> Self {
        Self {
            config: SyncRwLock::new(config),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            callbacks: Arc::new(RwLock::new(Vec::new())),
            audit_repo: None,
            event_emitter: None,
            background_task: Arc::new(Mutex::new(None)),
            current_user: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with basic auto-lock config
    pub fn with_basic_config(config: AutoLockConfig) -> Self {
        Self::new(config.into())
    }

    /// Update the base auto-lock configuration in place.
    ///
    /// [`crate::PersonaService::configure_auto_lock`] 经此同步命令层传来的
    /// 设置。只换 `base`：其余增强字段（并发上限、宽限期等）保持不变，
    /// 在管 session 与后台任务也不受影响。
    pub fn update_base_config(&self, base: AutoLockConfig) {
        let mut config = self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        config.base = base;
    }

    /// Set audit repository for logging
    pub fn with_audit_repo(mut self, audit_repo: AuditLogRepository) -> Self {
        self.audit_repo = Some(audit_repo);
        self
    }

    /// 注入/摘除审计事件上报器（`None` = 摘除）。调用方约定：
    /// [`crate::PersonaService::set_event_emitter`] 会同步传播到这里，
    /// 换上报器时先摘旧再挂新，防止双任务。
    pub fn set_event_emitter(&mut self, emitter: Option<Emitter>) {
        self.event_emitter = emitter;
    }

    /// Register a callback for auto-lock events
    pub async fn register_callback(&self, callback: AutoLockCallback) {
        let mut callbacks = self.callbacks.write().await;
        callbacks.push(callback);
    }
}

impl AutoLockManager {
    /// Get auto-lock statistics
    pub async fn get_statistics(&self) -> AutoLockStatistics {
        let (inactivity_timeout_secs, max_concurrent_sessions) = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                config.base.inactivity_timeout_secs,
                config.max_concurrent_sessions,
            )
        };
        let sessions = self.sessions.read().await;
        let total_sessions = sessions.len();
        let active_sessions = sessions.values().filter(|si| si.session.is_valid()).count();
        let locked_sessions = sessions.values().filter(|si| si.session.locked).count();
        let idle_sessions = sessions
            .values()
            .filter(|si| {
                si.session.is_valid()
                    && si
                        .session
                        .is_idle(Duration::from_secs(inactivity_timeout_secs))
            })
            .count();

        AutoLockStatistics {
            total_sessions,
            active_sessions,
            locked_sessions,
            idle_sessions,
            max_concurrent_sessions,
        }
    }
}

impl AutoLockManager {
    /// Set current user context
    pub async fn set_current_user(&self, user_id: Uuid) {
        let mut current_user = self.current_user.write().await;
        *current_user = Some(user_id);
    }

    /// Clear current user context
    pub async fn clear_current_user(&self) {
        let mut current_user = self.current_user.write().await;
        *current_user = None;
    }

    /// Force cleanup of expired sessions
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();

        sessions.retain(|_, session_info| {
            !session_info.session.is_expired()
                || (session_info.session.locked && session_info.session.get_idle_seconds() > 3600)
        });

        initial_count - sessions.len()
    }
}
/// Auto-lock statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoLockStatistics {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub locked_sessions: usize,
    pub idle_sessions: usize,
    pub max_concurrent_sessions: usize,
}
