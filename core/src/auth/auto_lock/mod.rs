use std::collections::HashMap;
use std::sync::{Arc, RwLock as SyncRwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};

use crate::events::Emitter;
use crate::models::{AuditAction, ResourceType};
use crate::storage::{AuditLogRepository, Repository};
use uuid::Uuid;

use super::Session;

mod config;
mod events;
mod lock;
mod manager;
mod monitor;
mod sessions;

pub use config::EnhancedAutoLockConfig;
pub use events::{AutoLockCallback, AutoLockEvent, LockReason};
pub use manager::AutoLockStatistics;

#[cfg(test)]
use monitor::{get_seconds_until_lock, should_send_warning};

#[cfg(test)]
mod tests;

/// Enhanced auto-lock manager with advanced features
pub struct AutoLockManager {
    /// 配置快照。锁保护的目的是支持运行期更新（`update_base_config`）：
    /// 服务层把命令传来的设置同步进来，而管理器不能重建——重建会丢掉
    /// 在管 session、后台任务与回调。读侧全是短临界区同步访问，用
    /// std 锁即可（不跨 await）。
    config: SyncRwLock<EnhancedAutoLockConfig>,
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    callbacks: Arc<RwLock<Vec<AutoLockCallback>>>,
    audit_repo: Option<AuditLogRepository>,
    /// 审计事件上报器（None = 不上报）。由
    /// [`crate::PersonaService::set_event_emitter`] 传播注入——service 是
    /// 唯一注入口，宿主（desktop/CLI）只跟 service 打交道。
    event_emitter: Option<Emitter>,
    background_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    current_user: Arc<RwLock<Option<Uuid>>>,
}

/// Extended session information for auto-lock management
#[derive(Debug, Clone)]
struct SessionInfo {
    session: Session,
    last_warning_time: Option<SystemTime>,
    warning_sent: bool,
}

impl AutoLockManager {
    // Private helper methods

    fn should_lock_session(&self, session: &Session) -> bool {
        let config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Check inactivity timeout
        if config.base.inactivity_timeout_secs > 0 {
            let inactivity = Duration::from_secs(config.base.inactivity_timeout_secs);
            if session.is_idle(inactivity) {
                return true;
            }
        }

        // Check absolute timeout
        if config.base.absolute_timeout_secs > 0 {
            let absolute = Duration::from_secs(config.base.absolute_timeout_secs);
            if session.get_lifetime_seconds() > absolute.as_secs() {
                return true;
            }
        }

        false
    }

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

    async fn log_audit_event(&self, session_id: &str, action: AuditAction, reason: &str) {
        if let Some(ref repo) = self.audit_repo {
            let current_user = *self.current_user.read().await;
            let log = session_audit_log(session_id, current_user, action, reason);
            let _ = repo.create(&log).await;
            // 先写本地库再尽力上报（与 PersonaService::log_audit 同序）
            if let Some(ref emitter) = self.event_emitter {
                emitter.emit(&log);
            }
        }
    }
}
/// 构造带 session 上下文的审计行（helper 与后台监控任务共用——后者是
/// 'static 闭包不能引用 self，只克隆本函数需要的数据进去）。
fn session_audit_log(
    session_id: &str,
    current_user: Option<Uuid>,
    action: AuditAction,
    reason: &str,
) -> crate::models::AuditLog {
    let mut log = crate::models::AuditLog::new(action, ResourceType::Session, true)
        .with_session_id(Some(session_id.to_string()))
        .with_details(Some(reason.to_string()));
    if let Some(user_id) = current_user {
        log = log.with_user_id(Some(user_id.to_string()));
    }
    log
}
