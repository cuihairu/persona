use super::*;

/// 审计日志查询条件。
///
/// 所有条件按 AND 组合：服务层先用最具选择性的数据库查询取数，
/// 再对剩余条件做内存过滤，`limit` 最后截断。
#[derive(Debug, Clone, Default)]
pub struct AuditLogQuery {
    pub user_id: Option<String>,
    pub identity_id: Option<Uuid>,
    pub action: Option<AuditAction>,
    pub failures_only: bool,
    pub security_sensitive_only: bool,
    pub time_range: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
    /// 最多返回条数（按时间降序取前 N 条）
    pub limit: Option<usize>,
}

impl PersonaService {
    /// Query audit logs (descending by time). Requires the service to be unlocked.
    ///
    /// All conditions are AND-combined: the service layer first uses the most selective
    /// database query, then filters the remaining conditions in memory.
    pub async fn query_audit_logs(&self, query: AuditLogQuery) -> Result<Vec<AuditLog>> {
        self.ensure_unlocked_with_auto_lock().await?;

        let mut logs = if let Some(user_id) = query.user_id.clone() {
            self.audit_repo.find_by_user(&user_id).await?
        } else if let Some(identity_id) = query.identity_id {
            self.audit_repo.find_by_identity(&identity_id).await?
        } else if let Some(action) = query.action.clone() {
            self.audit_repo.find_by_action(&action).await?
        } else if query.failures_only {
            self.audit_repo.find_failures().await?
        } else if query.security_sensitive_only {
            self.audit_repo.find_security_sensitive().await?
        } else if let Some((start, end)) = query.time_range {
            self.audit_repo.find_by_time_range(start, end).await?
        } else {
            self.audit_repo.find_all().await?
        };

        logs.retain(|log| {
            query
                .user_id
                .as_ref()
                .is_none_or(|u| log.user_id.as_ref() == Some(u))
                && query
                    .identity_id
                    .is_none_or(|id| log.identity_id == Some(id))
                && query
                    .action
                    .as_ref()
                    .is_none_or(|a| log.action.to_string() == a.to_string())
                && (!query.failures_only || !log.success)
                && (!query.security_sensitive_only
                    || SECURITY_SENSITIVE_AUDIT_ACTIONS.contains(&log.action.to_string().as_str()))
        });

        if let Some((start, end)) = query.time_range {
            logs.retain(|log| log.timestamp >= start && log.timestamp <= end);
        }

        if let Some(limit) = query.limit {
            logs.truncate(limit);
        }

        Ok(logs)
    }

    /// Audit statistics (total count / failed operations / recent logins / active users)
    pub async fn audit_log_statistics(&self) -> Result<AuditLogStatistics> {
        self.ensure_unlocked_with_auto_lock().await?;
        self.audit_repo.get_statistics().await
    }

    /// Clean up audit logs older than the retention period, returning the number of deleted rows
    pub async fn cleanup_audit_logs(&self, retain_days: u32) -> Result<u64> {
        self.ensure_unlocked_with_auto_lock().await?;
        self.audit_repo.cleanup_old_logs(retain_days).await
    }

    pub(crate) async fn log_audit(
        &self,
        action: AuditAction,
        resource_type: ResourceType,
        success: bool,
        identity_or_cred: Option<Uuid>,
        identity_id: Option<Uuid>,
        error: Option<String>,
    ) {
        self.log_audit_with_metadata(
            action,
            resource_type,
            success,
            identity_or_cred,
            identity_id,
            error,
            None,
        )
        .await;
    }

    /// Same as [`Self::log_audit`] plus one free-form metadata pair (see
    /// [`AuditLog::with_metadata`]); used e.g. to distinguish which trust
    /// path performed a passkey assertion (`via=extension` / `os_provider`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn log_audit_with_metadata(
        &self,
        action: AuditAction,
        resource_type: ResourceType,
        success: bool,
        identity_or_cred: Option<Uuid>,
        identity_id: Option<Uuid>,
        error: Option<String>,
        metadata: Option<(&'static str, String)>,
    ) {
        let action_kind = action.clone();
        let mut log = AuditLog::new(action, resource_type, success)
            .with_user_id(self.current_user.map(|u| u.to_string()))
            .with_error_message(error);
        if let Some((key, value)) = metadata {
            log = log.with_metadata(key.to_string(), value);
        }
        if let Some(id) = identity_or_cred {
            // Always store the raw resource identifier so deletion events can still be recorded
            // without violating foreign key constraints.
            log = log.with_resource_id(Some(id.to_string()));

            match action_kind {
                AuditAction::IdentityDeleted => {
                    // Identity no longer exists; don't set FK-backed fields.
                }
                AuditAction::PasskeyCreated
                | AuditAction::PasskeyViewed
                | AuditAction::PasskeyAsserted
                | AuditAction::PasskeyExported
                | AuditAction::PasskeyDeleted
                | AuditAction::ConnectTokenCreated
                | AuditAction::ConnectTokenRevoked
                | AuditAction::ConnectTokenUsed => {
                    // Passkey/Connect token id 均不是 credential/identity FK;
                    // resource_id 载主键,只附身份上下文。
                    if let Some(identity_id_val) = identity_id {
                        log = log.with_identity_id(Some(identity_id_val));
                    }
                }
                AuditAction::CredentialDeleted => {
                    // Credential no longer exists; keep identity context if available.
                    if let Some(identity_id_val) = identity_id {
                        log = log.with_identity_id(Some(identity_id_val));
                    }
                }
                _ => {
                    // If identity_id provided, treat `id` as credential_id; else treat `id` as identity_id.
                    if let Some(identity_id_val) = identity_id {
                        log = log
                            .with_identity_id(Some(identity_id_val))
                            .with_credential_id(Some(id));
                    } else {
                        log = log.with_identity_id(Some(id));
                    }
                }
            }
        }
        let _ = self.audit_repo.create(&log).await;
        // 尽力而为的远端复制（见 events::Emitter）：本地审计库才是存证源
        if let Some(emitter) = &self.event_emitter {
            emitter.emit(&log);
        }
    }
}
