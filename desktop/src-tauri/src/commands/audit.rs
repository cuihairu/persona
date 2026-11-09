use super::*;

/// Query audit logs with filters
#[command]
pub async fn audit_query(
    request: AuditQueryRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableAuditLog>>, String> {
    let query = match build_audit_query(&request) {
        Ok(q) => q,
        Err(msg) => return Ok(ApiResponse::error(msg)),
    };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.query_audit_logs(query).await {
            Ok(logs) => Ok(ApiResponse::success(
                logs.into_iter().map(SerializableAuditLog::from).collect(),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!("Audit query failed: {}", msg))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get audit statistics
#[command]
pub async fn audit_statistics(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableAuditStatistics>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.audit_log_statistics().await {
            Ok(stats) => Ok(ApiResponse::success(SerializableAuditStatistics {
                total_logs: stats.total_logs,
                failed_operations: stats.failed_operations,
                recent_login_attempts: stats.recent_login_attempts,
                active_users_last_week: stats.active_users_last_week,
            })),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Audit statistics failed: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete audit logs older than `retain_days` (destructive; requires unlocked service)
#[command(rename_all = "snake_case")]
pub async fn audit_cleanup(
    retain_days: u32,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<u64>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.cleanup_audit_logs(retain_days).await {
            Ok(deleted) => Ok(ApiResponse::success(deleted)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!("Audit cleanup failed: {}", msg))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Parse an `AuditQueryRequest` into the core `AuditLogQuery`.
///
/// Separated as a pure function so invalid IDs/actions are testable without
/// a running service.
pub(crate) fn build_audit_query(
    request: &AuditQueryRequest,
) -> std::result::Result<persona_core::AuditLogQuery, String> {
    let identity_id = match &request.identity_id {
        Some(raw) => {
            Some(Uuid::from_str(raw).map_err(|_| format!("Invalid identity_id: {}", raw))?)
        }
        None => None,
    };
    let action = match &request.action {
        Some(raw) => Some(
            persona_core::AuditAction::from_str(raw)
                .map_err(|_| format!("Unknown audit action: {}", raw))?,
        ),
        None => None,
    };
    let time_range = match &request.time_range {
        Some((start, end)) => {
            let start = chrono::DateTime::parse_from_rfc3339(start)
                .map_err(|e| format!("Invalid time_range start: {}", e))?
                .with_timezone(&chrono::Utc);
            let end = chrono::DateTime::parse_from_rfc3339(end)
                .map_err(|e| format!("Invalid time_range end: {}", e))?
                .with_timezone(&chrono::Utc);
            Some((start, end))
        }
        None => None,
    };

    Ok(persona_core::AuditLogQuery {
        user_id: request.user_id.clone(),
        identity_id,
        action,
        failures_only: request.failures_only.unwrap_or(false),
        security_sensitive_only: request.security_sensitive_only.unwrap_or(false),
        time_range,
        limit: request.limit,
    })
}
