use super::*;

/// Configure auto-lock settings (requires unlocked service)
#[command]
pub async fn configure_auto_lock(
    request: AutoLockConfigRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => {
            let config = persona_core::auth::AutoLockConfig {
                inactivity_timeout_secs: request.inactivity_timeout_secs,
                absolute_timeout_secs: request.absolute_timeout_secs.unwrap_or(0),
                require_reauth_sensitive: request.require_reauth_sensitive.unwrap_or(false),
                sensitive_operation_timeout_secs: request
                    .sensitive_operation_timeout_secs
                    .unwrap_or(300),
            };
            match service.configure_auto_lock(config).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to configure auto-lock: {}",
                            msg
                        ))),
                    }
                }
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get auto-lock status
#[command]
pub async fn get_auto_lock_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AutoLockStatusResponse>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => Ok(ApiResponse::success(AutoLockStatusResponse {
            is_unlocked: service.is_unlocked(),
            session_locked: service.is_session_locked().await,
            needs_reauth: service.needs_reauth().await,
            inactivity_timeout_secs: service.inactivity_timeout_secs(),
        })),
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Report user activity to postpone auto-lock
#[command]
pub async fn touch_activity(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            service.touch_activity();
            Ok(ApiResponse::success(true))
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Start background auto-lock monitoring
#[command]
pub async fn start_auto_lock_monitoring(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.start_auto_lock_monitoring().await {
            Ok(()) => Ok(ApiResponse::success(true)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to start auto-lock monitoring: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Stop background auto-lock monitoring
#[command]
pub async fn stop_auto_lock_monitoring(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            service.stop_auto_lock_monitoring().await;
            Ok(ApiResponse::success(true))
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}
