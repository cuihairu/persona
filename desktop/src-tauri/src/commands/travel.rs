use super::*;

/// 旅行模式状态（无门禁：锁屏也能看，帮助用户理解当前库处境）。
/// `inconsistent = active && !sidecar_exists` 由 core 判定，前端红警告。
#[command]
pub async fn get_travel_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TravelStatus>, String> {
    // 与命令层错误模式一致：缺 db_path 走 Ok(ApiResponse::error)，不让
    // Err(String) 逃出命令边界（前端统一按 success 字段分流）
    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(db_path) => db_path,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.travel_status(Path::new(&db_path)).await {
            Ok(status) => Ok(ApiResponse::success(status)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                Ok(match code {
                    Some(code) => ApiResponse::error_with_code(code, msg),
                    None => ApiResponse::error(msg),
                })
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// 窄写身份的 travel 标记位（进旅行模式时随之移出本设备的身份清单）。
/// 门禁与 set_feature_flags 一致（已解锁即可，core 再做审计）。
#[command]
pub async fn set_travel_marked(
    identity_id: String,
    marked: bool,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let uuid = match Uuid::from_str(&identity_id) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiResponse::error(
                "Invalid identity UUID format".to_string(),
            ))
        }
    };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.set_travel_marked(&uuid, marked).await {
            Ok(()) => Ok(ApiResponse::success(true)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                Ok(match code {
                    Some(code) => ApiResponse::error_with_code(code, msg),
                    None => ApiResponse::error(msg),
                })
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// 进入旅行模式：被标记身份打包加密进 sidecar 并从主库删除。
///
/// 命令层不设解锁门禁——core 的 `ensure_sensitive_operation_allowed` 是
/// 权威（未重新认证 → REAUTH_REQUIRED 码，前端弹 ReauthModal 后重试）。
#[command]
pub async fn enter_travel_mode(
    passphrase: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TravelCounts>, String> {
    // 与命令层错误模式一致：缺 db_path 走 Ok(ApiResponse::error)，不让
    // Err(String) 逃出命令边界（前端统一按 success 字段分流）
    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(db_path) => db_path,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    };
    let result = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => {
                service
                    .enter_travel_mode(Path::new(&db_path), &passphrase)
                    .await
            }
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    match result {
        Ok(counts) => {
            // agent 内存可能仍持有被移除身份的密钥：进入旅行模式即停
            //（exit 后由用户在 SSH 面板重新 start，对齐 set_feature_flags 语义）
            stop_ssh_agent_internal(&state).await;
            Ok(ApiResponse::success(counts))
        }
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            })
        }
    }
}

/// 退出旅行模式：输 travel 口令把被移除身份原样恢复回主库。
#[command]
pub async fn exit_travel_mode(
    passphrase: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TravelCounts>, String> {
    // 与命令层错误模式一致：缺 db_path 走 Ok(ApiResponse::error)，不让
    // Err(String) 逃出命令边界（前端统一按 success 字段分流）
    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(db_path) => db_path,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service
            .exit_travel_mode(Path::new(&db_path), &passphrase)
            .await
        {
            Ok(counts) => Ok(ApiResponse::success(counts)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                Ok(match code {
                    Some(code) => ApiResponse::error_with_code(code, msg),
                    None => ApiResponse::error(msg),
                })
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}
