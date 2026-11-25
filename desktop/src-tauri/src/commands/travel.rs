use super::*;

/// Travel mode status (no gate: visible from the lock screen too, helping the
/// user understand the vault's situation).
/// `inconsistent = active && !sidecar_exists` is determined by core; the
/// frontend shows a red warning.
#[command]
pub async fn get_travel_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TravelStatus>, String> {
    // Consistent with the command-layer error pattern: a missing db_path yields
    // Ok(ApiResponse::error) and never lets Err(String) escape the command
    // boundary (the frontend branches uniformly on the success field)
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

/// Narrow-write the identity's travel marked flag (when travel mode is entered,
/// marked identities are removed from this device's identity list).
/// Same gate as set_feature_flags (unlocked is enough; core audits on top).
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

/// Enter travel mode: marked identities are packaged, encrypted into the
/// sidecar, and removed from the main vault.
///
/// The command layer sets no unlock gate — core's
/// `ensure_sensitive_operation_allowed` is the authority (no re-auth ->
/// REAUTH_REQUIRED code; the frontend shows the ReauthModal then retries).
#[command]
pub async fn enter_travel_mode(
    passphrase: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TravelCounts>, String> {
    // Consistent with the command-layer error pattern: a missing db_path yields
    // Ok(ApiResponse::error) and never lets Err(String) escape the command
    // boundary (the frontend branches uniformly on the success field)
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
            // The agent's memory may still hold keys of the removed identities:
            // stop the agent when travel mode is entered (the user restarts it
            // from the SSH panel after exit, matching set_feature_flags semantics)
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

/// Exit travel mode: enter the travel passphrase to restore the removed
/// identities back into the main vault unchanged.
#[command]
pub async fn exit_travel_mode(
    passphrase: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TravelCounts>, String> {
    // Consistent with the command-layer error pattern: a missing db_path yields
    // Ok(ApiResponse::error) and never lets Err(String) escape the command
    // boundary (the frontend branches uniformly on the success field)
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
