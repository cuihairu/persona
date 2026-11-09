use super::*;

/// 只读 passkey 开关：vault 打不开/行不存在一律视为关（审批链路另有
/// 解锁门禁兜底，静默跳过安全）。
pub(crate) async fn passkeys_flag_enabled(db_path: &str) -> bool {
    let Ok(db) = Database::from_file(db_path).await else {
        return false;
    };
    if db.migrate().await.is_err() {
        return false;
    }
    let workspace_path = workspace_path_for_db_path(db_path);
    let repo = WorkspaceRepository::new(db);
    match repo.find_by_path(&workspace_path).await {
        Ok(Some(ws)) => ws.settings.features.passkeys,
        _ => false,
    }
}

/// 按 workspace 开关门禁启动 passkey 审批服务端（init_service 成功尾部调用）。
///
/// 不放 setup：setup 时 db_path 尚未写入，猜默认路径会读错 vault。只读
/// `find_by_path` 不开 workspace 行；开关关闭/读取失败 → 不 spawn。设置页
/// 打开开关后，下一次 lock→unlock（重新 init_service）即生效，无需重启。
/// `passkey_server_started` 保证多次 init_service 只 spawn 一次；关停通道
/// 存入 AppState 供 [`stop_passkey_server`] 使用。
pub(crate) async fn maybe_start_passkey_server<R: tauri::Runtime>(
    db_path: &str,
    state: &State<'_, AppState>,
    app: &tauri::AppHandle<R>,
) {
    use std::sync::atomic::Ordering;

    if state.passkey_server_started.load(Ordering::SeqCst) {
        return;
    }
    if !passkeys_flag_enabled(db_path).await {
        return;
    }

    let (pending, service) = (state.passkey_approvals.clone(), state.service.clone());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    *state.passkey_server_shutdown.lock().await = Some(shutdown_tx);
    let handle = app.clone();
    state.passkey_server_started.store(true, Ordering::SeqCst);
    tauri::async_runtime::spawn(async move {
        if let Err(err) = crate::passkey_bridge::run_passkey_approval_server(
            handle,
            pending,
            service,
            shutdown_rx,
        )
        .await
        {
            eprintln!("passkey approval server exited: {err}");
        }
    });
}

/// 关停 passkey 审批服务端（工作区关掉 passkeys 开关时调用）。
///
/// 发送信号后服务端自行退出并清 socket 文件与未应答审批；本函数同步做
/// 的是复位 `passkey_server_started`（下次开开关可重启）并兜底丢弃残留
/// 审批（服务端退出前的窗口期内新进的请求）。
pub(crate) async fn stop_passkey_server(state: &State<'_, AppState>) {
    use std::sync::atomic::Ordering;

    if let Some(tx) = state.passkey_server_shutdown.lock().await.take() {
        let _ = tx.send(());
    }
    state.passkey_server_started.store(false, Ordering::SeqCst);
    if let Ok(mut map) = state.passkey_approvals.lock() {
        map.clear();
    }
}

/// List passkeys for an identity
#[command(rename_all = "snake_case")]
pub async fn passkey_list(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializablePasskey>>, String> {
    let uuid = match Uuid::from_str(&identity_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.list_passkeys(&uuid).await {
            Ok(items) => Ok(ApiResponse::success(
                items.into_iter().map(SerializablePasskey::from).collect(),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to list passkeys: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// List passkeys by relying-party ID
#[command(rename_all = "snake_case")]
pub async fn passkey_list_by_rp(
    rp_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializablePasskey>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.list_passkeys_by_rp(&rp_id).await {
            Ok(items) => Ok(ApiResponse::success(
                items.into_iter().map(SerializablePasskey::from).collect(),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to list passkeys: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get a single passkey by ID
#[command]
pub async fn passkey_get(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<SerializablePasskey>>, String> {
    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_passkey(&uuid).await {
            Ok(item) => Ok(ApiResponse::success(item.map(SerializablePasskey::from))),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to get passkey: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete a passkey
#[command]
pub async fn passkey_delete(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.delete_passkey(&uuid).await {
            Ok(deleted) => Ok(ApiResponse::success(deleted)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to delete passkey: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Create a passkey (software authenticator registration ceremony)
#[command]
pub async fn passkey_create(
    request: CreatePasskeyRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<PasskeyCreationResponse>, String> {
    use base64::Engine;

    let identity_id = match Uuid::from_str(&request.identity_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid identity_id".to_string())),
    };

    let engine = base64::engine::general_purpose::STANDARD;
    let client_data_json = match engine.decode(&request.client_data_json_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Invalid client_data_json_b64: {}",
                e
            )))
        }
    };
    let user_handle = match &request.user_handle_b64 {
        Some(raw) => match engine.decode(raw) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Invalid user_handle_b64: {}",
                    e
                )))
            }
        },
        None => None,
    };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match service
                .create_passkey_full(
                    identity_id,
                    request.rp_id.clone(),
                    &request.origin,
                    &client_data_json,
                    user_handle,
                    request.user_name.clone(),
                    request.user_display_name.clone(),
                    request.user_verification,
                )
                .await
            {
                Ok(creation) => Ok(ApiResponse::success(PasskeyCreationResponse {
                    passkey: SerializablePasskey::from(creation.item),
                    attestation_object_b64: engine.encode(creation.attestation_object),
                })),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to create passkey: {}",
                            msg
                        ))),
                    }
                }
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Run a passkey self-test (sign + verify round-trip; sensitive, re-auth gated)
#[command]
pub async fn passkey_self_test(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.passkey_self_test(&uuid).await {
            Ok(()) => Ok(ApiResponse::success(true)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Passkey self-test failed: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Export a passkey private key (base64; sensitive, re-auth gated + audited)
#[command]
pub async fn passkey_export_private_key(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
    use base64::Engine;

    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.export_passkey_private_key(&uuid).await {
            Ok(bytes) => Ok(ApiResponse::success(
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to export passkey private key: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}
