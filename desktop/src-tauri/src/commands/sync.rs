use super::*;

/// 读当前 vault 的同步服务器配置段（vault 打不开/行不存在一律 None——
/// attach 是尽力而为的旁路，不能阻塞解锁主链路）。
///
/// 顺带做 legacy 一次性迁移：keyring 批次前 DB 里存的是明文 token，
/// 读到非空值时搬进 keyring、DB 窄写为空串。keyring 写失败则保留
/// 明文不销毁数据（下次 attach 重试迁移），上报因读不到 keyring 自然
/// fail-closed。
pub(crate) async fn read_sync_config(
    state: &State<'_, AppState>,
    db_path: &str,
) -> Option<persona_core::SyncConfig> {
    let db = Database::from_file(db_path).await.ok()?;
    db.migrate().await.ok()?;
    let workspace_path = workspace_path_for_db_path(db_path);
    let mut ws = ensure_workspace_for_path(&db, &workspace_path).await.ok()?;
    let mut sync = ws.settings.sync.clone()?;

    if !sync.server_token.is_empty() {
        match state.token_store.set(db_path, &sync.server_token) {
            Ok(()) => {
                sync.server_token = String::new();
                ws.settings.sync = Some(sync.clone());
                ws.touch();
                let repo = WorkspaceRepository::new(db);
                if let Err(e) = repo.update(&ws).await {
                    tracing::warn!(error = %e, "failed to clear legacy sync token from vault settings; will retry next attach");
                }
            }
            Err(error) => {
                tracing::warn!(%error, "OS keyring unavailable; legacy sync token stays in vault settings and event reporting stays disabled");
            }
        }
    }
    Some(sync)
}

/// 按当前 vault settings 的 sync 段构造/替换 AppState 槽位中的上报器，
/// 并把它注入（或从）当前 service 摘除。未启用/配置不完整时一律摘除
/// （`set_event_emitter(None)`），与 CLI 宿主的 env 决策语义一致。
///
/// token 真值从 OS keyring 读（vault JSON 恒空串）：读不到/为空/出错
/// 一律不启用（fail-closed）——enabled、url 非空、keyring 有 token 三者
/// 齐备才挂。
///
/// 锁顺序固定 sync_emitter → service；旧 emitter 在槽位替换后、锁外
/// stop（flush 可能走网络，不持有锁等待）。
pub(crate) async fn attach_sync_emitter(state: &State<'_, AppState>) {
    let db_path = {
        let guard = state.db_path.lock().await;
        guard.clone()
    };
    let sync_config = match db_path.as_deref() {
        Some(path) => read_sync_config(state, path).await,
        None => None,
    };
    let new_emitter = match db_path.as_deref() {
        Some(path) => match sync_config {
            Some(config) if config.enabled && !config.server_url.trim().is_empty() => {
                let token = match state.token_store.get(path) {
                    Ok(Some(token)) if !token.is_empty() => Some(token),
                    Ok(_) => {
                        tracing::warn!(
                            "sync token not found in OS keyring; event reporting disabled"
                        );
                        None
                    }
                    Err(error) => {
                        tracing::warn!(%error, "OS keyring read failed; event reporting disabled");
                        None
                    }
                };
                match token {
                    Some(token) => {
                        match persona_core::ServerEventSink::new(&config.server_url, token) {
                            Ok(sink) => {
                                let emitter =
                                    persona_core::events::Emitter::new(std::sync::Arc::new(sink));
                                emitter.start();
                                Some(emitter)
                            }
                            Err(error) => {
                                tracing::warn!(%error, "invalid sync server_url; event reporting disabled");
                                None
                            }
                        }
                    }
                    None => None,
                }
            }
            _ => None,
        },
        None => None,
    };

    let old = {
        let mut slot = state.sync_emitter.lock().await;
        let old = slot.take();
        *slot = new_emitter.clone();
        old
    };
    if let Some(old) = old {
        old.stop().await;
    }

    let mut guard = state.service.lock().await;
    if let Some(service) = guard.as_mut() {
        service.set_event_emitter(new_emitter);
    }
}

/// 窄写同步服务器配置（`settings.sync` 段），返回更新后的全量 settings
/// 作为服务端真相。要求已解锁（照 `set_feature_flags` 门禁）；保存成功
/// 后立即重挂上报器（停旧换新），无需重新解锁。
///
/// token 真值存 OS keyring（经 `AppState.token_store`），vault JSON 的
/// `server_token` 恒写空串：`server_token` 传空串 = **保留 keyring 里的
/// 既有令牌**（避免把令牌常驻前端内存）；非空 = 覆盖写入 keyring，
/// keyring 不可用时拒绝保存（fail-closed，绝不落明文）。`enabled=false`
/// 时尽力清除 keyring 令牌（失败仅 warn，不阻塞关闭）。`enabled` 且
/// `server_url` 空白时报错。
#[command(rename_all = "snake_case")]
pub async fn set_sync_config(
    enabled: bool,
    server_url: String,
    server_token: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WorkspaceSettings>, String> {
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

    let server_url = server_url.trim().to_string();
    if enabled && server_url.is_empty() {
        return Ok(ApiResponse::error(
            "Server URL is required when sync is enabled".to_string(),
        ));
    }

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);

    // token 编排先于 DB 写：keyring 失败直接拒绝保存，不留半套配置
    let trimmed_token = server_token.trim();
    if enabled {
        if !trimmed_token.is_empty() {
            if let Err(error) = state.token_store.set(&db_path, trimmed_token) {
                return Ok(ApiResponse::error(format!(
                    "Cannot store sync token in OS keyring: {}",
                    error
                )));
            }
        } else if let Some(old) = ws.settings.sync.as_ref() {
            // 空串 = 保留旧值。legacy vault 的 DB 里可能还有 keyring 批次
            // 之前的明文 token——先搬进 keyring 再清 DB，否则真值会丢
            if !old.server_token.is_empty() {
                if let Err(error) = state.token_store.set(&db_path, &old.server_token) {
                    return Ok(ApiResponse::error(format!(
                        "Cannot store sync token in OS keyring: {}",
                        error
                    )));
                }
            }
        }
    } else if let Err(error) = state.token_store.delete(&db_path) {
        tracing::warn!(%error, "failed to remove sync token from OS keyring; it stays available for a later re-enable");
    }

    // vault JSON 恒存空串占位——真值只在 OS keyring
    ws.settings.sync = Some(persona_core::SyncConfig {
        enabled,
        server_url,
        server_token: String::new(),
    });
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);
    let settings = updated.settings;

    attach_sync_emitter(&state).await;
    Ok(ApiResponse::success(settings))
}

/// 只读：OS keyring 里是否存有 sync token（免解锁——设置页用它决定
/// placeholder 提示）。只泄露"是否配置过"这一位元数据（与
/// `get_workspace_settings` 暴露 `sync.enabled` 同级）；真值永不离开
/// keyring、不经 IPC。
#[command]
pub async fn sync_token_present(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
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
    let present = match state.token_store.get(&db_path) {
        Ok(Some(token)) => !token.is_empty(),
        Ok(None) => false,
        Err(error) => return Ok(ApiResponse::error(error)),
    };
    Ok(ApiResponse::success(present))
}

/// 本机设备身份（keyring → DeviceIdentity）的三态。
pub(crate) enum LocalDevice {
    NotJoined,
    /// 记录存在但解析失败——不猜、不带病运行，UI 引导重新 join。
    Corrupted,
    Joined(persona_core::sync::device::DeviceIdentity),
}

pub(crate) async fn require_db_path(state: &State<'_, AppState>) -> Option<String> {
    let guard = state.db_path.lock().await;
    guard.clone()
}

/// 门禁：已解锁。`None` = 通过；`Some(消息)` = 未初始化/已锁定（调用方
/// 转 `ApiResponse::error`——各 sync 命令的 data 类型不同，在此收口消息）。
pub(crate) async fn require_unlocked(state: &State<'_, AppState>) -> Option<String> {
    let guard = state.service.lock().await;
    match guard.as_ref() {
        None => Some("Service not initialized".to_string()),
        Some(service) if service.is_unlocked() => None,
        Some(_) => Some("Service is locked".to_string()),
    }
}

pub(crate) async fn local_device(state: &State<'_, AppState>, db_path: &str) -> LocalDevice {
    match state.device_store.get(db_path) {
        Ok(Some(raw)) => match persona_core::sync::device::DeviceIdentity::from_stored_json(&raw) {
            Ok(identity) => LocalDevice::Joined(identity),
            Err(_) => LocalDevice::Corrupted,
        },
        Ok(None) => LocalDevice::NotJoined,
        Err(_) => LocalDevice::NotJoined, // keyring 读失败视同未加入（join 会再报具体错误）
    }
}

/// settings.sync.server_url + keyring sync token（sync_now 与管理命令
/// 共用的环境取用；任一缺失/环境失败返回用户可读消息）。
pub(crate) async fn sync_server_creds_for(
    state: &State<'_, AppState>,
) -> std::result::Result<(String, String), String> {
    let db_path = require_db_path(state)
        .await
        .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?;
    // fresh vault 的 sync 段是 None——与 URL 空白同义：未配置服务器
    let sync_config = match read_sync_config(state, &db_path).await {
        Some(config) => config,
        None => return Err("Sync server URL is not configured".to_string()),
    };
    let server_url = sync_config.server_url.trim().to_string();
    if server_url.is_empty() {
        return Err("Sync server URL is not configured".to_string());
    }
    let token = state
        .token_store
        .get(&db_path)
        .map_err(|e| format!("OS keyring read failed: {e}"))?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| "Sync server token is not configured".to_string())?;
    Ok((server_url, token))
}

/// settings.sync.server_url + keyring sync token 齐备时构造管理客户端。
pub(crate) async fn sync_admin_api_for(
    state: &State<'_, AppState>,
) -> std::result::Result<persona_core::sync::remote::SyncAdminApi, String> {
    let (server_url, token) = sync_server_creds_for(state).await?;
    persona_core::sync::remote::SyncAdminApi::new(&server_url, &token)
        .map_err(|e| format!("Invalid sync server configuration: {e}"))
}

/// 只读：本 vault 是否已加入 E2EE 同步（纯本地 keyring，免解锁）。
/// `corrupted = true` 表示有条目但解析失败——引导用户重新 join。
#[command]
pub async fn sync_device_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncDeviceStatus>, String> {
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let status = match local_device(&state, &db_path).await {
        LocalDevice::NotJoined => SyncDeviceStatus {
            joined: false,
            corrupted: false,
            device_id: None,
            device_name: None,
        },
        LocalDevice::Corrupted => SyncDeviceStatus {
            joined: false,
            corrupted: true,
            device_id: None,
            device_name: None,
        },
        LocalDevice::Joined(identity) => SyncDeviceStatus {
            joined: true,
            corrupted: false,
            device_id: Some(identity.device_id.to_string()),
            device_name: Some(identity.device_name),
        },
    };
    Ok(ApiResponse::success(status))
}

/// 加入 E2EE 同步：生成本机设备密钥对 → 向服务器登记 → keyring 落身份。
/// keyring 写失败时尽力吊销刚登记的服务器记录（不留半态，fail-closed）。
/// 门禁：已解锁；device_name 1..=128 字节（服务器限制）。
#[command]
pub async fn sync_join(
    device_name: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncJoinOutcome>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let device_name = device_name.trim().to_string();
    if device_name.is_empty() || device_name.len() > 128 {
        return Ok(ApiResponse::error(
            "Device name must be 1..=128 bytes".to_string(),
        ));
    }
    match local_device(&state, &db_path).await {
        LocalDevice::Joined(_) | LocalDevice::Corrupted => {
            return Ok(ApiResponse::error(
                "This vault already joined sync; leave first".to_string(),
            ))
        }
        LocalDevice::NotJoined => {}
    }
    let api = match sync_admin_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let identity = match persona_core::sync::device::DeviceIdentity::generate(&device_name) {
        Ok(identity) => identity,
        Err(e) => return Ok(ApiResponse::error(format!("Key generation failed: {e}"))),
    };
    let device_id = match api
        .register_device(&device_name, identity.key_pair.public_bytes())
        .await
    {
        Ok(device_id) => device_id,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Server rejected device registration: {e}"
            )))
        }
    };
    let identity = identity.with_device_id(device_id);
    if let Err(e) = state.device_store.set(&db_path, &identity.to_stored_json()) {
        tracing::warn!(%e, "keyring write failed after registration; revoking the just-registered device");
        if let Err(revoke_error) = api.delete_device(device_id).await {
            tracing::error!(
                %revoke_error,
                device_id = %device_id,
                "rollback revoke failed; a stray device record remains on the server"
            );
        }
        return Ok(ApiResponse::error(format!(
            "Cannot store device identity in OS keyring: {e}"
        )));
    }
    // pending = group-keys 尚无本机信封；查询失败按「等授权」保守处理
    // （fail-closed：授权状态宁可显示未授权）。空组时本机自举：全新服务器
    // 上没有既有设备可代为授权，首台设备生成 group key 自封信封上传——
    // 否则第一台设备永远停在待授权（无人能授权它）。
    let pending = match api
        .bootstrap_group_if_empty(device_id, identity.key_pair.public_bytes())
        .await
    {
        Ok(bootstrapped) => !bootstrapped,
        Err(_) => true,
    };
    Ok(ApiResponse::success(SyncJoinOutcome {
        device_id: device_id.to_string(),
        device_name,
        pending,
    }))
}

/// 离开同步：尽力吊销服务器侧记录（不可达/未配置仅 warn——本地清理优先，
/// 残留可由其他设备 revoke），然后无条件清 keyring 身份。私钥随条目删除
/// 不可恢复；已同步进本库的数据仍可用（主库密文归主密码体系）。
#[command]
pub async fn sync_leave(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    match local_device(&state, &db_path).await {
        LocalDevice::NotJoined => {
            return Ok(ApiResponse::error(
                "This vault has not joined sync".to_string(),
            ))
        }
        LocalDevice::Joined(identity) => {
            if let Ok(api) = sync_admin_api_for(&state).await {
                if let Err(e) = api.delete_device(identity.device_id).await {
                    // 服务器吊销失败不阻塞离开：本地清理优先，残留记录
                    // 由其他设备 revoke（或管理员清理）
                    tracing::warn!(%e, device_id = %identity.device_id, "server-side device revoke failed during leave; the record may remain");
                }
            } else {
                tracing::warn!(
                    "sync admin client unavailable during leave; skipping server-side revoke"
                );
            }
        }
        LocalDevice::Corrupted => {
            tracing::warn!(
                "corrupted device record during leave; clearing keyring without server-side revoke"
            );
        }
    }
    if let Err(e) = state.device_store.delete(&db_path) {
        return Ok(ApiResponse::error(format!(
            "Cannot remove device identity from OS keyring: {e}"
        )));
    }
    Ok(ApiResponse::success(true))
}

/// 列出同步组全部设备（含授权状态与本机标记）。要求已加入、已解锁。
#[command]
pub async fn sync_list_devices(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SyncDeviceView>>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let identity = match local_device(&state, &db_path).await {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            return Ok(ApiResponse::error(
                "This vault has not joined sync".to_string(),
            ))
        }
    };
    let api = match sync_admin_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let devices = match api.list_devices().await {
        Ok(devices) => devices,
        Err(e) => return Ok(ApiResponse::error(format!("Failed to list devices: {e}"))),
    };
    let keys = match api.group_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Failed to list group keys: {e}"
            )))
        }
    };
    let views = devices
        .into_iter()
        .map(|device| SyncDeviceView {
            id: device.id.to_string(),
            device_name: device.device_name,
            created_at: device.created_at,
            remark: device.remark,
            authorized: keys.iter().any(|k| k.device_id == device.id),
            this_device: device.id == identity.device_id,
        })
        .collect();
    Ok(ApiResponse::success(views))
}

/// 设置本设备的自由备注（S4）：服务端按令牌归属锁定设备行，无跨设备
/// 路径——写谁的名字由令牌决定。空串/纯空白 = 清除。返回服务端规整
/// （trim）后的备注。
#[command]
pub async fn sync_set_device_remark(
    remark: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    match local_device(&state, &db_path).await {
        LocalDevice::Joined(_) => {}
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            return Ok(ApiResponse::error(
                "This vault has not joined sync".to_string(),
            ))
        }
    }
    let api = match sync_admin_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.set_device_remark(&remark).await {
        Ok(stored) => Ok(ApiResponse::success(stored)),
        Err(e) => Ok(ApiResponse::error(format!(
            "Failed to set device remark: {e}"
        ))),
    }
}

/// 为目标设备授权：拆本机信封得 group key → 用目标公钥封新信封上传。
/// 本机未授权（信封拆不开）fail-closed——未授权设备无法授权他人；
/// 目标必须是已登记的其他设备。
#[command]
pub async fn sync_authorize(
    target_device_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let identity = match local_device(&state, &db_path).await {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            return Ok(ApiResponse::error(
                "This vault has not joined sync".to_string(),
            ))
        }
    };
    let target_id = match uuid::Uuid::parse_str(target_device_id.trim()) {
        Ok(target_id) => target_id,
        Err(_) => return Ok(ApiResponse::error("Malformed target device id".to_string())),
    };
    if target_id == identity.device_id {
        return Ok(ApiResponse::error(
            "This device is already authorized; use leave to remove it".to_string(),
        ));
    }
    let api = match sync_admin_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let keys = match api.group_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Failed to fetch group keys: {e}"
            )))
        }
    };
    // 本机信封拆不开 = 本机未授权（fail-closed），无法授权他人
    let group_key_bytes = match keys.iter().find(|k| k.device_id == identity.device_id) {
        Some(own) => {
            match persona_core::sync::envelope::open_group_key(
                &own.envelope,
                identity.key_pair.secret_bytes(),
            ) {
                Ok(group_key) => group_key,
                Err(_) => {
                    return Ok(ApiResponse::error(
                        "This device is not authorized yet; it cannot authorize others".to_string(),
                    ))
                }
            }
        }
        None => {
            return Ok(ApiResponse::error(
                "This device is not authorized yet; it cannot authorize others".to_string(),
            ))
        }
    };
    let target = match api.list_devices().await {
        Ok(devices) => match devices.into_iter().find(|d| d.id == target_id) {
            Some(device) => device,
            None => {
                return Ok(ApiResponse::error(
                    "Target device not found on the server".to_string(),
                ))
            }
        },
        Err(e) => return Ok(ApiResponse::error(format!("Failed to list devices: {e}"))),
    };
    let envelope =
        match persona_core::sync::envelope::seal_group_key(&group_key_bytes, &target.public_key) {
            Ok(envelope) => envelope,
            Err(e) => return Ok(ApiResponse::error(format!("Failed to seal group key: {e}"))),
        };
    match api.put_group_key(target_id, &envelope).await {
        Ok(()) => Ok(ApiResponse::success(true)),
        Err(e) => Ok(ApiResponse::error(format!(
            "Failed to upload group key: {e}"
        ))),
    }
}

/// 吊销设备（服务器侧删登记+信封，幂等）。吊销自己请走 sync_leave。
/// 已知的 group key 不可追溯撤销（DR-3 诚实边界）——提示文案归前端。
#[command]
pub async fn sync_revoke(
    target_device_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let identity = match local_device(&state, &db_path).await {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            return Ok(ApiResponse::error(
                "This vault has not joined sync".to_string(),
            ))
        }
    };
    let target_id = match uuid::Uuid::parse_str(target_device_id.trim()) {
        Ok(target_id) => target_id,
        Err(_) => return Ok(ApiResponse::error("Malformed target device id".to_string())),
    };
    if target_id == identity.device_id {
        return Ok(ApiResponse::error(
            "Use leave to remove this device from sync".to_string(),
        ));
    }
    let api = match sync_admin_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.delete_device(target_id).await {
        Ok(()) => Ok(ApiResponse::success(true)),
        Err(e) => Ok(ApiResponse::error(format!("Failed to revoke device: {e}"))),
    }
}

/// sync 命令族共用的门禁 + 会话装配（sync_now / sync_conflicts_list /
/// sync_conflict_resolve 同序，阶段 3c 起抽公共 helper）：解锁检查 →
/// db_path → 本机设备身份 → 服务器凭据 → 打开数据库并 migrate → travel
/// 闸采样 → 拆本机信封装配会话。任一步失败返回 `Err(用户可读消息)`，
/// 命令体在边界转 `Ok(ApiResponse::error(...))`（不逃逸）。
///
/// master 密钥不在此取——它是挂 service guard 的借用，须留在命令体内
/// 与后续 service 调用同锁段；这里只在 travel 采样时短暂持锁（采样值
/// Copy，与会话生命周期无关）。
pub(crate) async fn open_sync_session(
    state: &State<'_, AppState>,
) -> std::result::Result<
    persona_core::sync::runtime::SyncSession<persona_core::sync::remote::HttpSyncRemote>,
    String,
> {
    if let Some(message) = require_unlocked(state).await {
        return Err(message);
    }
    let db_path = require_db_path(state)
        .await
        .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?;
    let identity = match local_device(state, &db_path).await {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::Corrupted => {
            return Err("Stored device identity is corrupted; leave and re-join sync".to_string())
        }
        LocalDevice::NotJoined => return Err("This vault has not joined sync".to_string()),
    };
    let (server_url, token) = sync_server_creds_for(state).await?;

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {e}"))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {e}"))?;

    let service_guard = state.service.lock().await;
    let service = service_guard
        .as_ref()
        .ok_or_else(|| "Service not initialized".to_string())?;
    // travel 闸在装配前采样一次：cycle 是短过程，中途不变；travel 激活
    // 期间 pull/push 由引擎拒绝（与捕获缝「不设闸」互补，见 engine 模块）
    let travel_active = service
        .travel_mode_active()
        .await
        .map_err(|e| format!("Travel mode check failed: {e}"))?;
    drop(service_guard);

    persona_core::sync::runtime::SyncSession::open(
        &db,
        &identity,
        &server_url,
        &token,
        Box::new(move || travel_active),
    )
    .await
    .map_err(|e| format!("Sync session failed: {e}"))
}

/// 立即同步（E2EE sync 阶段 3b 的宿主入口）：拆本机信封装配会话 →
/// 存量灌入 → pull/materialize/push 周期 → 把捕获缝挂上 service（此后
/// 本地写自动入 oplog）。协议/密码学/编排全在 core `SyncSession`；这里
/// 只做宿主编排——门禁走 `open_sync_session`，master 借出与捕获缝挂载
/// 在本命令的锁段内。
#[command]
pub async fn sync_now(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncNowReport>, String> {
    let session = match open_sync_session(&state).await {
        Ok(session) => session,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let service_guard = state.service.lock().await;
    let service = match service_guard.as_ref() {
        Some(service) => service,
        None => return Ok(ApiResponse::error("Service not initialized".to_string())),
    };
    let master = match service.get_master_encryption_service() {
        Ok(master) => master,
        Err(e) => return Ok(ApiResponse::error(e.to_string())),
    };

    let backfilled = match session.backfill_existing(master).await {
        Ok(backfilled) => backfilled,
        Err(e) => return Ok(ApiResponse::error(format!("Sync backfill failed: {e}"))),
    };
    let mut report = match session.run_cycle(master).await {
        Ok(report) => report,
        Err(e) => return Ok(ApiResponse::error(format!("Sync cycle failed: {e}"))),
    };
    report.backfilled = backfilled;

    service
        .attach_sync_capture(Some(
            session.capture() as std::sync::Arc<dyn persona_core::sync::capture::SyncCapture>
        ))
        .await;

    Ok(ApiResponse::success(SyncNowReport::from(report)))
}

/// 同步状态快照（sync-group-mode §二.5.5）：组最新版本号 / 本机已同步水位 /
/// 落后 N 条 / 待推 N 条 / 最近同步时间。只读，不跑任何周期——「立即同步」
/// 仍是 sync_now。门禁与 sync_now 同（需解锁且已入组；head 查询走服务器，
/// 服务器不可达时如实报错，不谎报「已最新」）。
#[command]
pub async fn sync_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncStatusInfo>, String> {
    let session = match open_sync_session(&state).await {
        Ok(session) => session,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match session.status().await {
        Ok(report) => Ok(ApiResponse::success(SyncStatusInfo::from(report))),
        Err(e) => Ok(ApiResponse::error(format!("Sync status failed: {e}"))),
    }
}

/// group key 轮换（E2EE sync 阶段 3d）：换信封 + 全量重包——吊销设备
/// 真正闭环的安全操作。核心流程在 core `SyncSession::rotate_group_key`；
/// 这里只做宿主编排。诚实边界（前端确认弹窗须如实提示，见 core 文档）：
/// 轮换前各保留设备应先「立即同步」；未裁决冲突副本随重包清出裁决视图；
/// 并发轮换以 epoch 乐观锁互斥（2026-09-24）——后到者得
/// CONCURRENT_CONFLICT 错误码，重读状态后可重试。
#[command]
pub async fn sync_rotate(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncRotateReport>, String> {
    let session = match open_sync_session(&state).await {
        Ok(session) => session,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let (server_url, token) = match sync_server_creds_for(&state).await {
        Ok(creds) => creds,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let admin = match persona_core::sync::remote::SyncAdminApi::new(&server_url, &token) {
        Ok(admin) => admin,
        Err(e) => return Ok(ApiResponse::error(format!("Sync admin unavailable: {e}"))),
    };
    let service_guard = state.service.lock().await;
    let master = sync_master_or_return!(service_guard);

    match session.rotate_group_key(master, &admin).await {
        Ok(report) => Ok(ApiResponse::success(SyncRotateReport::from(report))),
        Err(e) => {
            // 并发轮换 409 经 PersonaError::ConcurrentConflict 翻出
            // CONCURRENT_CONFLICT 码（前端可识别分流），其余无专用码
            let (code, msg) = map_persona_error(&e);
            match code {
                Some(code) => Ok(ApiResponse::error_with_code(
                    code,
                    format!("Group key rotation failed: {msg}"),
                )),
                None => Ok(ApiResponse::error(format!(
                    "Group key rotation failed: {msg}"
                ))),
            }
        }
    }
}

/// 冲突裁决列表（E2EE sync 阶段 3c）：全部待裁决条目（主位 + 副本的
/// 解密快照）。只读，不改任何状态；损坏副本的条目整条跳过（留驻
/// oplog，不阻塞其余展示）。
#[command]
pub async fn sync_conflicts_list(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SyncConflictEntry>>, String> {
    let session = match open_sync_session(&state).await {
        Ok(session) => session,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    // 不借 master：list 的解密走 group key（会话装配时拆信封得），只
    // 要求解锁门禁；与 resolve（需 master 重包 item key）不同。

    match session.list_conflicts().await {
        Ok(entries) => Ok(ApiResponse::success(
            entries.into_iter().map(SyncConflictEntry::from).collect(),
        )),
        Err(e) => Ok(ApiResponse::error(format!(
            "Failed to list sync conflicts: {e}"
        ))),
    }
}

/// 冲突裁决（E2EE sync 阶段 3c）：采纳一个副本——先按副本内容写主库
/// （put 复用其 payload 字节 / delete 删行），再以本机新 lamport 重新
/// 入账，其余版本淘汰出裁决视图。重复采纳已裁决的 op_id 返回错误
/// （NotFound，已在视图外）。
#[command]
pub async fn sync_conflict_resolve(
    item_id: String,
    adopt_op_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let item = match uuid::Uuid::parse_str(item_id.trim()) {
        Ok(item) => item,
        Err(_) => return Ok(ApiResponse::error("Malformed item id".to_string())),
    };
    let adopt = match uuid::Uuid::parse_str(adopt_op_id.trim()) {
        Ok(adopt) => adopt,
        Err(_) => return Ok(ApiResponse::error("Malformed conflict op id".to_string())),
    };
    let session = match open_sync_session(&state).await {
        Ok(session) => session,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let service_guard = state.service.lock().await;
    let master = sync_master_or_return!(service_guard);

    match session.resolve_conflict(master, item, adopt).await {
        Ok(()) => Ok(ApiResponse::success(true)),
        Err(e) => Ok(ApiResponse::error(format!(
            "Failed to resolve conflict: {e}"
        ))),
    }
}

/// 组密钥 hex 编解码（32 字节 ↔ 64 字符；keyring 值格式）。
pub(crate) fn group_key_to_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn group_key_from_hex(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// 本 vault 是否已加入同步组（keyring 组密钥条目；读失败 fail-closed
/// 视为未加入——host 出码会生成新组密钥，guest 加入不受影响）。
pub(crate) fn sync_group_joined(state: &State<'_, AppState>, db_path: &str) -> bool {
    state
        .sync_group_store
        .get(db_path)
        .ok()
        .and_then(|v| v)
        .is_some()
}

/// 同步组状态（只读，免解锁——同 sync_device_status 口径）。
#[command]
pub async fn sync_group_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    Ok(ApiResponse::success(sync_group_joined(&state, &db_path)))
}

/// host 出码：新建配对会话与中转信箱，返回动态密码与邀请串。
/// 组密钥：本机已在组 = 复用；首次 = 随机生成（poll 完成时落 keyring）。
#[command]
pub async fn sync_group_pairing_create(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncPairingCreateOutcome>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = db_path_or_return!(state);
    let relay_url = match account_server_for(&state).await {
        Ok(url) => url,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let (host, invite) = match persona_core::sync::pairing::PairingHost::new_invite() {
        Ok(pair) => pair,
        Err(e) => return Ok(ApiResponse::error(format!("{e}"))),
    };
    let group_key = match state.sync_group_store.get(&db_path) {
        Ok(Some(hex)) => match group_key_from_hex(&hex) {
            Some(key) => persona_core::sync::keys::GroupKey::from_bytes(key),
            None => {
                return Ok(ApiResponse::error(
                    "Existing sync-group key entry is corrupted; refuse to start pairing"
                        .to_string(),
                ))
            }
        },
        Ok(None) => match persona_core::sync::keys::GroupKey::generate() {
            Ok(key) => key,
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Group key generation failed: {e}"
                )))
            }
        },
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Cannot read sync-group key from OS keyring: {e}"
            )))
        }
    };
    let relay = match persona_core::sync::pairing::relay::PairingRelayClient::new(&relay_url) {
        Ok(relay) => relay,
        Err(e) => return Ok(ApiResponse::error(format!("{e}"))),
    };
    let (session_id, expires_in_secs) = match relay.create_session(&invite.salt).await {
        Ok(pair) => pair,
        Err(e) => return Ok(ApiResponse::error(format!("{e}"))),
    };
    let code = invite.code.clone();
    let invite_link = persona_core::sync::pairing::PairingInviteLink {
        code: code.clone(),
        relay_url: relay_url.clone(),
        session_id: session_id.clone(),
    }
    .encode();
    state
        .pairing_sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            session_id.clone(),
            PairingSession::Host {
                host,
                group_key,
                relay_url,
            },
        );
    Ok(ApiResponse::success(SyncPairingCreateOutcome {
        code,
        invite_link,
        session_id,
        expires_in_secs,
    }))
}

/// host 等待 guest 加入：阻塞驱动握手直到完成（90s 窗口，期间可取消
/// ——cancel 删中转信箱后本命令即报错返回）。完成时组密钥落 keyring。
#[command]
pub async fn sync_group_pairing_poll(
    session_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncPairingPollOutcome>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = db_path_or_return!(state);
    let taken = state
        .pairing_sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&session_id);
    let (mut host, group_key, relay_url) = match taken {
        Some(PairingSession::Host {
            host,
            group_key,
            relay_url,
        }) => (host, group_key, relay_url),
        Some(session @ PairingSession::Guest { .. }) => {
            state
                .pairing_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(session_id, session);
            return Ok(ApiResponse::error(
                "Session is a guest join, not a pairing host".to_string(),
            ));
        }
        None => {
            return Ok(ApiResponse::error(
                "No active pairing session; create one first".to_string(),
            ))
        }
    };
    let relay = match persona_core::sync::pairing::relay::PairingRelayClient::new(&relay_url) {
        Ok(relay) => relay,
        Err(e) => {
            state
                .pairing_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    session_id,
                    PairingSession::Host {
                        host,
                        group_key,
                        relay_url,
                    },
                );
            return Ok(ApiResponse::error(format!("{e}")));
        }
    };
    match relay
        .drive_host(&mut host, group_key.as_bytes(), &session_id)
        .await
    {
        Ok(fingerprint) => {
            if let Err(e) = state
                .sync_group_store
                .set(&db_path, &group_key_to_hex(group_key.as_bytes()))
            {
                return Ok(ApiResponse::error(format!(
                    "Pairing completed but cannot persist the group key: {e}"
                )));
            }
            Ok(ApiResponse::success(SyncPairingPollOutcome {
                completed: true,
                fingerprint: Some(fingerprint),
            }))
        }
        Err(e) => {
            // 未等到 guest（90s 超时）或中转故障：会话放回可重试（TTL 内）
            state
                .pairing_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    session_id,
                    PairingSession::Host {
                        host,
                        group_key,
                        relay_url,
                    },
                );
            Ok(ApiResponse::error(format!("{e}")))
        }
    }
}

/// 取消配对/加入会话（两角色通用）：移除本地会话并尽力清理中转信箱。
/// 幂等：会话不存在也返回成功（页面残留状态可重复点）。
#[command]
pub async fn sync_group_pairing_cancel(
    session_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let relay_url = state
        .pairing_sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&session_id)
        .map(|session| match session {
            PairingSession::Host { relay_url, .. } | PairingSession::Guest { relay_url, .. } => {
                relay_url
            }
        });
    if let Some(relay_url) = relay_url {
        if let Ok(relay) = persona_core::sync::pairing::relay::PairingRelayClient::new(&relay_url) {
            // 信箱清理尽力而为：中转不可达时本地已清，TTL 到期自然回收
            if let Err(e) = relay.delete_session(&session_id).await {
                tracing::warn!(%e, "pairing relay mailbox cleanup failed; TTL will reclaim it");
            }
        }
    }
    Ok(ApiResponse::success(true))
}

/// guest 输码第一步：解码邀请串、起配并把 client_public 投给 host，
/// 等回 host 应答后返回短指纹（UI 与 host 端比对，一致才 confirm）。
#[command]
pub async fn sync_group_join_begin(
    invite_link: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncJoinBeginOutcome>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = db_path_or_return!(state);
    if sync_group_joined(&state, &db_path) {
        return Ok(ApiResponse::error(
            "This vault already joined a sync group; leave it before joining another".to_string(),
        ));
    }
    let link = match persona_core::sync::pairing::PairingInviteLink::decode(invite_link.trim()) {
        Ok(link) => link,
        Err(e) => return Ok(ApiResponse::error(format!("{e}"))),
    };
    let relay = match persona_core::sync::pairing::relay::PairingRelayClient::new(&link.relay_url) {
        Ok(relay) => relay,
        Err(e) => return Ok(ApiResponse::error(format!("{e}"))),
    };
    let (guest, fingerprint) = match relay.join_begin(&link).await {
        Ok(pair) => pair,
        Err(e) => return Ok(ApiResponse::error(format!("{e}"))),
    };
    state
        .pairing_sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            link.session_id.clone(),
            PairingSession::Guest {
                guest,
                relay_url: link.relay_url.clone(),
            },
        );
    Ok(ApiResponse::success(SyncJoinBeginOutcome {
        fingerprint,
        code: link.code,
        session_id: link.session_id,
    }))
}

/// guest 第二步：指纹比对通过后确认入组——投 M1、收组密钥交接、解出
/// 组密钥落 keyring。失败时本地会话作废（需重新输码起配）。
#[command]
pub async fn sync_group_join_confirm(
    session_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = db_path_or_return!(state);
    if sync_group_joined(&state, &db_path) {
        state
            .pairing_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&session_id);
        return Ok(ApiResponse::error(
            "This vault already joined a sync group".to_string(),
        ));
    }
    let taken = state
        .pairing_sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&session_id);
    let (mut guest, relay_url) = match taken {
        Some(PairingSession::Guest { guest, relay_url }) => (guest, relay_url),
        Some(session @ PairingSession::Host { .. }) => {
            state
                .pairing_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(session_id, session);
            return Ok(ApiResponse::error(
                "Session is a pairing host, not a guest join".to_string(),
            ));
        }
        None => {
            return Ok(ApiResponse::error(
                "No active join session; scan the invite again".to_string(),
            ))
        }
    };
    let relay = match persona_core::sync::pairing::relay::PairingRelayClient::new(&relay_url) {
        Ok(relay) => relay,
        Err(e) => return Ok(ApiResponse::error(format!("{e}"))),
    };
    if let Err(e) = relay.join_confirm(&mut guest, &session_id).await {
        // M1 已投出或交接超时：会话状态不再可靠，作废（重新输码起配）
        return Ok(ApiResponse::error(format!("{e}")));
    }
    let group_key = match guest.group_key() {
        Some(key) => persona_core::sync::keys::GroupKey::from_bytes(*key),
        None => {
            return Ok(ApiResponse::error(
                "Pairing completed without a group key (unexpected)".to_string(),
            ))
        }
    };
    if let Err(e) = state
        .sync_group_store
        .set(&db_path, &group_key_to_hex(group_key.as_bytes()))
    {
        return Ok(ApiResponse::error(format!(
            "Joined the sync group but cannot persist the group key: {e}"
        )));
    }
    Ok(ApiResponse::success(true))
}

/// guest 取消加入（指纹比对不通过/放弃）：本地会话移除 + 中转信箱清理。
/// 即 pairing_cancel 的 guest 侧别名，语义同幂等。
#[command]
pub async fn sync_group_join_cancel(
    session_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    sync_group_pairing_cancel(session_id, state).await
}
