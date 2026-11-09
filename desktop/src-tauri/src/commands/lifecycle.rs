use super::*;

pub(crate) fn workspace_path_for_db_path(db_path: &str) -> String {
    Path::new(db_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_string_lossy()
        .to_string()
}

pub(crate) async fn ensure_workspace_for_path(
    db: &Database,
    workspace_path: &str,
) -> std::result::Result<persona_core::models::Workspace, String> {
    let repo = WorkspaceRepository::new(db.clone());

    if let Some(ws) = repo
        .find_by_path(workspace_path)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(ws);
    }

    let mut all = repo.find_all().await.map_err(|e| e.to_string())?;
    if all.len() == 1 {
        let mut ws = all.remove(0);
        ws.path = PathBuf::from(workspace_path);
        ws.touch();
        let updated = repo.update(&ws).await.map_err(|e| e.to_string())?;
        return Ok(updated);
    }

    let name = PathBuf::from(workspace_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Persona".to_string());

    let ws = persona_core::models::Workspace::new(PathBuf::from(workspace_path), name);
    repo.create(&ws).await.map_err(|e| e.to_string())
}

/// 把 PersonaService 的 auto-lock 事件桥接到前端 + 强制落锁闭环。
///
/// - 任何事件都 `emit("persona://auto-lock", …)` 给前端（倒计时横幅/回解锁屏）
/// - `Locked` 事件时在独立任务里直接 `service.lock()` 清掉内存主密钥——
///   不依赖前端存活（AutoLockManager 只锁 session，不清主密钥）
///
/// 回调只注册一次（`AtomicBool` 防重复，多次 init_service 安全）。
pub(crate) async fn register_auto_lock_bridge<R: tauri::Runtime>(
    state: &State<'_, AppState>,
    app: &tauri::AppHandle<R>,
) {
    use std::sync::atomic::Ordering;

    if state.auto_lock_registered.swap(true, Ordering::SeqCst) {
        return;
    }

    let service_arc = Arc::clone(&state.service);
    let app_handle = app.clone();
    let callback = Arc::new(move |event: persona_core::AutoLockEvent| {
        let is_locked = matches!(&event, persona_core::AutoLockEvent::Locked { .. });
        let payload = SerializableAutoLockEvent::from(event);
        if let Err(e) = app_handle.emit("persona://auto-lock", payload) {
            tracing::warn!("failed to emit auto-lock event: {}", e);
        }

        if is_locked {
            let service_arc = Arc::clone(&service_arc);
            tauri::async_runtime::spawn(async move {
                let mut guard = service_arc.lock().await;
                if let Some(service) = guard.as_mut() {
                    service.lock();
                }
            });
        }
    });

    let service_guard = state.service.lock().await;
    if let Some(service) = service_guard.as_ref() {
        service.register_auto_lock_callback(callback).await;
    }
}

/// 默认 vault 路径（init_service 与 biometric status/unlock 的路径解析
/// 共用——解锁屏上 `state.db_path` 还是 None，必须能独立解析）
pub(crate) fn default_db_path() -> String {
    let app_data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap())
        .join("persona");
    std::fs::create_dir_all(&app_data_dir).ok();
    app_data_dir
        .join("persona.db")
        .to_string_lossy()
        .to_string()
}

/// Initialize the Persona service with master password
#[command]
pub async fn init_service<R: tauri::Runtime>(
    request: InitRequest,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    init_service_inner(request, None, state, app).await
}

/// init 的内部分流：`master_key` 为 Some 时跳过密码验证、直接以已解出
/// 的主密钥建立会话（硬件绑定 biometric 解锁路径——密钥来自包裹层，
/// 包裹层在解密那一刻已经过硬件认证）。IPC 面永不传密钥：该参数只在
/// 进程内由 `biometric_unlock` 构造。
pub(crate) async fn init_service_inner<R: tauri::Runtime>(
    request: InitRequest,
    master_key: Option<[u8; 32]>,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = request.db_path.unwrap_or_else(default_db_path);

    // Store db_path
    {
        let mut db_path_guard = state.db_path.lock().await;
        *db_path_guard = Some(db_path.clone());
    }

    match Database::from_file(&db_path).await {
        Ok(db) => {
            if let Err(e) = db.migrate().await {
                return Ok(ApiResponse::error(format!(
                    "Database migration failed: {}",
                    e
                )));
            }

            let workspace_path = workspace_path_for_db_path(&db_path);
            if let Err(e) = ensure_workspace_for_path(&db, &workspace_path).await {
                return Ok(ApiResponse::error(format!(
                    "Failed to initialize workspace metadata: {}",
                    e
                )));
            }
            let db_for_attachments = db.clone();

            match PersonaService::new(db).await {
                Ok(mut service) => {
                    // 注入 OS 级 biometric provider：PersonaService::new 内置
                    // 的 Mock（恒通过）会让 service.authenticate_biometric
                    // 的任何未来调用方静默放行——一律换成 AppState 持有的
                    // 真实 provider（SSH agent 的 require_biometric 策略
                    // 同一份）
                    service.set_biometric_provider(state.biometric_provider.clone());
                    // 附件 blob 存储跟随库文件（<db dir>/attachments）。
                    // 初始化失败只降级附件功能（相关命令报 not initialized），
                    // 绝不阻断解锁主流程。
                    let attachments_dir = std::path::Path::new(&workspace_path).join("attachments");
                    if let Err(e) = service
                        .init_attachment_storage(&attachments_dir, db_for_attachments.clone())
                        .await
                    {
                        tracing::warn!("attachment storage init failed: {}", e);
                    }
                    // Check if this is first-time setup or existing user.
                    // 红线：查询出错必须 fail-closed——把错误当成"空库"会在
                    // 已有用户的保险库上插第二行 user_auth（新 salt），旧密
                    // 码从此解不开已存凭据。多实例并发/库锁超时正是会走到
                    // 这里的场景。
                    let has_users = match service.has_users().await {
                        Ok(has_users) => has_users,
                        Err(e) => {
                            return Ok(ApiResponse::error(format!(
                                "Failed to check vault state: {}",
                                e
                            )));
                        }
                    };
                    let is_first_time = !has_users;

                    if is_first_time {
                        // 硬件密钥路径对首次建户无意义（还没有用户/密钥可验）
                        if master_key.is_some() {
                            return Ok(ApiResponse::error(
                                "Vault is not initialized; biometric key unlock requires an existing vault"
                                    .to_string(),
                            ));
                        }
                        // First-time setup: initialize user with master password
                        match service.initialize_user(&request.master_password).await {
                            Ok(_user_id) => {
                                // 在语句内完成存入并立即释放 guard：
                                // register_auto_lock_bridge 会再次锁 state.service，
                                // 若 guard 跨越该调用，tokio Mutex 非重入 → 死锁
                                *state.service.lock().await = Some(service);
                                register_auto_lock_bridge(&state, &app).await;
                                maybe_start_passkey_server(&db_path, &state, &app).await;
                                attach_sync_emitter(&state).await;
                                apply_quick_access(&state, &app, &db_path).await;
                                Ok(ApiResponse::success(true))
                            }
                            Err(e) => Ok(ApiResponse::error(format!(
                                "Failed to initialize user: {}",
                                e
                            ))),
                        }
                    } else if let Some(key) = master_key {
                        // Existing user + 已认证主密钥：锁户/强制改密旗标在
                        // core 内与密码路径同序生效；session/审计同建
                        match service
                            .authenticate_with_master_key(&key, "biometric-wrap")
                            .await
                        {
                            Ok(persona_core::AuthResult::Success) => {
                                // 同上：先释放 guard 再注册 auto-lock 桥
                                *state.service.lock().await = Some(service);
                                register_auto_lock_bridge(&state, &app).await;
                                maybe_start_passkey_server(&db_path, &state, &app).await;
                                attach_sync_emitter(&state).await;
                                apply_quick_access(&state, &app, &db_path).await;
                                Ok(ApiResponse::success(true))
                            }
                            Ok(persona_core::AuthResult::InvalidCredentials) => {
                                Ok(ApiResponse::error("Vault has no user record".to_string()))
                            }
                            Ok(persona_core::AuthResult::AccountLocked) => Ok(ApiResponse::error(
                                "Account is locked due to too many failed attempts".to_string(),
                            )),
                            Ok(persona_core::AuthResult::PasswordChangeRequired) => {
                                // 生物解锁同样被强制改密旗标拦下（core 对齐语义）
                                Ok(ApiResponse::error_with_code(
                                    crate::error::CODE_PASSWORD_CHANGE_REQUIRED.to_string(),
                                    "Master password change required".to_string(),
                                ))
                            }
                            Ok(_) => Ok(ApiResponse::error("Authentication failed".to_string())),
                            Err(e) => {
                                Ok(ApiResponse::error(format!("Authentication error: {}", e)))
                            }
                        }
                    } else {
                        // Existing user: authenticate with stored credentials
                        match service.authenticate_user(&request.master_password).await {
                            Ok(auth_result) => match auth_result {
                                persona_core::AuthResult::Success => {
                                    // 同上：先释放 guard 再注册 auto-lock 桥
                                    *state.service.lock().await = Some(service);
                                    register_auto_lock_bridge(&state, &app).await;
                                    maybe_start_passkey_server(&db_path, &state, &app).await;
                                    attach_sync_emitter(&state).await;
                                    apply_quick_access(&state, &app, &db_path).await;
                                    Ok(ApiResponse::success(true))
                                }
                                persona_core::AuthResult::InvalidCredentials => {
                                    Ok(ApiResponse::error("Invalid master password".to_string()))
                                }
                                persona_core::AuthResult::AccountLocked => Ok(ApiResponse::error(
                                    "Account is locked due to too many failed attempts".to_string(),
                                )),
                                persona_core::AuthResult::PasswordChangeRequired => {
                                    // 机器可读错误码：前端凭此引导强制改密流程
                                    Ok(ApiResponse::error_with_code(
                                        crate::error::CODE_PASSWORD_CHANGE_REQUIRED.to_string(),
                                        "Master password change required".to_string(),
                                    ))
                                }
                                _ => Ok(ApiResponse::error("Authentication failed".to_string())),
                            },
                            Err(e) => {
                                Ok(ApiResponse::error(format!("Authentication error: {}", e)))
                            }
                        }
                    }
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to create service: {}",
                    e
                ))),
            }
        }
        Err(e) => Ok(ApiResponse::error(format!(
            "Database connection failed: {}",
            e
        ))),
    }
}

/// Lock the service
#[command]
pub async fn lock_service(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    if let Some(service) = service_guard.as_mut() {
        service.lock();
        // 捕获缝持 group key，不应跨锁存活；下次 sync_now 重新装配
        service.attach_sync_capture(None).await;
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error("Service not initialized".to_string()))
    }
}

/// Check if service is unlocked
#[command]
pub async fn is_service_unlocked(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => Ok(ApiResponse::success(service.is_unlocked())),
        None => Ok(ApiResponse::success(false)),
    }
}

/// Get the active identity ID for this workspace (if any).
#[command]
pub async fn get_active_identity(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<String>>, String> {
    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(p) => p,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    };

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let ws = workspace_or_return!(db, workspace_path);
    Ok(ApiResponse::success(
        ws.active_identity_id.map(|id| id.to_string()),
    ))
}

/// Set the active identity ID for this workspace.
#[command(rename_all = "snake_case")]
pub async fn set_active_identity(
    identity_id: String,
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

    let identity_id = ok_or_error_response!(
        Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())
    );

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.switch_identity(identity_id);
    ok_or_error_response!(repo.update(&ws).await);

    Ok(ApiResponse::success(true))
}

/// Clear the active identity for this workspace.
#[command]
pub async fn clear_active_identity(
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

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.clear_active_identity();
    ok_or_error_response!(repo.update(&ws).await);

    Ok(ApiResponse::success(true))
}

/// Get the full workspace settings（免解锁：解锁屏也要按开关裁剪 UI 外壳）。
#[command]
pub async fn get_workspace_settings(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WorkspaceSettings>, String> {
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

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let ws = workspace_or_return!(db, workspace_path);
    Ok(ApiResponse::success(ws.settings))
}

/// Change the workspace master password（解锁屏强引导与 Settings 手动改密
/// 共用；不触碰 `state.service`——前端随后用新密码重新 init 建会话）
#[command]
pub async fn change_master_password(
    request: crate::types::ChangeMasterPasswordRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = match request.db_path {
        Some(p) => p,
        None => db_path_or_return!(state),
    };

    let db = open_db_or_return!(db_path);

    let mut service = ok_or_error_response_ctx!(
        PersonaService::new(db).await,
        "Failed to create service: {}"
    );
    if !ok_or_error_response!(service.has_users().await) {
        return Ok(ApiResponse::error("Workspace not initialized".to_string()));
    }

    match service
        .change_master_password(&request.old_password, &request.new_password)
        .await
    {
        Ok(()) => {
            // biometric 托管条目联动：条目存在 → 更新为新密码；写失败 →
            // 删除（fail-closed：宁可让用户重新启用，也不留坏条目——
            // 坏条目会在每次 biometric_unlock 时触发 InvalidCredentials
            // 自删 + 白白累计失败计数）。CLI 改密不经此处，那条路由
            // biometric_unlock 的陈旧自愈兜底。
            match state.biometric_store.get(&db_path) {
                Ok(Some(_)) => {
                    if let Err(e) = state.biometric_store.set(&db_path, &request.new_password) {
                        tracing::warn!("biometric keyring update failed: {}", e);
                        let _ = state.biometric_store.delete(&db_path);
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("biometric keyring probe failed: {}", e),
            }
            // 硬件包裹 blob 联动：blob 包的是**旧**主密钥，改密后解出来
            // 的是 stale key（item key 已轮换）——不能"更新"（包裹层只认
            // 硬件 ceremony，不认新密码），只能删除并让用户重新启用。
            // 删失败仅打日志：unlock 侧解出 stale key 走正常 init 链，
            // 密码路径的失败计数/锁户语义不变，不会静默放行。
            match state.biometric_wrap_store.get(&db_path) {
                Ok(Some(_)) => {
                    if let Err(e) = state.biometric_wrap_store.delete(&db_path) {
                        tracing::warn!("biometric wrap blob delete failed: {}", e);
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("biometric wrap probe failed: {}", e),
            }
            Ok(ApiResponse::success(true))
        }
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            match code {
                Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                None => Ok(ApiResponse::error(msg)),
            }
        }
    }
}

/// 窄写高级功能开关：只动 `settings.features` 四个位，返回更新后的全量
/// settings 作为服务端真相（避免前端 clobber 其它设置字段）。
///
/// 后端开关联动（开关即生效，无需 lock→unlock）：
/// - passkeys 关：关停已 spawn 的审批服务端；开：本会话即时拉起
///   （此前要等下次 init_service）
/// - ssh_agent 关：停止已运行的 SSH agent（开：不自动启动——入口显隐
///   归 UI，agent 由用户在面板里 start，对齐 1Password 语义）
#[command(rename_all = "snake_case")]
pub async fn set_feature_flags<R: tauri::Runtime>(
    ssh_agent: bool,
    wallet: bool,
    passkeys: bool,
    fetch_favicons: bool,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
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

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    let prev = ws.settings.features;
    ws.settings.features = FeatureFlags {
        ssh_agent,
        wallet,
        passkeys,
        fetch_favicons,
    };
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);

    if prev.passkeys && !passkeys {
        stop_passkey_server(&state).await;
    } else if !prev.passkeys && passkeys {
        maybe_start_passkey_server(&db_path, &state, &app).await;
    }
    if prev.ssh_agent && !ssh_agent {
        stop_ssh_agent_internal(&state).await;
    }

    Ok(ApiResponse::success(updated.settings))
}

/// 窄写界面语言（"zh-CN" / "en"）。与 `set_feature_flags` 同范式：解锁
/// 门禁 + 窄写单字段 + 返回全量 settings。非法值拒绝（前端只发受支持项）。
#[command]
pub async fn set_locale(
    locale: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WorkspaceSettings>, String> {
    if locale != "zh-CN" && locale != "en" {
        return Ok(ApiResponse::error(format!(
            "Unsupported locale: {}",
            locale
        )));
    }

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

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.settings.locale = Some(locale);
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);
    Ok(ApiResponse::success(updated.settings))
}

/// 托盘右键菜单换文案：前端把 i18n locale 表（tray.* 命名空间）的真值
/// 推过来渲染——原生托盘菜单不归 useTranslation 管，这是它接入既有 i18n
/// 体系的唯一通道。无状态、无锁屏门禁（锁屏时右键菜单也要跟着界面语言）；
/// 无托盘（无显示会话的降级运行）时是无害 no-op。
#[command(rename_all = "snake_case")]
pub fn set_tray_locale<R: tauri::Runtime>(
    labels: crate::TrayLocaleLabels,
    app: tauri::AppHandle<R>,
) -> ApiResponse<bool> {
    if let Some(tray) = app.tray_by_id("persona-tray") {
        if let Err(e) =
            crate::build_tray_menu(&app, &labels).and_then(|menu| tray.set_menu(Some(menu)))
        {
            tracing::warn!("tray locale update failed: {e}");
        }
    }
    ApiResponse::success(true)
}

/// 窄写主密码过期策略（天）；None = 不过期。`Some(0)` 无意义，拒绝。
/// 与 `set_feature_flags` 同范式：解锁门禁 + 窄写单字段 + 返回全量 settings。
#[command]
pub async fn set_password_expiry(
    days: Option<u32>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WorkspaceSettings>, String> {
    if let Some(0) = days {
        return Ok(ApiResponse::error(
            "Password expiry must be at least 1 day".to_string(),
        ));
    }

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

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.settings.password_expiry_days = days;
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);
    Ok(ApiResponse::success(updated.settings))
}

/// 把主窗口拉到前台（浮窗锁定态的"去解锁"出口）
#[command]
pub async fn focus_main_window<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if crate::quick_access::focus_main_window(&app) {
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error("Main window unavailable".to_string()))
    }
}

/// 前端错误上报：production 构建里 ErrorBoundary / handleError 落本地
/// 日志文件（setup 安装的脱敏 subscriber）。各字段截断防日志爆炸；上报
/// 路径永不失败——错误已经发生，上报再报错只会制造二次噪声。
#[command]
pub fn report_frontend_error(
    message: String,
    stack: Option<String>,
    component_stack: Option<String>,
) -> ApiResponse<bool> {
    const MAX_FIELD_BYTES: usize = 8 * 1024;

    fn truncate_field(value: &str, max_bytes: usize) -> String {
        if value.len() <= max_bytes {
            value.to_string()
        } else {
            // 按 char 边界回退，不切断 UTF-8
            let mut end = max_bytes;
            while end > 0 && !value.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…[truncated]", &value[..end])
        }
    }

    tracing::error!(
        target: "frontend",
        message = %truncate_field(&message, MAX_FIELD_BYTES),
        stack = %stack.as_deref().map(|s| truncate_field(s, MAX_FIELD_BYTES)).unwrap_or_default(),
        component_stack = %component_stack.as_deref().map(|s| truncate_field(s, MAX_FIELD_BYTES)).unwrap_or_default(),
        "frontend error reported"
    );
    ApiResponse::success(true)
}
