use crate::error::map_persona_error;
use crate::types::*;
use persona_core::models::wallet::BlockchainNetwork;
use persona_core::models::wallet::CryptoWallet;
use persona_core::models::CredentialType;
use persona_core::storage::{CryptoWalletRepository, Database, WorkspaceRepository};
use persona_core::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tauri::{command, Emitter, State};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

// 命令边界错误纪律（与 get_workspace_settings 早期手写 match 同语义）：
// 基础设施失败不逃出 #[command] 边界，一律 `return Ok(ApiResponse::error(..))`
// ——前端 `catch(e) => String(e)` 只该收到 ApiResponse 的 error/error_code，
// 不该收到 invoke 层的裸 String。宏内 `return` 就地从命令函数返回，不跨边界。
// 内部 helper（如 ensure_workspace_for_path / wallet_db）裸签名
// `Result<T, String>` 不跨边界，合法保留。

/// `state.db_path` 缺失 → Ok(ApiResponse::error)，否则解出 String。
macro_rules! db_path_or_return {
    ($state:expr) => {{
        let guard = $state.db_path.lock().await;
        match guard.clone() {
            Some(p) => p,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    }};
}

/// 打开 vault（from_file + migrate）；连接/迁移失败 → Ok(ApiResponse::error)。
macro_rules! open_db_or_return {
    ($db_path:expr) => {{
        let db = match Database::from_file(&$db_path).await {
            Ok(db) => db,
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Database connection failed: {}",
                    e
                )))
            }
        };
        if let Err(e) = db.migrate().await {
            return Ok(ApiResponse::error(format!(
                "Database migration failed: {}",
                e
            )));
        }
        db
    }};
}

/// ensure_workspace_for_path 失败 → Ok(ApiResponse::error)。
macro_rules! workspace_or_return {
    ($db:expr, $workspace_path:expr) => {
        match ensure_workspace_for_path(&$db, &$workspace_path).await {
            Ok(ws) => ws,
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Failed to access workspace metadata: {}",
                    e
                )))
            }
        }
    };
}

/// Result<T, E: Display> → T；Err → Ok(ApiResponse::error(e.to_string()))。
/// 适合 Err 已是 String（map_err(|_| "...".to_string())、ok_or_else）或
/// 语义就是原始错误文本的调用点。
macro_rules! ok_or_error_response {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(ApiResponse::error(e.to_string())),
        }
    };
}

/// 同 [`ok_or_error_response`]，但用格式串保留语义前缀：
/// `ok_or_error_response_ctx!(repo.find().await, "Failed to load X: {}")`。
macro_rules! ok_or_error_response_ctx {
    ($expr:expr, $fmt:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(ApiResponse::error(format!($fmt, e))),
        }
    };
}

/// wallet_db 的命令边界形态："Service is locked" 映射 SERVICE_LOCKED
/// 码（前端回解锁屏），"Service not initialized" 无码透传。
macro_rules! wallet_db_or_return {
    ($state:expr) => {
        match wallet_db(&$state).await {
            Ok(db) => db,
            Err(msg) => {
                let code = if msg == "Service is locked" {
                    Some(crate::error::CODE_SERVICE_LOCKED.to_string())
                } else {
                    None
                };
                return Ok(ApiResponse::error_maybe_coded(code, msg));
            }
        }
    };
}

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
                    // Check if this is first-time setup or existing user
                    let is_first_time = !service.has_users().await.unwrap_or(false);

                    if is_first_time {
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
                                Ok(ApiResponse::success(true))
                            }
                            Err(e) => Ok(ApiResponse::error(format!(
                                "Failed to initialize user: {}",
                                e
                            ))),
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
#[command]
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

// ---------------------------------------------------------------------------
// 旅行模式（Travel Mode）
// ---------------------------------------------------------------------------

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

/// 窄写高级功能开关：只动 `settings.features` 四个位，返回更新后的全量
/// settings 作为服务端真相（避免前端 clobber 其它设置字段）。
///
/// 后端开关联动（开关即生效，无需 lock→unlock）：
/// - passkeys 关：关停已 spawn 的审批服务端；开：本会话即时拉起
///   （此前要等下次 init_service）
/// - ssh_agent 关：停止已运行的 SSH agent（开：不自动启动——入口显隐
///   归 UI，agent 由用户在面板里 start，对齐 1Password 语义）
#[command]
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

// ---------------------------------------------------------------------------
// Biometric unlock（OS 认证弹框 + OS keychain 托管主密码）
// ---------------------------------------------------------------------------

/// biometric 命令的 vault 路径解析：参数优先（前端勾选自定义库路径时
/// 传入——一个 db_path 一把钥匙），其次本会话 db_path，最后默认路径
/// （解锁屏上 state.db_path 还是 None）。
async fn resolve_biometric_db_path(
    requested: Option<String>,
    state: &State<'_, AppState>,
) -> String {
    if let Some(path) = requested {
        return path;
    }
    if let Some(path) = state.db_path.lock().await.clone() {
        return path;
    }
    default_db_path()
}

/// 在 blocking 线程上跑一次 OS 认证弹框（provider 内部自带 120s 超时，
/// 不泊车 tokio worker）。
async fn run_biometric_ceremony(
    provider: Arc<dyn persona_core::BiometricProvider>,
    reason: &str,
) -> std::result::Result<(), String> {
    let reason = reason.to_string();
    let result = tauri::async_runtime::spawn_blocking(move || {
        provider.authenticate(&persona_core::BiometricPrompt {
            user_id: uuid::Uuid::nil(),
            reason,
            platform: None,
        })
    })
    .await
    .map_err(|e| format!("biometric ceremony task failed: {}", e))?;
    result
        .map(|_| ())
        .map_err(|e| format!("Biometric verification failed: {}", e))
}

/// 只读：biometric unlock 状态（免解锁——解锁屏 mount 即查，决定指纹
/// 按钮显隐）。`enabled` 只泄露"本 vault 是否配置过生物解锁"一位元
/// 数据（与 sync_token_present 同级）；托管的主密码真值永不出 keyring、
/// 不经 IPC。
#[command]
pub async fn biometric_status(
    db_path: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BiometricStatusResponse>, String> {
    let db_path = resolve_biometric_db_path(db_path, &state).await;
    // keyring 可达性也是 availability 的一部分：存不进去的 keyring 没有
    // 可启用的生物解锁（fail-closed，与 attach_sync_emitter 同口径）。
    // 探测错误一律 enabled=false——不把读取故障误报成已配置。
    let entry_probe = state.biometric_store.get(&db_path);
    let provider = state.biometric_provider.clone();
    let provider_available =
        tauri::async_runtime::spawn_blocking(move || provider.is_available(None))
            .await
            .unwrap_or(false);
    Ok(ApiResponse::success(BiometricStatusResponse {
        available: provider_available && entry_probe.is_ok(),
        enabled: matches!(entry_probe, Ok(Some(_))),
        platform: crate::biometric::platform_name().to_string(),
    }))
}

/// 启用 biometric unlock：验主密码 → OS 认证弹框 → 主密码托管进
/// keyring。顺序刻意为先密码后弹框——密码是要托管的秘密，必须先证明
/// 正确（绝不把未验证的密码写进 keyring）；毫秒级验证先跑可 fail-fast，
/// 把系统级弹窗这个稀缺的注意力资源留到最后。设备指纹通过者 ≠ 必然
/// 知道 vault 主密码，已解锁会话中仍要求主密码 = 复用"敏感操作再认证"
/// 先例（1Password 启用 Touch ID 同款体验）。
#[command]
pub async fn biometric_enable(
    request: BiometricEnableRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BiometricStatusResponse>, String> {
    // 解锁门禁（同 set_locale）：启用是解锁会话里的敏感配置操作
    {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) if service.is_unlocked() => {}
            Some(_) => return Ok(ApiResponse::error("Service is locked".to_string())),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    }
    let db_path = db_path_or_return!(state);

    // 1. 验主密码（走活服务，继承失败计数 / AccountLocked 语义；语义同
    //    reauth_verify——错误码原样映射；authenticate_user 需 &mut）
    {
        let mut guard = state.service.lock().await;
        let service = ok_or_error_response!(guard.as_mut().ok_or("Service not initialized"));
        match service.authenticate_user(&request.master_password).await {
            Ok(persona_core::AuthResult::Success) => {}
            Ok(persona_core::AuthResult::AccountLocked) => {
                return Ok(ApiResponse::error(
                    "Account is locked due to too many failed attempts".to_string(),
                ))
            }
            Ok(_) => return Ok(ApiResponse::error("Invalid master password".to_string())),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                return Ok(match code {
                    Some(code) => ApiResponse::error_with_code(code, msg),
                    None => ApiResponse::error(format!("Authentication error: {}", msg)),
                });
            }
        }
    }

    // 2. OS 认证弹框
    if !state.biometric_provider.is_available(None) {
        return Ok(ApiResponse::error(
            "Biometric authentication is not available on this device".to_string(),
        ));
    }
    ok_or_error_response!(
        run_biometric_ceremony(
            state.biometric_provider.clone(),
            "Enable biometric unlock for Persona",
        )
        .await
    );

    // 3. 托管进 keyring（ceremony 已花掉：写失败给明确错误，不留半态；
    //    用户改用密码登录不受影响）
    if let Err(e) = state
        .biometric_store
        .set(&db_path, &request.master_password)
    {
        return Ok(ApiResponse::error(format!(
            "Biometric verified but OS keyring write failed: {}",
            e
        )));
    }

    Ok(ApiResponse::success(BiometricStatusResponse {
        available: true,
        enabled: true,
        platform: crate::biometric::platform_name().to_string(),
    }))
}

/// 禁用 biometric unlock：删 keyring 条目（幂等，连删两次都成功）。
/// 不需要 ceremony 也不设解锁门禁——这是收紧暴露面的操作（无敏感
/// 读取，删掉后解锁屏指纹按钮消失，主密码登录不受影响）。
#[command]
pub async fn biometric_disable(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BiometricStatusResponse>, String> {
    let db_path = db_path_or_return!(state);
    if let Err(e) = state.biometric_store.delete(&db_path) {
        return Ok(ApiResponse::error(format!(
            "OS keyring delete failed: {}",
            e
        )));
    }
    Ok(ApiResponse::success(BiometricStatusResponse {
        available: false,
        enabled: false,
        platform: crate::biometric::platform_name().to_string(),
    }))
}

/// biometric 解锁：先查条目（没有就干净报错，不弹系统框）→ OS 认证
/// 弹框 → keyring 取回主密码 → 走既有 [`init_service`] 全链路（成功/
/// InvalidCredentials / AccountLocked / PASSWORD_CHANGE_REQUIRED 原样
/// 透传；主密码全程不出进程、不进 ApiResponse）。
#[command]
pub async fn biometric_unlock<R: tauri::Runtime>(
    request: BiometricUnlockRequest,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = resolve_biometric_db_path(request.db_path, &state).await;

    let master_password = match state.biometric_store.get(&db_path) {
        Ok(Some(password)) => password,
        Ok(None) => {
            // 未配置/已被重置：BIOMETRIC_RESET 让前端隐藏按钮并提示
            return Ok(ApiResponse::error_with_code(
                crate::error::CODE_BIOMETRIC_RESET.to_string(),
                "Biometric unlock is not configured for this vault".to_string(),
            ));
        }
        Err(e) => return Ok(ApiResponse::error(format!("OS keyring read failed: {}", e))),
    };

    if !state.biometric_provider.is_available(None) {
        return Ok(ApiResponse::error(
            "Biometric authentication is not available on this device".to_string(),
        ));
    }
    ok_or_error_response!(
        run_biometric_ceremony(state.biometric_provider.clone(), "Unlock Persona").await
    );

    // init_service 本尊复用：锁内全链路（auto-lock 桥、passkey 服务端、
    // sync emitter、biometric provider 注入）与密码解锁完全一致
    let biometric_store = state.biometric_store.clone();
    let resp = ok_or_error_response!(
        init_service(
            InitRequest {
                master_password,
                db_path: Some(db_path.clone()),
            },
            state,
            app,
        )
        .await
    );

    // 陈旧条目自愈（桌面外改密等场景）：取回的密码对这把锁已证明
    // 错误，条目必坏，当场删除——防止反复点指纹白白累计失败计数
    // （core 5 次失败锁户）把账号锁死
    if !resp.success && resp.error.as_deref() == Some("Invalid master password") {
        if let Err(e) = biometric_store.delete(&db_path) {
            tracing::warn!("stale biometric entry cleanup failed: {}", e);
        }
        return Ok(ApiResponse::error_with_code(
            crate::error::CODE_BIOMETRIC_RESET.to_string(),
            "Stored biometric credential was stale and has been removed; unlock with your master password".to_string(),
        ));
    }
    Ok(resp)
}

/// 读当前 vault 的同步服务器配置段（vault 打不开/行不存在一律 None——
/// attach 是尽力而为的旁路，不能阻塞解锁主链路）。
///
/// 顺带做 legacy 一次性迁移：keyring 批次前 DB 里存的是明文 token，
/// 读到非空值时搬进 keyring、DB 窄写为空串。keyring 写失败则保留
/// 明文不销毁数据（下次 attach 重试迁移），上报因读不到 keyring 自然
/// fail-closed。
async fn read_sync_config(
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
#[command]
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

// ---- E2EE sync 设备管理（core SyncAdminApi 的 desktop 宿主层）----
//
// 职责切分：协议/密码学全在 core（SyncAdminApi + DeviceIdentity + 信封），
// 这里只做宿主编排——keyring 身份读写、settings.sync 的 url/token 取用、
// 错误映射。门禁沿用设置页语境：已解锁（status 免解锁，只泄露「是否加
// 入」一位元数据，与 get_workspace_settings 暴露 sync.enabled 同级）。

/// 本机设备身份（keyring → DeviceIdentity）的三态。
enum LocalDevice {
    NotJoined,
    /// 记录存在但解析失败——不猜、不带病运行，UI 引导重新 join。
    Corrupted,
    Joined(persona_core::sync::device::DeviceIdentity),
}

async fn require_db_path(state: &State<'_, AppState>) -> Option<String> {
    let guard = state.db_path.lock().await;
    guard.clone()
}

/// 门禁：已解锁。`None` = 通过；`Some(消息)` = 未初始化/已锁定（调用方
/// 转 `ApiResponse::error`——各 sync 命令的 data 类型不同，在此收口消息）。
async fn require_unlocked(state: &State<'_, AppState>) -> Option<String> {
    let guard = state.service.lock().await;
    match guard.as_ref() {
        None => Some("Service not initialized".to_string()),
        Some(service) if service.is_unlocked() => None,
        Some(_) => Some("Service is locked".to_string()),
    }
}

async fn local_device(state: &State<'_, AppState>, db_path: &str) -> LocalDevice {
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
async fn sync_server_creds_for(
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
async fn sync_admin_api_for(
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
            authorized: keys.iter().any(|k| k.device_id == device.id),
            this_device: device.id == identity.device_id,
        })
        .collect();
    Ok(ApiResponse::success(views))
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
        persona_core::sync::envelope::seal_group_key(&group_key_bytes, &target.public_key);
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
async fn open_sync_session(
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

/// 锁定检查后借出 master 密钥；失败转 `Ok(ApiResponse::error(...))` 返回。
/// 须在命令体内调用（借用挂 service guard，不跨函数边界）。
macro_rules! sync_master_or_return {
    ($service_guard:expr) => {{
        let service = match $service_guard.as_ref() {
            Some(service) => service,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        };
        match service.get_master_encryption_service() {
            Ok(master) => master,
            Err(e) => return Ok(ApiResponse::error(e.to_string())),
        }
    }};
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

/// group key 轮换（E2EE sync 阶段 3d）：换信封 + 全量重包——吊销设备
/// 真正闭环的安全操作。核心流程在 core `SyncSession::rotate_group_key`；
/// 这里只做宿主编排。诚实边界（前端确认弹窗须如实提示，见 core 文档）：
/// 轮换前各保留设备应先「立即同步」；未裁决冲突副本随重包清出裁决视图；
/// 并发轮换无仲裁。
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
        Err(e) => Ok(ApiResponse::error(format!(
            "Group key rotation failed: {e}"
        ))),
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

/// 只读 passkey 开关：vault 打不开/行不存在一律视为关（审批链路另有
/// 解锁门禁兜底，静默跳过安全）。
async fn passkeys_flag_enabled(db_path: &str) -> bool {
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

/// 只读 favicon 开关：vault 打不开/行不存在一律视为关。
///
/// 这是 favicon 外联的后端兜底门禁——不依赖前端藏按钮，开关关闭时
/// `fetch_credential_favicon` 直接拒绝、`get_favicons` 静默回空。
async fn favicon_flag_enabled(db_path: &str) -> bool {
    let Ok(db) = Database::from_file(db_path).await else {
        return false;
    };
    if db.migrate().await.is_err() {
        return false;
    }
    let workspace_path = workspace_path_for_db_path(db_path);
    let repo = WorkspaceRepository::new(db);
    match repo.find_by_path(&workspace_path).await {
        Ok(Some(ws)) => ws.settings.features.fetch_favicons,
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

/// Create a new identity
#[command]
pub async fn create_identity(
    request: CreateIdentityRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableIdentity>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            let identity_type = match request.identity_type.as_str() {
                "Personal" => IdentityType::Personal,
                "Work" => IdentityType::Work,
                "Social" => IdentityType::Social,
                "Financial" => IdentityType::Financial,
                "Gaming" => IdentityType::Gaming,
                custom => IdentityType::Custom(custom.to_string()),
            };

            match service.create_identity(request.name, identity_type).await {
                Ok(mut identity) => {
                    if let Some(desc) = request.description {
                        identity.description = Some(desc);
                    }
                    if let Some(email) = request.email {
                        identity.email = Some(email);
                    }
                    if let Some(phone) = request.phone {
                        identity.phone = Some(phone);
                    }

                    match service.update_identity(&identity).await {
                        Ok(updated_identity) => {
                            // If this is the first identity, make it the active one for this workspace.
                            if let Some(db_path) = state.db_path.lock().await.clone() {
                                if let Ok(db) = Database::from_file(&db_path).await {
                                    let _ = db.migrate().await;
                                    let workspace_path = workspace_path_for_db_path(&db_path);
                                    if let Ok(ws) =
                                        ensure_workspace_for_path(&db, &workspace_path).await
                                    {
                                        if ws.active_identity_id.is_none() {
                                            let repo = WorkspaceRepository::new(db.clone());
                                            let mut ws = ws;
                                            ws.switch_identity(updated_identity.id);
                                            let _ = repo.update(&ws).await;
                                        }
                                    }
                                }
                            }

                            Ok(ApiResponse::success(updated_identity.into()))
                        }
                        Err(e) => Ok(ApiResponse::error(format!(
                            "Failed to update identity: {}",
                            e
                        ))),
                    }
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to create identity: {}",
                    e
                ))),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get all identities
#[command]
pub async fn get_identities(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableIdentity>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_identities().await {
            Ok(identities) => {
                let serializable: Vec<SerializableIdentity> =
                    identities.into_iter().map(|id| id.into()).collect();
                Ok(ApiResponse::success(serializable))
            }
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to get identities: {}",
                e
            ))),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get identity by ID
#[command]
pub async fn get_identity(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<SerializableIdentity>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&id) {
            Ok(uuid) => match service.get_identity(&uuid).await {
                Ok(identity) => Ok(ApiResponse::success(identity.map(|id| id.into()))),
                Err(e) => Ok(ApiResponse::error(format!("Failed to get identity: {}", e))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Update an existing identity
#[command]
pub async fn update_identity(
    request: UpdateIdentityRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableIdentity>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            let uuid = match Uuid::from_str(&request.id) {
                Ok(uuid) => uuid,
                Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
            };

            match service.get_identity(&uuid).await {
                Ok(Some(mut identity)) => {
                    let identity_type = match request.identity_type.as_str() {
                        "Personal" => IdentityType::Personal,
                        "Work" => IdentityType::Work,
                        "Social" => IdentityType::Social,
                        "Financial" => IdentityType::Financial,
                        "Gaming" => IdentityType::Gaming,
                        custom => IdentityType::Custom(custom.to_string()),
                    };

                    identity.name = request.name.trim().to_string();
                    identity.identity_type = identity_type;
                    identity.description = request.description.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    });
                    identity.email = request.email.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    });
                    identity.phone = request.phone.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    });
                    if let Some(tags) = request.tags {
                        identity.tags = tags
                            .into_iter()
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect();
                    }

                    match service.update_identity(&identity).await {
                        Ok(updated_identity) => Ok(ApiResponse::success(updated_identity.into())),
                        Err(e) => Ok(ApiResponse::error(format!(
                            "Failed to update identity: {}",
                            e
                        ))),
                    }
                }
                Ok(None) => Ok(ApiResponse::error("Identity not found".to_string())),
                Err(e) => Ok(ApiResponse::error(format!("Failed to get identity: {}", e))),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete an identity
#[command]
pub async fn delete_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&identity_id) {
            Ok(uuid) => match service.delete_identity(&uuid).await {
                Ok(ok) => {
                    if ok {
                        if let Some(db_path) = state.db_path.lock().await.clone() {
                            if let Ok(db) = Database::from_file(&db_path).await {
                                let _ = db.migrate().await;
                                let workspace_path = workspace_path_for_db_path(&db_path);
                                if let Ok(ws) =
                                    ensure_workspace_for_path(&db, &workspace_path).await
                                {
                                    if ws.active_identity_id == Some(uuid) {
                                        let repo = WorkspaceRepository::new(db.clone());
                                        let mut ws = ws;
                                        ws.clear_active_identity();
                                        let _ = repo.update(&ws).await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(ApiResponse::success(ok))
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to delete identity: {}",
                    e
                ))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Create a new credential
#[command]
pub async fn create_credential(
    request: CreateCredentialRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.identity_id) {
            Ok(identity_uuid) => {
                let credential_type = match request.credential_type.as_str() {
                    "Password" => CredentialType::Password,
                    "CryptoWallet" => CredentialType::CryptoWallet,
                    "SshKey" => CredentialType::SshKey,
                    "ApiKey" => CredentialType::ApiKey,
                    "BankCard" => CredentialType::BankCard,
                    "GameAccount" => CredentialType::GameAccount,
                    "ServerConfig" => CredentialType::ServerConfig,
                    "Certificate" => CredentialType::Certificate,
                    "TwoFactor" => CredentialType::TwoFactor,
                    "SecureNote" => CredentialType::SecureNote,
                    "Identity" => CredentialType::Identity,
                    "SoftwareLicense" => CredentialType::SoftwareLicense,
                    custom => CredentialType::Custom(custom.to_string()),
                };

                let security_level = match request.security_level.as_str() {
                    "Critical" => SecurityLevel::Critical,
                    "High" => SecurityLevel::High,
                    "Medium" => SecurityLevel::Medium,
                    "Low" => SecurityLevel::Low,
                    _ => SecurityLevel::Medium,
                };

                let credential_data = request.credential_data.to_credential_data();

                match service
                    .create_credential(
                        identity_uuid,
                        request.name,
                        credential_type,
                        security_level,
                        &credential_data,
                    )
                    .await
                {
                    Ok(mut credential) => {
                        if let Some(url) = request.url {
                            credential.url = Some(url);
                        }
                        if let Some(username) = request.username {
                            credential.username = Some(username);
                        }
                        if let Some(notes) = request.notes {
                            let trimmed = notes.trim().to_string();
                            credential.notes = if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed)
                            };
                        }
                        if let Some(tags) = request.tags {
                            credential.tags = tags
                                .into_iter()
                                .map(|t| t.trim().to_string())
                                .filter(|t| !t.is_empty())
                                .collect();
                        }

                        match service.update_credential(&credential).await {
                            Ok(updated_credential) => {
                                Ok(ApiResponse::success(updated_credential.into()))
                            }
                            Err(e) => Ok(ApiResponse::error(format!(
                                "Failed to update credential: {}",
                                e
                            ))),
                        }
                    }
                    Err(e) => Ok(ApiResponse::error(format!(
                        "Failed to create credential: {}",
                        e
                    ))),
                }
            }
            Err(_) => Ok(ApiResponse::error(
                "Invalid identity UUID format".to_string(),
            )),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Edit credential metadata（name/username/url/notes/tags/security_level；
/// 条目类型不可变，payload 编辑走 update_credential_data）
#[command]
pub async fn update_credential(
    request: UpdateCredentialRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.id) {
            Ok(uuid) => match service.get_credential(&uuid).await {
                Ok(Some(mut credential)) => {
                    credential.name = request.name;
                    if let Some(level) = request.security_level {
                        credential.security_level = match level.as_str() {
                            "Critical" => SecurityLevel::Critical,
                            "High" => SecurityLevel::High,
                            "Medium" => SecurityLevel::Medium,
                            "Low" => SecurityLevel::Low,
                            _ => credential.security_level.clone(),
                        };
                    }
                    if let Some(url) = request.url {
                        let trimmed = url.trim().to_string();
                        credential.url = if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        };
                    }
                    if let Some(username) = request.username {
                        let trimmed = username.trim().to_string();
                        credential.username = if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        };
                    }
                    if let Some(notes) = request.notes {
                        let trimmed = notes.trim().to_string();
                        credential.notes = if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        };
                    }
                    if let Some(tags) = request.tags {
                        credential.tags = tags
                            .into_iter()
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect();
                    }

                    match service.update_credential(&credential).await {
                        Ok(updated) => Ok(ApiResponse::success(updated.into())),
                        Err(e) => {
                            let (code, msg) = map_persona_error(&e);
                            match code {
                                Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                                None => Ok(ApiResponse::error(format!(
                                    "Failed to update credential: {}",
                                    msg
                                ))),
                            }
                        }
                    }
                }
                Ok(None) => Ok(ApiResponse::error(format!(
                    "Credential {} not found",
                    request.id
                ))),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to update credential: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Edit a credential's encrypted payload（敏感：复用原 item key 重封，
/// 附件不受影响；走敏感门禁，reauth 超时返回 REAUTH_REQUIRED）
#[command]
pub async fn update_credential_data(
    request: UpdateCredentialDataRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.credential_id) {
            Ok(uuid) => {
                let credential_data = request.credential_data.to_credential_data();
                match service
                    .update_credential_data(&uuid, &credential_data)
                    .await
                {
                    Ok(updated) => Ok(ApiResponse::success(updated.into())),
                    Err(e) => {
                        let (code, msg) = map_persona_error(&e);
                        match code {
                            Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                            None => Ok(ApiResponse::error(format!(
                                "Failed to update credential data: {}",
                                msg
                            ))),
                        }
                    }
                }
            }
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get credentials for an identity
#[command]
pub async fn get_credentials_for_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableCredential>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&identity_id) {
            Ok(uuid) => match service.get_credentials_for_identity(&uuid).await {
                Ok(credentials) => {
                    let serializable: Vec<SerializableCredential> =
                        credentials.into_iter().map(|cred| cred.into()).collect();
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to get credentials: {}",
                    e
                ))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get credential data (decrypted)
#[command]
pub async fn get_credential_data(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<SerializableCredentialData>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.get_credential_data(&uuid).await {
                Ok(credential_data) => {
                    let serializable = credential_data.map(|data| SerializableCredentialData {
                        credential_type: match &data {
                            CredentialData::Password(_) => "Password".to_string(),
                            CredentialData::CryptoWallet(_) => "CryptoWallet".to_string(),
                            CredentialData::SshKey(_) => "SshKey".to_string(),
                            CredentialData::ApiKey(_) => "ApiKey".to_string(),
                            CredentialData::BankCard(_) => "BankCard".to_string(),
                            CredentialData::ServerConfig(_) => "ServerConfig".to_string(),
                            CredentialData::TwoFactor(_) => "TwoFactor".to_string(),
                            CredentialData::Raw(_) => "Raw".to_string(),
                            CredentialData::GameToken(_) => "GameToken".to_string(),
                            CredentialData::SecureNote(_) => "SecureNote".to_string(),
                            CredentialData::Identity(_) => "Identity".to_string(),
                            CredentialData::SoftwareLicense(_) => "SoftwareLicense".to_string(),
                        },
                        data: credential_data_to_json(&data),
                    });
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to get credential data: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get change history for a credential (item history; metadata-only,
/// 字段级 diff 不含任何密文/密钥材料)
#[command]
pub async fn get_credential_history(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableChangeHistory>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service
                .get_entity_history(persona_core::models::EntityType::Credential, &uuid)
                .await
            {
                Ok(history) => {
                    let serializable: Vec<SerializableChangeHistory> =
                        history.into_iter().map(|entry| entry.into()).collect();
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to get credential history: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Restore a credential's metadata to an earlier item-history version.
/// 只回滚元数据（name/username/url/notes/tags 等 9 字段）；历史快照从不含
/// 密文，密码等秘密不会被回滚。删除行无可恢复状态，不支持重建已删条目。
#[command]
pub async fn restore_credential_version(
    credential_id: String,
    version: u32,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.restore_credential_version(&uuid, version).await {
                Ok(restored) => Ok(ApiResponse::success(restored.into())),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to restore credential version: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// List attachments for a credential (metadata only; no blob content)
#[command]
pub async fn list_attachments(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableAttachment>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.get_attachments(&uuid).await {
                Ok(attachments) => Ok(ApiResponse::success(
                    attachments.into_iter().map(|a| a.into()).collect(),
                )),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to list attachments: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Attach a local file to a credential. `file_path` comes from the native
/// file dialog on the frontend; the blob is sealed under the credential's
/// per-item key when `encrypt` is set.
#[command]
pub async fn attach_file_to_credential(
    credential_id: String,
    file_path: String,
    encrypt: bool,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableAttachment>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.attach_file(uuid, &file_path, encrypt).await {
                Ok(attachment_id) => {
                    let attachment = service
                        .get_attachments(&uuid)
                        .await
                        .ok()
                        .and_then(|list| list.into_iter().find(|a| a.id == attachment_id));
                    match attachment {
                        Some(a) => Ok(ApiResponse::success(a.into())),
                        None => Ok(ApiResponse::error(
                            "Attachment stored but metadata could not be read back".to_string(),
                        )),
                    }
                }
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to attach file: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Save an attachment to disk (decrypted). `output_path` comes from the
/// native save dialog on the frontend.
#[command]
pub async fn save_attachment_to_file(
    attachment_id: String,
    output_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&attachment_id) {
            Ok(uuid) => match service.save_attachment(&uuid, &output_path, true).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to save attachment: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete an attachment (blob + metadata)
#[command]
pub async fn delete_attachment(
    attachment_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => match Uuid::from_str(&attachment_id) {
            Ok(uuid) => match service.delete_attachment(&uuid).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to delete attachment: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Generate a TOTP code for a TwoFactor credential (without exposing the secret)
#[command]
pub async fn get_totp_code(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TotpCodeResponse>, String> {
    let service_guard = state.service.lock().await;
    let service = ok_or_error_response!(service_guard
        .as_ref()
        .ok_or_else(|| "Service not initialized".to_string()));

    let uuid = ok_or_error_response!(
        Uuid::from_str(&credential_id).map_err(|_| "Invalid UUID format".to_string())
    );
    let credential_data = ok_or_error_response_ctx!(
        service.get_credential_data(&uuid).await,
        "Failed to get credential data: {}"
    );

    let data =
        ok_or_error_response!(credential_data.ok_or_else(|| "Credential not found".to_string()));
    match data {
        CredentialData::TwoFactor(tf) => {
            // 协议逻辑统一下沉到 core（RFC 4226/6238），桌面端只做调用。
            let generated = ok_or_error_response_ctx!(
                persona_core::crypto::totp::totp_now(&tf),
                "Failed to generate TOTP code: {}"
            );

            Ok(ApiResponse::success(TotpCodeResponse {
                code: generated.code,
                remaining_seconds: generated.remaining_seconds,
                period: tf.period.max(1),
                digits: tf.digits.clamp(4, 10),
                algorithm: tf.algorithm,
                issuer: tf.issuer,
                account_name: tf.account_name,
            }))
        }
        // 游戏令牌经 core 统一调度器（Steam Guard 离线可算；绑定型
        // provider 在此报错而不是生成错误码）
        CredentialData::GameToken(gt) => {
            let generated = ok_or_error_response_ctx!(
                persona_core::crypto::game_token::generate_game_token_code_now(&gt),
                "Failed to generate game token code: {}"
            );

            Ok(ApiResponse::success(TotpCodeResponse {
                code: generated.code,
                remaining_seconds: generated.remaining_seconds,
                period: generated.period,
                digits: persona_core::crypto::STEAM_GUARD_DIGITS as u8,
                algorithm: gt.provider.to_ascii_uppercase(),
                issuer: gt.issuer,
                account_name: gt.account_name,
            }))
        }
        _ => Ok(ApiResponse::error(
            "Credential is not a TwoFactor entry".to_string(),
        )),
    }
}

/// Search credentials
#[command]
pub async fn search_credentials(
    query: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableCredential>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.search_credentials(&query).await {
            Ok(credentials) => {
                let serializable: Vec<SerializableCredential> =
                    credentials.into_iter().map(|cred| cred.into()).collect();
                Ok(ApiResponse::success(serializable))
            }
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to search credentials: {}",
                e
            ))),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Generate password
#[command]
pub async fn generate_password(
    length: usize,
    include_symbols: bool,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            let password = service.generate_password(length, include_symbols);
            Ok(ApiResponse::success(password))
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get service statistics
#[command]
pub async fn get_statistics(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_statistics().await {
            Ok(stats) => {
                let json_stats = serde_json::json!({
                    "total_identities": stats.total_identities,
                    "total_credentials": stats.total_credentials,
                    "active_credentials": stats.active_credentials,
                    "favorite_credentials": stats.favorite_credentials,
                    "credential_types": stats.credential_types,
                    "security_levels": stats.security_levels,
                });
                Ok(ApiResponse::success(json_stats))
            }
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to get statistics: {}",
                e
            ))),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Toggle credential favorite status
#[command]
pub async fn toggle_credential_favorite(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.get_credential(&uuid).await {
                Ok(Some(mut credential)) => {
                    credential.is_favorite = !credential.is_favorite;
                    match service.update_credential(&credential).await {
                        Ok(updated_credential) => {
                            Ok(ApiResponse::success(updated_credential.into()))
                        }
                        Err(e) => Ok(ApiResponse::error(format!(
                            "Failed to update credential: {}",
                            e
                        ))),
                    }
                }
                Ok(None) => Ok(ApiResponse::error("Credential not found".to_string())),
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to get credential: {}",
                    e
                ))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// 按需抓取凭据对应站点的 favicon 并入缓存（隐私红线：唯一外联入口，
/// 由详情面板 "Fetch icon" 按钮触发；flag 关闭时后端兜底拒绝）。
#[command]
pub async fn fetch_credential_favicon(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableFavicon>, String> {
    // 检查顺序照 set_feature_flags：service 状态在先（错误语义优先），
    // flag 门禁随后（开新 DB 连接的 IO 不持 service 锁做）
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
    if !favicon_flag_enabled(&db_path).await {
        return Ok(ApiResponse::error(
            "Favicon fetching is disabled in settings".to_string(),
        ));
    }

    let service_guard = state.service.lock().await;
    let service = match service_guard.as_ref() {
        Some(service) => service,
        None => return Ok(ApiResponse::error("Service not initialized".to_string())),
    };
    if !service.is_unlocked() {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let uuid = match Uuid::from_str(&credential_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };

    let fetcher = match persona_core::favicon::FaviconFetcher::new() {
        Ok(fetcher) => fetcher,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Failed to fetch favicon: {}",
                e
            )))
        }
    };

    match service.fetch_favicon_for_credential(&uuid, &fetcher).await {
        Ok(entry) => Ok(ApiResponse::success(entry.into())),
        Err(e) => Ok(ApiResponse::error(format!(
            "Failed to fetch favicon: {}",
            e
        ))),
    }
}

/// 批量读已缓存的 favicon（纯本地读，绝不外联）。
///
/// flag 关闭 / 未初始化 / 锁定一律静默回空数组——批量读是列表渲染的
/// 后台优化路径，缺席项回退静态图标即可，报错无意义。
#[command]
pub async fn get_favicons(
    hosts: Vec<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableFavicon>>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::success(Vec::new())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::success(Vec::new()));
    }

    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(db_path) => db_path,
            None => return Ok(ApiResponse::success(Vec::new())),
        }
    };
    if !favicon_flag_enabled(&db_path).await {
        return Ok(ApiResponse::success(Vec::new()));
    }

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_cached_favicons(&hosts).await {
            Ok(entries) => Ok(ApiResponse::success(
                entries.into_iter().map(Into::into).collect(),
            )),
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to load favicons: {}",
                e
            ))),
        },
        None => Ok(ApiResponse::success(Vec::new())),
    }
}

/// Delete a credential
#[command]
pub async fn delete_credential(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.delete_credential(&uuid).await {
                Ok(deleted) => Ok(ApiResponse::success(deleted)),
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to delete credential: {}",
                    e
                ))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get SSH agent runtime status
#[command]
pub async fn get_ssh_agent_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SshAgentStatus>, String> {
    let running = state
        .agent_handle
        .lock()
        .await
        .as_ref()
        .map(|handle| !handle.inner().is_finished())
        .unwrap_or(false);
    let status = read_agent_status(running);
    Ok(ApiResponse::success(status))
}

/// Start the embedded SSH agent
#[command]
pub async fn start_ssh_agent<R: tauri::Runtime>(
    request: StartAgentRequest,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<SshAgentStatus>, String> {
    let db_path = db_path_or_return!(state);

    let already_running = state
        .agent_handle
        .lock()
        .await
        .as_ref()
        .map(|handle| !handle.inner().is_finished())
        .unwrap_or(false);
    if already_running {
        return get_ssh_agent_status(state).await;
    }

    let mut handle_guard = state.agent_handle.lock().await;
    let password = request.master_password.clone();
    let db_path_clone = db_path.clone();
    let state_dir = agent_state_dir().to_string_lossy().to_string();
    // Desktop has no TTY: route RequireConfirm prompts through the GUI.
    // PERSONA_AGENT_REQUIRE_CONFIRM=1 enables the confirm policy (read by
    // PolicyEnforcer::from_env inside Agent::new).
    std::env::set_var("PERSONA_AGENT_REQUIRE_CONFIRM", "1");
    let handler = Arc::new(crate::approval::DesktopApprovalHandler::new(
        app,
        state.ssh_approvals.clone(),
    ));
    // biometric provider 与解锁屏/init_service 注入的是同一份：SSH key 的
    // require_biometric 策略走 OS 认证弹框（Agent::new 默认拒绝，注入才放行）
    let biometric = state.biometric_provider.clone();
    // tauri 全局运行时而非调用方的 tokio 上下文：mock_app（测试）的
    // reactor 上 socket IO 永不唤醒，agent 必须活在健康的多线程运行时里。
    let handle = tauri::async_runtime::spawn(async move {
        if let Some(pass) = password {
            std::env::set_var("PERSONA_MASTER_PASSWORD", pass);
        } else {
            std::env::remove_var("PERSONA_MASTER_PASSWORD");
        }
        std::env::set_var("PERSONA_DB_PATH", &db_path_clone);
        std::env::set_var("PERSONA_AGENT_STATE_DIR", &state_dir);
        if let Err(err) = persona_ssh_agent::run_agent_with_hooks(
            Some(handler as Arc<dyn persona_ssh_agent::ApprovalHandler>),
            Some(biometric as Arc<dyn persona_core::BiometricProvider>),
        )
        .await
        {
            eprintln!("SSH agent exited: {}", err);
        }
        std::env::remove_var("PERSONA_AGENT_STATE_DIR");
        std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");
    });
    *handle_guard = Some(handle);
    drop(handle_guard);

    sleep(Duration::from_millis(400)).await;
    let status = read_agent_status(true);
    Ok(ApiResponse::success(status))
}

/// Stop the embedded SSH agent
#[command]
pub async fn stop_ssh_agent(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    stop_ssh_agent_internal(&state).await;
    Ok(ApiResponse::success(true))
}

/// 停止 SSH agent 的实际逻辑（`stop_ssh_agent` 命令与
/// `set_feature_flags` 关开关联动共用）。
async fn stop_ssh_agent_internal(state: &State<'_, AppState>) {
    if let Some(handle) = state.agent_handle.lock().await.take() {
        handle.abort();
    }
    // 丢弃所有未应答审批：sender 被 drop 后 agent 侧收到断连 → 拒签
    if let Ok(mut map) = state.ssh_approvals.lock() {
        map.clear();
    }
    std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");
    cleanup_agent_state_files();
}

/// Answer a pending SSH signature approval (from the approval modal).
///
/// Unknown/already-answered ids resolve to deny so double-clicks and
/// stale modals can never approve anything.
#[derive(serde::Deserialize)]
pub struct SshApprovalRespondRequest {
    pub request_id: String,
    pub allow: bool,
}

#[command]
pub async fn ssh_approval_respond(
    request: SshApprovalRespondRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let delivered =
        crate::approval::resolve_from_map(&state.ssh_approvals, &request.request_id, request.allow);
    if delivered {
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error(format!(
            "Unknown or expired approval request: {}",
            request.request_id
        )))
    }
}

/// Answer a pending bridge passkey approval (from the approval modal).
///
/// Unknown/already-answered ids resolve to deny so double-clicks and
/// stale modals can never approve anything.
#[derive(serde::Deserialize)]
pub struct PasskeyApprovalRespondRequest {
    pub request_id: String,
    pub allow: bool,
}

#[command]
pub async fn passkey_approval_respond(
    request: PasskeyApprovalRespondRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let delivered = crate::approval::resolve_from_map(
        &state.passkey_approvals,
        &request.request_id,
        request.allow,
    );
    if delivered {
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error(format!(
            "Unknown or expired approval request: {}",
            request.request_id
        )))
    }
}

/// List stored SSH key credentials
#[command]
pub async fn get_ssh_keys(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SshKeySummary>>, String> {
    let identities = {
        let service_guard = state.service.lock().await;
        let service = match service_guard.as_ref() {
            Some(service) => service,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        };
        ok_or_error_response_ctx!(
            service.get_identities().await,
            "Failed to load identities: {}"
        )
    };
    let mut identity_map: HashMap<Uuid, String> = HashMap::new();
    for identity in &identities {
        identity_map.insert(identity.id, identity.name.clone());
    }

    let mut summaries = Vec::new();
    for identity in identities {
        let creds = {
            let service_guard = state.service.lock().await;
            let service = match service_guard.as_ref() {
                Some(service) => service,
                None => return Ok(ApiResponse::error("Service not initialized".to_string())),
            };
            ok_or_error_response_ctx!(
                service.get_credentials_for_identity(&identity.id).await,
                "Failed to load credentials: {}"
            )
        };
        for credential in creds {
            if credential.credential_type == CredentialType::SshKey {
                summaries.push(SshKeySummary {
                    id: credential.id.to_string(),
                    identity_id: credential.identity_id.to_string(),
                    identity_name: identity_map
                        .get(&credential.identity_id)
                        .cloned()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    name: credential.name,
                    tags: credential.tags,
                    created_at: credential.created_at.to_rfc3339(),
                    updated_at: credential.updated_at.to_rfc3339(),
                });
            }
        }
    }

    Ok(ApiResponse::success(summaries))
}

#[command]
pub async fn wallet_list(
    identity_id: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletListResponse>, String> {
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

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallets = match identity_id {
        Some(identity_id) => {
            let uuid = ok_or_error_response!(Uuid::from_str(&identity_id)
                .map_err(|_| "Invalid identity UUID format".to_string()));
            ok_or_error_response!(repo.find_by_identity(&uuid).await)
        }
        None => ok_or_error_response!(repo.find_all().await),
    };

    let serializable = wallets
        .into_iter()
        .map(|wallet| SerializableWallet {
            id: wallet.id.to_string(),
            name: wallet.name,
            network: wallet.network.to_string(),
            wallet_type: format!("{:?}", wallet.wallet_type),
            balance: "-".to_string(),
            address_count: wallet.addresses.len(),
            watch_only: wallet.watch_only,
            security_level: wallet.security_level.to_string(),
            created_at: wallet.created_at.to_rfc3339(),
            updated_at: wallet.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(ApiResponse::success(WalletListResponse {
        wallets: serializable,
    }))
}

#[command]
pub async fn wallet_list_addresses(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletAddressesResponse>, String> {
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

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let uuid = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())
    );
    let wallet: CryptoWallet = match repo.find_by_id(&uuid).await.map_err(|e| e.to_string())? {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let addresses = wallet
        .addresses
        .into_iter()
        .map(|addr| SerializableWalletAddress {
            address: addr.address,
            address_type: match addr.address_type {
                persona_core::models::wallet::AddressType::P2PKH => "P2PKH".to_string(),
                persona_core::models::wallet::AddressType::P2SH => "P2SH".to_string(),
                persona_core::models::wallet::AddressType::P2WPKH => "P2WPKH".to_string(),
                persona_core::models::wallet::AddressType::P2TR => "P2TR".to_string(),
                persona_core::models::wallet::AddressType::Ethereum => "ETH".to_string(),
                persona_core::models::wallet::AddressType::Solana => "SOL".to_string(),
                persona_core::models::wallet::AddressType::Custom(name) => name,
            },
            index: addr.index,
            used: addr.used,
            balance: addr.balance.unwrap_or_else(|| "-".to_string()),
            derivation_path: addr.derivation_path,
        })
        .collect();

    Ok(ApiResponse::success(WalletAddressesResponse { addresses }))
}

#[command]
pub async fn wallet_generate(
    identity_id: String,
    request: WalletGenerateRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletGenerateResponse>, String> {
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
    let network = ok_or_error_response!(parse_network(&request.network));
    let address_count = request.address_count.unwrap_or(5);

    if request.password.len() < 8 {
        return Ok(ApiResponse::error(
            "Wallet password must be at least 8 characters".to_string(),
        ));
    }

    let mnemonic = ok_or_error_response!(
        persona_core::crypto::wallet_crypto::SecureMnemonic::generate(
            persona_core::crypto::wallet_crypto::MnemonicWordCount::Words24,
        )
    );
    let mnemonic_phrase = mnemonic.phrase();

    let derivation_path = match request.wallet_type.to_lowercase().as_str() {
        "hd" | "hierarchical" | "hierarchical_deterministic" => None,
        other => {
            return Ok(ApiResponse::error(format!(
                "Unsupported wallet_type '{}'. Use 'hd'.",
                other
            )))
        }
    };

    let wallet = ok_or_error_response!(
        persona_core::crypto::wallet_import_export::import_from_mnemonic(
            identity_id,
            request.name.clone(),
            &mnemonic_phrase,
            "",
            network,
            derivation_path,
            address_count,
            &request.password,
        )
    );

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let created = ok_or_error_response!(repo.create(&wallet).await);
    let first_address = created
        .addresses
        .first()
        .map(|addr| addr.address.clone())
        .unwrap_or_else(|| "-".to_string());

    Ok(ApiResponse::success(WalletGenerateResponse {
        wallet_id: created.id.to_string(),
        name: created.name,
        network: created.network.to_string(),
        mnemonic: mnemonic_phrase,
        first_address,
    }))
}

#[command]
pub async fn wallet_import(
    identity_id: String,
    request: WalletImportRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableWallet>, String> {
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
    let wallet = match import_wallet_from_request(identity_id, &request) {
        Ok(wallet) => wallet,
        Err(error) => return Ok(ApiResponse::error(error)),
    };

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let created = ok_or_error_response!(repo.create(&wallet).await);
    Ok(ApiResponse::success(serialize_wallet_summary(&created)))
}

#[command]
pub async fn wallet_add_address(
    wallet_id: String,
    password: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableWalletAddress>, String> {
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

    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())
    );
    if password.len() < 8 {
        return Ok(ApiResponse::error(
            "Wallet password must be at least 8 characters".to_string(),
        ));
    }

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet: CryptoWallet = match ok_or_error_response!(repo.find_by_id(&wallet_id).await) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    if wallet.watch_only {
        return Ok(ApiResponse::error(
            "Address generation for watch-only wallets is not implemented yet.".to_string(),
        ));
    }

    if !matches!(
        wallet.wallet_type,
        persona_core::models::wallet::WalletType::HierarchicalDeterministic { .. }
    ) {
        return Ok(ApiResponse::error(
            "Address generation is only supported for HD wallets.".to_string(),
        ));
    }

    let derivation_path = wallet
        .derivation_path
        .clone()
        .unwrap_or_else(|| CryptoWallet::recommended_derivation_path(&wallet.network, 0));

    let next_index = wallet
        .addresses
        .iter()
        .map(|addr| addr.index)
        .max()
        .map(|v| v + 1)
        .unwrap_or(0);

    let encrypted_key: persona_core::crypto::wallet_encryption::EncryptedWalletKey = ok_or_error_response_ctx!(
        serde_json::from_slice(&wallet.encrypted_private_key),
        "Invalid wallet key encoding: {}"
    );
    let master_key = ok_or_error_response!(
        persona_core::crypto::wallet_encryption::decrypt_master_key(&encrypted_key, &password)
    );

    let parent = ok_or_error_response!(master_key.derive_path(&derivation_path));
    let child = ok_or_error_response!(parent.derive_child(next_index, false));

    let (address_string, address_type) = match wallet.network {
        BlockchainNetwork::Bitcoin => (
            ok_or_error_response!(
                persona_core::crypto::address_generator::generate_bitcoin_address(
                    &child,
                    persona_core::crypto::address_generator::BitcoinAddressType::P2WPKH,
                    false,
                )
            ),
            persona_core::models::wallet::AddressType::P2WPKH,
        ),
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => (
            ok_or_error_response!(
                persona_core::crypto::address_generator::generate_ethereum_address_checksummed(
                    &child
                )
            ),
            persona_core::models::wallet::AddressType::Ethereum,
        ),
        other => {
            return Ok(ApiResponse::error(format!(
                "Address generation not implemented for {}",
                other
            )))
        }
    };

    let wallet_address = persona_core::models::wallet::WalletAddress {
        address: address_string,
        address_type,
        derivation_path: Some(format!("{}/{}", derivation_path, next_index)),
        index: next_index,
        used: false,
        balance: None,
        last_activity: None,
        metadata: HashMap::new(),
        created_at: chrono::Utc::now(),
    };

    ok_or_error_response!(repo.add_address(&wallet_id, &wallet_address).await);
    ok_or_error_response!(repo.touch(&wallet_id).await);

    Ok(ApiResponse::success(serialize_wallet_address(
        wallet_address,
    )))
}

#[command]
pub async fn wallet_delete(
    wallet_id: String,
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

    let repo = CryptoWalletRepository::new(Arc::new(db));
    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())
    );

    let deleted = ok_or_error_response!(repo.delete(&wallet_id).await);
    if !deleted {
        return Ok(ApiResponse::error("Wallet not found".to_string()));
    }

    Ok(ApiResponse::success(true))
}

#[command]
pub async fn wallet_export(
    request: WalletExportRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
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

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet_id =
        ok_or_error_response!(Uuid::from_str(&request.wallet_id)
            .map_err(|_| "Invalid wallet UUID format".to_string()));
    let wallet = match ok_or_error_response!(repo.find_by_id(&wallet_id).await) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let exported = match export_wallet_from_request(&wallet, &request) {
        Ok(exported) => exported,
        Err(error) => return Ok(ApiResponse::error(error)),
    };

    Ok(ApiResponse::success(exported))
}

// ---------------------------------------------------------------------------
// 钱包交易：创建 / 待签列表 / 签名确认（对齐 CLI wallet sign 流程）
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct WalletCreateTransactionRequest {
    pub wallet_id: String,
    pub to_address: String,
    /// 最小单位字符串（wei / satoshi / lamport）
    pub amount: String,
    pub fee: String,
    pub gas_price: Option<String>,
    pub gas_limit: Option<u64>,
    pub nonce: Option<u64>,
    pub memo: Option<String>,
    pub expires_in_minutes: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct WalletSignTransactionRequest {
    pub transaction_id: String,
    pub password: String,
}

/// 从数据库加载钱包交易仓库。
///
/// 钱包命令绕过 PersonaService 直用 `CryptoWalletRepository`（既有架构决策）。
async fn wallet_db(state: &State<'_, AppState>) -> std::result::Result<Database, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Err("Service not initialized".to_string()),
        }
    };
    if !service_unlocked {
        return Err("Service is locked".to_string());
    }

    // helper 内部：Err(String) 不跨命令边界，走手写样板（宏会往
    // ApiResponse 边界 return，类型在这里不成立）。
    let db_path = {
        let guard = state.db_path.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;
    Ok(db)
}

/// Create a pending transaction request for a wallet
#[command]
pub async fn wallet_create_transaction(
    request: WalletCreateTransactionRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    use persona_core::models::wallet::TransactionRequest;

    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&request.wallet_id).map_err(|_| "Invalid wallet_id".to_string())
    );
    let db = wallet_db_or_return!(state);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet = match ok_or_error_response!(repo.find_by_id(&wallet_id).await) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let from_address = ok_or_error_response!(wallet
        .addresses
        .first()
        .map(|a| a.address.clone())
        .ok_or_else(|| "Wallet has no addresses".to_string()));

    let transaction = TransactionRequest {
        id: Uuid::new_v4(),
        wallet_id: wallet.id,
        network: wallet.network.clone(),
        from_address,
        to_address: request.to_address,
        amount: request.amount,
        fee: request.fee,
        gas_price: request.gas_price,
        gas_limit: request.gas_limit,
        nonce: request.nonce,
        memo: request.memo,
        raw_transaction_data: None,
        required_signatures: 1,
        created_at: chrono::Utc::now(),
        expires_at: request
            .expires_in_minutes
            .map(|mins| chrono::Utc::now() + chrono::Duration::minutes(mins as i64)),
        metadata: HashMap::new(),
    };

    let created = ok_or_error_response_ctx!(
        repo.create_transaction_request(&transaction).await,
        "Failed to create transaction: {}"
    );
    let value = ok_or_error_response_ctx!(
        serde_json::to_value(&created),
        "Failed to serialize transaction: {}"
    );
    Ok(ApiResponse::success(value))
}

/// List pending (unsigned) transaction requests for a wallet
#[command]
pub async fn wallet_pending_transactions(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<serde_json::Value>>, String> {
    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet_id".to_string())
    );
    let db = wallet_db_or_return!(state);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let requests = ok_or_error_response_ctx!(
        repo.get_pending_requests(&wallet_id).await,
        "Failed to list pending transactions: {}"
    );
    let values = ok_or_error_response!(requests
        .into_iter()
        .map(|r| serde_json::to_value(&r).map_err(|e| e.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>());
    Ok(ApiResponse::success(values))
}

/// Sign a pending transaction (derive key → sign → verify → persist).
///
/// 流程与 CLI `wallet --sign` 一致：签名后先本地验签，验签失败拒绝落库。
#[command]
pub async fn wallet_sign_transaction(
    request: WalletSignTransactionRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    let request_id =
        ok_or_error_response!(Uuid::from_str(&request.transaction_id)
            .map_err(|_| "Invalid transaction_id".to_string()));
    let db = wallet_db_or_return!(state);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let transaction = match ok_or_error_response_ctx!(
        repo.get_request_by_id(&request_id).await,
        "Failed to load transaction: {}"
    ) {
        Some(tx) => tx,
        None => return Ok(ApiResponse::error("Transaction not found".to_string())),
    };

    let wallet = match ok_or_error_response_ctx!(
        repo.find_by_id(&transaction.wallet_id).await,
        "Failed to load wallet: {}"
    ) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let signed = ok_or_error_response!(
        sign_wallet_transaction(&repo, &wallet, &transaction, &request.password).await
    );
    let value = ok_or_error_response_ctx!(
        serde_json::to_value(&signed),
        "Failed to serialize signed transaction: {}"
    );
    Ok(ApiResponse::success(value))
}

/// 按地址派生签名钥 → 签名 → 本地验签 → 落库。
///
/// 与 CLI `CreateTransaction { sign: true }` 保持一致；验签失败时
/// **拒绝落库**（不产生 signed_transactions 记录）。
async fn sign_wallet_transaction(
    repo: &CryptoWalletRepository,
    wallet: &CryptoWallet,
    request: &persona_core::models::wallet::TransactionRequest,
    password: &str,
) -> std::result::Result<persona_core::models::wallet::SignedTransaction, String> {
    use persona_core::crypto::transaction_signing::{
        build_raw_transaction, sign_transaction, verify_ethereum_transaction,
        verify_solana_transaction,
    };
    use persona_core::crypto::wallet_import_export::signing_key_for_address;
    use persona_core::models::wallet::{BroadcastStatus, SignedTransaction};
    use sha2::Digest;

    let key = signing_key_for_address(wallet, password, &request.from_address)
        .map_err(|e| format!("Failed to derive signing key (wrong password?): {}", e))?;
    let signature = sign_transaction(request, &key)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    // 本地验签：失败一律拒绝落库
    match request.network {
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => {
            let ok = verify_ethereum_transaction(request, &signature)
                .map_err(|e| format!("Verification error: {}", e))?;
            if !ok {
                return Err(
                    "Signature verification failed; refusing to store signed transaction"
                        .to_string(),
                );
            }
        }
        BlockchainNetwork::Solana => {
            let message = request
                .raw_transaction_data
                .clone()
                .ok_or_else(|| "Solana signing requires raw_transaction_data".to_string())?;
            let ok = verify_solana_transaction(&signature, &message)
                .map_err(|e| format!("Verification error: {}", e))?;
            if !ok {
                return Err(
                    "Signature verification failed; refusing to store signed transaction"
                        .to_string(),
                );
            }
        }
        _ => {}
    }

    // Bitcoin 等需要 UTXO 集的网络：raw 组装失败时只落审计签名记录
    let (raw_bytes, tx_hash) = match build_raw_transaction(request, &key) {
        Ok(raw) => (raw.raw, raw.hash),
        Err(e) => {
            tracing::warn!(
                "raw transaction not assembled ({}); storing audit-only record",
                e
            );
            let audit_hash = format!(
                "audit:{}",
                hex::encode(sha2::Sha256::digest(&signature.signature))
            );
            (Vec::new(), audit_hash)
        }
    };

    let signed = SignedTransaction {
        id: Uuid::new_v4(),
        request: request.clone(),
        signatures: vec![signature],
        raw_signed_transaction: raw_bytes,
        transaction_hash: tx_hash,
        signed_at: chrono::Utc::now(),
        broadcast_status: BroadcastStatus::NotBroadcast,
    };

    repo.create_signed_transaction(&signed)
        .await
        .map_err(|e| format!("Failed to store signed transaction: {}", e))
}

fn parse_network(network_str: &str) -> std::result::Result<BlockchainNetwork, String> {
    match network_str.to_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(BlockchainNetwork::Bitcoin),
        "ethereum" | "eth" => Ok(BlockchainNetwork::Ethereum),
        "solana" | "sol" => Ok(BlockchainNetwork::Solana),
        "bitcoin-cash" | "bitcoin cash" | "bitcoincash" | "bch" => {
            Ok(BlockchainNetwork::BitcoinCash)
        }
        "litecoin" | "ltc" => Ok(BlockchainNetwork::Litecoin),
        "dogecoin" | "doge" => Ok(BlockchainNetwork::Dogecoin),
        "polygon" | "matic" => Ok(BlockchainNetwork::Polygon),
        "arbitrum" | "arb" => Ok(BlockchainNetwork::Arbitrum),
        "optimism" | "op" => Ok(BlockchainNetwork::Optimism),
        "binance" | "bsc" | "bnb" | "binance smart chain" => {
            Ok(BlockchainNetwork::BinanceSmartChain)
        }
        other => Ok(BlockchainNetwork::Custom(other.to_string())),
    }
}

fn serialize_wallet_address(
    addr: persona_core::models::wallet::WalletAddress,
) -> SerializableWalletAddress {
    SerializableWalletAddress {
        address: addr.address,
        address_type: match addr.address_type {
            persona_core::models::wallet::AddressType::P2PKH => "P2PKH".to_string(),
            persona_core::models::wallet::AddressType::P2SH => "P2SH".to_string(),
            persona_core::models::wallet::AddressType::P2WPKH => "P2WPKH".to_string(),
            persona_core::models::wallet::AddressType::P2TR => "P2TR".to_string(),
            persona_core::models::wallet::AddressType::Ethereum => "ETH".to_string(),
            persona_core::models::wallet::AddressType::Solana => "SOL".to_string(),
            persona_core::models::wallet::AddressType::Custom(name) => name,
        },
        index: addr.index,
        used: addr.used,
        balance: addr.balance.unwrap_or_else(|| "-".to_string()),
        derivation_path: addr.derivation_path,
    }
}

fn serialize_wallet_summary(wallet: &CryptoWallet) -> SerializableWallet {
    SerializableWallet {
        id: wallet.id.to_string(),
        name: wallet.name.clone(),
        network: wallet.network.to_string(),
        wallet_type: format!("{:?}", wallet.wallet_type),
        balance: "-".to_string(),
        address_count: wallet.addresses.len(),
        watch_only: wallet.watch_only,
        security_level: wallet.security_level.to_string(),
        created_at: wallet.created_at.to_rfc3339(),
        updated_at: wallet.updated_at.to_rfc3339(),
    }
}

fn import_wallet_from_request(
    identity_id: Uuid,
    request: &WalletImportRequest,
) -> std::result::Result<CryptoWallet, String> {
    if request.password.len() < 8 {
        return Err("Wallet password must be at least 8 characters".to_string());
    }

    let address_count = request.address_count.unwrap_or(5);
    match request.import_type.to_lowercase().as_str() {
        "mnemonic" | "phrase" | "seed" => {
            let network = parse_network(&request.network)?;
            persona_core::crypto::wallet_import_export::import_from_mnemonic(
                identity_id,
                request.name.clone(),
                request.data.trim(),
                "",
                network,
                None,
                address_count,
                &request.password,
            )
            .map_err(|e| e.to_string())
        }
        "private_key" | "privatekey" | "key" => {
            let network = parse_network(&request.network)?;
            persona_core::crypto::wallet_import_export::import_from_private_key(
                identity_id,
                request.name.clone(),
                request.data.trim(),
                network,
                &request.password,
            )
            .map_err(|e| e.to_string())
        }
        "wif" => persona_core::crypto::wallet_import_export::import_from_wif(
            identity_id,
            request.name.clone(),
            request.data.trim(),
            &request.password,
        )
        .map_err(|e| e.to_string()),
        other => Err(format!(
            "Unsupported import_type '{}'. Use 'mnemonic', 'private_key', or 'wif'.",
            other
        )),
    }
}

fn export_wallet_from_request(
    wallet: &CryptoWallet,
    request: &WalletExportRequest,
) -> std::result::Result<String, String> {
    let format = persona_core::crypto::wallet_import_export::parse_export_format(&request.format)
        .map_err(|e| e.to_string())?;

    match format {
        persona_core::crypto::wallet_import_export::ExportFormat::Json => {
            persona_core::crypto::wallet_import_export::export_to_json(
                wallet,
                request.include_private,
                request.password.as_deref(),
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Mnemonic => {
            persona_core::crypto::wallet_import_export::export_mnemonic(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for mnemonic export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Xpub => {
            persona_core::crypto::wallet_import_export::export_xpub(wallet)
                .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::PrivateKey => {
            persona_core::crypto::wallet_import_export::export_private_key(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for private key export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Wif => {
            persona_core::crypto::wallet_import_export::export_to_wif(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for WIF export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Auto-lock 配置与状态
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 审计查询（只读，不含敏感负载）
// ---------------------------------------------------------------------------

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
#[command]
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
fn build_audit_query(
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

// ---------------------------------------------------------------------------
// Watchtower 健康扫描（只读聚合；报告只含元数据、不含密文）
// ---------------------------------------------------------------------------

/// 可选请求字段 → core 扫描配置；缺省字段回落 core 默认值。
/// 独立成纯函数以便无需运行中的服务即可测试。
fn build_health_scan_config(request: &HealthScanRequest) -> persona_core::HealthScanConfig {
    persona_core::HealthScanConfig {
        min_password_score: request
            .min_password_score
            .unwrap_or(persona_core::DEFAULT_MIN_PASSWORD_SCORE),
        expiry_warning_days: request
            .expiry_warning_days
            .unwrap_or(persona_core::DEFAULT_EXPIRY_WARNING_DAYS),
        stale_after_days: request
            .stale_after_days
            .unwrap_or(persona_core::DEFAULT_STALE_AFTER_DAYS),
    }
}

/// Run the Watchtower health scan (weak / reused / expired / stale).
///
/// The report is metadata only — credential names and issue kinds, never
/// the decrypted secrets — and the scan writes one aggregate audit entry.
#[command]
pub async fn health_scan(
    request: Option<HealthScanRequest>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<HealthReport>, String> {
    let request = request.unwrap_or_default();
    let config = build_health_scan_config(&request);

    // check_breaches → HIBP k-anonymity checker；构造失败（罕见）降级为
    // 离线扫描而非报错，网络失败在 scan_health_with 内部也只告警。
    let checker: Option<std::sync::Arc<dyn persona_core::BreachChecker>> =
        if request.check_breaches.unwrap_or(false) {
            match persona_core::HibpBreachChecker::new() {
                Ok(checker) => Some(std::sync::Arc::new(checker)),
                Err(e) => {
                    tracing::warn!("health scan: breach checker unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.scan_health_with(config, checker.as_deref()).await {
            Ok(report) => Ok(ApiResponse::success(report)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!("Health scan failed: {}", msg))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// Passkey 管理（P3 命令层接缝）
// ---------------------------------------------------------------------------

/// List passkeys for an identity
#[command]
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
#[command]
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

// ---------------------------------------------------------------------------
// 身份导出
// ---------------------------------------------------------------------------

/// Export an identity with its credentials (audited by core; metadata only —
/// no ciphertext/secret material is included in the payload)
#[command]
pub async fn export_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableIdentityExport>, String> {
    let uuid = match Uuid::from_str(&identity_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.export_identity(&uuid).await {
            Ok(export) => Ok(ApiResponse::success(SerializableIdentityExport {
                exported_at: chrono::Utc::now().to_rfc3339(),
                data: serde_json::json!({
                    "identity": SerializableIdentity::from(export.identity),
                    "credentials": export
                        .credentials
                        .into_iter()
                        .map(SerializableCredential::from)
                        .collect::<Vec<_>>(),
                }),
            })),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to export identity: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// 敏感字段 reveal + 重新认证
// ---------------------------------------------------------------------------

/// Extract a named secret field from decrypted credential data.
///
/// Pure function so the full field×type matrix is unit-testable.
/// Returns `Err` on invalid field names and on field/type mismatches
/// (e.g. requesting "ssh_private_key" from a Password credential).
pub(crate) fn extract_secret_field(
    data: &CredentialData,
    field: &str,
) -> std::result::Result<String, String> {
    match (data, field) {
        (CredentialData::Password(p), "password") => Ok(p.password.clone()),
        (CredentialData::Password(p), "security_questions") => serde_json::to_string(
            &p.security_questions
                .iter()
                .map(|q| serde_json::json!({ "question": q.question, "answer": q.answer }))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string()),
        (CredentialData::CryptoWallet(w), "wallet_private_key") => w
            .private_key
            .clone()
            .ok_or_else(|| "This wallet has no stored private key".to_string()),
        (CredentialData::CryptoWallet(w), "wallet_mnemonic") => w
            .mnemonic_phrase
            .clone()
            .ok_or_else(|| "This wallet has no stored mnemonic phrase".to_string()),
        (CredentialData::SshKey(k), "ssh_private_key") => Ok(k.private_key.clone()),
        (CredentialData::SshKey(k), "ssh_passphrase") => k
            .passphrase
            .clone()
            .ok_or_else(|| "This SSH key has no stored passphrase".to_string()),
        (CredentialData::ApiKey(a), "api_key") => Ok(a.api_key.clone()),
        (CredentialData::ApiKey(a), "api_secret") => a
            .api_secret
            .clone()
            .ok_or_else(|| "This API credential has no stored secret".to_string()),
        (CredentialData::ApiKey(a), "token") => a
            .token
            .clone()
            .ok_or_else(|| "This API credential has no stored token".to_string()),
        (CredentialData::Raw(raw), "raw_data") => {
            String::from_utf8(raw.clone()).map_err(|_| "Raw data is not valid UTF-8".to_string())
        }
        _ => Err(format!(
            "Field '{}' is not available for this credential type",
            field
        )),
    }
}

/// Reveal a single secret field of a credential (sensitive; re-auth gated +
/// audited via the underlying decrypt)
#[command]
pub async fn reveal_credential_secret(
    request: RevealSecretRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SecretRevealResponse>, String> {
    let uuid = match Uuid::from_str(&request.credential_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_credential_data(&uuid).await {
            Ok(Some(data)) => match extract_secret_field(&data, &request.field) {
                Ok(value) => Ok(ApiResponse::success(SecretRevealResponse {
                    field: request.field,
                    value,
                })),
                Err(msg) => Ok(ApiResponse::error(msg)),
            },
            Ok(None) => Ok(ApiResponse::error("Credential not found".to_string())),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to reveal secret: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Verify the master password to re-authorize sensitive operations
#[command]
pub async fn reauth_verify(
    request: ReauthRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => match service.authenticate_user(&request.master_password).await {
            Ok(persona_core::AuthResult::Success) => {
                // 恢复会话并刷新活动时间，让后续敏感操作直接放行
                if let Err(e) = service.unlock_session().await {
                    tracing::warn!("unlock_session after re-auth failed: {}", e);
                }
                service.touch_activity();
                Ok(ApiResponse::success(true))
            }
            Ok(persona_core::AuthResult::PasswordChangeRequired) => {
                Ok(ApiResponse::error_with_code(
                    crate::error::CODE_PASSWORD_CHANGE_REQUIRED.to_string(),
                    "Master password change required".to_string(),
                ))
            }
            Ok(persona_core::AuthResult::AccountLocked) => Ok(ApiResponse::error(
                "Account is locked due to too many failed attempts".to_string(),
            )),
            Ok(_) => Ok(ApiResponse::error("Invalid master password".to_string())),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Re-authentication failed: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// SSH agent 状态探测（平台相关 helper，供命令与测试共用）
// ---------------------------------------------------------------------------

pub(crate) fn agent_state_dir() -> PathBuf {
    std::env::var("PERSONA_AGENT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
        })
}

fn cleanup_agent_state_files() {
    let dir = agent_state_dir();
    for name in &["ssh-agent.sock", "ssh-agent.pid"] {
        let path = dir.join(name);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
}

fn read_agent_status(running_hint: bool) -> SshAgentStatus {
    let dir = agent_state_dir();
    let sock_path = dir.join("ssh-agent.sock");
    let pid_path = dir.join("ssh-agent.pid");
    let socket_value = if sock_path.exists() {
        fs::read_to_string(&sock_path)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    };
    let pid_value = if pid_path.exists() {
        fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    } else {
        None
    };
    let key_count = socket_value
        .as_deref()
        .and_then(|sock| query_agent_key_count(sock).ok());

    SshAgentStatus {
        running: running_hint || socket_value.is_some() || pid_value.is_some(),
        socket_path: socket_value,
        pid: pid_value,
        key_count,
        state_dir: dir.to_string_lossy().to_string(),
    }
}

#[cfg(unix)]
pub(crate) fn query_agent_key_count(sock_path: &str) -> std::result::Result<usize, String> {
    use byteorder::{BigEndian, ByteOrder};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream =
        UnixStream::connect(sock_path).map_err(|e| format!("Failed to connect to agent: {}", e))?;
    // request identities: len=1 payload 11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11;
    stream.write_all(&pkt).map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(|e| e.to_string())?;
    if resp.is_empty() || resp[0] != 12 {
        return Err("Unexpected agent response".to_string());
    }
    if resp.len() < 5 {
        return Err("Malformed agent response".to_string());
    }
    let count = BigEndian::read_u32(&resp[1..5]) as usize;
    Ok(count)
}

#[cfg(not(unix))]
fn query_agent_key_count(_sock_path: &str) -> std::result::Result<usize, String> {
    Err("Agent key count not supported on this platform".to_string())
}

// -----------------------------------------------------------------------
// Connect 本机自动化（CONNECT_AUTOMATION_DESIGN DR-1/DR-4/DR-5）。服务面
// 在 connect_server.rs（三防线/限额/端点）；这里只做生命周期命令与 token
// 管理命令。错误模式与命令层一致：业务失败一律 Ok(ApiResponse::error)，
// reauth 走 map_persona_error 的 REAUTH_REQUIRED 码。
// -----------------------------------------------------------------------

/// Connect listener 运行状态（设置页渲染 + 自动化开关判定）。
#[derive(Debug, Serialize)]
pub struct ConnectServerStatus {
    pub running: bool,
    /// listener 实际端口（未运行 = None；端口 0 = OS 分配后的真实值）。
    pub port: Option<u16>,
}

/// token 管理列表视图——剥除哈希（哈希不出库；列表只展示指纹）。
#[derive(Debug, Serialize)]
pub struct ConnectTokenView {
    pub id: String,
    pub label: String,
    pub fingerprint: String,
    pub scope: persona_core::connect::ConnectTokenScope,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl From<&persona_core::connect::ConnectTokenRow> for ConnectTokenView {
    fn from(row: &persona_core::connect::ConnectTokenRow) -> Self {
        Self {
            id: row.id.to_string(),
            label: row.label.clone(),
            fingerprint: row.fingerprint.clone(),
            scope: row.scope.clone(),
            created_at: row.created_at.to_rfc3339(),
            last_used_at: row.last_used_at.map(|t| t.to_rfc3339()),
            revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// 创建成功响应：明文 token 只此一次（前端展示 + 复制，关闭后无法再查）。
#[derive(Debug, Serialize)]
pub struct ConnectTokenCreatedView {
    pub token: String,
    pub info: ConnectTokenView,
}

async fn connect_server_status_of(state: &State<'_, AppState>) -> ConnectServerStatus {
    let guard = state.connect_server.lock().await;
    match guard.as_ref() {
        Some(handle) => ConnectServerStatus {
            running: true,
            port: Some(handle.port),
        },
        None => ConnectServerStatus {
            running: false,
            port: None,
        },
    }
}

/// 启动 Connect listener（bind 硬编码 127.0.0.1；端口 None = 0 = OS 分配）。
/// 需要解锁会话；已运行时报错（前端先 stop 或按状态渲染）。
#[command]
pub async fn connect_server_start(
    state: State<'_, AppState>,
    port: Option<u16>,
) -> std::result::Result<ApiResponse<ConnectServerStatus>, String> {
    {
        let guard = state.connect_server.lock().await;
        if guard.is_some() {
            return Ok(ApiResponse::error(
                "Connect server is already running".to_string(),
            ));
        }
    }
    let unlocked = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => false,
        }
    };
    if !unlocked {
        return Ok(ApiResponse::error_with_code(
            crate::error::CODE_SERVICE_LOCKED.to_string(),
            "Vault must be unlocked before starting the Connect server".to_string(),
        ));
    }
    match crate::connect_server::start_connect_server(state.service.clone(), port.unwrap_or(0))
        .await
    {
        Ok(handle) => {
            let status = ConnectServerStatus {
                running: true,
                port: Some(handle.port),
            };
            let mut guard = state.connect_server.lock().await;
            // 竞态防御：重入时后到者不写槽（先到者已持有 listener），
            // 后到的 handle 直接 drop（oneshot sender drop = 没有启动过
            // 的 shutdown 通道被丢弃，不影响先到 listener）。
            if guard.is_some() {
                drop(handle);
                return Ok(ApiResponse::error(
                    "Connect server is already running".to_string(),
                ));
            }
            *guard = Some(handle);
            Ok(ApiResponse::success(status))
        }
        Err(e) => Ok(ApiResponse::error(format!("Failed to start: {}", e))),
    }
}

/// 停止 Connect listener（幂等：未运行返回 running=false）。
#[command]
pub async fn connect_server_stop(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<ConnectServerStatus>, String> {
    let handle = state.connect_server.lock().await.take();
    if let Some(handle) = handle {
        handle.stop();
    }
    Ok(ApiResponse::success(ConnectServerStatus {
        running: false,
        port: None,
    }))
}

/// 查询 Connect listener 运行状态。
#[command]
pub async fn connect_server_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<ConnectServerStatus>, String> {
    Ok(ApiResponse::success(connect_server_status_of(&state).await))
}

/// 创建 Connect token（敏感操作：core 权威 reauth 门禁；明文仅响应一次）。
#[command]
pub async fn connect_token_create(
    state: State<'_, AppState>,
    label: String,
    scope: persona_core::connect::ConnectTokenScope,
) -> std::result::Result<ApiResponse<ConnectTokenCreatedView>, String> {
    let result = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.create_connect_token(label, scope).await,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    match result {
        Ok((token, row)) => Ok(ApiResponse::success(ConnectTokenCreatedView {
            token,
            info: ConnectTokenView::from(&row),
        })),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            })
        }
    }
}

/// token 管理列表（含已吊销，剥除哈希）。敏感面：需解锁会话。
#[command]
pub async fn connect_token_list(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<ConnectTokenView>>, String> {
    let result = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.list_connect_tokens().await,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    match result {
        Ok(rows) => Ok(ApiResponse::success(
            rows.iter().map(ConnectTokenView::from).collect(),
        )),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            })
        }
    }
}

/// 吊销 Connect token（幂等；core 权威 reauth 门禁）。即时生效。
#[command]
pub async fn connect_token_revoke(
    state: State<'_, AppState>,
    id: String,
) -> std::result::Result<ApiResponse<bool>, String> {
    let token_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return Ok(ApiResponse::error(format!("Invalid token id: {}", id))),
    };
    let result = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.revoke_connect_token(&token_id).await,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    match result {
        Ok(revoked) => Ok(ApiResponse::success(revoked)),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use persona_core::models::Identity;

    async fn setup_wallet_test_db() -> (tempfile::TempDir, Database, Identity) {
        // 委托共享夹具（test_support.rs），避免每套测试重建样板
        let fixture = crate::test_support::test_db().await;
        (fixture._dir, fixture.db, fixture.identity)
    }

    #[tokio::test]
    async fn wallet_import_request_imports_bitcoin_wif_as_single_address_wallet() {
        let (_dir, _db, identity) = setup_wallet_test_db().await;
        let request = WalletImportRequest {
            name: "BTC WIF".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "wif".to_string(),
            data: "KzgibHVnBeHWb4vnmrqXfJcEcfPQbYC2xPxz932rCiHxSc8u3GhA".to_string(),
            password: "test_password".to_string(),
            address_count: None,
        };

        let wallet = import_wallet_from_request(identity.id, &request).unwrap();

        assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
        assert!(matches!(
            wallet.wallet_type,
            persona_core::models::wallet::WalletType::SingleAddress
        ));
        assert_eq!(wallet.addresses.len(), 1);
        assert!(!wallet.watch_only);
    }

    #[tokio::test]
    async fn wallet_import_request_rejects_short_passwords() {
        let (_dir, _db, identity) = setup_wallet_test_db().await;
        let request = WalletImportRequest {
            name: "Bad Wallet".to_string(),
            network: "Ethereum".to_string(),
            import_type: "private_key".to_string(),
            data: "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b".to_string(),
            password: "short".to_string(),
            address_count: None,
        };

        let error = import_wallet_from_request(identity.id, &request).unwrap_err();
        assert_eq!(error, "Wallet password must be at least 8 characters");
    }

    #[tokio::test]
    async fn wallet_export_request_requires_password_for_wif() {
        let (_dir, _db, identity) = setup_wallet_test_db().await;
        let import_request = WalletImportRequest {
            name: "BTC WIF".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "private_key".to_string(),
            data: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            password: "test_password".to_string(),
            address_count: None,
        };
        let wallet = import_wallet_from_request(identity.id, &import_request).unwrap();

        let export_request = WalletExportRequest {
            wallet_id: wallet.id.to_string(),
            format: "wif".to_string(),
            include_private: false,
            password: None,
        };

        let error = export_wallet_from_request(&wallet, &export_request).unwrap_err();
        assert_eq!(error, "Password required for WIF export");
    }

    #[tokio::test]
    async fn wallet_delete_removes_wallet_from_repository() {
        let (_dir, db, identity) = setup_wallet_test_db().await;
        let repo = CryptoWalletRepository::new(Arc::new(db));
        let request = WalletImportRequest {
            name: "ETH Wallet".to_string(),
            network: "Ethereum".to_string(),
            import_type: "private_key".to_string(),
            data: "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b".to_string(),
            password: "test_password".to_string(),
            address_count: None,
        };
        let wallet = import_wallet_from_request(identity.id, &request).unwrap();
        let created = repo.create(&wallet).await.unwrap();

        let deleted = repo.delete(&created.id).await.unwrap();
        let fetched = repo.find_by_id(&created.id).await.unwrap();

        assert!(deleted);
        assert!(fetched.is_none());
    }

    // -------------------------------------------------------------------------
    // extract_secret_field：字段 × 类型矩阵
    // -------------------------------------------------------------------------

    fn password_data() -> CredentialData {
        CredentialData::Password(PasswordCredentialData {
            password: "hunter2".to_string(),
            email: Some("a@b.c".to_string()),
            security_questions: vec![SecurityQuestion {
                question: "Pet?".to_string(),
                answer: "Cat".to_string(),
            }],
        })
    }

    #[test]
    fn reveal_extracts_password_and_questions() {
        let data = password_data();
        assert_eq!(extract_secret_field(&data, "password").unwrap(), "hunter2");
        let qs = extract_secret_field(&data, "security_questions").unwrap();
        assert!(qs.contains("Pet?") && qs.contains("Cat"));
    }

    #[test]
    fn reveal_extracts_ssh_key_and_flags_missing_passphrase() {
        let data = CredentialData::SshKey(SshKeyData {
            private_key: "-----BEGIN".to_string(),
            public_key: "ssh-ed25519 AAA".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        });
        assert_eq!(
            extract_secret_field(&data, "ssh_private_key").unwrap(),
            "-----BEGIN"
        );
        assert!(extract_secret_field(&data, "ssh_passphrase").is_err());
        // 跨类型取 password 必须失败
        assert!(extract_secret_field(&data, "password").is_err());
    }

    #[test]
    fn reveal_extracts_api_fields_and_flags_missing_ones() {
        let data = CredentialData::ApiKey(ApiKeyData {
            api_key: "key123".to_string(),
            api_secret: Some("secret456".to_string()),
            token: None,
            permissions: vec![],
            expires_at: None,
        });
        assert_eq!(extract_secret_field(&data, "api_key").unwrap(), "key123");
        assert_eq!(
            extract_secret_field(&data, "api_secret").unwrap(),
            "secret456"
        );
        assert!(extract_secret_field(&data, "token").is_err());
    }

    #[test]
    fn reveal_extracts_wallet_secrets_only_when_present() {
        let empty = CredentialData::CryptoWallet(CryptoWalletData {
            wallet_type: "evm".to_string(),
            mnemonic_phrase: None,
            private_key: None,
            public_key: "pub".to_string(),
            address: "0x0".to_string(),
            network: "Ethereum".to_string(),
        });
        assert!(extract_secret_field(&empty, "wallet_private_key").is_err());
        assert!(extract_secret_field(&empty, "wallet_mnemonic").is_err());

        let full = CredentialData::CryptoWallet(CryptoWalletData {
            wallet_type: "evm".to_string(),
            mnemonic_phrase: Some("test test".to_string()),
            private_key: Some("0xabc".to_string()),
            public_key: "pub".to_string(),
            address: "0x0".to_string(),
            network: "Ethereum".to_string(),
        });
        assert_eq!(
            extract_secret_field(&full, "wallet_private_key").unwrap(),
            "0xabc"
        );
    }

    #[test]
    fn reveal_raw_requires_utf8_and_unknown_field_fails() {
        let raw = CredentialData::Raw("hello".to_string().into_bytes());
        assert_eq!(extract_secret_field(&raw, "raw_data").unwrap(), "hello");
        assert!(extract_secret_field(&raw, "nope").is_err());
        assert!(
            extract_secret_field(&CredentialData::Raw(vec![0xff]), "raw_data").is_err(),
            "非 UTF-8 原始数据必须报错"
        );
    }

    // -------------------------------------------------------------------------
    // build_health_scan_config：扫描参数解析
    // -------------------------------------------------------------------------

    #[test]
    fn health_scan_empty_request_uses_core_defaults() {
        let c = build_health_scan_config(&HealthScanRequest::default());
        assert_eq!(
            c,
            persona_core::HealthScanConfig {
                min_password_score: persona_core::DEFAULT_MIN_PASSWORD_SCORE,
                expiry_warning_days: persona_core::DEFAULT_EXPIRY_WARNING_DAYS,
                stale_after_days: persona_core::DEFAULT_STALE_AFTER_DAYS,
            }
        );
    }

    #[test]
    fn health_scan_request_overrides_each_field() {
        let raw = serde_json::json!({
            "min_password_score": 2,
            "expiry_warning_days": 7,
            "stale_after_days": 90
        });
        let request: HealthScanRequest = serde_json::from_value(raw).unwrap();
        let c = build_health_scan_config(&request);
        assert_eq!(c.min_password_score, 2);
        assert_eq!(c.expiry_warning_days, 7);
        assert_eq!(c.stale_after_days, 90);

        // 前端可以只传部分字段，其余回落默认值
        let partial: HealthScanRequest =
            serde_json::from_value(serde_json::json!({ "min_password_score": 1 })).unwrap();
        let c = build_health_scan_config(&partial);
        assert_eq!(c.min_password_score, 1);
        assert_eq!(
            c,
            persona_core::HealthScanConfig {
                min_password_score: 1,
                expiry_warning_days: persona_core::DEFAULT_EXPIRY_WARNING_DAYS,
                stale_after_days: persona_core::DEFAULT_STALE_AFTER_DAYS,
            }
        );
    }

    #[test]
    fn health_scan_check_breaches_flag_parses_with_default_off() {
        // 缺省 = 不查泄露库
        let absent: HealthScanRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(absent.check_breaches, None);

        let on: HealthScanRequest =
            serde_json::from_value(serde_json::json!({ "check_breaches": true })).unwrap();
        assert_eq!(on.check_breaches, Some(true));
        // flag 不影响扫描配置本体
        assert_eq!(build_health_scan_config(&on), HealthScanConfig::default());
    }

    // -------------------------------------------------------------------------
    // build_audit_query：过滤参数解析
    // -------------------------------------------------------------------------

    #[test]
    fn audit_query_empty_request_uses_defaults() {
        let q = build_audit_query(&AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        })
        .unwrap();
        assert!(!q.failures_only);
        assert!(!q.security_sensitive_only);
        assert!(q.time_range.is_none() && q.action.is_none() && q.limit.is_none());
    }

    #[test]
    fn audit_query_parses_action_time_and_rejects_garbage() {
        let q = build_audit_query(&AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: Some("identity_created".to_string()),
            failures_only: Some(true),
            security_sensitive_only: None,
            time_range: Some((
                "2026-01-01T00:00:00Z".to_string(),
                "2026-02-01T00:00:00Z".to_string(),
            )),
            limit: Some(50),
        })
        .unwrap();
        assert!(q.failures_only);
        assert_eq!(q.limit, Some(50));
        assert!(q.time_range.is_some());

        let mut bad = AuditQueryRequest {
            action: Some("not_a_real_action".to_string()),
            ..AuditQueryRequest {
                user_id: None,
                identity_id: None,
                action: None,
                failures_only: None,
                security_sensitive_only: None,
                time_range: None,
                limit: None,
            }
        };
        // 未知动作名按 core 语义解析为 Custom（查询合法，结果为空），不报错
        assert!(build_audit_query(&bad).is_ok());
        bad.action = None;
        bad.identity_id = Some("not-a-uuid".to_string());
        assert!(build_audit_query(&bad).is_err());
    }

    /// parse_network 的全部别名臂（大小写不敏感，未知值 → Custom）。
    #[test]
    fn parse_network_covers_every_alias_arm() {
        use persona_core::models::wallet::BlockchainNetwork;

        let cases: &[(&str, BlockchainNetwork)] = &[
            ("bitcoin", BlockchainNetwork::Bitcoin),
            ("BTC", BlockchainNetwork::Bitcoin),
            ("ethereum", BlockchainNetwork::Ethereum),
            ("ETH", BlockchainNetwork::Ethereum),
            ("solana", BlockchainNetwork::Solana),
            ("SOL", BlockchainNetwork::Solana),
            ("bitcoin-cash", BlockchainNetwork::BitcoinCash),
            ("Bitcoin Cash", BlockchainNetwork::BitcoinCash),
            ("bitcoincash", BlockchainNetwork::BitcoinCash),
            ("BCH", BlockchainNetwork::BitcoinCash),
            ("litecoin", BlockchainNetwork::Litecoin),
            ("LTC", BlockchainNetwork::Litecoin),
            ("dogecoin", BlockchainNetwork::Dogecoin),
            ("DOGE", BlockchainNetwork::Dogecoin),
            ("polygon", BlockchainNetwork::Polygon),
            ("MATIC", BlockchainNetwork::Polygon),
            ("arbitrum", BlockchainNetwork::Arbitrum),
            ("ARB", BlockchainNetwork::Arbitrum),
            ("optimism", BlockchainNetwork::Optimism),
            ("OP", BlockchainNetwork::Optimism),
            ("binance", BlockchainNetwork::BinanceSmartChain),
            ("bsc", BlockchainNetwork::BinanceSmartChain),
            ("BNB", BlockchainNetwork::BinanceSmartChain),
            ("Binance Smart Chain", BlockchainNetwork::BinanceSmartChain),
            (
                "Fancy Chain",
                BlockchainNetwork::Custom("fancy chain".to_string()),
            ),
        ];
        for (input, expected) in cases {
            // to_lowercase 在函数内做，输入大小写自由。
            let got = parse_network(&input.to_lowercase())
                .unwrap_or_else(|e| panic!("parse_network({input}) errored: {e}"));
            assert_eq!(&got, expected, "arm for {input}");
        }
        // 直接传原样输入（不做预 lowercase）再验一次未知臂路径。
        let custom = parse_network("FancyChain").unwrap();
        assert_eq!(custom, BlockchainNetwork::Custom("fancychain".to_string()));
    }

    /// serialize_wallet_address 的全部 AddressType 标签臂 + 余额缺省。
    #[test]
    fn serialize_wallet_address_covers_every_address_type() {
        use persona_core::models::wallet::{AddressType, WalletAddress};

        let addr = |address_type: AddressType| WalletAddress {
            address: "addr".to_string(),
            address_type,
            derivation_path: Some("m/0".to_string()),
            index: 3,
            used: true,
            balance: None,
            last_activity: None,
            metadata: std::collections::HashMap::new(),
            created_at: chrono::Utc::now(),
        };

        let cases = [
            (AddressType::P2PKH, "P2PKH"),
            (AddressType::P2SH, "P2SH"),
            (AddressType::P2WPKH, "P2WPKH"),
            (AddressType::P2TR, "P2TR"),
            (AddressType::Ethereum, "ETH"),
            (AddressType::Solana, "SOL"),
        ];
        for (address_type, label) in cases {
            let serialized = serialize_wallet_address(addr(address_type.clone()));
            assert_eq!(serialized.address_type, label);
            assert_eq!(serialized.index, 3);
            assert!(serialized.used);
            assert_eq!(serialized.balance, "-", "missing balance renders as dash");
            assert_eq!(serialized.derivation_path.as_deref(), Some("m/0"));
        }
        let custom = serialize_wallet_address(addr(AddressType::Custom("nft-vault".to_string())));
        assert_eq!(custom.address_type, "nft-vault");
    }
}
