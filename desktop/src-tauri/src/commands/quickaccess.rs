use super::*;

/// 解锁成功后按 DB 真值重放 Quick Access 全局热键（开关 + 绑定）。
///
/// 每次解锁都重放而不是"与上次一致就跳过"：绑定可能被另一端改过
/// （CLI 手改 settings JSON / 换了台机器同步来的 vault），重放的代价是
/// 一次 unregister_all + 一次 register，换来的是任何改法都在下次解锁
/// 收敛。**读 settings 失败只 warn**——全局热键是增强功能，绝不阻断解锁。
pub(crate) async fn apply_quick_access<R: tauri::Runtime>(
    state: &State<'_, AppState>,
    app: &tauri::AppHandle<R>,
    db_path: &str,
) {
    let db = match Database::from_file(db_path).await {
        Ok(db) => db,
        Err(e) => {
            tracing::warn!("quick access: open vault failed: {}", e);
            return;
        }
    };
    if let Err(e) = db.migrate().await {
        tracing::warn!("quick access: vault migrate failed: {}", e);
        return;
    }
    let workspace_path = workspace_path_for_db_path(db_path);
    match ensure_workspace_for_path(&db, &workspace_path).await {
        Ok(ws) => crate::quick_access::apply_from_settings(app, &state.quick_access, &ws.settings),
        Err(e) => tracing::warn!("quick access: workspace metadata unavailable: {}", e),
    }
}

/// 读 Quick Access 状态面（**免解锁**：绑定与开关在 workspace settings 里，
/// 锁定后浮窗/设置页仍要如实显示"热键到底生效没有"）。
///
/// 运行态取自 `AppState.quick_access`（真实抢注结果），配置侧取自 DB——
/// 两者不一致正是要暴露给人看的事：抢注失败时 configured 有值而 registered
/// 为空，UI 据此显示"未生效 + 原因"。
#[command]
pub async fn quick_access_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::quick_access::QuickAccessStatus>, String> {
    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);
    let workspace_path = workspace_path_for_db_path(&db_path);
    let ws = workspace_or_return!(db, workspace_path);

    let runtime = state
        .quick_access
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Ok(ApiResponse::success(runtime.snapshot(&ws.settings)))
}

/// 设置 Quick Access 开关与绑定：解锁门禁 → 校验语法 → 落库 → 重注册。
///
/// 写入要过解锁门禁（同 `set_locale` / `set_feature_flags` / `set_password_expiry`）：
/// 读（status）免解锁是给锁屏/设置页看"热键到底生效没有"用的，改配置
/// 不该在锁定态发生。
///
/// 落库在前是刻意的：重注册成功但落库失败会留下"内存里热键变了、DB 里
/// 没变"的漂移（下次解锁又被 DB 拉回去，用户以为改绑失败）。抢注失败
/// **不算命令失败**——绑定已持久化，返回体里带 `error` 让设置页如实显示
/// （Wayland 无 portal / 被别的应用占用是常态，不是错误流）。
#[command]
pub async fn quick_access_set<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    enabled: bool,
    accelerator: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::quick_access::QuickAccessStatus>, String> {
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

    // 语法校验先行：非法串不落库（否则下次解锁还在反复失败）
    let normalized = match accelerator.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            let normalized = crate::quick_access::normalize_accelerator(raw);
            if let Err(err) = crate::quick_access::parse_accelerator(&normalized) {
                return Ok(ApiResponse::error(err));
            }
            Some(normalized)
        }
        // 空串 = 恢复平台默认绑定（存 None，不把默认值钉进 DB）
        _ => None,
    };

    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);
    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.settings.quick_access_enabled = enabled;
    ws.settings.quick_access_hotkey = normalized.clone();
    ws.touch();
    ok_or_error_response!(repo.update(&ws).await);

    let status = crate::quick_access::apply_explicit(
        &app,
        &state.quick_access,
        enabled,
        normalized.as_deref(),
    );
    Ok(ApiResponse::success(status))
}

/// 从托盘菜单/设置页直接拉起浮窗（不依赖全局热键——热键被占用时它仍是入口）
#[command]
pub async fn quick_access_open<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    crate::quick_access::open(&app);
    Ok(ApiResponse::success(true))
}

/// 读生成器热键状态面（免解锁，语义同 [`quick_access_status`]）
#[command]
pub async fn generator_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::quick_access::GeneratorStatus>, String> {
    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);
    let workspace_path = workspace_path_for_db_path(&db_path);
    let ws = workspace_or_return!(db, workspace_path);

    let runtime = state
        .quick_access
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Ok(ApiResponse::success(
        crate::quick_access::GeneratorStatus::snapshot(&runtime, &ws.settings),
    ))
}

/// 设置生成器热键开关与绑定（语义同 [`quick_access_set`]：解锁门禁 →
/// 语法校验 → 落库 → 重注册，抢注失败不算命令失败）
#[command]
pub async fn generator_set<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    enabled: bool,
    accelerator: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::quick_access::GeneratorStatus>, String> {
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

    // 语法校验先行：非法串不落库（否则下次解锁还在反复失败）
    let normalized = match accelerator.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            let normalized = crate::quick_access::normalize_accelerator(raw);
            if let Err(err) = crate::quick_access::parse_accelerator(&normalized) {
                return Ok(ApiResponse::error(err));
            }
            Some(normalized)
        }
        // 空串 = 恢复平台默认绑定（存 None，不把默认值钉进 DB）
        _ => None,
    };

    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);
    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.settings.generator_panel_enabled = enabled;
    ws.settings.generator_panel_hotkey = normalized.clone();
    ws.touch();
    ok_or_error_response!(repo.update(&ws).await);

    let status = crate::quick_access::apply_explicit_generator(
        &app,
        &state.quick_access,
        enabled,
        normalized.as_deref(),
    );
    Ok(ApiResponse::success(status))
}

/// 从托盘菜单直接拉起生成器浮窗（语义同 [`quick_access_open`]）
#[command]
pub async fn generator_open<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    crate::quick_access::open_generator(&app);
    Ok(ApiResponse::success(true))
}

/// 浮窗里"在 Persona 中打开"：定向通知主窗口切身份 + 选中条目，并把主
/// 窗口拉到前台。两个窗口各有独立 JS store，跨窗跳转只能走事件（载荷
/// 见 `quick_access::OpenCredentialPayload`）
#[command]
pub async fn quick_access_open_credential<R: tauri::Runtime>(
    request: QuickAccessOpenCredentialRequest,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    // UUID 形态先过一遍：主窗口拿到非法 id 只会静默不选中，白跑一趟
    if Uuid::from_str(&request.identity_id).is_err()
        || Uuid::from_str(&request.credential_id).is_err()
    {
        return Ok(ApiResponse::error("Invalid UUID format".to_string()));
    }
    let delivered = crate::quick_access::open_credential_in_main(
        &app,
        &request.identity_id,
        &request.credential_id,
    );
    if delivered {
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error("Main window unavailable".to_string()))
    }
}

/// 查询桌面填充注入目标状态（#12）。前端据此决定浮窗填充动作是否可用
///（未捕获/已失效时点了也只会报错，提前暴露状态更诚实）。
/// 就绪态与真实状态一致（安全评审 P2 收紧）：Windows 上对槽位做指纹
/// 重验证，已失效目标（窗口关闭/复用/进程更换）即时清槽并报 not ready。
#[command]
pub async fn fill_target_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::desktop_fill::FillTargetStatus>, String> {
    let supported = crate::desktop_fill::fill_supported();
    let mut guard = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
    // 注入路径就绪 = 快照存在且当前指纹（hwnd 存活 + pid + 类名 + 可执行
    // 文件 + 标题前缀）仍然一致；失效即刻丢弃。非 Windows 平台无指纹
    // 校验能力，槽位本应为空，防御性视为失效。
    let still_valid = match guard.as_ref() {
        Some(t) => {
            #[cfg(target_os = "windows")]
            {
                crate::desktop_fill::win::validate_target(t, std::process::id())
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = t;
                false
            }
        }
        None => false,
    };
    if !still_valid {
        *guard = None;
    }
    let target = guard.as_ref();
    let ready = still_valid;
    let target_title = target.map(|t| t.title.clone());
    let target_app = target.map(|t| crate::desktop_fill::exe_file_name(&t.exe_path));
    let snapshot_id = target.map(|t| t.snapshot_id.clone());
    drop(guard);
    Ok(ApiResponse::success(
        crate::desktop_fill::FillTargetStatus {
            supported,
            ready,
            target_title,
            target_app,
            snapshot_id,
        },
    ))
}

/// 桌面应用内填充注入（#12）：把凭据的用户名/密码注入到检索浮窗唤起前
/// 持有前台的目标窗口。范围（诚实边界，见 desktop_fill 模块注释）：
/// - 仅 Windows（其余平台 `fill_supported()` = false，如实报错）；
/// - 仅经典 Win32 EDIT 控件宿主（自绘/浏览器宿主不适用，浏览器归扩展）；
/// - 仅 Password 类型凭据（用户名 + 密码两个字段）；
/// - 仅注入带 `ES_PASSWORD` 样式且可见/启用/非只读的密码框——没有合格
///   密码框即拒绝，普通框永不充当密码框（安全评审 P1 收紧）；
/// - **必须先经用户确认**：浮窗展示目标应用名（可执行文件名）与窗口标题，
///   用户显式确认后前端才带 `confirmed = true` 调用本命令；`confirmed`
///   缺失/为 false 一律拒绝——不存在静默注入路径。
/// - **确认绑定具体快照（P1 收紧）**：前端确认时带回捕获生成的
///   `snapshot_id`；解密（在途窗口）完成后锁内按 id 与当前槽位比对——
///   槽位已空（浮窗收起清槽）如实报 `FILL_TARGET_DISCARDED`，槽位已被
///   重新捕获替换（确认 A 后又捕获了 B）如实报 `FILL_TARGET_CHANGED`，
///   在途请求绝不转投新目标。
/// 敏感面与 reveal_credential_secret 同级：走 `get_credential_data` 解密
/// 路径（自带审计与 re-auth 门禁）。
#[command]
pub async fn desktop_fill_credential(
    credential_id: String,
    confirmed: bool,
    snapshot_id: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::desktop_fill::DesktopFillResult>, String> {
    // 平台诚实性：非 Windows 不假装有功能
    if !crate::desktop_fill::fill_supported() {
        return Ok(ApiResponse::error(
            "Desktop fill injection is only implemented on Windows".to_string(),
        ));
    }
    // 用户确认面（安全评审 P1）：目标应用名已在浮窗展示并由用户显式确认，
    // 后端只放行显式确认的调用。确认不是授权边界本身（目标指纹才是），
    // 但它是"不可静默直写"的硬门。
    if !confirmed {
        return Ok(ApiResponse::error(
            "Desktop fill requires explicit user confirmation of the target app".to_string(),
        ));
    }
    let uuid = match Uuid::from_str(&credential_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return Ok(ApiResponse::error("Service not initialized".to_string()));
    };
    // 用户名走元数据（低敏），密码走解密路径（与 reveal 同一审计面）
    let credential = match service.get_credential(&uuid).await {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(ApiResponse::error("Credential not found".to_string())),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            return Ok(ApiResponse::error_maybe_coded(code, msg));
        }
    };
    let data = match service.get_credential_data(&uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(ApiResponse::error("Credential not found".to_string())),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            return Ok(ApiResponse::error_maybe_coded(code, msg));
        }
    };
    let password = match extract_secret_field(&data, "password") {
        Ok(p) => p,
        Err(msg) => {
            return Ok(ApiResponse::error(format!(
                "Desktop fill supports password credentials only: {msg}"
            )))
        }
    };
    let username = credential.username.unwrap_or_default();

    // 确认绑定具体快照（P1 收紧）：解密是在途窗口——期间浮窗可能被重新
    // 唤起捕获了别的目标，也可能已收起清槽。持锁按请求携带的 snapshot_id
    // 绑定后克隆（注入是慢 FFI 调用，锁外执行；注入目标因此就是被确认的
    // 那份快照，指纹重验证 + 逐控件重验证都锚定它，而非「此刻槽位里的目标」）。
    // 绑定之后注入仍在锁外——第四轮取消边界收口：注入循环内每个字段写入
    // 前经 `slot_recheck_for` 重查槽位（与绑定比较同一语义），清槽/换目标
    // 即中止剩余写入并如实报部分完成（`FILL_TARGET_DISCARDED` /
    // `FILL_TARGET_CHANGED`），不把凭据的任何字段写进非确认目标。
    let target = {
        let guard = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
        match crate::desktop_fill::bind_confirmed_snapshot(guard.as_ref(), snapshot_id.as_deref()) {
            Ok(t) => t,
            Err(crate::desktop_fill::ConfirmBindRejection::SnapshotRequired) => {
                return Ok(ApiResponse::error_maybe_coded(
                    Some("FILL_TARGET_SNAPSHOT_REQUIRED".to_string()),
                    "Desktop fill confirmation must carry the snapshot id it confirmed".to_string(),
                ));
            }
            Err(crate::desktop_fill::ConfirmBindRejection::TargetDiscarded) => {
                return Ok(ApiResponse::error_maybe_coded(
                    Some("FILL_TARGET_DISCARDED".to_string()),
                    "Confirmed fill target was discarded (floating window hidden or target cleared)"
                        .to_string(),
                ));
            }
            Err(crate::desktop_fill::ConfirmBindRejection::TargetChanged) => {
                return Ok(ApiResponse::error_maybe_coded(
                    Some("FILL_TARGET_CHANGED".to_string()),
                    "Fill target changed after confirmation (a new window was captured); refusing to fill into the new target"
                        .to_string(),
                ));
            }
        }
    };
    let slot_recheck =
        crate::desktop_fill::slot_recheck_for(&state.fill_target, target.snapshot_id.clone());
    let (username_filled, password_filled, target_title) = match crate::desktop_fill::execute_fill(
        &target,
        &username,
        &password,
        std::process::id(),
        &slot_recheck,
    ) {
        Ok(result) => result,
        Err(crate::desktop_fill::FillError::Rejected(msg)) if msg == "CAPTURED_TARGET_INVALID" => {
            // 失效目标即刻丢弃，避免下一次再撞同一堵墙——但只丢弃仍是
            // 本请求确认的那份快照：槽位若已被新一轮捕获（别的目标），
            // 不能替用户清掉它
            let mut guard = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
            if guard.as_ref().map(|t| t.snapshot_id.as_str()) == Some(target.snapshot_id.as_str()) {
                *guard = None;
            }
            return Ok(ApiResponse::error(
                "Captured fill target is no longer valid (window closed or reused)".to_string(),
            ));
        }
        Err(crate::desktop_fill::FillError::Rejected(msg)) => return Ok(ApiResponse::error(msg)),
        Err(crate::desktop_fill::FillError::Aborted {
            reason,
            username_filled,
            password_filled,
            title: _,
        }) => {
            let partial = format!(
                "partial completion reported honestly: username_filled={} password_filled={}",
                username_filled, password_filled
            );
            match reason {
                crate::desktop_fill::ConfirmBindRejection::TargetDiscarded => {
                    return Ok(ApiResponse::error_maybe_coded(
                        Some("FILL_TARGET_DISCARDED".to_string()),
                        format!(
                            "Confirmed fill target was discarded mid-fill ({partial}); no remaining field was written"
                        ),
                    ));
                }
                crate::desktop_fill::ConfirmBindRejection::TargetChanged => {
                    return Ok(ApiResponse::error_maybe_coded(
                        Some("FILL_TARGET_CHANGED".to_string()),
                        format!(
                            "Fill target changed mid-fill ({partial}); refusing to write remaining fields into the new target"
                        ),
                    ));
                }
                crate::desktop_fill::ConfirmBindRejection::SnapshotRequired => {
                    // 不可达：重查闭包恒携带快照 id；防御性按协议错处理
                    return Ok(ApiResponse::error_maybe_coded(
                        Some("FILL_TARGET_SNAPSHOT_REQUIRED".to_string()),
                        "Desktop fill confirmation must carry the snapshot id it confirmed"
                            .to_string(),
                    ));
                }
            }
        }
    };
    Ok(ApiResponse::success(
        crate::desktop_fill::DesktopFillResult {
            username_filled,
            password_filled,
            target_title,
            warning: None,
        },
    ))
}
