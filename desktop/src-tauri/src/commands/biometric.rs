use super::*;

/// biometric 命令的 vault 路径解析：参数优先（前端勾选自定义库路径时
/// 传入——一个 db_path 一把钥匙），其次本会话 db_path，最后默认路径
/// （解锁屏上 state.db_path 还是 None）。
pub(crate) async fn resolve_biometric_db_path(
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
pub(crate) async fn run_biometric_ceremony(
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

/// 本 vault 当前生效（或下一次 enable 将采用）的包裹档位，前端展示用。
/// wrap blob 存在 = 本 vault 解链已走硬件；否则按平台 capability 报档。
pub(crate) fn wrap_tier_for(state: &AppState, wrap_blob_exists: bool) -> String {
    use persona_core::BiometricWrapCapability as Cap;
    if wrap_blob_exists {
        return "hardware-bound".to_string();
    }
    match state.biometric_wrapper.capability() {
        Cap::HardwareBound => "hardware-bound".to_string(),
        Cap::OsGateOnly => "os-gate".to_string(),
        Cap::Unsupported => "unsupported".to_string(),
    }
}

/// 只读：biometric unlock 状态（免解锁——解锁屏 mount 即查，决定指纹
/// 按钮显隐）。`enabled` 只泄露"本 vault 是否配置过生物解锁"一位元
/// 数据（与 sync_token_present 同级）；托管的主密码/包裹 blob 真值永远
/// 不出 keyring、不经 IPC。
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
    let wrap_probe = state.biometric_wrap_store.get(&db_path);
    let tier = wrap_tier_for(&state, matches!(wrap_probe, Ok(Some(_))));
    let provider = state.biometric_provider.clone();
    let provider_available =
        tauri::async_runtime::spawn_blocking(move || provider.is_available(None))
            .await
            .unwrap_or(false);
    Ok(ApiResponse::success(BiometricStatusResponse {
        available: provider_available && entry_probe.is_ok() && wrap_probe.is_ok(),
        enabled: matches!(entry_probe, Ok(Some(_))) || matches!(wrap_probe, Ok(Some(_))),
        platform: crate::biometric::platform_name().to_string(),
        wrap_tier: tier,
    }))
}

/// 启用 biometric unlock：验主密码 → OS 认证弹框 → 托管（硬件绑定档：
/// 主密钥被平台硬件密钥包裹后 blob 进独立 keyring；门禁档：主密码托管进
/// keyring）。顺序刻意为先密码后弹框——密码是要托管的秘密，必须先证明
/// 正确（绝不把未验证的密码写进 keyring）；毫秒级验证先跑可 fail-fast，
/// 把系统级弹窗这个稀缺的注意力资源留到最后。设备指纹通过者 ≠ 必然
/// 知道 vault 主密码，已解锁会话中仍要求主密码 = 复用"敏感操作再认证"
/// 先例（1Password 启用 Touch ID 同款体验）。
#[command]
pub async fn biometric_enable(
    request: BiometricEnableRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BiometricStatusResponse>, String> {
    use base64::Engine;

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

    // 3. 托管：硬件绑定档（capability HardwareBound）走密钥包裹——主密钥
    //    被平台硬件密钥 ECIES 包裹后 blob 进独立 keyring service，密码
    //    条目不落盘；门禁档维持历史行为（密码托管）。ceremony 已花掉：
    //    写失败给明确错误，不留半态；用户改用密码登录不受影响。
    let use_hardware = state.biometric_wrapper.capability()
        == persona_core::BiometricWrapCapability::HardwareBound;
    if use_hardware {
        let wrap_result = {
            let guard = state.service.lock().await;
            match guard.as_ref() {
                Some(service) => {
                    service
                        .derive_master_key_for_wrap(&request.master_password)
                        .await
                }
                None => Err(anyhow::anyhow!(persona_core::PersonaError::NotFound(
                    "service not initialized".to_string(),
                ))),
            }
        };
        match wrap_result {
            Ok(master_key) => {
                // 包裹用公钥（不弹框；弹框在解锁侧的解密时刻）
                let wrapper = state.biometric_wrapper.clone();
                let envelope = tauri::async_runtime::spawn_blocking(move || {
                    persona_core::wrap_master_key(
                        wrapper.as_ref(),
                        &master_key,
                        "Enable biometric unlock for Persona",
                    )
                })
                .await
                .map_err(|e| format!("biometric wrap task failed: {}", e))?;
                match envelope {
                    Ok(envelope) => {
                        let blob = base64::engine::general_purpose::STANDARD.encode(&envelope);
                        if let Err(e) = state.biometric_wrap_store.set(&db_path, &blob) {
                            return Ok(ApiResponse::error(format!(
                                "Biometric verified but OS keyring write failed: {}",
                                e
                            )));
                        }
                        // 门禁层密码条目双保险清理（两类互斥；删失败只影响
                        // fallback 顺序，unlock 以 wrap 条目优先）
                        let _ = state.biometric_store.delete(&db_path);
                    }
                    Err(e) => {
                        return Ok(ApiResponse::error(format!(
                            "Hardware key wrap failed: {}",
                            e
                        )));
                    }
                }
            }
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Master key derivation failed: {}",
                    e
                )));
            }
        }
    } else if let Err(e) = state
        .biometric_store
        .set(&db_path, &request.master_password)
    {
        return Ok(ApiResponse::error(format!(
            "Biometric verified but OS keyring write failed: {}",
            e
        )));
    }

    let wrap_probe = state.biometric_wrap_store.get(&db_path);
    Ok(ApiResponse::success(BiometricStatusResponse {
        available: true,
        enabled: true,
        platform: crate::biometric::platform_name().to_string(),
        wrap_tier: wrap_tier_for(&state, matches!(wrap_probe, Ok(Some(_)))),
    }))
}

/// 禁用 biometric unlock：双删 keyring 条目（包裹 blob + 门禁层密码；
/// 各自幂等，连删两次都成功）。不需要 ceremony 也不设解锁门禁——这是
/// 收紧暴露面的操作（无敏感读取，删掉后解锁屏指纹按钮消失，主密码
/// 登录不受影响）。
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
    if let Err(e) = state.biometric_wrap_store.delete(&db_path) {
        return Ok(ApiResponse::error(format!(
            "OS keyring delete failed: {}",
            e
        )));
    }
    Ok(ApiResponse::success(BiometricStatusResponse {
        available: false,
        enabled: false,
        platform: crate::biometric::platform_name().to_string(),
        wrap_tier: wrap_tier_for(&state, false),
    }))
}

/// Secure Enclave spike 探针（macOS 真机专用，设计文档 §5.2）。
///
/// 跑 `macos_se::run_spike` 的全部探针并逐项回报 OSStatus/结论：调用方
/// 在真机上以 `PERSONA_BIOMETRIC_SE_SPIKE=1` 启动应用后调本命令，
/// 把输出贴回设计文档 §5.2。非 macOS 直接报 Unsupported（探针本身是
/// Security.framework 调用，无跨平台含义）；macOS 上未开 spike 门控
/// 也允许调用（探针只读/写自家 test key，不碰生产 unlock 链）。
#[command]
pub async fn biometric_wrap_spike(
) -> std::result::Result<ApiResponse<Vec<BiometricSpikeStep>>, String> {
    #[cfg(target_os = "macos")]
    {
        let steps = tauri::async_runtime::spawn_blocking(crate::biometric::macos_se::run_spike)
            .await
            .map_err(|e| format!("biometric spike task failed: {}", e))?;
        Ok(spike_response(
            steps.into_iter().map(|s| (s.name, s.ok, s.detail)),
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(ApiResponse::error(
            "biometric hardware spike is only available on macOS".to_string(),
        ))
    }
}

/// Passport KSP 探针（Windows 真机专用，设计文档 §6.1）。
///
/// 与 macOS 的 `biometric_wrap_spike` 同款：跑 `windows_tpm::run_spike`
/// 的全部探针并逐项回报 HRESULT/结论——在真机上以
/// `PERSONA_BIOMETRIC_TPM_SPIKE=1` 启动应用后调本命令，把输出贴回设计
/// 文档 §6.1。探针只碰自家包裹密钥，不接生产 unlock 链。非 Windows 直接
/// 报 Unsupported（探针本身是 NCrypt 调用，无跨平台含义）。
#[command]
pub async fn biometric_tpm_spike(
) -> std::result::Result<ApiResponse<Vec<BiometricSpikeStep>>, String> {
    #[cfg(target_os = "windows")]
    {
        let steps = tauri::async_runtime::spawn_blocking(crate::biometric::windows_tpm::run_spike)
            .await
            .map_err(|e| format!("biometric tpm spike task failed: {}", e))?;
        Ok(spike_response(
            steps.into_iter().map(|s| (s.name, s.ok, s.detail)),
        ))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(ApiResponse::error(
            "biometric hardware spike is only available on Windows".to_string(),
        ))
    }
}

/// 平台 spike 步骤 → 命令返回体（macOS SE 与 Windows TPM 两个探针共用；
/// 仅这两个平台调用，其余平台 cfg 掉免得 dead_code 警告）
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn spike_response(
    steps: impl IntoIterator<Item = (&'static str, bool, String)>,
) -> ApiResponse<Vec<BiometricSpikeStep>> {
    ApiResponse::success(
        steps
            .into_iter()
            .map(|(name, ok, detail)| BiometricSpikeStep {
                name: name.to_string(),
                ok,
                detail,
            })
            .collect(),
    )
}

/// 硬件绑定路径：解包裹 blob（SE/TPM 在解密那一刻强制生物识别）→ 以
/// 主密钥直进 init。blob 形状坏/解不开/注册集漂移 → 自动删除并返回
/// BIOMETRIC_RESET（回退链终态 = 主密码，绝不死锁）。
pub(crate) async fn biometric_unlock_with_wrap<R: tauri::Runtime>(
    wrap_blob: String,
    db_path: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> ApiResponse<bool> {
    use base64::Engine;
    use persona_core::BiometricWrapError as WrapErr;

    let envelope = match base64::engine::general_purpose::STANDARD.decode(&wrap_blob) {
        Ok(bytes) => bytes,
        Err(_) => {
            // blob 不是 base64：必坏，当场删除（与陈旧密码条目同自愈语义）
            let _ = state.biometric_wrap_store.delete(&db_path);
            return ApiResponse::error_with_code(
                crate::error::CODE_BIOMETRIC_RESET.to_string(),
                "Stored biometric wrap was malformed and has been removed; unlock with your master password"
                    .to_string(),
            );
        }
    };

    let wrapper = state.biometric_wrapper.clone();
    let unwrap_result = tauri::async_runtime::spawn_blocking(move || {
        persona_core::unwrap_master_key(wrapper.as_ref(), &envelope, "Unlock Persona")
    })
    .await
    .map_err(|e| format!("biometric unwrap task failed: {}", e));

    let master_key = match unwrap_result {
        Ok(Ok(key)) => key,
        Ok(Err(
            err @ (WrapErr::EnrollmentChanged
            | WrapErr::WrapInvalid
            | WrapErr::Platform(_)
            | WrapErr::NotAvailable
            | WrapErr::Unsupported),
        )) => {
            // 硬件说这份包裹再也打不开（换指纹/密钥重建/平台降级）：
            // 自动失效 + 明确引导主密码（设计文档 §3.4 回退链终态）
            let _ = state.biometric_wrap_store.delete(&db_path);
            return ApiResponse::error_with_code(
                crate::error::CODE_BIOMETRIC_RESET.to_string(),
                format!(
                    "Biometric wrap is no longer valid ({err}) and has been removed; unlock with your master password"
                ),
            );
        }
        Ok(Err(WrapErr::UserCancelled)) => {
            return ApiResponse::error_with_code(
                crate::error::CODE_BIOMETRIC_CANCELLED.to_string(),
                "Biometric prompt cancelled".to_string(),
            );
        }
        Err(task_err) => return ApiResponse::error(task_err),
    };

    // 密钥全程不出进程：init 内部分流直接消费主密钥
    match init_service_inner(
        InitRequest {
            master_password: String::new(),
            db_path: Some(db_path),
        },
        Some(*master_key),
        state,
        app,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => ApiResponse::error(format!("Biometric key unlock failed: {}", e)),
    }
}

/// biometric 解锁：包裹 blob 存在 → 硬件绑定链（解密时刻弹框）；否则
/// 门禁链（先查条目——没有就干净报错不弹系统框 → OS 认证弹框 → keyring
/// 取回主密码 → 走既有 [`init_service`] 全链路；成功/InvalidCredentials /
/// AccountLocked / PASSWORD_CHANGE_REQUIRED 原样透传；主密码全程不出
/// 进程、不进 ApiResponse）。
#[command]
pub async fn biometric_unlock<R: tauri::Runtime>(
    request: BiometricUnlockRequest,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = resolve_biometric_db_path(request.db_path, &state).await;

    // 硬件绑定链优先（两类条目互斥，enable 时已双保险）
    if let Ok(Some(wrap_blob)) = state.biometric_wrap_store.get(&db_path) {
        return Ok(biometric_unlock_with_wrap(wrap_blob, db_path, state, app).await);
    }

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
