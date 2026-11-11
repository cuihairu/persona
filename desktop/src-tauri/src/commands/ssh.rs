use super::*;

/// Get SSH agent runtime status
#[command(rename_all = "snake_case")]
pub async fn get_ssh_agent_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SshAgentStatus>, String> {
    let handle_alive = state
        .agent_handle
        .lock()
        .await
        .as_ref()
        .map(|handle| !handle.inner().is_finished())
        .unwrap_or(false);
    let status = read_agent_status(handle_alive);
    Ok(ApiResponse::success(status))
}

/// Start the embedded SSH agent
#[command(rename_all = "snake_case")]
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
    // Desktop has no TTY: route RequireConfirm prompts through the GUI.
    let handler = Arc::new(crate::approval::DesktopApprovalHandler::new(
        app,
        state.ssh_approvals.clone(),
    ));
    // biometric provider 与解锁屏/init_service 注入的是同一份：SSH key 的
    // require_biometric 策略走 OS 认证弹框（Agent::new 默认拒绝，注入才放行）
    let biometric = state.biometric_provider.clone();
    // 显式传参取代 set_var：多线程进程里写进程级 env 与并发 getenv 是数据
    // 竞争（Rust 2024 起 set_var 为 unsafe），且主密码一旦进 env 就终身
    // 驻留。override 只活在 agent 任务栈上，主密码在密钥加载后被消费。
    // 稳定 socket 路径：写进 ~/.ssh/config 的 IdentityAgent 必须跨重启不
    // 变；daemon 缺省路径带 pid，只留给一次性 CLI 场景。外部已指定（测试
    // guard 预占 bind 失败路径/自定义部署）则尊重不覆盖。
    let injected_socket_path = std::env::var_os("PERSONA_AGENT_SOCKET_PATH")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from);
    let overrides = persona_ssh_agent::AgentEnvOverrides {
        master_password: request.master_password.clone(),
        db_path: Some(std::path::PathBuf::from(&db_path)),
        state_dir: Some(agent_state_dir()),
        socket_path: injected_socket_path
            .or_else(|| Some(crate::ssh_integration::agent_stable_socket())),
        require_confirm: Some(true),
    };
    // 启动失败不得静默：agent 任务把 run_agent_with_hooks 的错误存进共享槽位，
    // 就绪轮询读它回传 UI（旧实现只 eprintln，UI 恒报"运行中"假绿）。
    let startup_error = Arc::new(std::sync::Mutex::new(None::<String>));
    let startup_error_task = Arc::clone(&startup_error);
    // tauri 全局运行时而非调用方的 tokio 上下文：mock_app（测试）的
    // reactor 上 socket IO 永不唤醒，agent 必须活在健康的多线程运行时里。
    let handle = tauri::async_runtime::spawn(async move {
        if let Err(err) = persona_ssh_agent::run_agent_with_hooks_and_env(
            Some(handler as Arc<dyn persona_ssh_agent::ApprovalHandler>),
            Some(biometric as Arc<dyn persona_core::BiometricProvider>),
            overrides,
        )
        .await
        {
            eprintln!("SSH agent exited: {}", err);
            if let Ok(mut slot) = startup_error_task.lock() {
                *slot = Some(err.to_string());
            }
        }
    });
    *handle_guard = Some(handle);

    // 就绪轮询：state 目录的 socket 记录文件出现 = daemon 完成 bind（写文件
    // 紧随 bind 成功之后）。上限 3s；任务提前退出立即判失败。旧实现的
    // 固定 400ms + running_hint=true 在慢启动与启动失败两态都撒谎。
    let sock_file = agent_state_dir().join("ssh-agent.sock");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut ready = false;
    let mut task_died = false;
    while std::time::Instant::now() < deadline {
        if handle_guard
            .as_ref()
            .map(|h| h.inner().is_finished())
            .unwrap_or(false)
        {
            task_died = true;
            break;
        }
        if sock_file.exists() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    if !ready {
        let detail = startup_error
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .unwrap_or_else(|| {
                if task_died {
                    "agent task exited during startup (see application logs)".to_string()
                } else {
                    "agent socket did not become ready within 3s; startup aborted".to_string()
                }
            });
        if let Some(h) = handle_guard.take() {
            h.abort();
        }
        drop(handle_guard);
        cleanup_agent_state_files();
        return Ok(ApiResponse::error(format!(
            "SSH agent failed to start: {detail}"
        )));
    }
    drop(handle_guard);

    let status = read_agent_status(true);
    Ok(ApiResponse::success(status))
}

/// Stop the embedded SSH agent
#[command(rename_all = "snake_case")]
pub async fn stop_ssh_agent(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    stop_ssh_agent_internal(&state).await;
    Ok(ApiResponse::success(true))
}

/// 停止 SSH agent 的实际逻辑（`stop_ssh_agent` 命令与
/// `set_feature_flags` 关开关联动共用）。
pub(crate) async fn stop_ssh_agent_internal(state: &State<'_, AppState>) {
    if let Some(handle) = state.agent_handle.lock().await.take() {
        handle.abort();
    }
    // 丢弃所有未应答审批：sender 被 drop 后 agent 侧收到断连 → 拒签
    if let Ok(mut map) = state.ssh_approvals.lock() {
        map.clear();
    }
    std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");
    // PERSONA_AGENT_SOCKET_PATH 不在这里清：测试 guard 预设的值由其 Drop
    // 恢复；未预设时的注入值由 agent task 尾部回收。
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

/// 集成状态三态检测：已启用（锚点块指向当前 socket）/ 未启用（无块）/
/// 配置异常（块存在但指向别处，重新启用即修复）。用户块外的配置一律只读。
#[command(rename_all = "snake_case")]
pub fn ssh_agent_integration_status() -> ApiResponse<crate::ssh_integration::SshIntegrationStatus> {
    use crate::ssh_integration as si;

    let config_path = si::ssh_config_path();
    // 读失败如实上报（权限/IO/非 UTF-8），绝不静默当空文件
    let (config, read_error) = match std::fs::read_to_string(&config_path) {
        Ok(c) => (c, None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), None),
        Err(e) => (String::new(), Some(e.to_string())),
    };
    let value = si::identity_agent_value();
    let managed = si::managed_block_identity_agent(&config);
    let enabled = managed.as_deref() == Some(value.as_str());
    // anomaly 存实际指向值（非句子）：前端按 locale 渲染提示文案
    let anomaly = managed.as_ref().filter(|v| *v != value.as_str()).cloned();
    ApiResponse::success(si::SshIntegrationStatus {
        enabled,
        anomaly,
        manual_entry: si::has_manual_persona_entry(&config),
        config_path: config_path.display().to_string(),
        socket_path: value.clone(),
        identity_agent: managed,
        ssh_version: si::probe_ssh_version(),
        config_exists: config_path.exists(),
        read_error,
    })
}

/// ~/.ssh/config 的 agent 面分析：Include 展开 + 环境变量 + socket 连通探测。
/// 只读不动配置；损坏/无权限落 read_error 字段如实显示，不崩。
#[command(rename_all = "snake_case")]
pub fn ssh_agent_config_analysis() -> ApiResponse<crate::ssh_integration::SshConfigAgentAnalysis> {
    use crate::ssh_integration as si;

    let config_path = si::ssh_config_path();
    let ssh_auth_sock = std::env::var("SSH_AUTH_SOCK")
        .ok()
        .filter(|s| !s.is_empty());
    ApiResponse::success(si::analyze_config(&config_path, ssh_auth_sock))
}

/// 一键启用：幂等 upsert 锚点块（损坏块收敛重写），原子写回。
/// 纯文件操作不解锁；agent 是否运行不影响写入（socket 路径是常量）。
#[command(rename_all = "snake_case")]
pub fn ssh_agent_integration_enable(
) -> std::result::Result<ApiResponse<crate::ssh_integration::SshIntegrationStatus>, String> {
    use crate::ssh_integration as si;

    let config_path = si::ssh_config_path();
    // 读失败（权限/IO）时拒绝写：空串 upsert 会把用户 config 整个覆盖掉
    let config = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "Failed to read {} ({e}); refusing to overwrite an unreadable config",
                config_path.display()
            ))
        }
    };
    let new = si::upsert_managed_block(&config, &si::identity_agent_value());
    si::write_config_atomic(&config_path, &new)
        .map_err(|e| format!("Failed to write {}: {e}", config_path.display()))?;
    Ok(ssh_agent_integration_status())
}

/// 一键停用：整块移除锚点块（只动块内），用户其余配置不碰。
#[command(rename_all = "snake_case")]
pub fn ssh_agent_integration_disable(
) -> std::result::Result<ApiResponse<crate::ssh_integration::SshIntegrationStatus>, String> {
    use crate::ssh_integration as si;

    let config_path = si::ssh_config_path();
    let config = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ssh_agent_integration_status());
        }
        Err(e) => return Err(format!("Failed to read {}: {e}", config_path.display())),
    };
    let new = si::remove_managed_block(&config);
    if new != config {
        si::write_config_atomic(&config_path, &new)
            .map_err(|e| format!("Failed to write {}: {e}", config_path.display()))?;
    }
    Ok(ssh_agent_integration_status())
}

/// 导入前预览（不解锁也能给指纹：OpenSSH 容器的公钥半边是明文）。
/// 键序沿 SshAgentStatus/SshKeySummary 的 snake_case 契约。
#[derive(Serialize)]
pub struct SshKeyInspectDto {
    pub file_name: String,
    pub key_type: String,
    pub ssh_algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub comment: String,
    pub encrypted: bool,
}

/// 入库结果。
#[derive(Serialize)]
pub struct SshKeyImportedDto {
    pub credential_id: String,
    pub name: String,
    pub key_type: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(serde::Deserialize)]
pub struct ImportSshKeyRequest {
    pub identity_id: String,
    pub path: String,
    pub name: Option<String>,
    pub passphrase: Option<String>,
}

/// 读文件并解析私钥容器（格式自动识别：OpenSSH/PKCS#8/PKCS#1/SEC1），
/// 返回导入确认所需字段（不入库）。
#[command(rename_all = "snake_case")]
pub async fn inspect_ssh_key_file(
    path: String,
) -> std::result::Result<ApiResponse<SshKeyInspectDto>, String> {
    let inspection = match fs::read_to_string(&path) {
        Ok(pem) => persona_core::crypto::ssh_import::inspect_private_key_file(&pem),
        Err(e) => Err(PersonaError::Io(format!(
            "Cannot read key file {path}: {e}"
        ))),
    };
    match inspection {
        Ok(info) => {
            let file_name = Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
            Ok(ApiResponse::success(SshKeyInspectDto {
                file_name,
                key_type: info.key_type,
                ssh_algorithm: info.ssh_algorithm,
                public_key: info.public_key,
                fingerprint: info.fingerprint,
                comment: info.comment,
                encrypted: info.encrypted,
            }))
        }
        Err(e) => {
            // ssh_import 直接返回 PersonaError（非 anyhow 包装），先归一
            let err: anyhow::Error = e.into();
            let (code, msg) = map_persona_error(&err);
            match code {
                Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                None => Ok(ApiResponse::error(msg)),
            }
        }
    }
}

/// 导入私钥文件入库为 SshKey 条目（格式自动识别）：解锁（如受保护）→
/// 私钥以明文 OpenSSH PEM 存 `SshKeyData.private_key`，封存由 per-item key 负责。
#[command(rename_all = "snake_case")]
pub async fn import_ssh_key(
    request: ImportSshKeyRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SshKeyImportedDto>, String> {
    let imported = match fs::read_to_string(&request.path) {
        Ok(pem) => persona_core::crypto::ssh_import::import_private_key_file(
            &pem,
            request.passphrase.as_deref(),
        ),
        Err(e) => Err(PersonaError::Io(format!(
            "Cannot read key file {}: {e}",
            request.path
        ))),
    };
    let imported = match imported {
        Ok(imported) => imported,
        Err(e) => {
            let err: anyhow::Error = e.into();
            let (code, msg) = map_persona_error(&err);
            return Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            });
        }
    };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.identity_id) {
            Ok(identity_uuid) => {
                // 条目名回退：--name > 钥匙 comment > 文件名 > 兜底
                let file_name = Path::new(&request.path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string());
                let name = request
                    .name
                    .filter(|n| !n.trim().is_empty())
                    .or_else(|| (!imported.comment.is_empty()).then(|| imported.comment.clone()))
                    .or(file_name)
                    .unwrap_or_else(|| "SSH Key (imported)".to_string());
                let ssh_data = persona_core::models::SshKeyData {
                    private_key: imported.private_key_pem.clone(),
                    public_key: imported.public_key.clone(),
                    key_type: imported.key_type.clone(),
                    passphrase: None,
                };
                match service
                    .create_credential(
                        identity_uuid,
                        name.clone(),
                        CredentialType::SshKey,
                        SecurityLevel::High,
                        &persona_core::models::CredentialData::SshKey(ssh_data),
                    )
                    .await
                {
                    Ok(credential) => Ok(ApiResponse::success(SshKeyImportedDto {
                        credential_id: credential.id.to_string(),
                        name,
                        key_type: imported.key_type,
                        public_key: imported.public_key,
                        fingerprint: imported.fingerprint,
                    })),
                    Err(e) => {
                        let (_code, msg) = map_persona_error(&e);
                        Ok(ApiResponse::error(msg))
                    }
                }
            }
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// 页面内生成结果：与导入 DTO 同形（前端复用同一成功态展示）。
#[derive(Serialize)]
pub struct SshKeyGeneratedDto {
    pub credential_id: String,
    pub name: String,
    pub key_type: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(serde::Deserialize)]
pub struct GenerateSshKeyRequest {
    pub identity_id: String,
    /// `ed25519`（默认口径）/ `rsa`（4096）/ `ecdsa`（NIST P-256）
    pub key_type: String,
    /// 写入钥匙与公钥行的 comment
    pub comment: Option<String>,
    /// 条目名；空缺时回退 comment > "SSH Key (generated)"
    pub name: Option<String>,
}

/// 页面内生成 SSH 密钥对并入库：私钥明文 PEM 存 `SshKeyData.private_key`，
/// 封存由 per-item key 负责（与导入通道同构）。
/// 生成（RSA 4096 可能数十秒）在拿 service 锁之前完成，不阻塞其它命令。
#[command(rename_all = "snake_case")]
pub async fn generate_ssh_key(
    request: GenerateSshKeyRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SshKeyGeneratedDto>, String> {
    // 未知类型在这里就地报错（不给 service 锁，也不碰 workspace）
    let generated = match persona_core::crypto::ssh_generate::generate_ssh_keypair(
        &request.key_type,
        request.comment.as_deref().unwrap_or_default(),
    ) {
        Ok(generated) => generated,
        Err(e) => {
            let err: anyhow::Error = e.into();
            let (_code, msg) = map_persona_error(&err);
            return Ok(ApiResponse::error(msg));
        }
    };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.identity_id) {
            Ok(identity_uuid) => {
                // 条目名回退与导入通道一致：显式名 > comment > 兜底
                let name = request
                    .name
                    .filter(|n| !n.trim().is_empty())
                    .or_else(|| (!generated.comment.is_empty()).then(|| generated.comment.clone()))
                    .unwrap_or_else(|| "SSH Key (generated)".to_string());
                let ssh_data = persona_core::models::SshKeyData {
                    private_key: generated.private_key_pem,
                    public_key: generated.public_key.clone(),
                    key_type: generated.key_type.clone(),
                    passphrase: None,
                };
                match service
                    .create_credential(
                        identity_uuid,
                        name.clone(),
                        CredentialType::SshKey,
                        SecurityLevel::High,
                        &persona_core::models::CredentialData::SshKey(ssh_data),
                    )
                    .await
                {
                    Ok(credential) => Ok(ApiResponse::success(SshKeyGeneratedDto {
                        credential_id: credential.id.to_string(),
                        name,
                        key_type: generated.key_type,
                        public_key: generated.public_key,
                        fingerprint: generated.fingerprint,
                    })),
                    Err(e) => {
                        let (_code, msg) = map_persona_error(&e);
                        Ok(ApiResponse::error(msg))
                    }
                }
            }
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

#[command(rename_all = "snake_case")]
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
#[command(rename_all = "snake_case")]
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
                // 指纹/算法/公钥行从凭据数据现算；单钥取数失败（门禁、
                // 数据损坏）只影响本行的展示列，不炸整个列表
                let key_info = {
                    let service_guard = state.service.lock().await;
                    match service_guard.as_ref() {
                        Some(service) => match service.get_credential_data(&credential.id).await {
                            Ok(Some(persona_core::models::CredentialData::SshKey(ssh_data))) => {
                                let describe =
                                    persona_core::crypto::ssh_import::describe_public_key_line(
                                        &ssh_data.public_key,
                                    );
                                (Some(ssh_data.public_key), describe)
                            }
                            _ => (None, None),
                        },
                        None => (None, None),
                    }
                };
                let (public_key, describe) = key_info;
                let (ssh_algorithm, fingerprint, key_size) = match describe {
                    Some((algo, fp, size)) => (Some(algo), Some(fp), size),
                    None => (None, None, None),
                };
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
                    ssh_algorithm,
                    fingerprint,
                    key_size,
                    public_key,
                });
            }
        }
    }

    Ok(ApiResponse::success(summaries))
}
