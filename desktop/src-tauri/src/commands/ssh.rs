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
    // The biometric provider is the same one injected into the unlock screen/
    // init_service: SSH keys whose require_biometric policy is set go through
    // the OS authentication dialog (Agent::new denies by default; the injection
    // is what allows it)
    let biometric = state.biometric_provider.clone();
    // Explicit parameters instead of set_var: writing process-level env in a
    // multithreaded process races with concurrent getenv (set_var is unsafe
    // as of Rust 2024), and once the master password enters env it stays there
    // forever. The override only lives on the agent task's stack; the master
    // password is consumed after key loading.
    // Stable socket path: the IdentityAgent written into ~/.ssh/config must
    // survive restarts unchanged; the daemon default path embeds a pid and is
    // reserved for one-shot CLI scenarios. If set externally (test guards that
    // reserve the bind-failure path / custom deployments), respect it rather
    // than overwriting.
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
    // Startup failure must not be silent: the agent task stores the
    // run_agent_with_hooks error into a shared slot, and the readiness poll
    // reads it to report back to the UI (the old implementation only eprintln'd,
    // so the UI always showed a false-green "running").
    let startup_error = Arc::new(std::sync::Mutex::new(None::<String>));
    let startup_error_task = Arc::clone(&startup_error);
    // The tauri global runtime instead of the caller's tokio context: on
    // mock_app's (test) reactor, socket IO never wakes up, so the agent must
    // live on a healthy multithreaded runtime.
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

    // Readiness poll: the socket record file appearing in the state dir = the
    // daemon finished bind (the file is written right after a successful bind).
    // 3s cap; an early task exit is an immediate failure. The old
    // implementation's fixed 400ms + running_hint=true lied in both the
    // slow-start and startup-failure cases.
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

/// The actual logic for stopping the SSH agent (shared by the
/// `stop_ssh_agent` command and the `set_feature_flags` toggle interplay).
pub(crate) async fn stop_ssh_agent_internal(state: &State<'_, AppState>) {
    if let Some(handle) = state.agent_handle.lock().await.take() {
        handle.abort();
    }
    // Drop all unanswered approvals: once the sender is dropped the agent side
    // sees a disconnect -> refuses to sign
    if let Ok(mut map) = state.ssh_approvals.lock() {
        map.clear();
    }
    std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");
    // PERSONA_AGENT_SOCKET_PATH is not cleared here: a value preset by a test
    // guard is restored by its Drop; the injected value when nothing was preset
    // is reclaimed at the tail of the agent task.
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

/// Three-state integration status detection: enabled (the anchor block points
/// at the current socket) / not enabled (no block) / config anomaly (the block
/// exists but points elsewhere; re-enabling fixes it). Anything outside the
/// user's managed block is strictly read-only.
#[command(rename_all = "snake_case")]
pub fn ssh_agent_integration_status() -> ApiResponse<crate::ssh_integration::SshIntegrationStatus> {
    use crate::ssh_integration as si;

    let config_path = si::ssh_config_path();
    // Report read failures honestly (permissions/IO/non-UTF-8); never silently
    // treat them as an empty file
    let (config, read_error) = match std::fs::read_to_string(&config_path) {
        Ok(c) => (c, None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), None),
        Err(e) => (String::new(), Some(e.to_string())),
    };
    let value = si::identity_agent_value();
    let managed = si::managed_block_identity_agent(&config);
    let enabled = managed.as_deref() == Some(value.as_str());
    // anomaly stores the actual pointed-to value (not a sentence): the frontend
    // renders the hint text per locale
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

/// Agent-side analysis of ~/.ssh/config: Include expansion + environment
/// variables + socket reachability probing.
/// Read-only, does not touch the config; a corrupted/permission-denied file
/// lands in the read_error field and is displayed as-is, without crashing.
#[command(rename_all = "snake_case")]
pub fn ssh_agent_config_analysis() -> ApiResponse<crate::ssh_integration::SshConfigAgentAnalysis> {
    use crate::ssh_integration as si;

    let config_path = si::ssh_config_path();
    let ssh_auth_sock = std::env::var("SSH_AUTH_SOCK")
        .ok()
        .filter(|s| !s.is_empty());
    ApiResponse::success(si::analyze_config(&config_path, ssh_auth_sock))
}

/// One-click enable: idempotently upsert the anchor block (a corrupted block
/// is normalized by rewriting), written back atomically.
/// A pure file operation requiring no unlock; whether the agent is running
/// does not affect the write (the socket path is a constant).
#[command(rename_all = "snake_case")]
pub fn ssh_agent_integration_enable(
) -> std::result::Result<ApiResponse<crate::ssh_integration::SshIntegrationStatus>, String> {
    use crate::ssh_integration as si;

    let config_path = si::ssh_config_path();
    // Refuse to write on a read failure (permissions/IO): upserting an empty
    // string would overwrite the user's entire config
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

/// One-click disable: remove the anchor block as a whole (only touching inside
/// the block), leaving the rest of the user's config alone.
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

/// Pre-import preview (a fingerprint is available without unlocking: the
/// public half of an OpenSSH container is plaintext).
/// Key order follows the snake_case contract of SshAgentStatus/SshKeySummary.
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

/// Import result.
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

/// Read a file and parse the private key container (format auto-detected:
/// OpenSSH/PKCS#8/PKCS#1/SEC1), returning the fields needed for import
/// confirmation (without importing into the vault).
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
            // ssh_import returns PersonaError directly (not wrapped in anyhow); normalize first
            let err: anyhow::Error = e.into();
            let (code, msg) = map_persona_error(&err);
            match code {
                Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                None => Ok(ApiResponse::error(msg)),
            }
        }
    }
}

/// Import a private key file into the vault as an SshKey entry (format
/// auto-detected): unlock if protected -> the private key is stored as plaintext
/// OpenSSH PEM in `SshKeyData.private_key`; sealing is the per-item key's job.
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
                // Item name fallback: --name > key comment > file name > last
                // resort
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

/// Result of an in-page generation: same shape as the import DTO (the
/// frontend reuses the same success-state view).
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
    /// `ed25519` (default) / `rsa` (4096) / `ecdsa` (NIST P-256)
    pub key_type: String,
    /// Comment written into the key and the public key line
    pub comment: Option<String>,
    /// Item name; falls back to comment > "SSH Key (generated)" when empty
    pub name: Option<String>,
}

/// Generate an SSH key pair in-page and store it: the plaintext PEM private
/// key goes into `SshKeyData.private_key`, with sealing handled by the
/// per-item key (isomorphic to the import channel).
/// Generation (RSA 4096 can take tens of seconds) finishes before taking the
/// service lock, so it does not block other commands.
#[command(rename_all = "snake_case")]
pub async fn generate_ssh_key(
    request: GenerateSshKeyRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SshKeyGeneratedDto>, String> {
    // An unknown type errors right here (no service lock, and the workspace
    // is not touched)
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
                // Same item-name fallback as the import channel: explicit
                // name > comment > last resort
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
                // Fingerprint / algorithm / public key line are computed on
                // the fly from the credential data; a fetch failure for one
                // key (gate, corrupted data) only affects this row's display
                // columns, not the whole list
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
