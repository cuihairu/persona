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

/// Bridge PersonaService's auto-lock events to the frontend + close the
/// forced-lock loop.
///
/// - Any event is `emit("persona://auto-lock", ...)`-ed to the frontend
///   (countdown banner / back to unlock screen)
/// - On a `Locked` event, a standalone task calls `service.lock()` directly
///   to clear the in-memory master key — it does not depend on the frontend
///   being alive (AutoLockManager only locks the session, not the master key)
///
/// The callback is registered exactly once (an `AtomicBool` guards against
/// duplicates; calling it on multiple init_service invocations is safe).
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

/// Default vault path (shared by the path resolution of init_service and
/// biometric status/unlock — on the unlock screen `state.db_path` is still
/// None, so it must be resolvable independently)
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

/// init's internal dispatch: when `master_key` is Some, password
/// verification is skipped and a session is established directly with the
/// already-decrypted master key (the hardware-bound biometric unlock path —
/// the key comes from the wrap layer, which is hardware-authenticated at
/// the moment of decryption). Keys are never passed across the IPC surface:
/// this argument is only constructed in-process by `biometric_unlock`.
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
                    // Inject an OS-level biometric provider: the Mock built
                    // into PersonaService::new (always passes) would let any
                    // future caller of service.authenticate_biometric through
                    // silently — always replace it with the real provider
                    // held in AppState (the same instance the SSH agent's
                    // require_biometric policy uses)
                    service.set_biometric_provider(state.biometric_provider.clone());
                    // Attachment blob storage follows the vault file
                    // (<db dir>/attachments). A failed init only degrades
                    // attachment features (related commands report not
                    // initialized); it never blocks the main unlock flow.
                    let attachments_dir = std::path::Path::new(&workspace_path).join("attachments");
                    if let Err(e) = service
                        .init_attachment_storage(&attachments_dir, db_for_attachments.clone())
                        .await
                    {
                        tracing::warn!("attachment storage init failed: {}", e);
                    }
                    // Check if this is first-time setup or existing user.
                    // Red line: a query error must fail closed — treating an
                    // error as an "empty vault" would insert a second
                    // user_auth row (new salt) into an existing user's
                    // vault, after which the old password can no longer
                    // decrypt the stored credentials. Concurrent
                    // multi-instance access / vault lock timeouts are
                    // exactly the scenarios that land here.
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
                        // The hardware key path is meaningless for first-time
                        // setup (there is no user/key to verify yet)
                        if master_key.is_some() {
                            return Ok(ApiResponse::error(
                                "Vault is not initialized; biometric key unlock requires an existing vault"
                                    .to_string(),
                            ));
                        }
                        // First-time setup: initialize user with master password
                        match service.initialize_user(&request.master_password).await {
                            Ok(_user_id) => {
                                // Complete the store inside the statement and
                                // release the guard immediately:
                                // register_auto_lock_bridge locks
                                // state.service again, and if the guard
                                // spanned that call the non-reentrant tokio
                                // Mutex would deadlock
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
                        // Existing user + authenticated master key: the
                        // lockout / forced-password-change flags take effect
                        // inside core in the same order as the password path;
                        // session/audit are built the same way
                        match service
                            .authenticate_with_master_key(&key, "biometric-wrap")
                            .await
                        {
                            Ok(persona_core::AuthResult::Success) => {
                                // Same as above: release the guard before
                                // registering the auto-lock bridge
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
                                // Biometric unlock is likewise blocked by the
                                // forced password change flag (semantics
                                // aligned with core)
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
                                    // Same as above: release the guard before
                                    // registering the auto-lock bridge
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
                                    // Machine-readable error code: the
                                    // frontend uses it to guide the forced
                                    // password change flow
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
        // The capture seam holds the group key and must not survive a lock;
        // it is reassembled on the next sync_now
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

/// Get the full workspace settings (no unlock required: the unlock screen
/// also needs the flags to trim down the UI shell).
#[command]
pub async fn get_workspace_settings(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WorkspaceSettings>, String> {
    // Consistent with the command-layer error pattern: a missing db_path goes
    // through Ok(ApiResponse::error), so no Err(String) escapes the command
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

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let ws = workspace_or_return!(db, workspace_path);
    Ok(ApiResponse::success(ws.settings))
}

/// Change the workspace master password (shared by the unlock screen's
/// strong prompt and Settings' manual change; does not touch
/// `state.service` — the frontend re-inits with the new password to build
/// the session)
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
            // Linked biometric custody entry: entry exists -> update it to
            // the new password; write failure -> delete (fail-closed: rather
            // have the user re-enable it than leave a broken entry — a
            // broken entry triggers an InvalidCredentials self-delete on
            // every biometric_unlock plus a wasted accumulation of failure
            // counts). The CLI password change does not come through here;
            // that route relies on biometric_unlock's stale-entry self-heal.
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
            // Linked hardware wrap blob: the blob wraps the **old** master
            // key, so after a password change it decrypts to a stale key
            // (the item key has already rotated) — it cannot be
            // "updated" (the wrap layer only recognizes the hardware
            // ceremony, not the new password), so it must be deleted and the
            // user asked to re-enable it. A failed delete is only logged:
            // on the unlock side, decrypting to a stale key still goes
            // through the normal init chain, and the password path's
            // failure-count/lockout semantics are unchanged — nothing is
            // silently allowed through.
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

/// Narrow write of the advanced feature flags: only the four
/// `settings.features` bits are touched, and the updated full settings are
/// returned as the server-side truth (so the frontend does not clobber other
/// settings fields).
///
/// Backend flag linkage (the flags take effect immediately, no
/// lock->unlock needed):
/// - passkeys off: shut down the already spawned approval server; on: bring
///   it up in this session (previously this waited for the next
///   init_service)
/// - ssh_agent off: stop the running SSH agent (on: no automatic start —
///   showing/hiding the entry is the UI's job, and the user starts the agent
///   in the panel, matching 1Password's semantics)
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

/// Narrow write of the UI language ("zh-CN" / "en"). Same pattern as
/// `set_feature_flags`: unlock gate + narrow write of a single field +
/// return the full settings. Invalid values are rejected (the frontend only
/// sends supported items).
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

/// Swap the tray right-click menu labels: the frontend pushes over the truth
/// from the i18n locale table (tray.* namespace) for rendering — the native
/// tray menu is not covered by useTranslation, so this is its only channel
/// into the existing i18n system. Stateless and no lock-screen gate (the
/// right-click menu must follow the UI language even while locked); with no
/// tray (degraded run without a display session) it is a harmless no-op.
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

/// Narrow write of the master password expiry policy (days); None = never
/// expires. `Some(0)` is meaningless and rejected.
/// Same pattern as `set_feature_flags`: unlock gate + narrow write of a
/// single field + return the full settings.
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

/// Bring the main window to the foreground (the "go unlock" exit out of the
/// floating-window locked state)
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

/// Frontend error reporting: in production builds, ErrorBoundary /
/// handleError write to a local log file (the redacting subscriber
/// installed at setup). Each field is truncated to prevent log explosion;
/// the reporting path never fails — the error has already happened, and
/// reporting it erroring again would only create secondary noise.
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
            // Back up on a char boundary so UTF-8 is not split
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
