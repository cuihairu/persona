use super::*;
// The device-management methods on `CloudGroupKeyStore` (register/put/group_keys/bootstrap)
// are `GroupKeyStore` trait methods — the trait must be in scope.
use base64::Engine as _;
use persona_core::sync::remote::GroupKeyStore as _;

/// Read the sync-server config section of the current vault (a vault that
/// cannot be opened or a missing row yields None — attach is a best-effort
/// side path and must not block the unlock main path).
///
/// Also performs a one-off legacy migration: before the keyring change the DB
/// stored the token in plaintext; a non-empty value is moved into the keyring
/// and the DB is narrow-written with an empty string. If the keyring write
/// fails the plaintext is kept rather than destroying data (the next attach
/// retries the migration), and reporting naturally falls back to fail-closed
/// because the keyring cannot be read.
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

/// Build or replace the reporter in the AppState slot from the sync section of
/// the current vault settings, and inject it into (or detach it from) the
/// current service. When sync is disabled or the config is incomplete it is
/// always detached (`set_event_emitter(None)`), matching the env-based
/// decision semantics of the CLI host.
///
/// The real token is read from the OS keyring (the vault JSON always holds an
/// empty string): unreadable/empty/errored all keep reporting disabled
/// (fail-closed) — it is only attached when all three hold: enabled, a
/// non-empty url, and a token in the keyring.
///
/// Lock order is fixed at sync_emitter -> service; the old emitter is stopped
/// after the slot is replaced, outside the lock (flush may hit the network, so
/// it must not be awaited while holding the lock).
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

/// Narrow-write the sync server config (the `settings.sync` section) and
/// return the updated full settings as the source of truth for the server.
/// Requires unlocked state (same gate as `set_feature_flags`); on save
/// success the reporter is immediately re-attached (stop old, start new)
/// without re-unlocking.
///
/// The real token lives in the OS keyring (via `AppState.token_store`); the
/// vault JSON's `server_token` is always written as an empty string: an empty
/// `server_token` means **keep the existing token in the keyring** (so the
/// token is not held resident in frontend memory); a non-empty value
/// overwrites the keyring, and an unavailable keyring rejects the save
/// (fail-closed, never falls back to plaintext). When `enabled=false` the
/// keyring token is removed on a best-effort basis (failure only warns and
/// does not block disable). Errors when `enabled` is set and `server_url` is
/// blank.
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

    // Token handling precedes the DB write: a keyring failure rejects the
    // save outright so no half-configured state is left behind.
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
            // Empty string = keep the old value. A legacy vault's DB may still
            // hold a plaintext token from before the keyring change — move it
            // into the keyring before clearing the DB, or the real value is lost.
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

    // The vault JSON always stores an empty-string placeholder — the real
    // value only lives in the OS keyring. The cloud-drive fields (Phase 2)
    // are separate transport configuration and are not touched by this
    // command: the old values are read back and preserved as-is so that
    // "change server config" does not silently wipe the cloud transport choice.
    let (old_cloud_dir, old_transport) = ws
        .settings
        .sync
        .as_ref()
        .map(|s| (s.cloud_drive_dir.clone(), s.sync_transport))
        .unwrap_or((None, persona_core::SyncTransport::default()));
    ws.settings.sync = Some(persona_core::SyncConfig {
        enabled,
        server_url,
        server_token: String::new(),
        cloud_drive_dir: old_cloud_dir,
        sync_transport: old_transport,
    });
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);
    let settings = updated.settings;

    attach_sync_emitter(&state).await;
    Ok(ApiResponse::success(settings))
}

/// Narrow-write the sync method toggles (the `settings.sync_methods`
/// section) and return the updated full settings as the source of truth for
/// the server. Requires unlocked state (same gate as `set_sync_config`).
///
/// **Writes the preference toggles only** — never deletes keyring entries,
/// never touches the network: turning off cross-device sync disables the
/// settings-page entry point but does not leave the sync group (the group key
/// stays in the keyring under `persona-sync-group`, and the data stays in the
/// group). The desktop app has no leave-sync-group entry yet (`sync_group_store`
/// only has get/set, no delete command); to stop participating, another
/// authorized device must revoke this one (`sync_revoke`). This is a separate
/// semantics from `SyncConfig.enabled` (audit event reporting); never merge
/// the two.
#[command(rename_all = "snake_case")]
pub async fn set_sync_methods(
    cross_device_sync: bool,
    account_sync: bool,
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

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);

    ws.settings.sync_methods = persona_core::SyncMethods {
        cross_device_sync,
        account_sync,
    };
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);
    Ok(ApiResponse::success(updated.settings))
}

/// Narrow-write the sync transport choice (`settings.sync.sync_transport` +
/// `cloud_drive_dir`) and return the updated full settings. Requires unlocked
/// state (same gate as `set_sync_methods`).
///
/// **Writes the transport preference only** — never touches the keyring,
/// never triggers network or cloud-drive I/O; the cloud-drive folder is only
/// required to be non-empty when `transport=cloud` (fail-closed: no folder
/// given means no config is written; the frontend picks the folder in the
/// settings page). With `transport=server`, `cloud_drive_dir` may keep the
/// previous value (so switching back to cloud does not lose it) or be cleared
/// by passing empty — this command keeps the old value when empty is passed,
/// avoiding silently losing the folder on "switch to server".
#[command(rename_all = "snake_case")]
pub async fn set_sync_transport(
    sync_transport: String,
    cloud_drive_dir: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WorkspaceSettings>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let transport = match sync_transport.trim() {
        "server" => persona_core::SyncTransport::Server,
        "cloud" => persona_core::SyncTransport::Cloud,
        _ => {
            return Ok(ApiResponse::error(format!(
                "Unknown sync transport: {sync_transport}"
            )))
        }
    };
    let dir = cloud_drive_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if transport == persona_core::SyncTransport::Cloud && dir.is_none() {
        return Ok(ApiResponse::error(
            "Cloud drive folder is required for the cloud transport".to_string(),
        ));
    }

    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);
    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);

    let old = ws.settings.sync.clone();
    let (enabled, server_url, old_dir) = match &old {
        Some(config) => (
            config.enabled,
            config.server_url.clone(),
            config.cloud_drive_dir.clone(),
        ),
        None => (false, String::new(), None),
    };
    ws.settings.sync = Some(persona_core::SyncConfig {
        enabled,
        server_url,
        server_token: String::new(),
        // An empty string (frontend switched to server / untouched) keeps the
        // old folder to avoid losing the config
        cloud_drive_dir: dir.map(String::from).or(old_dir),
        sync_transport: transport,
    });
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);
    Ok(ApiResponse::success(updated.settings))
}

/// Read-only: whether a sync token is stored in the OS keyring (no unlock
/// needed — the settings page uses it to choose the placeholder hint). Only
/// leaks the single bit of "was configured" metadata (same level as
/// `get_workspace_settings` exposing `sync.enabled`); the real token never
/// leaves the keyring and never travels over IPC.
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

/// The three states of the local device identity (keyring -> DeviceIdentity).
pub(crate) enum LocalDevice {
    NotJoined,
    /// The record exists but fails to parse — do not guess and do not run in
    /// a degraded state; the UI steers the user to re-join.
    Corrupted,
    Joined(persona_core::sync::device::DeviceIdentity),
}

pub(crate) async fn require_db_path(state: &State<'_, AppState>) -> Option<String> {
    let guard = state.db_path.lock().await;
    guard.clone()
}

/// Gate: must be unlocked. `None` = pass; `Some(message)` = not initialized
/// or locked (the caller converts it to `ApiResponse::error` — the data types
/// of the sync commands differ, so the messages are consolidated here).
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
        Err(_) => LocalDevice::NotJoined, // A keyring read failure counts as not joined (join reports the specific error)
    }
}

/// settings.sync.server_url + keyring sync token (shared environment lookup for
/// sync_now and the admin commands; a missing value or environment failure
/// returns a user-readable message).
pub(crate) async fn sync_server_creds_for(
    state: &State<'_, AppState>,
) -> std::result::Result<(String, String), String> {
    let db_path = require_db_path(state)
        .await
        .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?;
    // A fresh vault's sync section is None — equivalent to a blank URL: no server configured
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

/// Build the admin client when both settings.sync.server_url and the keyring
/// sync token are present.
pub(crate) async fn sync_admin_api_for(
    state: &State<'_, AppState>,
) -> std::result::Result<persona_core::sync::remote::SyncAdminApi, String> {
    let (server_url, token) = sync_server_creds_for(state).await?;
    persona_core::sync::remote::SyncAdminApi::new(&server_url, &token)
        .map_err(|e| format!("Invalid sync server configuration: {e}"))
}

/// Read-only: whether this vault has joined E2EE sync (purely local keyring,
/// no unlock needed). `corrupted = true` means an entry exists but failed to
/// parse — steer the user to re-join.
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

/// Join E2EE sync: generate the local device key pair -> register via the
/// current transport (server API / cloud-drive `registry.json`) -> persist the
/// identity to the keyring. On a keyring write failure, best-effort revoke the
/// registration just written (leave no half-state; fail-closed). Gate: must be
/// unlocked; device_name 1..=128 bytes.
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
    let (transport, cloud_dir) = sync_transport_config(&state).await;
    match transport {
        // Cloud-drive registration: device_id is generated locally (no
        // server-assigned step); if the keyring write fails, roll back the
        // registration (delete the registry entry; the envelope has not been
        // written yet, so it needs no cleanup).
        persona_core::SyncTransport::Cloud => {
            let dir = match cloud_dir {
                Some(dir) if !dir.trim().is_empty() => dir,
                _ => {
                    return Ok(ApiResponse::error(
                        "Cloud drive folder is not configured; pick one in sync settings"
                            .to_string(),
                    ))
                }
            };
            let identity = match persona_core::sync::device::DeviceIdentity::generate(&device_name)
            {
                Ok(identity) => identity.with_device_id(uuid::Uuid::new_v4()),
                Err(e) => return Ok(ApiResponse::error(format!("Key generation failed: {e}"))),
            };
            let store = persona_core::sync::remote::CloudGroupKeyStore::new(&dir);
            if let Err(e) = store.register_device(&identity).await {
                return Ok(ApiResponse::error(format!(
                    "Cloud sync registry rejected device registration: {e}"
                )));
            }
            if let Err(e) = state.device_store.set(&db_path, &identity.to_stored_json()) {
                tracing::warn!(%e, "keyring write failed after cloud registration; removing the registry entry");
                if let Err(remove_error) = store.remove_device(identity.device_id).await {
                    tracing::error!(
                        %remove_error,
                        device_id = %identity.device_id,
                        "registry rollback failed; a stray cloud registry entry remains"
                    );
                }
                return Ok(ApiResponse::error(format!(
                    "Cannot store device identity in OS keyring: {e}"
                )));
            }
            // Empty-group bootstrap (the first device seals its own envelope =
            // authorized); a non-empty group = waiting for authorization. A
            // failed query is conservatively treated as "waiting for
            // authorization" (fail-closed, same as the server path).
            let pending = match store
                .bootstrap_group_if_empty(identity.device_id, identity.key_pair.public_bytes())
                .await
            {
                Ok(bootstrapped) => !bootstrapped,
                Err(_) => true,
            };
            Ok(ApiResponse::success(SyncJoinOutcome {
                device_id: identity.device_id.to_string(),
                device_name,
                pending,
            }))
        }
        persona_core::SyncTransport::Server => {
            let api = match sync_admin_api_for(&state).await {
                Ok(api) => api,
                Err(message) => return Ok(ApiResponse::error(message)),
            };
            let identity = match persona_core::sync::device::DeviceIdentity::generate(&device_name)
            {
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
            // pending = group-keys has no envelope for this device yet; a failed
            // query is conservatively treated as "waiting for authorization"
            // (fail-closed: better to show unauthorized than to misreport). On an
            // empty group this device bootstraps itself: a brand-new server has no
            // existing device to authorize on its behalf, so the first device
            // generates the group key, seals its own envelope, and uploads it —
            // otherwise the first device would wait for authorization forever
            // (nobody can authorize it).
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
    }
}

/// Leave sync: best-effort revoke the server-side record (unreachable/
/// unconfigured only warns — local cleanup takes priority and leftovers can be
/// revoked by another device), then unconditionally clear the keyring identity.
/// The private key is deleted with the entry and cannot be recovered; data
/// already synced into this vault remains usable (the main vault's ciphertext
/// belongs to the master-password system).
///
/// Cloud-drive transport: best-effort remove self from `registry.json` and
/// delete the local envelope file; failure does not block (local cleanup takes
/// priority, and leftover registrations can be revoked by another device with
/// the same semantics).
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
    let (transport, cloud_dir) = sync_transport_config(&state).await;
    match local_device(&state, &db_path).await {
        LocalDevice::NotJoined => {
            return Ok(ApiResponse::error(
                "This vault has not joined sync".to_string(),
            ))
        }
        LocalDevice::Joined(identity) => match transport {
            persona_core::SyncTransport::Cloud => {
                if let Some(dir) = cloud_dir {
                    let store = persona_core::sync::remote::CloudGroupKeyStore::new(&dir);
                    if let Err(e) = store.remove_device(identity.device_id).await {
                        tracing::warn!(%e, device_id = %identity.device_id, "cloud registry removal failed during leave; the entry may remain");
                    }
                } else {
                    tracing::warn!(
                        "cloud drive dir unconfigured during leave; skipping registry removal"
                    );
                }
            }
            persona_core::SyncTransport::Server => {
                if let Ok(api) = sync_admin_api_for(&state).await {
                    if let Err(e) = api.delete_device(identity.device_id).await {
                        // A failed server-side revoke does not block leaving: local cleanup
                        // takes priority, and the leftover record can be revoked by another
                        // device (or cleaned up by an admin)
                        tracing::warn!(%e, device_id = %identity.device_id, "server-side device revoke failed during leave; the record may remain");
                    }
                } else {
                    tracing::warn!(
                        "sync admin client unavailable during leave; skipping server-side revoke"
                    );
                }
            }
        },
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

/// List all devices in the sync group (with authorization status and a
/// this-device flag). Requires having joined and being unlocked.
///
/// Cloud-drive transport: reads `registry.json` plus `env-<device>.bin`
/// existence (unauthorized = registered but the envelope was never uploaded).
/// A failed listing / missing registry = report the error honestly.
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
    let (transport, cloud_dir) = sync_transport_config(&state).await;
    match transport {
        persona_core::SyncTransport::Cloud => {
            let dir = match cloud_dir {
                Some(dir) if !dir.trim().is_empty() => dir,
                _ => {
                    return Ok(ApiResponse::error(
                        "Cloud drive folder is not configured; pick one in sync settings"
                            .to_string(),
                    ))
                }
            };
            let store = persona_core::sync::remote::CloudGroupKeyStore::new(&dir);
            let devices = match store.list_devices().await {
                Ok(devices) => devices,
                Err(e) => return Ok(ApiResponse::error(format!("Failed to list devices: {e}"))),
            };
            let keys = match store.group_keys().await {
                Ok(keys) => keys,
                Err(e) => {
                    return Ok(ApiResponse::error(format!(
                        "Failed to list group keys: {e}"
                    )))
                }
            };
            let views = devices
                .into_iter()
                .map(|device| {
                    let id = device.device_id.clone();
                    SyncDeviceView {
                        id: id.clone(),
                        device_name: device.device_name,
                        created_at: device.created_at,
                        remark: device.remark,
                        authorized: keys.iter().any(|k| k.device_id.to_string() == id),
                        this_device: id == identity.device_id.to_string(),
                    }
                })
                .collect();
            Ok(ApiResponse::success(views))
        }
        persona_core::SyncTransport::Server => {
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
    }
}

/// Set the free-form remark for this device (S4): the server pins the device
/// row to the token's owner, so there is no cross-device path — whose remark
/// is written is decided by the token. Empty string / whitespace only = clear.
/// Returns the remark as normalized (trimmed) by the server.
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
    let identity = match local_device(&state, &db_path).await {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            return Ok(ApiResponse::error(
                "This vault has not joined sync".to_string(),
            ))
        }
    };
    let (transport, cloud_dir) = sync_transport_config(&state).await;
    match transport {
        // Cloud-drive remarks: the registry is a cooperative trust surface (no
        // server-side token pinning), so the command layer forces writes to the
        // local device's entry only — writing someone else's remark is
        // meaningless and would overwrite each other.
        persona_core::SyncTransport::Cloud => {
            let dir = match cloud_dir {
                Some(dir) if !dir.trim().is_empty() => dir,
                _ => {
                    return Ok(ApiResponse::error(
                        "Cloud drive folder is not configured; pick one in sync settings"
                            .to_string(),
                    ))
                }
            };
            let store = persona_core::sync::remote::CloudGroupKeyStore::new(&dir);
            match store.set_device_remark(identity.device_id, &remark).await {
                Ok(stored) => Ok(ApiResponse::success(stored)),
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to set device remark: {e}"
                ))),
            }
        }
        persona_core::SyncTransport::Server => {
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
    }
}

/// Authorize the target device: open the local envelope to obtain the group key
/// -> seal a new envelope with the target's public key and upload it.
/// An unauthorized local device (envelope cannot be opened) fails closed — an
/// unauthorized device cannot authorize others; the target must be another
/// registered device.
///
/// Cloud-drive transport: read `registry.json` for the target public key
/// (X25519) and write `env-<target>.bin` (target absent from the registry =
/// error, same semantics as a server 404).
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
    let (transport, cloud_dir) = sync_transport_config(&state).await;
    match transport {
        persona_core::SyncTransport::Cloud => {
            let dir = match cloud_dir {
                Some(dir) if !dir.trim().is_empty() => dir,
                _ => {
                    return Ok(ApiResponse::error(
                        "Cloud drive folder is not configured; pick one in sync settings"
                            .to_string(),
                    ))
                }
            };
            let store = persona_core::sync::remote::CloudGroupKeyStore::new(&dir);
            // Open the local envelope to obtain the group key (fail-closed:
            // unauthorized cannot authorize others)
            let keys = match store.group_keys().await {
                Ok(keys) => keys,
                Err(e) => {
                    return Ok(ApiResponse::error(format!(
                        "Failed to fetch group keys: {e}"
                    )))
                }
            };
            let group_key_bytes = match keys.iter().find(|k| k.device_id == identity.device_id) {
                Some(own) => {
                    match persona_core::sync::envelope::open_group_key(
                        &own.envelope,
                        identity.key_pair.secret_bytes(),
                    ) {
                        Ok(group_key) => group_key,
                        Err(_) => {
                            return Ok(ApiResponse::error(
                                "This device is not authorized yet; it cannot authorize others"
                                    .to_string(),
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
            let devices = match store.list_devices().await {
                Ok(devices) => devices,
                Err(e) => return Ok(ApiResponse::error(format!("Failed to list devices: {e}"))),
            };
            let target = match devices
                .iter()
                .find(|d| d.device_id == target_id.to_string())
            {
                Some(device) => device,
                None => {
                    return Ok(ApiResponse::error(
                        "Target device not found in the cloud sync registry".to_string(),
                    ))
                }
            };
            let target_public = match base64::engine::general_purpose::STANDARD
                .decode(target.public_key.trim())
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            {
                Some(public) => public,
                None => {
                    return Ok(ApiResponse::error(
                        "Target device public key is malformed in the registry".to_string(),
                    ))
                }
            };
            let envelope = match persona_core::sync::envelope::seal_group_key(
                &group_key_bytes,
                &target_public,
            ) {
                Ok(envelope) => envelope,
                Err(e) => return Ok(ApiResponse::error(format!("Failed to seal group key: {e}"))),
            };
            match store.put_group_key(target_id, &envelope).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to write group key envelope: {e}"
                ))),
            }
        }
        persona_core::SyncTransport::Server => {
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
            // The local envelope cannot be opened = local device is unauthorized
            // (fail-closed); it cannot authorize others
            let group_key_bytes = match keys.iter().find(|k| k.device_id == identity.device_id) {
                Some(own) => {
                    match persona_core::sync::envelope::open_group_key(
                        &own.envelope,
                        identity.key_pair.secret_bytes(),
                    ) {
                        Ok(group_key) => group_key,
                        Err(_) => {
                            return Ok(ApiResponse::error(
                                "This device is not authorized yet; it cannot authorize others"
                                    .to_string(),
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
            let envelope = match persona_core::sync::envelope::seal_group_key(
                &group_key_bytes,
                &target.public_key,
            ) {
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
    }
}

/// Revoke a device (delete registration + envelope; idempotent; on the server
/// side the row is deleted, on the cloud drive the registry entry and files).
/// To revoke yourself, use sync_leave. A known group key cannot be revoked
/// retroactively (the DR-3 honesty boundary) — the wording is the frontend's
/// business.
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
    let (transport, cloud_dir) = sync_transport_config(&state).await;
    match transport {
        persona_core::SyncTransport::Cloud => {
            let dir = match cloud_dir {
                Some(dir) if !dir.trim().is_empty() => dir,
                _ => {
                    return Ok(ApiResponse::error(
                        "Cloud drive folder is not configured; pick one in sync settings"
                            .to_string(),
                    ))
                }
            };
            let store = persona_core::sync::remote::CloudGroupKeyStore::new(&dir);
            match store.remove_device(target_id).await {
                // Idempotent: absent from the registry = already revoked (or never
                // registered), return success
                Ok(_) => Ok(ApiResponse::success(true)),
                Err(e) => Ok(ApiResponse::error(format!("Failed to revoke device: {e}"))),
            }
        }
        persona_core::SyncTransport::Server => {
            let api = match sync_admin_api_for(&state).await {
                Ok(api) => api,
                Err(message) => return Ok(ApiResponse::error(message)),
            };
            match api.delete_device(target_id).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => Ok(ApiResponse::error(format!("Failed to revoke device: {e}"))),
            }
        }
    }
}

/// Shared gate + session assembly for the sync command family (sync_now /
/// sync_conflicts_list / sync_conflict_resolve share the same order; factored
/// into a common helper since phase 3c): unlock check -> db_path -> local
/// device identity -> server credentials -> open database and migrate ->
/// travel-gate sampling -> open the local envelope to assemble the session.
/// Any failed step returns `Err(user-readable message)`; the command body
/// converts it at the boundary to `Ok(ApiResponse::error(...))` (it never
/// escapes).
///
/// The master key is not fetched here — it is a borrow tied to the service
/// guard and must stay in the command body in the same lock section as the
/// subsequent service calls; the lock is only briefly held here for the travel
/// sampling (the sampled value is Copy and independent of the session
/// lifetime).
///
/// Transport routing (Phase 2 cloud-drive dual track): `settings.sync.sync_transport`
/// decides which transport to assemble — `Server` = HTTP (the existing path is
/// unchanged), `Cloud` =
/// `open_cloud` (the cloud-drive folder is the transport; no server credentials needed).
pub(crate) async fn open_sync_session(
    state: &State<'_, AppState>,
) -> std::result::Result<HostSyncSession, String> {
    let (transport, cloud_dir) = sync_transport_config(state).await;
    match transport {
        persona_core::SyncTransport::Cloud => {
            let dir = cloud_dir.filter(|p| !p.trim().is_empty()).ok_or_else(|| {
                "Cloud drive folder is not configured; pick one in sync settings".to_string()
            })?;
            HostSyncSession::open_cloud(state, dir).await
        }
        persona_core::SyncTransport::Server => HostSyncSession::open_server(state).await,
    }
}

/// The transport choice from `settings.sync` (transport + cloud dir). A
/// config section that cannot be read (fresh vault) = default Server / no
/// cloud-drive folder.
pub(crate) async fn sync_transport_config(
    state: &State<'_, AppState>,
) -> (persona_core::SyncTransport, Option<String>) {
    match require_db_path(state).await {
        Some(db_path) => match read_sync_config(state, &db_path).await {
            Some(config) => (config.sync_transport, config.cloud_drive_dir),
            None => (persona_core::SyncTransport::default(), None),
        },
        None => (persona_core::SyncTransport::default(), None),
    }
}

/// Shared tail of session assembly: unlock gate -> db_path -> device identity
/// -> open DB and migrate -> travel-gate sampling. The only difference between
/// the two transports is the last step ("get remote + key_store"), which the
/// caller [`HostSyncSession`] supplies per variant.
async fn open_session_common(
    state: &State<'_, AppState>,
) -> std::result::Result<
    (
        String,
        persona_core::sync::device::DeviceIdentity,
        Database,
        Box<dyn Fn() -> bool + Send + Sync>,
    ),
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
    let travel_active = service
        .travel_mode_active()
        .await
        .map_err(|e| format!("Travel mode check failed: {e}"))?;
    drop(service_guard);
    Ok((db_path, identity, db, Box::new(move || travel_active)))
}

/// Host-side enum over the sessions assembled by either transport.
/// `SyncSession<R>` is a different concrete type per transport, while the four
/// commands sync_now/status/conflict-resolve do not care about the transport —
/// forward these methods, and route rotate (which needs the server admin plane)
/// separately via [`Self::into_server`].
pub(crate) enum HostSyncSession {
    Server(persona_core::sync::runtime::SyncSession<persona_core::sync::remote::HttpSyncRemote>),
    Cloud(persona_core::sync::runtime::SyncSession<persona_core::sync::remote::CloudDriveRemote>),
}

impl HostSyncSession {
    async fn open_server(state: &State<'_, AppState>) -> std::result::Result<Self, String> {
        let (_db_path, identity, db, travel) = open_session_common(state).await?;
        let (server_url, token) = sync_server_creds_for(state).await?;
        persona_core::sync::runtime::SyncSession::open(&db, &identity, &server_url, &token, travel)
            .await
            .map(Self::Server)
            .map_err(|e| format!("Sync session failed: {e}"))
    }

    async fn open_cloud(
        state: &State<'_, AppState>,
        dir: String,
    ) -> std::result::Result<Self, String> {
        let (_db_path, identity, db, travel) = open_session_common(state).await?;
        persona_core::sync::runtime::SyncSession::open_cloud(&db, &identity, dir, travel)
            .await
            .map(Self::Cloud)
            .map_err(|e| format!("Sync session failed: {e}"))
    }

    /// The server session (rotate-only: it needs the HTTP admin plane). A
    /// cloud-drive session cannot be produced here — the caller should check the
    /// transport choice before deciding whether to attempt rotate.
    fn into_server(
        self,
    ) -> std::result::Result<
        persona_core::sync::runtime::SyncSession<persona_core::sync::remote::HttpSyncRemote>,
        String,
    > {
        match self {
            Self::Server(session) => Ok(session),
            Self::Cloud(_) => Err("Group key rotation requires the server transport".to_string()),
        }
    }

    /// Which transport the session actually uses. Used for classifying failure
    /// reasons ([`sync_failure`]): when opening the session fails there is no
    /// session to ask, so the transport read from configuration is used;
    /// failures inside the cycle use the session itself.
    fn transport(&self) -> persona_core::SyncTransport {
        match self {
            Self::Server(_) => persona_core::SyncTransport::Server,
            Self::Cloud(_) => persona_core::SyncTransport::Cloud,
        }
    }

    async fn backfill_existing(
        &self,
        master: &persona_core::crypto::encryption::EncryptionService,
    ) -> persona_core::Result<u64> {
        match self {
            Self::Server(session) => session.backfill_existing(master).await,
            Self::Cloud(session) => session.backfill_existing(master).await,
        }
    }

    async fn run_cycle(
        &self,
        master: &persona_core::crypto::encryption::EncryptionService,
    ) -> persona_core::Result<persona_core::sync::runtime::SyncNowReport> {
        match self {
            Self::Server(session) => session.run_cycle(master).await,
            Self::Cloud(session) => session.run_cycle(master).await,
        }
    }

    async fn status(&self) -> persona_core::Result<persona_core::sync::engine::SyncStatusReport> {
        match self {
            Self::Server(session) => session.status().await,
            Self::Cloud(session) => session.status().await,
        }
    }

    async fn list_conflicts(
        &self,
    ) -> persona_core::Result<Vec<persona_core::sync::resolve::ConflictEntry>> {
        match self {
            Self::Server(session) => session.list_conflicts().await,
            Self::Cloud(session) => session.list_conflicts().await,
        }
    }

    async fn resolve_conflict(
        &self,
        master: &persona_core::crypto::encryption::EncryptionService,
        item_id: uuid::Uuid,
        adopt_op_id: uuid::Uuid,
    ) -> persona_core::Result<()> {
        match self {
            Self::Server(session) => session.resolve_conflict(master, item_id, adopt_op_id).await,
            Self::Cloud(session) => session.resolve_conflict(master, item_id, adopt_op_id).await,
        }
    }

    /// The capture seam (transport-agnostic: both sides' `OplogCapture<R>`
    /// implement the `SyncCapture` trait object, and the service slot only
    /// accepts a trait object).
    fn capture(&self) -> std::sync::Arc<dyn persona_core::sync::capture::SyncCapture> {
        match self {
            Self::Server(session) => session.capture(),
            Self::Cloud(session) => session.capture(),
        }
    }
}

/// The structured cause of a failed sync cycle (CLOUD_DRIVE_SYNC §9.4): the UI
/// must present "cloud folder unavailable" and "server unreachable" distinctly —
/// the two have different fixes (point at an existing cloud folder / check OS
/// cloud proxy distribution vs. check the server URL and token). The
/// discrimination is structural: on the sync path
/// [`persona_core::PersonaError::Io`] is the only transport-layer I/O failure
/// variant (cloud = folder read/write, server = HTTP request), and the host has
/// already read the transport choice — two axes to locate it. What is checked is
/// that variant's stable Display prefix (`#[error("IO operation failed: …")]`),
/// not arbitrary text parsing.
pub(crate) struct SyncFailure {
    /// Machine-readable error code (written into `ApiResponse.error_code`);
    /// None = no dedicated code.
    pub code: Option<&'static str>,
    pub message: String,
}

impl std::fmt::Display for SyncFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Build a [`SyncFailure`] from the transport choice + error message. The
/// stable display prefix of `PersonaError::Io` filters "transport-layer I/O
/// failure" out from other failures such as crypto/database/validation, and
/// the transport choice then decides which side it is attributed to.
pub(crate) fn sync_failure(transport: persona_core::SyncTransport, message: String) -> SyncFailure {
    let code = message
        .contains("IO operation failed")
        .then_some(match transport {
            persona_core::SyncTransport::Server => "SYNC_SERVER_UNREACHABLE",
            persona_core::SyncTransport::Cloud => "SYNC_CLOUD_FOLDER_UNAVAILABLE",
        });
    SyncFailure { code, message }
}

/// The host orchestration body of one sync cycle (shared by the `sync_now`
/// command and the cloud-drive watcher): assemble the session (per the current
/// transport) -> backfill existing data -> pull/materialize/push -> attach the
/// capture seam to the service. Protocol/cryptography/orchestration all live in
/// core `SyncSession`; this only does host orchestration. Returns
/// `Err(SyncFailure)` without converting to ApiResponse — the command body
/// converts at the boundary, and the watcher just logs it.
pub(crate) async fn sync_cycle_once(
    state: &State<'_, AppState>,
) -> std::result::Result<SyncNowReport, SyncFailure> {
    let transport = sync_transport_config(state).await.0;
    let session = open_sync_session(state)
        .await
        .map_err(|message| sync_failure(transport, message))?;
    let transport = session.transport();
    let service_guard = state.service.lock().await;
    let service = service_guard
        .as_ref()
        .ok_or_else(|| sync_failure(transport, "Service not initialized".to_string()))?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| sync_failure(transport, e.to_string()))?;

    let backfilled = session
        .backfill_existing(master)
        .await
        .map_err(|e| sync_failure(transport, format!("Sync backfill failed: {e}")))?;
    let mut report = session
        .run_cycle(master)
        .await
        .map_err(|e| sync_failure(transport, format!("Sync cycle failed: {e}")))?;
    report.backfilled = backfilled;

    service.attach_sync_capture(Some(session.capture())).await;
    Ok(SyncNowReport::from(report))
}

/// Sync now (the host entry point of E2EE sync phase 3b): open the local
/// envelope to assemble the session -> backfill existing data -> the
/// pull/materialize/push cycle -> attach the capture seam to the service
/// (after which local writes land in the oplog automatically).
/// Protocol/cryptography/orchestration all live in core `SyncSession`; this
/// only does host orchestration — the gate runs via `open_sync_session`, and the
/// master borrow plus capture-seam attachment stay inside this command's lock
/// section.
#[command]
pub async fn sync_now(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncNowReport>, String> {
    match sync_cycle_once(&state).await {
        Ok(report) => Ok(ApiResponse::success(report)),
        Err(failure) => Ok(match failure.code {
            Some(code) => ApiResponse::error_with_code(code.to_string(), failure.message),
            None => ApiResponse::error(failure.message),
        }),
    }
}

/// Sync status snapshot (sync-group-mode §2.5.5): group latest version /
/// local synced watermark / N entries behind / N entries pending push / last
/// sync time. Read-only and runs no cycle — "sync now" is still sync_now.
/// Same gate as sync_now (unlocked and joined; the head query goes to the
/// server, and when the server is unreachable the error is reported honestly
/// rather than falsely claiming "already up to date").
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

/// Group key rotation (E2EE sync phase 3d): swap envelopes + full re-wrap —
/// the safety operation that actually closes the loop for device revocation.
/// The core flow lives in core `SyncSession::rotate_group_key`; this only does
/// host orchestration. Honesty boundaries (the frontend confirm dialog must
/// state them; see the core docs): devices that are kept should "sync now"
/// before rotation; unresolved conflict replicas leave the resolution view along
/// with the re-wrap; concurrent rotations are mutually excluded by an epoch
/// optimistic lock (2026-09-24) — the later one gets the CONCURRENT_CONFLICT
/// error code and can retry after re-reading the status.
#[command]
pub async fn sync_rotate(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SyncRotateReport>, String> {
    let session = match open_sync_session(&state).await {
        Ok(session) => session,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    // The cloud-drive transport has no admin plane to swap all envelopes
    // (rotation = envelope swap + full re-wrap, which the server arbitrates with
    // the epoch optimistic lock) — report this honestly; registered under
    // CLOUD_DRIVE_SYNC §9.
    let session = match session.into_server() {
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
            // A concurrent-rotation 409 surfaces via
            // PersonaError::ConcurrentConflict as the CONCURRENT_CONFLICT code
            // (so the frontend can branch on it); everything else has no
            // dedicated code
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

/// Conflict resolution list (E2EE sync phase 3c): all entries awaiting
/// resolution (the primary copy plus a decrypted snapshot of each replica).
/// Read-only, changes no state; entries whose replica is corrupted are skipped
/// entirely (they stay in the oplog without blocking the rest of the display).
#[command]
pub async fn sync_conflicts_list(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SyncConflictEntry>>, String> {
    let session = match open_sync_session(&state).await {
        Ok(session) => session,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    // No master borrow: list's decryption goes through the group key (obtained
    // by opening the envelope during session assembly) and only the unlock gate
    // is required; differs from resolve (which needs master to re-wrap the item key).

    match session.list_conflicts().await {
        Ok(entries) => Ok(ApiResponse::success(
            entries.into_iter().map(SyncConflictEntry::from).collect(),
        )),
        Err(e) => Ok(ApiResponse::error(format!(
            "Failed to list sync conflicts: {e}"
        ))),
    }
}

/// Resolve a conflict (E2EE sync phase 3c): adopt one replica — write it into
/// the main vault per the replica content (put reuses its payload bytes /
/// delete removes the row), then re-book it with a fresh local lamport, and
/// the remaining versions are evicted from the resolution view. Adopting an
/// already-resolved op_id again returns an error
/// (NotFound; it is already outside the view).
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

/// Group key hex encoding/decoding (32 bytes <-> 64 chars; the keyring value format).
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

/// Whether this vault has joined the sync group (the keyring group-key
/// entry; a read failure fails closed and is treated as not joined — the
/// host pairing code generates a new group key, and a guest joining is
/// unaffected).
pub(crate) fn sync_group_joined(state: &State<'_, AppState>, db_path: &str) -> bool {
    state
        .sync_group_store
        .get(db_path)
        .ok()
        .and_then(|v| v)
        .is_some()
}

/// Sync group status (read-only, no unlock needed — same convention as
/// sync_device_status).
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

/// Host code generation: create a pairing session and relay mailbox, return the
/// dynamic code and invite string.
/// Group key: if this device is already in the group, reuse it; on first use,
/// generate one randomly (persisted to the keyring when the poll completes).
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

/// Host waits for the guest to join: blocks driving the handshake until
/// completion (a 90s window, cancellable during that time — once cancel deletes
/// the relay mailbox this command errors out). On completion the group key is
/// persisted to the keyring.
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
            // Guest not seen (90s timeout) or relay failure: put the session back
            // for retry (within the TTL)
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

/// Cancel a pairing/join session (works for both roles): remove the local
/// session and best-effort clean up the relay mailbox.
/// Idempotent: succeeds even when the session does not exist (a stale page can
/// be clicked again).
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
            // Mailbox cleanup is best-effort: if the relay is unreachable the local
            // side is already clean, and the TTL will reclaim it naturally
            if let Err(e) = relay.delete_session(&session_id).await {
                tracing::warn!(%e, "pairing relay mailbox cleanup failed; TTL will reclaim it");
            }
        }
    }
    Ok(ApiResponse::success(true))
}

/// Guest step 1 of entering the code: decode the invite string, start pairing,
/// send client_public to the host, and wait for the host's reply before
/// returning the short fingerprint (the UI compares it against the host side;
/// only on a match is confirm called).
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

/// Guest step 2: after the fingerprint matches, confirm joining — send M1,
/// receive the group-key handover, and decode the group key into the keyring.
/// On failure the local session is discarded (the code must be re-entered to
/// restart pairing).
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
        // M1 already sent or the handover timed out: the session state is no longer
        // reliable, discard it (re-enter the code to restart pairing)
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

/// Guest cancels joining (fingerprint mismatch / given up): remove the local
/// session + clean up the relay mailbox.
/// This is the guest-side alias of pairing_cancel, with the same idempotent
/// semantics.
#[command]
pub async fn sync_group_join_cancel(
    session_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    sync_group_pairing_cancel(session_id, state).await
}

#[cfg(test)]
mod sync_failure_tests {
    use super::sync_failure;

    /// Transport-layer I/O failures are attributed to the side chosen by the
    /// transport (CLOUD_DRIVE_SYNC §9.4)
    #[test]
    fn transport_io_failure_classifies_by_side() {
        let server = sync_failure(
            persona_core::SyncTransport::Server,
            "Sync cycle failed: IO operation failed: sync status request failed: timed out"
                .to_string(),
        );
        assert_eq!(server.code, Some("SYNC_SERVER_UNREACHABLE"));

        let cloud = sync_failure(
            persona_core::SyncTransport::Cloud,
            "Sync session failed: IO operation failed: create cloud drive dir failed: No such file"
                .to_string(),
        );
        assert_eq!(cloud.code, Some("SYNC_CLOUD_FOLDER_UNAVAILABLE"));
    }

    /// Gate-type failures (locked / not joined / folder not configured /
    /// service not initialized) get no classification: the UI keeps a generic
    /// message and does not falsely claim "server unreachable"
    #[test]
    fn non_transport_failures_have_no_code() {
        for message in [
            "Vault is locked: unlock to sync".to_string(),
            "Sync config not found".to_string(),
            "Service not initialized".to_string(),
        ] {
            for transport in [
                persona_core::SyncTransport::Server,
                persona_core::SyncTransport::Cloud,
            ] {
                let failure = sync_failure(transport, message.clone());
                assert_eq!(failure.code, None, "{message}");
            }
        }
    }

    /// The original message is kept for logging and generic display (Display prints only the message)
    #[test]
    fn failure_message_survives() {
        let failure = sync_failure(
            persona_core::SyncTransport::Cloud,
            "IO operation failed: read sync registry failed".to_string(),
        );
        assert_eq!(
            failure.to_string(),
            "IO operation failed: read sync registry failed"
        );
        assert_eq!(failure.code, Some("SYNC_CLOUD_FOLDER_UNAVAILABLE"));
    }
}
