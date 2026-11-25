use super::*;

/// After a successful unlock, replay the Quick Access global hotkey
/// (toggle + binding) according to the DB's real values.
///
/// Replay on every unlock rather than "skip when identical to the last time":
/// the binding may have been changed on the other side (settings JSON edited
/// by hand via the CLI / a vault synced from another machine); replaying costs
/// one unregister_all plus one register, and buys the guarantee that any
/// change converges at the next unlock. **A failed settings read only warns** —
/// the global hotkey is an enhancement and must never block the unlock.
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

/// Read the Quick Access status surface (**no unlock required**: the binding
/// and the toggle live in workspace settings, so the popover / settings page
/// must still report truthfully "whether the hotkey actually took effect"
/// while locked).
///
/// The runtime side comes from `AppState.quick_access` (the real grab
/// outcome), the configured side from the DB — a mismatch between the two is
/// exactly what should be exposed: when the grab fails, configured has a value
/// while registered is empty, and the UI shows "not in effect + reason"
/// accordingly.
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

/// Set the Quick Access toggle and binding: unlock gate -> syntax validation
/// -> persist -> re-register.
///
/// Writing requires the unlock gate (as with `set_locale` /
/// `set_feature_flags` / `set_password_expiry`): reads (status) being unlocked-free
/// exists so the lock screen / settings page can see "whether the hotkey
/// actually took effect"; a config change should not happen while locked.
///
/// Persisting first is deliberate: a successful re-registration paired with a
/// failed write would leave a "hotkey changed in memory but not in the DB"
/// drift (the next unlock pulls it back from the DB, and the user assumes the
/// rebind failed). A failed grab does **not count as a command failure** — the
/// binding is already persisted; the response carries an `error` so the
/// settings page can display it truthfully (no portal on Wayland / taken by
/// another app is the normal case, not an error flow).
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

    // Validate syntax first: an invalid string must not be persisted (otherwise
    // it keeps failing at every subsequent unlock)
    let normalized = match accelerator.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            let normalized = crate::quick_access::normalize_accelerator(raw);
            if let Err(err) = crate::quick_access::parse_accelerator(&normalized) {
                return Ok(ApiResponse::error(err));
            }
            Some(normalized)
        }
        // Empty string = restore the platform default binding (store None; do
        // not pin the default value into the DB)
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

/// Open the popover directly from the tray menu / settings page (does not rely
/// on the global hotkey — when the hotkey is taken this remains the entry point)
#[command]
pub async fn quick_access_open<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    crate::quick_access::open(&app);
    Ok(ApiResponse::success(true))
}

/// Read the generator hotkey status surface (no unlock needed, same semantics as
/// [`quick_access_status`])
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

/// Set the generator hotkey toggle and binding (same semantics as
/// [`quick_access_set`]: unlock gate -> syntax validation -> persist ->
/// re-register; a failed grab is not a command failure)
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

    // Validate syntax first: an invalid string must not be persisted (otherwise
    // it keeps failing at every subsequent unlock)
    let normalized = match accelerator.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            let normalized = crate::quick_access::normalize_accelerator(raw);
            if let Err(err) = crate::quick_access::parse_accelerator(&normalized) {
                return Ok(ApiResponse::error(err));
            }
            Some(normalized)
        }
        // Empty string = restore the platform default binding (store None; do
        // not pin the default value into the DB)
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

/// Open the generator popover directly from the tray menu (same semantics as
/// [`quick_access_open`])
#[command]
pub async fn generator_open<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    crate::quick_access::open_generator(&app);
    Ok(ApiResponse::success(true))
}

/// The popover's "Open in Persona": sends a targeted notification to the main
/// window to switch identity + select the entry, and brings the main window to
/// the front. The two windows each have an independent JS store, so a
/// cross-window jump can only go through events (payload in
/// `quick_access::OpenCredentialPayload`)
#[command]
pub async fn quick_access_open_credential<R: tauri::Runtime>(
    request: QuickAccessOpenCredentialRequest,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    // Check the UUID shape first: with an invalid id the main window would only
    // silently fail to select anything, wasting the round trip
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

/// Query the desktop-fill injection target status (#12). The frontend uses this
/// to decide whether the popover's fill action is available (clicking it when
/// nothing is captured or the target is stale would only produce an error;
/// exposing the state earlier is more honest).
/// The ready state must match the real state (security review P2 tightening):
/// on Windows the slot is re-verified by fingerprint, and a stale target
/// (window closed / reused / different process) clears the slot immediately and
/// reports not ready.
#[command]
pub async fn fill_target_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::desktop_fill::FillTargetStatus>, String> {
    let supported = crate::desktop_fill::fill_supported();
    let mut guard = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
    // Injection path ready = a snapshot exists and the current fingerprint
    // (hwnd alive + pid + class name + executable file + title prefix) still
    // matches; a stale one is discarded immediately. Non-Windows platforms have
    // no fingerprint verification capability, so the slot should be empty and
    // is defensively treated as stale.
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

/// Desktop in-app fill injection (#12): inject the credential's username/password
/// into the target window that held the foreground before the search popover
/// was summoned. Scope (honesty boundaries; see the desktop_fill module
/// comments):
/// - Windows only (other platforms: `fill_supported()` = false, reported
///   honestly);
/// - only classic Win32 EDIT control hosts (self-drawn/browser hosts do not
///   apply; browsers belong to the extension);
/// - only Password-type credentials (the username + password two fields);
/// - only inject into password boxes with the `ES_PASSWORD` style that are
///   visible/enabled/not read-only — with no qualifying password box it
///   refuses, and a plain box never impersonates a password box (security
///   review P1 tightening);
/// - **must first go through user confirmation**: the popover shows the target
///   app name (executable file name) and window title, and only after the user
///   explicitly confirms does the frontend call this command with
///   `confirmed = true`; a missing/false `confirmed` is always rejected — no
///   silent injection path exists.
/// - **confirmation binds to a specific snapshot (P1 tightening)**: on confirm
///   the frontend returns the `snapshot_id` generated at capture time; after
///   decryption (the in-flight window) completes, the id is compared against
///   the current slot under the lock — an empty slot (the popover collapsed and
///   cleared it) reports `FILL_TARGET_DISCARDED` truthfully, and a slot
///   replaced by a re-capture (B captured after confirming A) reports
///   `FILL_TARGET_CHANGED` truthfully; an in-flight request is never
///   redirected to a new target.
/// The sensitive surface is on par with reveal_credential_secret: it goes
/// through the `get_credential_data` decryption path (with its built-in audit
/// and re-auth gate).
#[command]
pub async fn desktop_fill_credential(
    credential_id: String,
    confirmed: bool,
    snapshot_id: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<crate::desktop_fill::DesktopFillResult>, String> {
    // Platform honesty: do not pretend the feature exists on non-Windows
    if !crate::desktop_fill::fill_supported() {
        return Ok(ApiResponse::error(
            "Desktop fill injection is only implemented on Windows".to_string(),
        ));
    }
    // User confirmation surface (security review P1): the target app name was
    // already shown in the popover and explicitly confirmed by the user, so the
    // backend only admits explicitly confirmed calls. Confirmation is not the
    // authorization boundary itself (the target fingerprint is), but it is the
    // hard gate that forbids silent direct writes.
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
    // Username goes through metadata (low sensitivity), the password through the
    // decryption path (the same audit surface as reveal)
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

    // Confirmation binds to a specific snapshot (P1 tightening): decryption is
    // an in-flight window — during it the popover may be re-summoned and capture
    // a different target, or may have collapsed and cleared the slot. Under the
    // lock, bind to the snapshot carried by the request and then clone (the
    // injection is a slow FFI call, executed outside the lock; the injection
    // target is therefore exactly the confirmed snapshot, and both the
    // fingerprint re-verification and the per-control re-verification anchor to
    // it, not to "whatever is in the slot right now").
    // The injection itself remains outside the lock — this closes the fourth
    // round's cancellation boundary: before each field write inside the injection
    // loop, `slot_recheck_for` re-checks the slot (the same semantics as the
    // bind comparison); a cleared slot / changed target aborts the remaining
    // writes and reports partial completion honestly (`FILL_TARGET_DISCARDED` /
    // `FILL_TARGET_CHANGED`), never writing any credential field into a
    // non-confirmed target.
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
            // Discard the stale target immediately so the next attempt does not
            // hit the same wall — but only discard the snapshot this request
            // confirmed: if the slot has already been re-captured (a different
            // target), do not clear it on the user's behalf
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
                    // Unreachable: the re-check closure always carries the snapshot id;
                    // handled defensively as a protocol error
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
