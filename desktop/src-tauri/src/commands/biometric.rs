use super::*;

/// Vault path resolution for the biometric commands: argument first
/// (passed when the frontend checked a custom vault path — one db_path, one
/// key), then the session's db_path, then the default path (state.db_path
/// is still None on the unlock screen).
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

/// Run one OS authentication prompt on a blocking thread (the provider has
/// its own 120s timeout; the tokio worker is not parked).
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

/// The wrap tier currently in effect for this vault (or the one the next
/// enable will use), for frontend display. A wrap blob exists = this
/// vault's unlock chain is hardware-backed; otherwise report by platform
/// capability.
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

/// Read-only: biometric unlock status (no unlock needed — queried on
/// unlock-screen mount to decide the fingerprint button's visibility).
/// `enabled` only leaks one bit of metadata, "whether this vault ever had
/// biometric unlock configured" (same tier as sync_token_present); the true
/// values of the custodial master password / wrap blob never leave the
/// keyring and never cross IPC.
#[command]
pub async fn biometric_status(
    db_path: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BiometricStatusResponse>, String> {
    let db_path = resolve_biometric_db_path(db_path, &state).await;
    // Keyring reachability is part of availability: a keyring that cannot
    // be written to has no biometric unlock to enable (fail-closed, same
    // convention as attach_sync_emitter).
    // Any probe error is reported as enabled=false — a read failure is never
    // misreported as configured.
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

/// Enable biometric unlock: verify master password -> OS authentication
/// prompt -> custody (hardware-bound tier: the master key is wrapped by the
/// platform hardware key and the blob goes into a separate keyring;
/// gate-only tier: the master password is custodied into the keyring). The
/// order is deliberately password first, prompt second — the password is
/// the secret being custodied and must be proven correct first (never write
/// an unverified password into the keyring); the millisecond-level
/// verification runs first to fail fast, saving the system-level prompt —
/// that scarce attention resource — for last. Passing a device fingerprint
/// does not mean knowing the vault's master password, so a master password
/// is still required in an unlocked session = reusing the "sensitive
/// operation re-authentication" precedent (the same UX as 1Password
/// enabling Touch ID).
#[command]
pub async fn biometric_enable(
    request: BiometricEnableRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BiometricStatusResponse>, String> {
    use base64::Engine;

    // Unlock gate (same as set_locale): enabling is a sensitive
    // configuration operation in an unlocked session
    {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) if service.is_unlocked() => {}
            Some(_) => return Ok(ApiResponse::error("Service is locked".to_string())),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    }
    let db_path = db_path_or_return!(state);

    // 1. Verify the master password (via the live service, inheriting the
    //    failure count / AccountLocked semantics; semantics are the same as
    //    reauth_verify — error codes map through as-is; authenticate_user
    //    needs &mut)
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

    // 2. OS authentication prompt
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

    // 3. Custody: the hardware-bound tier (capability HardwareBound) uses
    //    key wrapping — the master key is ECIES-wrapped by the platform
    //    hardware key and the blob goes into a separate keyring service,
    //    with no password entry on disk; the gate-only tier keeps the
    //    historical behavior (password custody). The ceremony has already
    //    been spent: a write failure returns an explicit error and leaves no
    //    half state; the user falling back to password login is unaffected.
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
                // The public key used for wrapping (no prompt; the prompt
                // happens at the decrypt moment on the unlock side)
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
                        // Belt-and-suspenders cleanup of the gate-layer
                        // password entry (the two kinds are mutually
                        // exclusive; a failed delete only affects the
                        // fallback order — unlock prefers the wrap entry)
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

/// Disable biometric unlock: double-delete the keyring entries (wrap blob +
/// gate-layer password; each is idempotent, so deleting both always
/// succeeds). No ceremony needed and no unlock gate is set — this is an
/// exposure-reducing operation (no sensitive reads; once deleted the
/// fingerprint button disappears from the unlock screen and master password
/// login is unaffected).
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

/// Secure Enclave spike probe (macOS real devices only, design doc §5.2).
///
/// Runs all the probes in `macos_se::run_spike` and reports each
/// OSStatus/verdict: the caller starts the app on a real device with
/// `PERSONA_BIOMETRIC_SE_SPIKE=1` and invokes this command, then pastes the
/// output back into design doc §5.2. Non-macOS reports Unsupported
/// immediately (the probe is a Security.framework call with no
/// cross-platform meaning); on macOS the call is allowed even when the
/// spike gate is off (the probe only reads/writes its own test keys and
/// never touches the production unlock chain).
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

/// Passport KSP spike probe (Windows real devices only, design doc §6.1).
///
/// Same pattern as macOS's `biometric_wrap_spike`: runs all the probes in
/// `windows_tpm::run_spike` and reports each HRESULT/verdict — start the
/// app on a real device with `PERSONA_BIOMETRIC_TPM_SPIKE=1` and invoke
/// this command, then paste the output back into design doc §6.1. The
/// probe only touches its own wrap keys and is not connected to the
/// production unlock chain. Non-Windows reports Unsupported immediately
/// (the probe is an NCrypt call with no cross-platform meaning).
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

/// Platform spike steps -> command response body (shared by the macOS SE
/// and Windows TPM probes; only called on those two platforms, cfg'd out
/// elsewhere to avoid dead_code warnings)
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

/// Hardware-bound path: unwrap the blob (SE/TPM force biometrics at the
/// decrypt moment) -> go straight into init with the master key. A
/// malformed / unopenable blob or an enrollment-set drift -> auto-delete
/// and return BIOMETRIC_RESET (the fallback chain's terminal state is the
/// master password, never a deadlock).
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
            // The blob is not base64: definitely broken, delete on the spot
            // (same self-heal semantics as a stale password entry)
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
            // The hardware says this wrap can never be opened again
            // (re-enrolled fingerprint / key rebuilt / platform downgrade):
            // auto-invalidate + clearly guide to the master password
            // (design doc §3.4, the fallback chain's terminal state)
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

    // The key never leaves the process: init's internal dispatch consumes
    // the master key directly
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

/// Biometric unlock: wrap blob exists -> hardware-bound chain (prompt at
/// the decrypt moment); otherwise the gate chain (check the entry first —
/// a clean error without a system prompt when absent -> OS authentication
/// prompt -> fetch the master password from the keyring -> run the
/// existing [`init_service`] full chain; Success / InvalidCredentials /
/// AccountLocked / PASSWORD_CHANGE_REQUIRED pass through as-is; the master
/// password never leaves the process and never enters an ApiResponse).
#[command]
pub async fn biometric_unlock<R: tauri::Runtime>(
    request: BiometricUnlockRequest,
    state: State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = resolve_biometric_db_path(request.db_path, &state).await;

    // Hardware-bound chain takes priority (the two entry kinds are mutually
    // exclusive; enable already did the belt-and-suspenders cleanup)
    if let Ok(Some(wrap_blob)) = state.biometric_wrap_store.get(&db_path) {
        return Ok(biometric_unlock_with_wrap(wrap_blob, db_path, state, app).await);
    }

    let master_password = match state.biometric_store.get(&db_path) {
        Ok(Some(password)) => password,
        Ok(None) => {
            // Not configured / already reset: BIOMETRIC_RESET makes the
            // frontend hide the button and show a message
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

    // Reuse init_service itself: the full in-lock chain (auto-lock bridge,
    // passkey server, sync emitter, biometric provider injection) is
    // identical to the password unlock
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

    // Stale-entry self-heal (e.g. a password changed outside the desktop):
    // the fetched password has just been proven wrong for this vault, so
    // the entry must be broken — delete it on the spot to stop repeated
    // fingerprint taps from pointlessly accumulating failure counts
    // (core locks the account after 5 failures) and locking it for good
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
