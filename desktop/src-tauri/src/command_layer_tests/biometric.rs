//! Command-layer integration tests — `biometric` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn biometric_status_reports_disabled_without_entry() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    init_service_ok(&app, "master-pw-123").await;
    let db_path = app
        .state::<AppState>()
        .db_path
        .lock()
        .await
        .clone()
        .unwrap();

    let resp = biometric_status(None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    // provider available + keyring reachable (Ok(None)) but no entry exists yet
    assert!(status.available);
    assert!(!status.enabled);
    assert_eq!(status.platform, crate::biometric::platform_name());

    // after configuration enabled flips; the explicit db_path arg shares the same key as the state path
    store.set(&db_path, "master-pw-123").unwrap();
    let resp = biometric_status(None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().enabled);
}
#[tokio::test]
async fn biometric_enable_rejects_wrong_password_without_writing() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "wrong-password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid master password"));
    // password first, then the dialog: a wrong password means no ceremony is even shown, and nothing is written to keyring
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_enable_ceremony_then_writes_entry() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    assert!(status.available && status.enabled);
    // what gets escrowed is the verified master password (key = db_path, one key per vault)
    assert_eq!(
        store.get(&db_path).unwrap().as_deref(),
        Some("correct-horse")
    );
}
#[tokio::test]
async fn biometric_enable_fails_closed_when_provider_unavailable() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(false, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not available"));
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_enable_ceremony_failure_writes_nothing() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, true), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    // a ceremony failure converts to Ok(ApiResponse::error) at the command boundary (does not escape), with zero writes
    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "ceremony failure must surface an error");
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_enable_requires_unlocked_service() {
    // Not initialized: rejected outright
    let app = mock_app_with_biometric(
        mock_provider(true, false),
        Arc::new(InMemoryTokenStore::default()),
    );
    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // Locked: enabling is a sensitive configuration operation within an unlocked session
    let app = mock_app_with_biometric(
        mock_provider(true, false),
        Arc::new(InMemoryTokenStore::default()),
    );
    init_service_ok(&app, "correct-horse").await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}
#[tokio::test]
async fn biometric_disable_is_idempotent() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    for _ in 0..2 {
        let resp = biometric_disable(app.state::<AppState>()).await.unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(!resp.data.unwrap().enabled);
    }
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_unlock_unlocks_via_init_service() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    // The response body is a bare bool — the escrowed password never leaves the process (it is not in the type at all)
    assert_eq!(resp.data, Some(true));

    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(
        resp.data,
        Some(true),
        "biometric unlock must unlock the service"
    );
}
#[tokio::test]
async fn biometric_unlock_without_entry_skips_ceremony_and_reports_reset() {
    // force_fail provider: if a dialog were really shown, the result would be Err(String) rather than a coded error
    let app = mock_app_with_biometric(
        mock_provider(true, true),
        Arc::new(InMemoryTokenStore::default()),
    );
    init_service_ok(&app, "correct-horse").await;
    // Start from the locked state: with no entry it must neither show a dialog nor unlock
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_RESET)
    );
    // No dialog was shown and no unlock happened
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));
}
#[tokio::test]
async fn biometric_unlock_stale_entry_self_heals() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;
    // Plant an entry with the wrong password: simulates a stale escrow after a password change made outside the desktop (via the CLI)
    store.set(&db_path, "stale-password").unwrap();
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_RESET)
    );
    // The entry is deleted on the spot (so repeated biometric taps cannot accumulate failure counts and lock the account out), and the service is still locked
    assert_eq!(store.get(&db_path).unwrap(), None);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));
}
#[tokio::test]
async fn biometric_unlock_fails_closed_when_provider_unavailable() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(false, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;
    store.set(&db_path, "correct-horse").unwrap();
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not available"));
    // The entry is kept (unavailable is not the same as stale); the unlock screen reports an error but the master password can still be used to log in
    assert_eq!(
        store.get(&db_path).unwrap().as_deref(),
        Some("correct-horse")
    );
}
#[tokio::test]
async fn biometric_enable_keyring_write_failure_reports_and_leaves_no_half_state() {
    let inner = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(
        mock_provider(true, false),
        Arc::new(FailingSetStore(inner.clone())),
    );
    init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    // The ceremony passed but the keyring write failed: a clear error (mentioning keyring)
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("keyring write failed"));
    assert_eq!(inner.get("any").unwrap(), None);
}
/// Wrapping-chain enable: what keyring stores is a ciphertext blob (the
/// gate-layer password entry is never persisted), and status reports
/// hardware-bound.
#[tokio::test]
async fn biometric_wrap_enable_stores_ciphertext_blob() {
    let gate_store = Arc::new(InMemoryTokenStore::default());
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_wrap_parts(
        Arc::new(InMemoryTokenStore::default()),
        mock_provider(true, false),
        gate_store.clone(),
        Arc::new(persona_core::MockKeyWrapper::default()),
        wrap_store.clone(),
    );
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    assert!(status.available && status.enabled);
    assert_eq!(status.wrap_tier, "hardware-bound");

    // The blob is ciphertext: decodable base64, magic BIOWRAP1, and definitely not the plaintext password
    let blob = wrap_store.get(&db_path).unwrap().expect("wrap blob stored");
    assert_ne!(blob, "correct-horse");
    let raw = base64_decode(&blob);
    assert_eq!(&raw[..8], b"BIOWRAP1");
    // The gate-layer password entry is never persisted (the two classes are mutually exclusive)
    assert_eq!(gate_store.get(&db_path).unwrap(), None);
}
/// Wrapping-chain unlock full loop: enable -> lock -> unlock, the service recovers and data is readable.
#[tokio::test]
async fn biometric_wrap_unlock_round_trip() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let wrapper = Arc::new(persona_core::MockKeyWrapper::default());
    let app = mock_app_with_biometric_wrap(wrapper, wrap_store);
    init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true));
}
/// Enrollment drift (fingerprints swapped): unlock reports BIOMETRIC_RESET and
/// the blob is deleted on the spot,
///
/// while master password login is unaffected.
#[tokio::test]
async fn biometric_wrap_enrollment_change_resets_to_master_password() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let wrapper = Arc::new(persona_core::MockKeyWrapper::default());
    let app = mock_app_with_biometric_wrap(wrapper.clone(), wrap_store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // The user swapped fingerprints on the system side
    wrapper.rotate_enrollment();
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_RESET)
    );
    // The blob is deleted on the spot (the old wrapping is never retried), and the service stays locked
    assert_eq!(wrap_store.get(&db_path).unwrap(), None);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));

    // End state of the fallback chain: the master password still logs in as usual
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(db_path),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// The user clicks cancel in the system dialog: reports BIOMETRIC_CANCELLED,
/// the blob is kept, and the service stays locked (cancelling is not a failure:
/// the wrapping is not deleted and no error is surfaced).
#[tokio::test]
async fn biometric_wrap_user_cancel_keeps_blob() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let wrapper = Arc::new(persona_core::MockKeyWrapper::default());
    let app = mock_app_with_biometric_wrap(wrapper.clone(), wrap_store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    wrapper.set_user_cancelled(true);
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_CANCELLED)
    );
    // The wrapping is still valid (it can still be unwrapped next time), and the service stays locked
    assert!(wrap_store.get(&db_path).unwrap().is_some());
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));
}
/// The blob has been tampered with (not base64 / corrupted envelope): reports
/// BIOMETRIC_RESET and deletes itself,
///
/// without accumulating failure counts or locking the account.
#[tokio::test]
async fn biometric_wrap_corrupted_blob_resets() {
    for corrupt in ["!!!not-base64!!!", "QUJDRA=="] {
        let wrap_store = Arc::new(InMemoryTokenStore::default());
        let app = mock_app_with_biometric_wrap(
            Arc::new(persona_core::MockKeyWrapper::default()),
            wrap_store.clone(),
        );
        let db_path = init_service_ok(&app, "correct-horse").await;
        // Forged entries: the first is not even base64, the second is valid base64 but not an envelope
        wrap_store.set(&db_path, corrupt).unwrap();
        lock_service(app.state::<AppState>()).await.unwrap();

        let resp = biometric_unlock(
            BiometricUnlockRequest { db_path: None },
            app.state::<AppState>(),
            app.handle().clone(),
        )
        .await
        .unwrap();
        assert!(!resp.success, "corrupt blob {corrupt:?} must fail");
        assert_eq!(
            resp.error_code.as_deref(),
            Some(crate::error::CODE_BIOMETRIC_RESET),
            "corrupt blob {corrupt:?}"
        );
        assert_eq!(wrap_store.get(&db_path).unwrap(), None);
    }
}
/// The wrapping blob becomes invalid after a password change: the old blob
/// unwraps to a stale key, so the password-change coupling must delete the blob
/// (the user re-enables), and status returns to disabled.
#[tokio::test]
async fn biometric_wrap_invalidated_on_password_change() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric_wrap(
        Arc::new(persona_core::MockKeyWrapper::default()),
        wrap_store.clone(),
    );
    let db_path = init_service_ok(&app, "old-password").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "old-password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(wrap_store.get(&db_path).unwrap().is_some());

    let resp = change_master_password(
        crate::types::ChangeMasterPasswordRequest {
            old_password: "old-password".to_string(),
            new_password: "new-password".to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    // The blob has been deleted: status returns to disabled and the frontend hides the biometric button
    assert_eq!(wrap_store.get(&db_path).unwrap(), None);
    let resp = biometric_status(None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.data.unwrap().enabled);
}
/// The spike command reports Unsupported on Linux (the probe is a Security.framework call).
#[tokio::test]
async fn biometric_wrap_spike_unsupported_off_macos() {
    let resp = biometric_wrap_spike().await.unwrap();
    #[cfg(target_os = "macos")]
    assert!(resp.success);
    #[cfg(not(target_os = "macos"))]
    {
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("only available on macOS"));
    }
}
/// The TPM spike command reports Unsupported off Windows (the probe is an NCrypt call).
#[tokio::test]
async fn biometric_tpm_spike_unsupported_off_windows() {
    let resp = biometric_tpm_spike().await.unwrap();
    #[cfg(target_os = "windows")]
    assert!(resp.success);
    #[cfg(not(target_os = "windows"))]
    {
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("only available on Windows"));
    }
}
