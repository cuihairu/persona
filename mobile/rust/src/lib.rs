//! Persona mobile bindings.
//!
//! Hand-written extern "C" FFI: wires the core [`PersonaService`] and the audit
//! event reporter ([`Emitter`] + [`ServerEventSink`]) into the mobile host.
//! Host wiring semantics match desktop/CLI: a half-configured config is
//! fail-closed (enabled only when both url and token are non-empty), write to
//! the local audit DB first then best-effort report, and shutdown does a
//! best-effort final flush.
//!
//! Memory contract: strings are passed out via `CString::into_raw` and returned
//! by the caller with `persona_free_string`/`persona_free_result`; all service
//! state lives in global slots on the Rust side (`state.rs`), and pointer
//! arguments are input-only, borrowed for the duration of this function.
//!
//! Panic line of defense: lifecycle entry points are uniformly wrapped in
//! [`guard_result`]/[`guard_bool`] (panic → error result instead of crossing
//! the C boundary; the build must use unwind, see their docs).

mod business;
mod runtime;
mod state;

// JNI export layer for the Android host: Kotlin (com.persona.mobile.PersonaBridge)
// goes through the platform-standard JNI via System.loadLibrary("persona_mobile"),
// forwarding internally to the C ABI in this same file — sharing one set of
// bridge semantics with iOS (staticlib + C ABI) and HarmonyOS (NAPI).
#[cfg(target_os = "android")]
mod jni_android;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;

use persona_core::events::Emitter;
use persona_core::storage::Database;
use persona_core::{AuthResult, PersonaService, ServerEventSink};

/// Initialize the mobile library
#[no_mangle]
pub extern "C" fn persona_init() -> i32 {
    // Initialize logging or other setup
    0 // Success
}

/// Get version string
#[no_mangle]
pub extern "C" fn persona_version() -> *mut c_char {
    // CARGO_PKG_VERSION is a compile-time literal containing no interior NUL,
    // so the unwrap's invariant holds at compile time (semver version string)
    CString::new(env!("CARGO_PKG_VERSION"))
        .expect("CARGO_PKG_VERSION contains no NUL")
        .into_raw()
}

/// Free a string allocated by this library
/// # Safety
/// Caller must pass a pointer returned by this library (e.g., from `persona_version`)
/// and ensure it is not used after freeing. Passing any other pointer is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn persona_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = CString::from_raw(s);
}

/// Error handling
#[repr(C)]
pub struct PersonaResult {
    pub success: bool,
    pub error_message: *mut c_char,
}

impl PersonaResult {
    fn success() -> Self {
        Self {
            success: true,
            error_message: std::ptr::null_mut(),
        }
    }

    fn error(message: &str) -> Self {
        let error_message = match CString::new(message) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => std::ptr::null_mut(),
        };

        Self {
            success: false,
            error_message,
        }
    }
}

/// Free a PersonaResult
/// # Safety
/// The `error_message` pointer inside `PersonaResult` must either be null or allocated
/// by this library. Caller must ensure it will not be reused after freeing.
#[no_mangle]
pub unsafe extern "C" fn persona_free_result(result: PersonaResult) {
    if !result.error_message.is_null() {
        let _ = CString::from_raw(result.error_message);
    }
}

/// Borrows a C string passed in by the caller (null / non-UTF-8 both error out).
///
/// # Safety
/// `ptr` must point to a valid null-terminated string (or be null — returns
/// Err rather than UB).
fn ptr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null argument".to_string());
    }
    // SAFETY: the caller contract guarantees the pointer is valid (or null,
    // already intercepted above)
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map_err(|_| "invalid UTF-8 in argument".to_string())
}

/// FFI panic line of defense (confirmed fix from the 2026-10-03 Android
/// walkthrough): catch_unwind converts a panic into a failed [`PersonaResult`]
/// carrying an error message, instead of crossing the extern "C" boundary
/// (UB / host process abort / the JNI layer receiving an unparseable return).
///
/// **Build prerequisite**: panics can only be caught in unwind builds — the
/// root `[profile.release]` `panic = "abort"` would terminate the process
/// before unwinding, bypassing this defense. The mobile FFI artifacts (shared
/// by Android/iOS/HarmonyOS) use the root Cargo.toml's
/// `[profile.mobile-ffi]` (inherits release + unwind); the CI android job
/// builds the .so with `--profile mobile-ffi`.
///
/// AssertUnwindSafe is intentional: raw pointers / global slots borrowed by
/// the closure are never touched again on the panic-escape path (only an
/// error message is produced), so no poisoned state exists.
fn guard_result<F: FnOnce() -> PersonaResult>(f: F) -> PersonaResult {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or_else(|payload| PersonaResult::error(&panic_message(&payload)))
}

/// Same defense for bool returns: panic → false (is_unlocked semantically
/// means "not unlocked").
fn guard_bool(f: impl FnOnce() -> bool) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(false)
}

/// panic payload → error message (&str/String are the two common shapes; no
/// guessing at contents for other types).
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        format!("internal panic: {s}")
    } else if let Some(s) = payload.downcast_ref::<String>() {
        format!("internal panic: {s}")
    } else {
        "internal panic (non-string payload)".to_string()
    }
}

/// AuthResult → unified error message mapping (shared by init/unlock, wording
/// matches the desktop `init_service`). Everything other than Success is
/// treated as failure; FactorRequired never occurs on the current auth path
/// (mobile has no factor flow) and, like desktop, falls into the
/// "Authentication failed" fallback.
fn auth_failure_message(result: AuthResult) -> Result<(), String> {
    match result {
        AuthResult::Success => Ok(()),
        AuthResult::InvalidCredentials => Err("Invalid master password".to_string()),
        AuthResult::AccountLocked => {
            Err("Account is locked due to too many failed attempts".to_string())
        }
        AuthResult::PasswordChangeRequired => Err("Password change required".to_string()),
        _ => Err("Authentication failed".to_string()),
    }
}

// ---------------------------------------------------------------------------
// PersonaService lifecycle host wiring
// ---------------------------------------------------------------------------

/// Initializes (or re-initializes) the Persona service: open the vault file →
/// migrate → create the account (first time) or authenticate (existing user,
/// semantics matching the desktop `init_service`). Success means unlocked. If
/// `persona_configure_sync` was configured first, the existing emitter is
/// injected into the service here.
/// # Safety
/// `db_path`/`master_password` must be valid null-terminated UTF-8 string
/// pointers.
#[no_mangle]
pub unsafe extern "C" fn persona_service_init(
    db_path: *const c_char,
    master_password: *const c_char,
) -> PersonaResult {
    guard_result(|| {
        let result = (|| {
            let db_path = ptr_to_str(db_path)?;
            let master_password = ptr_to_str(master_password)?;
            Ok::<_, String>((db_path.to_string(), master_password.to_string()))
        })();
        let (db_path, master_password) = match result {
            Ok(v) => v,
            Err(e) => return PersonaResult::error(&e),
        };
        runtime::block_on(async move {
            match init_service_inner(&db_path, &master_password).await {
                Ok(()) => PersonaResult::success(),
                Err(e) => PersonaResult::error(&e),
            }
        })
    })
}

async fn init_service_inner(db_path: &str, master_password: &str) -> Result<(), String> {
    let db = Database::from_file(db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;

    let mut service = PersonaService::new(db)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    if !service
        .has_users()
        .await
        .map_err(|e| format!("Failed to query users: {}", e))?
    {
        service
            .initialize_user(master_password)
            .await
            .map_err(|e| format!("Failed to initialize user: {}", e))?;
    } else {
        let auth_result = service
            .authenticate_user(master_password)
            .await
            .map_err(|e| format!("Authentication error: {}", e))?;
        auth_failure_message(auth_result)?;
    }

    // Configure-then-init ordering: inject the existing emitter slot value
    // into the service
    let emitter = state::emitter_slot().lock().await.clone();
    if emitter.is_some() {
        service.set_event_emitter(emitter);
    }
    *state::service_slot().lock().await = Some(service);
    Ok(())
}

/// Unlocks the existing session with the master password (`authenticate_user`;
/// rejected when uninitialized).
/// # Safety
/// `master_password` must be a valid null-terminated UTF-8 string pointer.
#[no_mangle]
pub unsafe extern "C" fn persona_service_unlock(master_password: *const c_char) -> PersonaResult {
    guard_result(|| {
        let master_password = match ptr_to_str(master_password) {
            Ok(s) => s.to_string(),
            Err(e) => return PersonaResult::error(&e),
        };
        runtime::block_on(async move {
            let mut guard = state::service_slot().lock().await;
            match guard.as_mut() {
                Some(service) => {
                    let auth_result = service
                        .authenticate_user(&master_password)
                        .await
                        .map_err(|e| format!("Authentication error: {}", e));
                    match auth_result.and_then(auth_failure_message) {
                        Ok(()) => PersonaResult::success(),
                        Err(msg) => PersonaResult::error(&msg),
                    }
                }
                None => PersonaResult::error("Service not initialized"),
            }
        })
    })
}

/// Locks immediately (clears the in-memory master key; semantics match the
/// desktop tray Lock).
#[no_mangle]
pub extern "C" fn persona_service_lock() -> PersonaResult {
    guard_result(|| {
        runtime::block_on(async {
            let mut guard = state::service_slot().lock().await;
            match guard.as_mut() {
                Some(service) => {
                    service.lock();
                    PersonaResult::success()
                }
                None => PersonaResult::error("Service not initialized"),
            }
        })
    })
}

/// Whether the current session is unlocked (an uninitialized service counts as
/// locked; a panic counts as locked too).
#[no_mangle]
pub extern "C" fn persona_service_is_unlocked() -> bool {
    guard_bool(|| {
        runtime::block_on(async {
            state::service_slot()
                .lock()
                .await
                .as_ref()
                .is_some_and(|s| s.is_unlocked())
        })
    })
}

// ---------------------------------------------------------------------------
// Audit event reporting wiring
// ---------------------------------------------------------------------------

/// Configures/disables audit event reporting (the mobile host counterpart of
/// `attach_sync_emitter`).
///
/// Both url and token non-empty (after trim) → build a `ServerEventSink` +
/// `Emitter` and enable; either blank → detach the existing reporter
/// (fail-closed, matching the CLI "only enable when both are non-empty"
/// semantics). The URL is not format-prevalidated (consistent with the
/// desktop attach: format errors surface at send time and retry with
/// backoff); construction failure (e.g. TLS init) returns an error.
///
/// When called before `persona_service_init` it only stores the slot and
/// injects at init time; when the service is already initialized it injects
/// synchronously. Replacing the new one stops the old (old emitter stopped
/// outside the lock).
///
/// # Safety
/// `server_url`/`token` must be valid null-terminated UTF-8 string pointers.
#[no_mangle]
pub unsafe extern "C" fn persona_configure_sync(
    server_url: *const c_char,
    token: *const c_char,
) -> PersonaResult {
    guard_result(|| {
        let result = (|| {
            let url = ptr_to_str(server_url)?;
            let token = ptr_to_str(token)?;
            Ok::<_, String>((url.trim().to_string(), token.trim().to_string()))
        })();
        let (url, token) = match result {
            Ok(v) => v,
            Err(e) => return PersonaResult::error(&e),
        };
        runtime::block_on(async move {
            let new_emitter = if !url.is_empty() && !token.is_empty() {
                match ServerEventSink::new(&url, token) {
                    Ok(sink) => {
                        let emitter = Emitter::new(Arc::new(sink));
                        emitter.start();
                        Some(emitter)
                    }
                    Err(e) => {
                        return PersonaResult::error(&format!("Invalid sync server_url: {}", e))
                    }
                }
            } else {
                None
            };

            // Lock ordering fixed as emitter → service (matching the desktop
            // attach_sync_emitter); the old emitter is stopped after the slot
            // swap, outside the lock (flush may go over the network)
            let old = {
                let mut slot = state::emitter_slot().lock().await;
                let old = slot.take();
                *slot = new_emitter.clone();
                old
            };
            if let Some(old) = old {
                old.stop().await;
            }

            let mut guard = state::service_slot().lock().await;
            if let Some(service) = guard.as_mut() {
                service.set_event_emitter(new_emitter);
            }
            PersonaResult::success()
        })
    })
}

/// Shuts down the host: locks the service to clear the in-memory master key,
/// does a best-effort final flush of the reporter, and clears both slots
/// (matching the stop semantics at the tail of the CLI main). Can be
/// re-initialized afterwards.
#[no_mangle]
pub extern "C" fn persona_shutdown() -> PersonaResult {
    guard_result(|| {
        runtime::block_on(async {
            {
                let mut guard = state::service_slot().lock().await;
                if let Some(service) = guard.as_mut() {
                    service.lock();
                }
                *guard = None;
            }
            let emitter = state::emitter_slot().lock().await.take();
            if let Some(emitter) = emitter {
                emitter.stop().await;
            }
            PersonaResult::success()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{cstr, reset_state, temp_db_path, test_lock};
    use std::ffi::CStr;

    /// Asserts the result succeeded. `PersonaResult::success()`'s error_message
    /// is always null, so no extraction logic is needed (failure paths all go
    /// through assert_err to check the message).
    fn assert_ok(result: PersonaResult, context: &str) {
        assert!(result.success, "{} failed", context);
        unsafe { persona_free_result(result) };
    }

    /// Asserts the result failed and returns the error message.
    fn assert_err(result: PersonaResult) -> String {
        assert!(!result.success, "expected error, got success");
        let msg = unsafe {
            CStr::from_ptr(result.error_message)
                .to_str()
                .unwrap()
                .to_string()
        };
        unsafe { persona_free_result(result) };
        msg
    }

    #[test]
    fn init_returns_success_code() {
        assert_eq!(persona_init(), 0);
    }

    // ---- FFI panic line of defense (confirmed by the Android walkthrough:
    // the init failure path used to return a crash instead of an error string
    // to the host) ----

    /// Panics print hook output in tests: run the capture inside a silencing
    /// window and restore afterwards.
    fn with_silent_panic_hook(f: impl FnOnce()) {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        f();
        std::panic::set_hook(prev);
    }

    #[test]
    fn guard_result_converts_panic_into_error_result() {
        with_silent_panic_hook(|| {
            let result = guard_result(|| panic!("boom at FFI boundary"));
            assert!(!result.success);
            let msg = unsafe {
                CStr::from_ptr(result.error_message)
                    .to_str()
                    .unwrap()
                    .to_string()
            };
            unsafe { persona_free_result(result) };
            assert_eq!(msg, "internal panic: boom at FFI boundary");
        });
    }

    #[test]
    fn guard_result_converts_non_string_panic_payload() {
        with_silent_panic_hook(|| {
            let result = guard_result(|| std::panic::panic_any(42u32));
            assert!(!result.success);
            let msg = unsafe {
                CStr::from_ptr(result.error_message)
                    .to_str()
                    .unwrap()
                    .to_string()
            };
            unsafe { persona_free_result(result) };
            assert_eq!(msg, "internal panic (non-string payload)");
        });
    }

    #[test]
    fn guard_result_passes_through_normal_results() {
        assert!(guard_result(PersonaResult::success).success);
        let err = guard_result(|| PersonaResult::error("plain error"));
        let msg = unsafe {
            CStr::from_ptr(err.error_message)
                .to_str()
                .unwrap()
                .to_string()
        };
        unsafe { persona_free_result(err) };
        assert_eq!(msg, "plain error");
    }

    #[test]
    fn guard_bool_defaults_to_false_on_panic() {
        assert!(guard_bool(|| true));
        with_silent_panic_hook(|| {
            assert!(!guard_bool(|| panic!("unlocked check blew up")));
        });
    }

    #[test]
    fn version_returns_package_version_and_frees_cleanly() {
        let ptr = persona_version();
        assert!(!ptr.is_null());
        unsafe {
            let version = CStr::from_ptr(ptr).to_str().unwrap();
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
            persona_free_string(ptr);
        }
    }

    #[test]
    fn free_string_accepts_null() {
        unsafe { persona_free_string(std::ptr::null_mut()) };
    }

    #[test]
    fn result_helpers_round_trip_error_messages() {
        let ok = PersonaResult::success();
        assert!(ok.success);
        assert!(ok.error_message.is_null());

        let err = PersonaResult::error("boom");
        assert!(!err.success);
        unsafe {
            let msg = CStr::from_ptr(err.error_message).to_str().unwrap();
            assert_eq!(msg, "boom");
            persona_free_result(err);
        }

        // Message containing an interior NUL: CString::new fails →
        // error_message degrades to null (the caller only sees the failure
        // flag, no half message leaks out)
        let nul = PersonaResult::error("interior\0NUL");
        assert!(!nul.success);
        assert!(nul.error_message.is_null());
    }

    /// Full host-wiring path: uninitialized gating → init creates account →
    /// lock/unlock → configure_sync enable/disable → shutdown reset → repeat
    /// init (authenticate branch). Global slots are serialized, covered in
    /// order within a single test function (see the test_lock docs).
    #[test]
    fn service_lifecycle_unlock_sync_and_shutdown() {
        let _guard = test_lock();
        reset_state();

        // Uninitialized: the service side of unlock/lock/configure_sync refuses
        let pw = cstr("master-pin");
        assert_eq!(
            assert_err(unsafe { persona_service_unlock(pw.as_ptr()) }),
            "Service not initialized"
        );
        assert!(!persona_service_lock().success);
        assert!(!persona_service_is_unlocked());

        // Null pointers safely refused (UB defense line)
        assert_eq!(
            assert_err(unsafe { persona_service_init(std::ptr::null(), pw.as_ptr()) }),
            "null argument"
        );
        assert_eq!(
            assert_err(unsafe { persona_configure_sync(std::ptr::null(), pw.as_ptr()) }),
            "null argument"
        );

        // init: first-time account creation leaves it unlocked
        let db_path = temp_db_path("lifecycle");
        let db = cstr(&db_path);
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "first-time init",
        );
        assert!(persona_service_is_unlocked());

        // lock → unlock (wrong password is refused without changing state) →
        // unlock restores
        assert_ok(persona_service_lock(), "lock");
        assert!(!persona_service_is_unlocked());
        let wrong = cstr("wrong-pin");
        assert_eq!(
            assert_err(unsafe { persona_service_unlock(wrong.as_ptr()) }),
            "Invalid master password"
        );
        assert!(!persona_service_is_unlocked());
        assert_ok(unsafe { persona_service_unlock(pw.as_ptr()) }, "unlock");
        assert!(persona_service_is_unlocked());

        // configure_sync: enable → audit action queues → blank detaches → no
        // longer queues
        let url = cstr("http://127.0.0.1:1");
        let token = cstr("tok-1");
        assert_ok(
            unsafe { persona_configure_sync(url.as_ptr(), token.as_ptr()) },
            "configure sync on",
        );
        assert_ok(persona_service_lock(), "lock for audit");
        // unlock is an audit action (login), queued if the emitter has been
        // injected (the FFI call must be made outside block_on — its internals
        // block_on the same global runtime, and nesting panics)
        assert_ok(
            unsafe { persona_service_unlock(pw.as_ptr()) },
            "unlock for audit",
        );
        let queued_with_sync = runtime::block_on(async {
            state::emitter_slot()
                .lock()
                .await
                .as_ref()
                .map(|e| e.queued())
        });
        assert!(
            queued_with_sync.unwrap_or(0) >= 1,
            "audit event should be queued while sync enabled"
        );

        assert_ok(
            unsafe { persona_configure_sync(cstr("  ").as_ptr(), token.as_ptr()) },
            "configure sync off",
        );
        assert_ok(persona_service_lock(), "lock again");
        assert_ok(
            unsafe { persona_service_unlock(pw.as_ptr()) },
            "unlock again",
        );
        let queued_after_detach = runtime::block_on(async {
            state::emitter_slot()
                .lock()
                .await
                .as_ref()
                .map(|e| e.queued())
        });
        assert_eq!(
            queued_after_detach, None,
            "no emitter after blank reconfigure"
        );

        // shutdown reset → repeat init takes the authenticate branch
        assert_ok(persona_shutdown(), "shutdown");
        assert!(!persona_service_is_unlocked());
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "re-init with correct password",
        );
        assert!(persona_service_is_unlocked());
        let wrong_again = cstr("nope");
        assert_eq!(
            assert_err(unsafe { persona_service_init(db.as_ptr(), wrong_again.as_ptr()) }),
            "Invalid master password"
        );
        assert_ok(persona_shutdown(), "final shutdown");
    }

    /// The configure-then-init injection ordering (slot decoupling).
    #[test]
    fn configure_sync_before_init_injects_on_init() {
        let _guard = test_lock();
        reset_state();

        let url = cstr("http://127.0.0.1:1");
        let token = cstr("tok-early");
        assert_ok(
            unsafe { persona_configure_sync(url.as_ptr(), token.as_ptr()) },
            "configure before init",
        );

        let db_path = temp_db_path("early-configure");
        let db = cstr(&db_path);
        let pw = cstr("master-pin");
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "init after configure",
        );
        // lock itself writes no audit (only clears the key); unlock (login) is
        // what produces an audit event
        assert_ok(persona_service_lock(), "lock");
        assert_ok(unsafe { persona_service_unlock(pw.as_ptr()) }, "unlock");
        let queued = runtime::block_on(async {
            state::emitter_slot()
                .lock()
                .await
                .as_ref()
                .map(|e| e.queued())
        });
        assert!(
            queued.unwrap_or(0) >= 1,
            "emitter configured before init should be injected"
        );
        assert_ok(persona_shutdown(), "cleanup shutdown");
    }

    /// Matching the desktop `attach_sync_emitter`: no URL format prevalidation
    /// (`ServerEventSink::new` is always constructible; format errors surface
    /// at send time with backoff), and reconfiguring with an invalid URL also
    /// just replaces the slot without panicking.
    #[test]
    fn configure_sync_accepts_malformed_url_like_desktop() {
        let _guard = test_lock();
        reset_state();

        let url = cstr("http://127.0.0.1:1");
        let token = cstr("tok");
        assert_ok(
            unsafe { persona_configure_sync(url.as_ptr(), token.as_ptr()) },
            "enable sync",
        );
        let emitter_before =
            runtime::block_on(async { state::emitter_slot().lock().await.as_ref().is_some() });
        assert!(emitter_before, "emitter should be set after enable");

        let bad_url = cstr("::::not-a-url::::");
        assert_ok(
            unsafe { persona_configure_sync(bad_url.as_ptr(), token.as_ptr()) },
            "malformed url accepted like desktop",
        );
        let emitter_after =
            runtime::block_on(async { state::emitter_slot().lock().await.as_ref().is_some() });
        assert!(
            emitter_after,
            "slot replaced with the new (malformed-url) emitter"
        );
        assert_ok(persona_shutdown(), "cleanup shutdown");
    }

    /// Directly flips the user_auth table's password_change_required bit from
    /// an external connection (the service pool is idle, no pending
    /// transactions, so the write lock is available).
    fn set_password_change_required(db_path: &str, value: bool) {
        runtime::block_on(async {
            let db = persona_core::storage::Database::from_file(db_path)
                .await
                .unwrap();
            sqlx::query("UPDATE user_auth SET password_change_required = ?")
                .bind(value)
                .execute(db.pool())
                .await
                .unwrap();
        });
    }

    /// The full set of auth error paths: non-UTF-8 argument,
    /// PasswordChangeRequired (both unlock and init entries), AccountLocked
    /// (triggered by 5 failures, both entries), and an authenticate internal
    /// Err (external connection drops the table). Order-sensitive — the
    /// lockout persists for 300s, and a locked DB is not reused.
    #[test]
    fn auth_error_paths_unlock_and_init() {
        let _guard = test_lock();
        reset_state();

        // Non-UTF-8 argument → ptr_to_str's UTF-8 branch (unlock entry)
        let bad = c"\xff\xfe";
        assert_eq!(
            assert_err(unsafe { persona_service_unlock(bad.as_ptr()) }),
            "invalid UTF-8 in argument"
        );

        // Create the account (unlocked state)
        let db_path = temp_db_path("auth-errors");
        let db = cstr(&db_path);
        let pw = cstr("master-pin");
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "init",
        );

        // PasswordChangeRequired: with the DB bit set, authenticate_password
        // short-circuits before validating the password — unlock entry
        set_password_change_required(&db_path, true);
        assert_eq!(
            assert_err(unsafe { persona_service_unlock(pw.as_ptr()) }),
            "Password change required"
        );
        // Repeat init takes the authenticate branch — same mapping at the init
        // entry
        assert_ok(persona_shutdown(), "shutdown");
        assert_eq!(
            assert_err(unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) }),
            "Password change required"
        );
        set_password_change_required(&db_path, false);

        // The previous init short-circuit failure was not stored in the slot —
        // re-init restores the session
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "re-init after PCR cleared",
        );

        // AccountLocked: 5 failures trigger the lock (unlock entry)
        let wrong = cstr("wrong-pin");
        for attempt in 0..5 {
            assert_eq!(
                assert_err(unsafe { persona_service_unlock(wrong.as_ptr()) }),
                "Invalid master password",
                "attempt {} should still be plain invalid-credentials",
                attempt
            );
        }
        assert_eq!(
            assert_err(unsafe { persona_service_unlock(wrong.as_ptr()) }),
            "Account is locked due to too many failed attempts"
        );
        // The lock persists in the user_auth row — the init entry refuses too
        assert_ok(persona_shutdown(), "shutdown");
        assert_eq!(
            assert_err(unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) }),
            "Account is locked due to too many failed attempts"
        );
        assert_ok(persona_shutdown(), "abandon locked db");

        // authenticate internal Err (unlock's Err branch): an external
        // connection drops the table, the get_first query errors →
        // "Authentication error: …"
        let db2_path = temp_db_path("auth-err-drop");
        let db2 = cstr(&db2_path);
        assert_ok(
            unsafe { persona_service_init(db2.as_ptr(), pw.as_ptr()) },
            "init db2",
        );
        exec_external(&db2_path, "DROP TABLE user_auth");
        let msg = assert_err(unsafe { persona_service_unlock(pw.as_ptr()) });
        assert!(
            msg.starts_with("Authentication error: "),
            "unexpected error: {}",
            msg
        );
        assert_ok(persona_shutdown(), "cleanup db2");
    }

    /// Executes destructive SQL from an external connection (PRAGMA
    /// foreign_keys is per-connection: the child table references user_auth,
    /// so disabling foreign keys and the statement must share one connection).
    fn exec_external(db_path: &str, sql: &str) {
        runtime::block_on(async {
            let db = persona_core::storage::Database::from_file(db_path)
                .await
                .unwrap();
            let mut conn = db.pool().acquire().await.unwrap();
            sqlx::query("PRAGMA foreign_keys = OFF")
                .execute(&mut *conn)
                .await
                .unwrap();
            sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
                .execute(&mut *conn)
                .await
                .unwrap();
        });
    }

    /// init's internal error branches: a bad path (connection), corrupted
    /// migration records (migration), and three forms of a corrupted
    /// user_auth table (query users / initialize user / authentication error —
    /// has_any only checks table existence, while get_first/INSERT go column
    /// by column).
    #[test]
    fn init_error_paths() {
        let _guard = test_lock();
        reset_state();
        let pw = cstr("master-pin");

        // connection failed: the parent directory does not exist, so even
        // mode=rwc cannot create the file
        let missing_dir = cstr("/nonexistent-persona-test-dir/nope.db");
        let msg = assert_err(unsafe { persona_service_init(missing_dir.as_ptr(), pw.as_ptr()) });
        assert!(
            msg.starts_with("Database connection failed"),
            "unexpected: {}",
            msg
        );

        // migration failed: clearing _sqlx_migrations → replaying an already
        // applied migration collides with existing tables
        let mig_path = temp_db_path("mig");
        let mig = cstr(&mig_path);
        assert_ok(
            unsafe { persona_service_init(mig.as_ptr(), pw.as_ptr()) },
            "seed",
        );
        assert_ok(persona_shutdown(), "shutdown");
        exec_external(&mig_path, "DELETE FROM _sqlx_migrations");
        let msg = assert_err(unsafe { persona_service_init(mig.as_ptr(), pw.as_ptr()) });
        assert!(
            msg.starts_with("Database migration failed"),
            "unexpected: {}",
            msg
        );

        // query users fails: the user_auth table is gone entirely → has_any
        // errors
        let no_table_path = temp_db_path("no-table");
        let no_table = cstr(&no_table_path);
        assert_ok(
            unsafe { persona_service_init(no_table.as_ptr(), pw.as_ptr()) },
            "seed",
        );
        assert_ok(persona_shutdown(), "shutdown");
        exec_external(&no_table_path, "DROP TABLE user_auth");
        let msg = assert_err(unsafe { persona_service_init(no_table.as_ptr(), pw.as_ptr()) });
        assert!(
            msg.starts_with("Failed to query users"),
            "unexpected: {}",
            msg
        );

        // initialize user fails: the table exists but lacks columns — an empty
        // table gives has_any=0 (taking initialize_user), and the INSERT
        // names columns → no such column
        let thin_path = temp_db_path("thin-table");
        let thin = cstr(&thin_path);
        assert_ok(
            unsafe { persona_service_init(thin.as_ptr(), pw.as_ptr()) },
            "seed",
        );
        assert_ok(persona_shutdown(), "shutdown");
        exec_external(&thin_path, "DROP TABLE user_auth");
        exec_external(&thin_path, "CREATE TABLE user_auth (id INTEGER)");
        let msg = assert_err(unsafe { persona_service_init(thin.as_ptr(), pw.as_ptr()) });
        assert!(
            msg.starts_with("Failed to initialize user"),
            "unexpected: {}",
            msg
        );

        // authentication error: the table has rows but lacks columns —
        // has_any=1 (taking authenticate), and get_first reads values column
        // by column → missing column error
        let garbled_path = temp_db_path("garbled-table");
        let garbled = cstr(&garbled_path);
        assert_ok(
            unsafe { persona_service_init(garbled.as_ptr(), pw.as_ptr()) },
            "seed",
        );
        assert_ok(persona_shutdown(), "shutdown");
        exec_external(&garbled_path, "DROP TABLE user_auth");
        exec_external(&garbled_path, "CREATE TABLE user_auth (user_id TEXT)");
        exec_external(
            &garbled_path,
            "INSERT INTO user_auth (user_id) VALUES ('x')",
        );
        let msg = assert_err(unsafe { persona_service_init(garbled.as_ptr(), pw.as_ptr()) });
        assert!(
            msg.starts_with("Authentication error: "),
            "unexpected: {}",
            msg
        );
        assert_ok(persona_shutdown(), "cleanup");
    }
}
