//! Global host state slots (matching the desktop AppState "slot is truth" model).
//!
//! All PersonaService/Emitter state stays on the Rust side; the Dart layer only
//! receives PersonaResult/bool — no raw pointer handles cross the FFI, and key
//! material never crosses the boundary. Slots are decoupled:
//! `persona_configure_sync` may be called before or after `persona_service_init`,
//! and either side injects its existing value into the other whenever it runs.

use std::sync::OnceLock;
use tokio::sync::Mutex;

use persona_core::events::Emitter;
use persona_core::PersonaService;

/// The single PersonaService instance (None = not initialized). Mobile is a single
/// vault with a single user, so a global singleton suffices — same shape as the
/// desktop `Arc<Mutex<Option<PersonaService>>>`.
static SERVICE: OnceLock<Mutex<Option<PersonaService>>> = OnceLock::new();

/// Audit event reporter (None = disabled). The swap-in-new-then-stop-old order
/// matches the desktop `attach_sync_emitter`: replace the slot first, then stop
/// the old emitter outside the lock.
static EMITTER: OnceLock<Mutex<Option<Emitter>>> = OnceLock::new();

pub(crate) fn service_slot() -> &'static Mutex<Option<PersonaService>> {
    SERVICE.get_or_init(|| Mutex::new(None))
}

pub(crate) fn emitter_slot() -> &'static Mutex<Option<Emitter>> {
    EMITTER.get_or_init(|| Mutex::new(None))
}

// ---------------------------------------------------------------------------
// Test helpers (shared by the test modules in lib.rs and business.rs: the global
// slots are process-wide singletons, so both test sets must serialize through the
// same lock or they will kick each other's service state out)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reset the global slots at the start of every lifecycle/business test.
#[cfg(test)]
pub(crate) fn reset_state() {
    assert!(crate::persona_shutdown().success);
}

#[cfg(test)]
pub(crate) fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}

/// A ready temporary vault path (the TempDir is leaked until test end and reclaimed on process exit).
#[cfg(test)]
pub(crate) fn temp_db_path(tag: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{}.db", tag));
    // Leak the directory: the service's sqlx pool may still touch the file briefly after shutdown
    std::mem::forget(dir);
    path.to_string_lossy().to_string()
}
