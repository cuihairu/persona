//! Desktop fill injection (per FEATURE_GAP_ANALYSIS #12: the fill injection
//! path inside Windows desktop applications).
//!
//! Approach (consistent with #22): **the floating window handles pickup and
//! target confirmation; injection runs through the desktop's secure path** —
//! filling inside a browser goes through the browser extension (Native
//! Messaging bridge); this module only handles post-pickup filling for
//! "non-browser native desktop apps": the user selects a credential in the
//! search floating window → **explicitly confirms the injection target
//! (target app executable name + window title)** → injection.
//!
//! Choices (design section in docs/src/design/desktop-fill.md; only the
//! conclusions are kept here):
//! - **Primary: direct WM_SETTEXT writes** — enumerate the classic Win32 EDIT
//!   child controls of the target window; username = first usable non-password
//!   field, password = first usable (visible/enabled/not read-only)
//!   `ES_PASSWORD`-styled field. **No password-styled field means refuse to
//!   inject** — a historical version fell back to a "second field" heuristic,
//!   removed after security review (codex 2026-11-05): any foreground process
//!   could place two plain Edit controls to fake a login form and harvest the
//!   password; the heuristic was a vulnerability, not a safety net. Direct
//!   writes need no focus, send no keystrokes, and are cross-process reliable
//!   (within the same desktop session).
//!   Cost: self-drawn input fields in Electron/Qt/browsers ignore
//!   WM_SETTEXT — those hosts should use the extension or UIA anyway; an
//!   honest boundary, not a defect.
//! - **Fallback: clipboard relay** (`with_clipboard_paste` +
//!   `paste_into_focused`): currently **not wired into the production path**
//!   (production uses WM_SETTEXT only). And it must be stated honestly: the
//!   system clipboard is shared across the whole session; while the value is
//!   resident, any same-desktop process can read it. This module's
//!   backup/restore only shrinks the exposure window and provides no
//!   confidentiality guarantee. That boundary must be disclosed explicitly
//!   before enabling.
//! - **No UIA**: UI Automation could cover self-drawn controls, but brings a
//!   `Win32_UI_Accessibility` dependency surface + COM lifetime management;
//!   not introduced in the first version. Recorded here as a future extension
//!   point for self-drawn hosts.
//!
//! Target trust model (tightened after security review):
//! 1. **Three-factor fingerprint snapshot**: when the hotkey raises the
//!    floating window (the show branch of `toggle_window`), the target app
//!    still holds the foreground — `GetForegroundWindow` at that moment is
//!    the injection target; store hwnd + title + pid + **top-level window
//!    class name + full process executable path** in runtime state. If the
//!    executable path cannot be queried (permissions/process exited),
//!    **no target is established** — no fingerprint, no trusted injection.
//! 2. **Re-validate the three factors before injection**: hwnd alive, pid
//!    unchanged, class name matches, executable matches; title compared by
//!    snapshot prefix (prefix matching only when the snapshot title is
//!    non-empty; an empty snapshot title requires the current title to also
//!    be empty, closing the hole where `starts_with("")` was always true in
//!    historical versions). Windows whose pid equals our own process are
//!    never targets (the floating/main window itself).
//! 3. **Re-validate each control before writing**: between enumeration and
//!    SendMessageW, child HWNDs can be destroyed and reused — before each
//!    field write, re-check IsWindow, GA_ROOT ownership of the target window,
//!    pid, class name Edit, style (password fields must still carry
//!    ES_PASSWORD), visible/enabled/not read-only. Win32 checks are not
//!    atomic, so a tiny race window remains between check and write — an
//!    inherent platform residual risk, backstopped by item 4's explicit user
//!    confirmation surface (the user sees the target app name and can spot a
//!    wrong window immediately).
//! 4. **User confirmation before injection**: the floating window shows the
//!    target app name (executable name) and window title; only after the user
//!    explicitly confirms does the command layer allow it (the `confirmed`
//!    parameter of `desktop_fill_credential`). No silent direct-write path
//!    exists.
//!
//! Non-Windows platforms: the command layer honestly reports "platform not
//! supported" (`fill_supported()`) rather than faking the feature — desktop
//! fill on Linux/macOS is a future topic; this module does not overpromise.

use serde::{Deserialize, Serialize};

/// In-process snapshot of the injection target window (held by
/// `AppState.fill_target`).
/// hwnd is stored as isize (no raw HWND type crosses the FFI boundary, and
/// tests can fabricate handles easily).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FillTarget {
    /// Win32 top-level window handle (raw value)
    pub hwnd: isize,
    /// Window title at capture time (re-validated by prefix at injection,
    /// against hwnd reuse; an empty title is only allowed when the current
    /// title is also empty)
    pub title: String,
    /// Owning process id of the window at capture time (checked at injection
    /// to still belong to the same process)
    pub pid: u32,
    /// Top-level window class name at capture time (fingerprint factor 2 of 3)
    pub window_class: String,
    /// Full executable path of the target process at capture time
    /// (fingerprint factor 3 of 3; no target is established if it cannot be
    /// queried)
    pub exe_path: String,
    /// Snapshot identifier generated at capture time (P1 confirmation binding):
    /// the frontend carries this id when the user confirms; after the async
    /// decryption (in-flight window) completes, the injection command compares
    /// it against the current slot — any mismatch or emptied slot is rejected,
    /// and in-flight requests are never re-routed to a newly captured target.
    pub snapshot_id: String,
}

/// State of a single candidate input field (produced by enumeration, shared by
/// classification and per-control revalidation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldState {
    pub hwnd: isize,
    /// Control carries the `ES_PASSWORD` style
    pub is_password: bool,
    /// IsWindowVisible
    pub visible: bool,
    /// IsWindowEnabled
    pub enabled: bool,
    /// Control carries the `ES_READONLY` style (read-only fields cannot be filled)
    pub read_only: bool,
}

impl FieldState {
    /// Injectability: visible, enabled, not read-only. Password fields
    /// additionally require the ES_PASSWORD style.
    pub fn eligible(&self) -> bool {
        self.visible && self.enabled && !self.read_only
    }
}

/// Classification result: optional username field + mandatory password field
/// handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedFields {
    /// None = the target window has no usable username field (fill password only,
    /// reported honestly in the result)
    pub username_hwnd: Option<isize>,
    /// Mandatory: `classify_fields` returns None outright when no eligible
    /// ES_PASSWORD field exists
    pub password_hwnd: isize,
}

/// Reasons for rejecting a confirmation binding (tightened in P1: confirmation
/// binds to a specific snapshot, and in-flight requests must not be re-routed
/// to a new target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmBindRejection {
    /// Request carried no snapshot_id (protocol mismatch / older frontend) —
    /// the confirmation-surface protocol error is reported first
    SnapshotRequired,
    /// Slot is empty: the floating window was dismissed / the target was
    /// cleared (hidden means discarded) — in-flight requests carrying a stale
    /// id are rejected honestly
    TargetDiscarded,
    /// Slot was replaced by a newer capture: the floating window re-captured B
    /// after A was confirmed — a request carrying A's id is rejected; B is
    /// never injected
    TargetChanged,
}

/// Binds "user confirmation" to a specific snapshot (tightened in P1; a
/// platform-independent pure function).
///
/// The command layer calls this after the async decryption (in-flight window)
/// completes and before injection: the request must carry the `snapshot_id`
/// generated at capture time and match **the current slot** to be allowed
/// through. A successful binding returns a clone of the confirmed snapshot (the
/// command layer then fingerprint-re-validates that snapshot before injecting —
/// so the injection target corresponds one-to-one with the target the user
/// confirmed, rather than "whatever was in the slot at the moment decryption
/// finished"):
/// - `requested` missing → [`ConfirmBindRejection::SnapshotRequired`];
/// - slot already empty (slot cleared on dismiss / cleared as invalid) →
///   [`ConfirmBindRejection::TargetDiscarded`];
/// - slot holds a different snapshot (the floating window was raised again
///   after confirmation and captured a new target) →
///   [`ConfirmBindRejection::TargetChanged`] — never re-routed to the new
///   target.
pub fn bind_confirmed_snapshot(
    slot: Option<&FillTarget>,
    requested_snapshot_id: Option<&str>,
) -> Result<FillTarget, ConfirmBindRejection> {
    let Some(requested) = requested_snapshot_id else {
        return Err(ConfirmBindRejection::SnapshotRequired);
    };
    let Some(target) = slot else {
        return Err(ConfirmBindRejection::TargetDiscarded);
    };
    if target.snapshot_id != requested {
        return Err(ConfirmBindRejection::TargetChanged);
    }
    Ok(target.clone())
}

/// Generates the snapshot identifier at capture time (P1 confirmation binding):
/// a UUID v4 uniquely identifying one capture.
/// Non-Windows compilation units have no capture path (the slot is always
/// empty); this function is kept for platform-independent binding semantics
/// tests and future platform implementations.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn new_snapshot_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The **honest forms** of injection failure/abort (fourth-round cancellation
/// boundary closure): the command layer uses this to distinguish "routine
/// rejection (nothing written)" from "snapshot invalidated mid-injection (fields
/// already written carry a partial-completion result honestly)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillError {
    /// Routine rejection: target fingerprint mismatch
    /// (`CAPTURED_TARGET_INVALID`), no eligible ES_PASSWORD field, per-control
    /// revalidation failure, etc. — the original text is passed through,
    /// consistent with the historical String error; no field writes happened in
    /// this form.
    Rejected(String),
    /// Snapshot invalidated mid-injection: the slot was cleared between field
    /// writes (floating window dismissed,
    /// [`ConfirmBindRejection::TargetDiscarded`]) or replaced by a newer capture
    /// (B captured after A was confirmed,
    /// [`ConfirmBindRejection::TargetChanged`]).
    /// **Fields already written are carried honestly** (partial completion); all
    /// remaining writes are aborted — the injection target corresponds one-to-one
    /// with the snapshot the user confirmed, and remaining fields are never
    /// written into a new target.
    Aborted {
        reason: ConfirmBindRejection,
        username_filled: bool,
        password_filled: bool,
        title: String,
    },
}

/// Slot recheck closure factory for the command layer: the binding comparison
/// (inside the lock after decryption completes) and the recheck before each
/// field write in the injection loop **share the same semantics** — compare
/// snapshot_id against the current slot; empty slot →
/// [`ConfirmBindRejection::TargetDiscarded`], slot replaced by a newer snapshot
/// → [`ConfirmBindRejection::TargetChanged`]. The returned closure only
/// performs the in-lock comparison (no cloning) and can be called repeatedly
/// inside the injection loop.
pub(crate) fn slot_recheck_for(
    slot: &std::sync::Mutex<Option<FillTarget>>,
    snapshot_id: String,
) -> impl Fn() -> Result<(), ConfirmBindRejection> + '_ {
    move || {
        let guard = slot.lock().unwrap_or_else(|p| p.into_inner());
        // Always carries Some(id), so the SnapshotRequired branch is unreachable;
        // handled defensively as a pass
        bind_confirmed_snapshot(guard.as_ref(), Some(&snapshot_id)).map(|_| ())
    }
}

/// Field classification (platform-independent, a testable pure function).
///
/// Input is the state of each field in Z order (EnumChildWindows order):
/// - password = the first **eligible** (visible/enabled/not read-only)
///   `ES_PASSWORD` field; **no password-styled field found → reject outright**
///   (None). No longer guesses "the second field": a plain field might be a
///   plaintext harvester faked by an attacker.
/// - username = the first eligible non-password field; filling the password
///   only is allowed when there is no eligible username field.
/// - All fields are password-styled (a change-password dialog): there is no
///   username field, so only the password is filled — a change-password dialog
///   is not this feature's intended shape, and the confirmation surface prompts
///   the user to verify the target for the password write.
pub fn classify_fields(fields: &[FieldState]) -> Option<ClassifiedFields> {
    let password = fields
        .iter()
        .find(|f| f.is_password && f.eligible())
        .map(|f| f.hwnd)?;
    let username = fields
        .iter()
        .find(|f| !f.is_password && f.eligible())
        .map(|f| f.hwnd);
    Some(ClassifiedFields {
        username_hwnd: username,
        password_hwnd: password,
    })
}

/// Whether the current platform implements the injection path (the command
/// layer uses this to decide between reporting an error honestly and
/// allowing through)
pub fn fill_supported() -> bool {
    cfg!(target_os = "windows")
}

/// Injection execution entry point for the command layer (platform dual-state):
/// Windows = re-validate the three fingerprint factors → enumerate EDIT fields →
/// classify (an eligible password field is mandatory) → per-control
/// pre-write revalidation + snapshot validity recheck → WM_SETTEXT injection;
/// other platforms = always Err (the command layer already has the
/// `fill_supported()` pre-check; this is the fallback).
/// Returns (whether username was injected, whether password was injected,
/// target window title).
///
/// `slot_recheck`: the snapshot validity recheck performed **before every field
/// write** inside the injection loop (fourth-round cancellation boundary
/// closure) — the binding comparison completes under the lock, then injection
/// runs outside the lock, during which the floating window may be dismissed
/// (clearing the slot) or re-capture a different target; before each field
/// write, this closure rechecks "the snapshot id is still the current binding
/// and has not been cleared/replaced", and on invalidation aborts the remaining
/// writes, reporting partial completion of the fields already written via
/// [`FillError::Aborted`].
#[cfg(target_os = "windows")]
pub fn execute_fill(
    target: &FillTarget,
    username: &str,
    password: &str,
    self_pid: u32,
    slot_recheck: &dyn Fn() -> Result<(), ConfirmBindRejection>,
) -> Result<(bool, bool, String), FillError> {
    if !win::validate_target(target, self_pid) {
        return Err(FillError::Rejected("CAPTURED_TARGET_INVALID".to_string()));
    }
    let fields = win::enumerate_edit_fields(target.hwnd);
    if fields.is_empty() {
        return Err(FillError::Rejected(format!(
            "Target window \"{}\" has no classic edit controls (self-drawn UI is not supported; browser fill goes through the extension)",
            target.title
        )));
    }
    let Some(classified) = classify_fields(&fields) else {
        return Err(FillError::Rejected(format!(
            "Target window \"{}\" has no eligible ES_PASSWORD field; refusing to fill (plain edit controls are never treated as password fields)",
            target.title
        )));
    };
    let aborted = |reason, username_filled: bool, password_filled: bool| FillError::Aborted {
        reason,
        username_filled,
        password_filled,
        title: target.title.clone(),
    };
    let mut username_filled = false;
    if let Some(user_hwnd) = classified.username_hwnd {
        if !username.is_empty() {
            // Snapshot validity recheck: the binding comparison completed under
            // the lock, and injection runs outside the lock — before the
            // username write the slot may already have been cleared (floating
            // window dismissed) or replaced by a newer capture; abort on
            // invalidation, and never write the confirmed credential into a
            // non-confirmed target
            slot_recheck().map_err(|reason| aborted(reason, false, false))?;
            win::revalidate_field(user_hwnd, target.hwnd, target.pid, false)
                .map_err(FillError::Rejected)?;
            username_filled = win::inject_settext(user_hwnd, username).is_ok();
        }
    }
    // Per-control revalidation once more before the password field write: between
    // enumeration and writing, the child HWND could be destroyed and reused, and
    // style/ownership may have changed (see item 3 of the "target trust model"
    // in the module header).
    // Likewise recheck snapshot validity first: between the first field write
    // completing and this moment the slot could still be cleared/replaced
    // (a real-machine case where the timing is controllable: the slot-clear hook
    // lands after the first field write) — abort on invalidation and report
    // partial completion of the written fields via Aborted honestly.
    slot_recheck().map_err(|reason| aborted(reason, username_filled, false))?;
    win::revalidate_field(classified.password_hwnd, target.hwnd, target.pid, true)
        .map_err(FillError::Rejected)?;
    let password_filled = win::inject_settext(classified.password_hwnd, password).is_ok();
    Ok((username_filled, password_filled, target.title.clone()))
}

/// Non-Windows: no injection implementation exists (see the honest boundary in
/// the module header comment)
#[cfg(not(target_os = "windows"))]
pub fn execute_fill(
    _target: &FillTarget,
    _username: &str,
    _password: &str,
    _self_pid: u32,
    _slot_recheck: &dyn Fn() -> Result<(), ConfirmBindRejection>,
) -> Result<(bool, bool, String), FillError> {
    Err(FillError::Rejected(
        "Desktop fill injection is only implemented on Windows".to_string(),
    ))
}

/// Return shape of `fill_target_status` (snake_case: aligned verbatim with the
/// frontend's `FillTargetStatus`). Carries only the title and app name, **not
/// the hwnd/pid/full executable path** — handles and paths are useless to the
/// frontend, and exposing in-process pointers would only widen the information
/// surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillTargetStatus {
    /// Whether this platform implements the injection path
    pub supported: bool,
    /// There is a captured injection target that is **still currently valid**
    /// (invalid targets are cleared from the slot immediately)
    pub ready: bool,
    /// Target window title (null when there is no target / it has become
    /// invalid)
    pub target_title: Option<String>,
    /// Target app executable file name (e.g. "notepad.exe"; shown on the
    /// confirmation surface)
    pub target_app: Option<String>,
    /// Identifier of the current valid snapshot (P1 confirmation binding): the
    /// confirmation surface captures this id and the injection request must
    /// return it verbatim — the backend uses it to bind the confirmation to a
    /// specific snapshot (null when there is no target / it has become invalid)
    pub snapshot_id: Option<String>,
}

/// Executable file name of the target app (for display on the confirmation
/// surface, e.g. "notepad.exe"). A platform-independent pure string operation
/// (splits on both Win32/Unix path separators).
pub fn exe_file_name(exe_path: &str) -> String {
    exe_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe_path)
        .to_string()
}

/// Return shape of `desktop_fill_credential` (snake_case: aligned verbatim with
/// the frontend's `DesktopFillResult`). Per-field results rather than an overall
/// boolean: when a single field fails (e.g. the target only has a password
/// field), the frontend can honestly say "only the password was filled".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopFillResult {
    pub username_filled: bool,
    pub password_filled: bool,
    /// Injected target window title (carried in the result so the user can
    /// verify "which window got filled")
    pub target_title: String,
    /// Non-fatal warning (e.g. clipboard restore failure — specific to the paste
    /// mode; always None on the SetText path)
    pub warning: Option<String>,
}

#[cfg(target_os = "windows")]
pub mod win;

#[cfg(test)]
mod tests;
