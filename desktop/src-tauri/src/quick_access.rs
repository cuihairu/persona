//! Quick Access: an OS-level global-hotkey popup window (matrix item #22).
//!
//! Layered mechanism:
//! - **Install layer**: the global-shortcut plugin is loaded **at runtime in
//!   `setup`** ([`install_plugin`], not via `Builder::plugin`). The reason is
//!   that its `setup` creates the X11/platform hotkey manager and fails with
//!   Err — through the Builder chain that Err would make the whole app
//!   build fail (`.expect` panics directly), and "a nice-to-have global
//!   hotkey must not keep the password manager from starting". Headless
//!   Linux / no XWayland is exactly this path.
//! - **Registration layer** (the rest of this module): two independent
//!   bindings each grab their own registration — the Quick Access lookup
//!   popup (matrix item #22) and the password generator popup (leftover of
//!   #9). Only on success is `registered` set to Some. **A failed grab is
//!   never silent**: the reason goes into `last_error` and the settings page
//!   shows it as-is (taken by another app/WM, or unsupported platform, both
//!   land here). Rebinding **only unregisters its own old key** (a single
//!   `unregister`), never the other binding.
//! - **Popup layer**: the `quick-access` / `generator-panel` two frameless
//!   always-on-top small windows (declared in tauri.conf.json, initially
//!   `visible: false`). The hotkey is a toggle: if shown, hide (returning
//!   focus to the previous app); if not shown, show + focus + emit that
//!   window's OPENED event so the frontend resets its state.
//!
//! Source-of-truth discipline: the **persistent truth** for bindings and
//! toggles lives in workspace settings
//! (`quick_access_enabled` / `quick_access_hotkey`, see
//! `core::models::WorkspaceSettings`). This module only holds in-process
//! runtime state; after a successful unlock `commands::apply_quick_access`
//! re-pushes it from the DB ([`apply_from_settings`]), and rebinding goes
//! through `commands::quick_access_set` (persist first, then re-register).
//! The frontend has no say in which key gets grabbed.
//!
//! Known limits (recorded honestly, not glossed over in docs):
//! - Linux only uses X11 (global-hotkey dlopens x11-dl at runtime, does not
//!   link X libs); Wayland needs XWayland, and without it the grab fails and
//!   is reported as-is.
//! - All lookup/copy inside the popup goes through the unlocked service;
//!   invoking while locked only shows "unlock first" and brings the main
//!   window to the front (the unlock flow is not replicated inside the
//!   popup; see the THREAT_MODEL entry).

use std::str::FromStr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_global_shortcut::{GlobalShortcut, ShortcutState};

use persona_core::models::WorkspaceSettings;

/// Popup window label (must match windows[1].label in tauri.conf.json)
pub const WINDOW_LABEL: &str = "quick-access";

/// Generator popup label (must match the label of that window in tauri.conf.json)
pub const GENERATOR_WINDOW_LABEL: &str = "generator-panel";

/// Event emitted to the popup's own webview when the hotkey wakes it: the
/// frontend uses it to clear the previous query and focus the input (the
/// wake channel between windows inside one process, no polling)
pub const OPENED_EVENT: &str = "persona://quick-access-opened";

/// The generator popup's wake event (same [`OPENED_EVENT`] semantics; each
/// webview listens for its own)
pub const GENERATOR_OPENED_EVENT: &str = "persona://generator-panel-opened";

/// "Open in Persona" inside the popup -> main window: the event plus its
/// payload (the only channel across webviews; the two windows each have
/// their own JS store, so they cannot hand things off via frontend memory)
pub const OPEN_CREDENTIAL_EVENT: &str = "persona://quick-access-open-credential";

/// Main window label (tauri.conf.json windows[0].label)
pub const MAIN_WINDOW_LABEL: &str = "main";

/// Failure reason when the popup does not exist (the hotkey's target is gone,
/// so grabbing registration is meaningless)
const ERR_WINDOW_MISSING: &str = "quick-access window is not available";

/// Payload of [`OPEN_CREDENTIAL_EVENT`] (snake_case: same convention as the
/// repo's existing DTOs, matching the frontend `types/index.ts`
/// `QuickAccessOpenCredential` field for field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCredentialPayload {
    pub identity_id: String,
    pub credential_id: String,
}

/// In-process runtime state (held by `AppState`). `registered` is not
/// necessarily in sync with `quick_access_hotkey` in the DB — on a failed
/// grab the former is None while the latter is kept, and the settings page
/// shows "bound to X, but not actually in effect (reason)" from that
#[derive(Debug, Default)]
pub struct QuickAccessRuntime {
    /// The accelerator currently actually registered (None = not registered:
    /// disabled, grab failed, or never pushed down)
    pub registered: Option<String>,
    /// Verbatim text of the most recent grab failure (shown on the settings
    /// page; cleared on success/disable)
    pub last_error: Option<String>,
    /// Grab result for the generator hotkey (same semantics as `registered`,
    /// an independent slot that does not affect the other)
    pub generator_registered: Option<String>,
    /// Verbatim text of the most recent generator hotkey grab failure (same
    /// semantics as `last_error`)
    pub generator_last_error: Option<String>,
    /// Plugin install failure reason (headless session / unsupported
    /// platform). Recorded separately from `last_error`: one means "global
    /// hotkeys simply cannot start on this machine", the other "the key is
    /// already taken". An install failure affects both bindings equally
    /// (same plugin instance)
    pub install_error: Option<String>,
}

impl QuickAccessRuntime {
    /// Collapse into the serializable status face returned by the
    /// `quick_access_status` command
    pub fn snapshot(&self, settings: &WorkspaceSettings) -> QuickAccessStatus {
        let enabled = settings.quick_access_enabled;
        let configured = settings
            .quick_access_hotkey
            .clone()
            .unwrap_or_else(|| default_accelerator().to_string());
        QuickAccessStatus {
            enabled,
            // The binding shown on the settings page (DB truth; the platform
            // default when unset)
            configured_accelerator: configured,
            // The binding actually in effect (Some only on a successful grab)
            registered_accelerator: self.registered.clone(),
            // One failure reason is enough for the UI: this grab's failure
            // takes priority over an install failure
            error: self
                .last_error
                .clone()
                .or_else(|| self.install_error.clone()),
        }
    }
}

/// Return shape of `generator_status` (isomorphic with
/// [`QuickAccessStatus`], fields snake_case: matching the frontend
/// `GeneratorStatus` field for field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorStatus {
    /// User toggle (DB truth)
    pub enabled: bool,
    /// The binding shown on the settings page
    pub configured_accelerator: String,
    /// The binding actually registered (None = not in effect)
    pub registered_accelerator: Option<String>,
    /// Why it is not in effect (grab failure or plugin install failure)
    pub error: Option<String>,
}

impl GeneratorStatus {
    /// Collapse runtime state + settings (isomorphic with
    /// [`QuickAccessRuntime::snapshot`])
    pub fn snapshot(runtime: &QuickAccessRuntime, settings: &WorkspaceSettings) -> Self {
        let enabled = settings.generator_panel_enabled;
        let configured = settings
            .generator_panel_hotkey
            .clone()
            .unwrap_or_else(|| default_generator_accelerator().to_string());
        GeneratorStatus {
            enabled,
            configured_accelerator: configured,
            registered_accelerator: runtime.generator_registered.clone(),
            error: runtime
                .generator_last_error
                .clone()
                .or_else(|| runtime.install_error.clone()),
        }
    }
}

/// Return shape of `quick_access_status` (snake_case: the command response
/// face follows the repo's existing DTO convention, matching the frontend
/// `QuickAccessStatus` field for field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickAccessStatus {
    /// User toggle (DB truth)
    pub enabled: bool,
    /// The binding shown on the settings page
    pub configured_accelerator: String,
    /// The binding actually registered (None = not in effect)
    pub registered_accelerator: Option<String>,
    /// Why it is not in effect (grab failure or plugin install failure)
    pub error: Option<String>,
}

/// Platform default binding. macOS uses ⌘⇧Space (mirrors the Spotlight
/// habit and dodges the system's common ⌘Space), Win/Linux use
/// Ctrl+Shift+Space — **not** low-traffic keys like Ctrl+Alt+\: those are
/// already claimed by window managers on some distros/WMs, so the grab
/// failure rate is high, and a failure reads to users as "the feature is
/// broken".
#[cfg(target_os = "macos")]
pub const fn default_accelerator() -> &'static str {
    "Command+Shift+Space"
}

#[cfg(not(target_os = "macos"))]
pub const fn default_accelerator() -> &'static str {
    "Control+Shift+Space"
}

/// Platform default binding for the generator hotkey. macOS uses ⌘⇧G
/// (overlaps Finder's "Go to Folder"; once globally registered the generator
/// wins — rebind in settings if that bothers you), Win/Linux use
/// Ctrl+Shift+G (avoids WM high-traffic keys, and mirrors the lookup popup's
/// default so it is easy to remember)
#[cfg(target_os = "macos")]
pub const fn default_generator_accelerator() -> &'static str {
    "Command+Shift+G"
}

#[cfg(not(target_os = "macos"))]
pub const fn default_generator_accelerator() -> &'static str {
    "Control+Shift+G"
}

/// Validate and parse an accelerator string (tauri global-shortcut syntax).
/// An empty or whitespace-only string is treated as "restore the platform
/// default" by the caller; here only the syntax is judged
pub fn parse_accelerator(raw: &str) -> Result<tauri_plugin_global_shortcut::Shortcut, String> {
    tauri_plugin_global_shortcut::Shortcut::from_str(raw.trim())
        .map_err(|e| format!("invalid accelerator: {e}"))
}

/// Normalize (strip whitespace only). **Deliberately not `Shortcut`'s
/// `Display`**: it rewrites "Ctrl+Shift+Space" as "shift+control+Space"
/// (lowercase modifiers + fixed ordering); showing and echoing the original
/// text better matches "what the settings page shows is exactly what I typed"
pub fn normalize_accelerator(raw: &str) -> String {
    raw.trim().to_string()
}

/// Install the global-shortcut plugin (called from `setup`; idempotent).
///
/// Loaded at runtime rather than via `Builder::plugin`: inside the plugin
/// setup, `GlobalHotKeyManager::new()` returns Err on headless Linux /
/// Wayland without XWayland, and through the Builder chain that Err makes
/// `build()` fail with a `.expect` panic — an unusable global hotkey must
/// not keep the whole password manager from starting. The failure reason is
/// stored in runtime state so the settings page can display it as-is.
///
/// **Must attach `with_handler`** (root cause of the 2026-09-28 "hotkey does
/// nothing" fix): the plugin's event dispatch has only two paths — the
/// per-shortcut handler stored by `register()` (always None on the Rust
/// side's `register`) and the Builder-level handler. Previously both paths
/// were None: the OS grab succeeded (no conflict error) and `registered`
/// was also set to Some, but key events were dispatched to an empty handler
/// and nothing happened. Attaching at the Builder level covers any
/// accelerator registered by this app (both the lookup and generator
/// bindings); it fires only on the `Pressed` edge — global-hotkey reports
/// both Pressed and Released, and without filtering it would show then
/// immediately hide. Which binding was pressed is resolved by looking the
/// registered string up in runtime state ([`dispatch_shortcut`]): when two
/// bindings grab the same accelerator, at most one can actually register
/// successfully (the second register must hit an OS conflict), so there is
/// no double trigger.
pub fn install_plugin<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    if app.try_state::<GlobalShortcut<R>>().is_some() {
        return Ok(());
    }
    app.plugin(
        tauri_plugin_global_shortcut::Builder::new()
            .with_handler(|app, shortcut, event| {
                if event.state == ShortcutState::Pressed {
                    dispatch_shortcut(app, shortcut);
                }
            })
            .build(),
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// The outcome of one grab attempt
enum Registration {
    /// Grab succeeded; what is stored is the **configured string** (not the
    /// `Display`-normalized string)
    Registered(String),
    /// Toggle off: release this binding's old key proactively (leaving the
    /// other binding alone)
    Disabled,
    /// Did not get the grab; the reason is passed to the settings page as-is
    Failed(String),
}

/// Locate the slot pair for this binding in runtime state by window label
/// (generator and lookup each own a field pair)
fn slots_for<'a>(
    guard: &'a mut QuickAccessRuntime,
    window_label: &str,
) -> (&'a mut Option<String>, &'a mut Option<String>) {
    if window_label == GENERATOR_WINDOW_LABEL {
        (
            &mut guard.generator_registered,
            &mut guard.generator_last_error,
        )
    } else {
        (&mut guard.registered, &mut guard.last_error)
    }
}

/// Sync the OS grab state and return the outcome (does not touch runtime
/// state; the caller persists uniformly — avoiding a half-committed state
/// from "changed state first, grab failed after"). `previous` is the
/// accelerator string this binding currently has registered: on rebind/off,
/// **only that one old key is unregistered** — `unregister_all` would also
/// kill the other binding's key, so a global clear is no longer possible
/// once the two bindings coexist.
fn compute_registration<R: tauri::Runtime>(
    app: &AppHandle<R>,
    window_label: &str,
    accelerator: Option<&str>,
    previous: Option<String>,
) -> Registration {
    // The off check comes first: off = the user explicitly does not want the
    // hotkey, **not a failure** — a missing popup, headless, or other
    // environment problems must not record an error reason against an
    // already-off toggle (the settings page would misrender "off" as "not in
    // effect (reason)"). When the plugin is available, unregister only this
    // binding's old key; when it is not (mock / not installed), nothing was
    // ever registered, so no cleanup is needed.
    let Some(raw) = accelerator else {
        if let (Some(plugin), Some(prev)) =
            (app.try_state::<GlobalShortcut<R>>(), previous.as_deref())
        {
            if let Ok(old) = parse_accelerator(prev) {
                let _ = plugin.unregister(old);
            }
        }
        return Registration::Disabled;
    };
    // The hotkey's only job is to summon the popup: if there is no popup
    // (integration tests' mock context has no window), there is nothing to
    // bind and we short-circuit. This also sidesteps a test hazard — the
    // mock runtime's run_on_main_thread only queues without executing, so
    // the blocking recv inside the plugin's register would hang the test.
    if app.get_webview_window(window_label).is_none() {
        return Registration::Failed(ERR_WINDOW_MISSING.to_string());
    }
    // Plugin install failed (headless / platform unsupported): report as-is, no panic
    let Some(plugin) = app.try_state::<GlobalShortcut<R>>() else {
        return Registration::Failed(
            "global shortcut support is unavailable on this session".to_string(),
        );
    };
    // Release this binding's old key first: on rebind the old key must yield
    // before the new one, or both would respond at once. Only our own — the
    // other binding's key is not this function's concern
    if let Some(prev) = previous.as_deref() {
        if let Ok(old) = parse_accelerator(prev) {
            let _ = plugin.unregister(old);
        }
    }

    let shortcut = match parse_accelerator(raw) {
        Ok(shortcut) => shortcut,
        Err(err) => return Registration::Failed(err),
    };
    match plugin.register(shortcut) {
        Ok(()) => Registration::Registered(normalize_accelerator(raw)),
        Err(err) => Registration::Failed(err.to_string()),
    }
}

/// Write the grab result back into runtime state (side chosen by `window_label`)
fn store_registration(
    runtime: &Mutex<QuickAccessRuntime>,
    window_label: &str,
    outcome: Registration,
) {
    let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    let (registered, last_error) = slots_for(&mut guard, window_label);
    match outcome {
        Registration::Registered(accelerator) => {
            *registered = Some(accelerator);
            *last_error = None;
        }
        Registration::Disabled => {
            *registered = None;
            *last_error = None;
        }
        Registration::Failed(reason) => {
            tracing::warn!("hotkey registration failed for {window_label}: {reason}");
            *registered = None;
            *last_error = Some(reason);
        }
    }
}

/// Read the accelerator string this binding currently has registered (the
/// `previous` of `compute_registration`)
fn current_registration(runtime: &Mutex<QuickAccessRuntime>, window_label: &str) -> Option<String> {
    let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    slots_for(&mut guard, window_label).0.clone()
}

/// Push down one binding's "toggle + accelerator string" (shared by lookup and
/// generator, distinguished by window label)
fn apply_binding<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    window_label: &str,
    enabled: bool,
    accelerator: Option<&str>,
    fallback_default: &str,
) {
    let effective = enabled.then(|| {
        accelerator
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback_default.to_string())
    });
    let previous = current_registration(runtime, window_label);
    let outcome = compute_registration(app, window_label, effective.as_deref(), previous);
    store_registration(runtime, window_label, outcome);
}

/// Push down both bindings from workspace settings (called after a successful
/// unlock; toggle off = unregister that binding's own old key).
///
/// The DB is the source of truth, so there is no "is it already consistent"
/// short-circuit here — every unlock replays it all, costing at most two
/// unregister + two register calls, and the payoff is that any end's rebind
/// (including a CLI edit of settings JSON) converges on the next unlock.
pub fn apply_from_settings<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    settings: &WorkspaceSettings,
) {
    apply_binding(
        app,
        runtime,
        WINDOW_LABEL,
        settings.quick_access_enabled,
        settings.quick_access_hotkey.as_deref(),
        default_accelerator(),
    );
    apply_binding(
        app,
        runtime,
        GENERATOR_WINDOW_LABEL,
        settings.generator_panel_enabled,
        settings.generator_panel_hotkey.as_deref(),
        default_generator_accelerator(),
    );
}

/// Explicitly push down the lookup binding (called after the settings page
/// changes the toggle/binding; same registration logic as
/// [`apply_from_settings`], except the accelerator string is given by the
/// caller rather than read from the DB)
pub fn apply_explicit<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    enabled: bool,
    accelerator: Option<&str>,
) -> QuickAccessStatus {
    apply_binding(
        app,
        runtime,
        WINDOW_LABEL,
        enabled,
        accelerator,
        default_accelerator(),
    );

    let guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    QuickAccessStatus {
        enabled,
        configured_accelerator: if enabled {
            accelerator
                .map(|s| s.to_string())
                .unwrap_or_else(|| default_accelerator().to_string())
        } else {
            Default::default()
        },
        registered_accelerator: guard.registered.clone(),
        error: guard
            .last_error
            .clone()
            .or_else(|| guard.install_error.clone()),
    }
}

/// Explicitly push down the generator binding (same semantics as
/// [`apply_explicit`], window and slots are independent)
pub fn apply_explicit_generator<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    enabled: bool,
    accelerator: Option<&str>,
) -> GeneratorStatus {
    apply_binding(
        app,
        runtime,
        GENERATOR_WINDOW_LABEL,
        enabled,
        accelerator,
        default_generator_accelerator(),
    );

    let guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    GeneratorStatus {
        enabled,
        configured_accelerator: if enabled {
            accelerator
                .map(|s| s.to_string())
                .unwrap_or_else(|| default_generator_accelerator().to_string())
        } else {
            Default::default()
        },
        registered_accelerator: guard.generator_registered.clone(),
        error: guard
            .generator_last_error
            .clone()
            .or_else(|| guard.install_error.clone()),
    }
}

/// Hotkey callback body: toggle the popup. Pulled into its own function so
/// the tray, commands, and the plugin callback can share it.
/// `window_label`/`opened_event` are passed as a pair (one set each for the
/// lookup and generator, same semantics)
fn toggle_window<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str, opened_event: &str) {
    let Some(window) = app.get_webview_window(window_label) else {
        return;
    };
    match window.is_visible() {
        Ok(true) => {
            let _ = window.hide();
            // Security review tightening: discard the fill target as soon as
            // the popup hides. The target snapshot is "the foreground window
            // before show"; once the popup is gone, the user's attention has
            // left that target, and keeping a stale slot would let an
            // injection outside the next hotkey cycle land on an outdated
            // fingerprint (ready state out of sync with reality; see the
            // codex 2026-11-05 review P2).
            if window_label == WINDOW_LABEL {
                clear_fill_target(app);
            }
        }
        _ => {
            // Desktop fill target capture (#12): at this moment the target
            // app still holds the foreground; snapshot before show and
            // re-verify by hwnd+title+pid at injection time. Only the lookup
            // popup captures (the generator popup consumes no injection
            // target). Failure does not block the popup — filling is a
            // value-add action of the popup, and a missing target is just
            // reported honestly.
            if window_label == WINDOW_LABEL {
                capture_fill_target(app);
            }
            let _ = window.show();
            let _ = window.set_focus();
            // Wake event: the frontend clears the query and focuses the input
            // (reusing the previous results in the popup would be confusing)
            let _ = window.emit(opened_event, ());
        }
    }
}

/// Capture the current foreground window as the fill injection target (#12).
/// Failure is silent: the injection command will report the missing/stale
/// target honestly when the time comes, so no log noise is produced here
/// (every hotkey press may legitimately have no target).
#[cfg(target_os = "windows")]
fn capture_fill_target<R: tauri::Runtime>(app: &AppHandle<R>) {
    use crate::AppState;
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let captured = crate::desktop_fill::win::capture_foreground(std::process::id());
    let mut slot = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
    *slot = captured;
}

/// Non-Windows platforms: no capture capability (`fill_supported()` = false),
/// so the target is always empty
#[cfg(not(target_os = "windows"))]
fn capture_fill_target<R: tauri::Runtime>(app: &AppHandle<R>) {
    use crate::AppState;
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let mut slot = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
    *slot = None;
}

/// Bring up the popup (used by the tray menu / settings page button; when it
/// is already shown, only focus it)
fn open_window<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str, opened_event: &str) {
    let Some(window) = app.get_webview_window(window_label) else {
        return;
    };
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.emit(opened_event, ());
}

/// Discard the lookup popup's fill injection target snapshot (reached by popup
/// hide / Esc / focus-loss cleanup alike).
/// No stale target is kept: `fill_target_status`'s ready must reflect the real
/// trustworthy state
#[cfg(target_os = "windows")]
fn clear_fill_target<R: tauri::Runtime>(app: &AppHandle<R>) {
    use crate::AppState;
    if let Some(state) = app.try_state::<AppState>() {
        let mut slot = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
        *slot = None;
    }
}

/// Non-Windows platforms: the slot is always empty, so nothing to clear (the
/// signature is aligned so call sites need no cfg branching)
#[cfg(not(target_os = "windows"))]
fn clear_fill_target<R: tauri::Runtime>(app: &AppHandle<R>) {
    use crate::AppState;
    if let Some(state) = app.try_state::<AppState>() {
        let mut slot = state.fill_target.lock().unwrap_or_else(|p| p.into_inner());
        *slot = None;
    }
}

/// Retract the popup (the frontend's Esc / focus-loss self-cleanup both go
/// through it, so `hide` is not written twice)
fn close_window<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str) {
    if let Some(window) = app.get_webview_window(window_label) {
        let _ = window.hide();
    }
    if window_label == WINDOW_LABEL {
        clear_fill_target(app);
    }
}

/// Lookup popup hotkey callback (toggle)
pub fn toggle<R: tauri::Runtime>(app: &AppHandle<R>) {
    toggle_window(app, WINDOW_LABEL, OPENED_EVENT);
}

/// Generator popup hotkey callback (toggle)
pub fn toggle_generator<R: tauri::Runtime>(app: &AppHandle<R>) {
    toggle_window(app, GENERATOR_WINDOW_LABEL, GENERATOR_OPENED_EVENT);
}

/// Bring up the lookup popup (used by the tray menu / settings page button)
pub fn open<R: tauri::Runtime>(app: &AppHandle<R>) {
    open_window(app, WINDOW_LABEL, OPENED_EVENT);
}

/// Bring up the generator popup (tray menu entry, same semantics as [`open`])
pub fn open_generator<R: tauri::Runtime>(app: &AppHandle<R>) {
    open_window(app, GENERATOR_WINDOW_LABEL, GENERATOR_OPENED_EVENT);
}

/// Retract the lookup popup
pub fn close<R: tauri::Runtime>(app: &AppHandle<R>) {
    close_window(app, WINDOW_LABEL);
}

/// Retract the generator popup. Although the generated result is not vault
/// ciphertext, the user may have just copied a password they are about to
/// use, so it likewise must not stay on screen when locked (same
/// data-exposure argument as [`close`])
pub fn close_generator<R: tauri::Runtime>(app: &AppHandle<R>) {
    close_window(app, GENERATOR_WINDOW_LABEL);
}

/// Retract both popups on lock (shared by the tray lock menu and the frontend
/// lock-screen action)
pub fn close_all<R: tauri::Runtime>(app: &AppHandle<R>) {
    close(app);
    close_generator(app);
}

/// Dispatch body of the Builder-level handler: resolve which binding
/// registered this key by checking runtime state.
/// Slots whose configured string fails to parse are skipped (should not
/// happen — a successful registration stores a valid string); if neither
/// binding matches, ignore (theoretically unreachable, defensively no panic).
fn dispatch_shortcut<R: tauri::Runtime>(
    app: &AppHandle<R>,
    fired: &tauri_plugin_global_shortcut::Shortcut,
) {
    use crate::AppState;
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let guard = state.quick_access.lock().unwrap_or_else(|p| p.into_inner());
    let search_hit = guard
        .registered
        .as_deref()
        .and_then(|raw| parse_accelerator(raw).ok())
        .is_some_and(|s| s == *fired);
    let generator_hit = guard
        .generator_registered
        .as_deref()
        .and_then(|raw| parse_accelerator(raw).ok())
        .is_some_and(|s| s == *fired);
    drop(guard);
    if search_hit {
        toggle(app);
    }
    if generator_hit {
        toggle_generator(app);
    }
}

/// A credential selected in the popup -> switch the main window to that
/// identity and open its details.
///
/// The event is delivered with `emit_to(MAIN_WINDOW_LABEL)` targeting:
/// a broadcast would also reach the popup itself, running one round of
/// side effects for nothing. Returning false = the main window does not
/// exist (should not happen; report it to the frontend for an error prompt
/// rather than staying silent).
pub fn open_credential_in_main<R: tauri::Runtime>(
    app: &AppHandle<R>,
    identity_id: &str,
    credential_id: &str,
) -> bool {
    let Some(main) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        return false;
    };
    let payload = OpenCredentialPayload {
        identity_id: identity_id.to_string(),
        credential_id: credential_id.to_string(),
    };
    if main
        .emit_to(MAIN_WINDOW_LABEL, OPEN_CREDENTIAL_EVENT, payload)
        .is_err()
    {
        return false;
    }
    let _ = main.unminimize();
    let _ = main.show();
    let _ = main.set_focus();
    close(app);
    true
}

/// Bring the main window to the front (the popup's "locked state" exit: the
/// unlock flow is not replicated inside the popup, everything falls back to
/// the main window's unlock screen — see the known limits in the module
/// comment)
pub fn focus_main_window<R: tauri::Runtime>(app: &AppHandle<R>) -> bool {
    match app.get_webview_window(MAIN_WINDOW_LABEL) {
        Some(main) => {
            let _ = main.unminimize();
            let _ = main.show();
            let _ = main.set_focus();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_accelerator_parses() {
        assert!(
            parse_accelerator(default_accelerator()).is_ok(),
            "默认绑定必须是合法加速键串"
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_accelerator("").is_err());
        assert!(parse_accelerator("Ctrl+").is_err());
        assert!(parse_accelerator("NotAKey").is_err());
    }

    #[test]
    fn normalize_trims_only() {
        // Does not rewrite case/order (deliberately different from Shortcut::Display normalization)
        assert_eq!(
            normalize_accelerator("  Ctrl+Shift+Space  "),
            "Ctrl+Shift+Space"
        );
    }

    #[test]
    fn snapshot_maps_settings_to_status() {
        let runtime = QuickAccessRuntime {
            registered: Some("Ctrl+Shift+Space".to_string()),
            last_error: None,
            ..QuickAccessRuntime::default()
        };
        // Enabled state (the default has since been switched off, 2026-09-28): no
        // custom binding -> configured falls back to the platform default
        let settings = WorkspaceSettings {
            quick_access_enabled: true,
            ..WorkspaceSettings::default()
        };
        let status = runtime.snapshot(&settings);
        assert!(status.enabled);
        assert_eq!(status.configured_accelerator, default_accelerator());
        assert_eq!(
            status.registered_accelerator.as_deref(),
            Some("Ctrl+Shift+Space")
        );
        assert!(status.error.is_none());
    }

    #[test]
    fn snapshot_surfaces_registration_failure() {
        // Registration failure: configured is still the binding from the DB, registered
        // is empty and error has a value
        let runtime = QuickAccessRuntime {
            registered: None,
            last_error: Some("Another process has already registered".to_string()),
            ..QuickAccessRuntime::default()
        };
        let settings = WorkspaceSettings {
            quick_access_hotkey: Some("Control+Alt+K".to_string()),
            ..WorkspaceSettings::default()
        };
        let status = runtime.snapshot(&settings);
        assert_eq!(status.configured_accelerator, "Control+Alt+K");
        assert!(status.registered_accelerator.is_none());
        assert!(status.error.is_some());
    }

    #[test]
    fn snapshot_prefers_registration_error_over_install_error() {
        // When both errors exist, report the more specific one (this grab
        // failure > install failure)
        let runtime = QuickAccessRuntime {
            registered: None,
            last_error: Some("hotkey taken".to_string()),
            install_error: Some("no display".to_string()),
            ..QuickAccessRuntime::default()
        };
        let status = runtime.snapshot(&WorkspaceSettings::default());
        assert_eq!(status.error.as_deref(), Some("hotkey taken"));
    }

    #[test]
    fn snapshot_falls_back_to_install_error() {
        let runtime = QuickAccessRuntime {
            registered: None,
            last_error: None,
            install_error: Some("no display".to_string()),
            ..QuickAccessRuntime::default()
        };
        let status = runtime.snapshot(&WorkspaceSettings::default());
        assert_eq!(status.error.as_deref(), Some("no display"));
    }

    #[test]
    fn snapshot_disabled_when_setting_off() {
        let settings = WorkspaceSettings {
            quick_access_enabled: false,
            ..WorkspaceSettings::default()
        };
        let status = QuickAccessRuntime::default().snapshot(&settings);
        assert!(!status.enabled);
        // When disabled, configured still shows the binding string (the settings page
        // needs to see the "current configuration")
        assert_eq!(status.configured_accelerator, default_accelerator());
        assert!(status.registered_accelerator.is_none());
    }

    #[test]
    fn generator_default_accelerator_parses() {
        assert!(
            parse_accelerator(default_generator_accelerator()).is_ok(),
            "生成器默认绑定必须是合法加速键串"
        );
    }

    #[test]
    fn generator_snapshot_maps_settings_to_status() {
        let runtime = QuickAccessRuntime {
            generator_registered: Some("Ctrl+Shift+G".to_string()),
            ..QuickAccessRuntime::default()
        };
        let settings = WorkspaceSettings {
            generator_panel_enabled: true,
            ..WorkspaceSettings::default()
        };
        let status = GeneratorStatus::snapshot(&runtime, &settings);
        assert!(status.enabled);
        assert_eq!(
            status.configured_accelerator,
            default_generator_accelerator()
        );
        assert_eq!(
            status.registered_accelerator.as_deref(),
            Some("Ctrl+Shift+G")
        );
        assert!(status.error.is_none());
    }

    #[test]
    fn generator_snapshot_surfaces_registration_failure() {
        // Registration failure: configured keeps the binding from the DB, registered
        // is empty and error has a value
        let runtime = QuickAccessRuntime {
            generator_last_error: Some("Another process has already registered".to_string()),
            ..QuickAccessRuntime::default()
        };
        let settings = WorkspaceSettings {
            generator_panel_hotkey: Some("Control+Alt+P".to_string()),
            ..WorkspaceSettings::default()
        };
        let status = GeneratorStatus::snapshot(&runtime, &settings);
        assert_eq!(status.configured_accelerator, "Control+Alt+P");
        assert!(status.registered_accelerator.is_none());
        assert_eq!(
            status.error.as_deref(),
            Some("Another process has already registered")
        );
    }

    #[test]
    fn generator_snapshot_disabled_shows_configured_only() {
        let settings = WorkspaceSettings {
            generator_panel_enabled: false,
            ..WorkspaceSettings::default()
        };
        let status = GeneratorStatus::snapshot(&QuickAccessRuntime::default(), &settings);
        assert!(!status.enabled);
        assert_eq!(
            status.configured_accelerator,
            default_generator_accelerator()
        );
        assert!(status.registered_accelerator.is_none());
        assert!(status.error.is_none());
    }

    #[test]
    fn generator_status_serializes_snake_case_keys() {
        let json = serde_json::to_value(GeneratorStatus::snapshot(
            &QuickAccessRuntime::default(),
            &WorkspaceSettings::default(),
        ))
        .unwrap();
        for key in [
            "enabled",
            "configured_accelerator",
            "registered_accelerator",
            "error",
        ] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
        assert!(json.get("configuredAccelerator").is_none());
    }

    // The grab path (compute_registration / apply_*) needs an AppHandle; its "no
    // popup -> definite failure" branch is covered by the quick_access_* cases
    // in command_layer_tests (where mock_app is the established convention).
    // **Do not** build a mock app in this module's unit tests: the mock
    // runtime of `tauri::test::mock_app()` poisons the process's tokio socket
    // IO probing, and sqlx cases running concurrently in the same process
    // would randomly hit disk I/O errors (see the lib.rs module comment and
    // the sqlite_works_after_mock_app_creation probe).

    /// Wire-format lock: the status-face field names are the frontend
    /// `QuickAccessStatus` contract; if you change them here you must change
    /// the TS side in lockstep, otherwise the UI silently reads undefined
    /// (far harder to debug than a compile error)
    #[test]
    fn status_serializes_snake_case_keys() {
        let json = serde_json::to_value(
            QuickAccessRuntime::default().snapshot(&WorkspaceSettings::default()),
        )
        .unwrap();
        for key in [
            "enabled",
            "configured_accelerator",
            "registered_accelerator",
            "error",
        ] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
        assert!(json.get("configuredAccelerator").is_none());
    }

    /// Same as above, for the cross-window event payload
    #[test]
    fn open_credential_payload_serializes_snake_case_keys() {
        let json = serde_json::to_value(OpenCredentialPayload {
            identity_id: "i1".to_string(),
            credential_id: "c1".to_string(),
        })
        .unwrap();
        assert_eq!(json["identity_id"], "i1");
        assert_eq!(json["credential_id"], "c1");
        assert!(json.get("identityId").is_none());
    }
}
