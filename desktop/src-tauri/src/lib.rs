//! Persona desktop library entry point.
//!
//! Application assembly (the Builder chain, tray) lives here, with `main.rs` keeping only a thin
//! entry. The passkey approval server is started by init_service, gated by the workspace switch
//! (see `commands::maybe_start_passkey_server`). Turning this into a lib lets integration tests
//! drive an `AppHandle` with a mock runtime through a separate `tests/` process (a mock runtime
//! poisons the tokio socket IO probe in its own process — see the FakeSink comment in
//! `passkey_bridge::tests`); in the single-process bin era those paths could only be worked
//! around with FakeSink.

pub mod approval;
pub mod biometric;
#[cfg(test)]
mod command_layer_tests;
pub mod commands;
pub mod desktop_fill;
// The Connect HTTP endpoint has been a separate crate since v0.1 (desktop/CLI share the same
// router); the re-export here keeps the `crate::connect_server::*` reference paths unchanged.
pub use persona_connect_server as connect_server;
mod error;
#[cfg(test)]
mod packaging_tests;
pub mod passkey_bridge;
pub mod quick_access;
pub mod ssh_integration;
mod sync_watcher;
#[cfg(test)]
mod test_support;
pub mod token_store;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;
use tokio::sync::Mutex;
use types::AppState;

/// Show the main window (shared by tray left-click / the Open menu item)
pub fn show_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Whether the current session has a display server (the muda backend used by the tray/menu
/// panics without a display).
#[cfg(target_os = "linux")]
fn display_session_available() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(not(target_os = "linux"))]
fn display_session_available() -> bool {
    true
}

/// Tray context-menu labels. The source of truth lives in the frontend i18n locale table (the
/// `tray.*` namespace); the frontend pushes the labels for the current language via
/// `set_tray_locale` for rendering. The defaults here only cover the startup window in which the
/// frontend has not yet reported (default language zh-CN, matching the frontend's
/// DEFAULT_LOCALE); the first push replaces them with the real values.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct TrayLocaleLabels {
    pub open: String,
    pub quick_access: String,
    pub generator: String,
    pub lock: String,
    pub quit: String,
}

/// Startup fallback labels (before the frontend has reported).
fn default_tray_labels() -> TrayLocaleLabels {
    TrayLocaleLabels {
        open: "打开 Persona".to_string(),
        quick_access: "快速访问".to_string(),
        generator: "密码生成器".to_string(),
        lock: "锁定".to_string(),
        quit: "退出".to_string(),
    }
}

/// Build the tray menu from labels: the setup fallback and runtime language switching share one
/// build path, and menu item ids map one-to-one onto the on_menu_event dispatch — do not touch
/// the ids.
pub(crate) fn build_tray_menu<R: tauri::Runtime, M: tauri::Manager<R>>(
    manager: &M,
    labels: &TrayLocaleLabels,
) -> Result<Menu<R>, tauri::Error> {
    let open_item = MenuItem::with_id(manager, "open", labels.open.as_str(), true, None::<&str>)?;
    let quick_item = MenuItem::with_id(
        manager,
        "quick-access",
        labels.quick_access.as_str(),
        true,
        None::<&str>,
    )?;
    let generator_item = MenuItem::with_id(
        manager,
        "generator-panel",
        labels.generator.as_str(),
        true,
        None::<&str>,
    )?;
    let lock_item = MenuItem::with_id(manager, "lock", labels.lock.as_str(), true, None::<&str>)?;
    let quit_item = MenuItem::with_id(manager, "quit", labels.quit.as_str(), true, None::<&str>)?;
    Menu::with_items(
        manager,
        &[
            &open_item,
            &quick_item,
            &generator_item,
            &lock_item,
            &quit_item,
        ],
    )
}

/// Build the system tray and its menu (requires a display session; the resident entry point
/// once the main window is closed).
fn setup_tray<R: tauri::Runtime>(app: &tauri::App<R>) -> Result<(), Box<dyn std::error::Error>> {
    let tray_menu = build_tray_menu(app, &default_tray_labels())?;

    TrayIconBuilder::with_id("persona-tray")
        .icon(
            // Fall back to the compile-time embedded icon when the bundle lacks one (dev/tests
            // have no bundle icon)
            app.default_window_icon()
                .cloned()
                .unwrap_or_else(|| tauri::include_image!("icons/32x32.png")),
        )
        .tooltip("Persona")
        .menu(&tray_menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            // Left click = bring up the main window (the menu stays on right click)
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            // Quick Access popup: when the hotkey is taken/unregistered, the tray stays the entry
            "quick-access" => quick_access::open(app),
            // Generator popup: same tray fallback entry
            "generator-panel" => quick_access::open_generator(app),
            "lock" => {
                // Dismiss both popups: search results left in a popup, or a freshly generated
                // password, should not stay on screen after locking (the data is in memory
                // anyway, but the exposure surface shouldn't grow)
                quick_access::close_all(app);
                // Go through the event chain (Locked -> persona://auto-lock -> the frontend
                // shows its unlock screen), then belt and braces clear the in-memory master key
                // (same action as the callback, idempotent)
                let service = app.state::<AppState>().service.clone();
                tauri::async_runtime::spawn(async move {
                    let mut guard = service.lock().await;
                    if let Some(service) = guard.as_mut() {
                        let _ = service.force_lock_session().await;
                        service.lock();
                    }
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// Install the redacting log subscriber: production writes a log file under `app_log_dir`
/// (>5 MiB, single-generation rotation), while dev builds and the fallback paths keep stdout.
///
/// Must be called before any tracing event (first thing in setup). A global subscriber can only
/// be installed once; repeated installs (multiple builds in a test process) silently keep the
/// existing one.
fn init_desktop_logging<R: tauri::Runtime>(app: &tauri::App<R>) {
    use std::io::Write;

    let init_stdout = || {
        let _ = persona_core::logging::init_redacted_tracing(tracing::Level::INFO);
    };

    // dev/test builds: visible on stdout and writes nothing to the dev machine's disk
    if cfg!(debug_assertions) {
        init_stdout();
        return;
    }

    let Some(log_dir) = app.path().app_log_dir().ok() else {
        init_stdout();
        return;
    };
    if std::fs::create_dir_all(&log_dir).is_err() {
        init_stdout();
        return;
    }

    let log_path = log_dir.join("persona-desktop.log");
    // Single-generation rotation: past the limit, rename to .1 (dropping any old .1) — a middle
    // ground between unbounded growth and write amplification
    const ROTATE_BYTES: u64 = 5 * 1024 * 1024;
    if std::fs::metadata(&log_path)
        .map(|meta| meta.len() > ROTATE_BYTES)
        .unwrap_or(false)
    {
        let rotated = log_dir.join("persona-desktop.log.1");
        let _ = std::fs::remove_file(&rotated);
        let _ = std::fs::rename(&log_path, &rotated);
    }

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(file) => Arc::new(std::sync::Mutex::new(file)),
        Err(_) => {
            init_stdout();
            return;
        }
    };

    struct SharedFileWriter(Arc<std::sync::Mutex<std::fs::File>>);
    impl Write for SharedFileWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .flush()
        }
    }

    let _ = persona_core::logging::RedactedLoggerBuilder::new(tracing::Level::INFO)
        .with_writer(move || Box::new(SharedFileWriter(file.clone())))
        .init();
}

/// Assemble the application (tray, passkey approval server, all command registrations).
///
/// context is parameterized: production [`run`] passes `generate_context!`, while integration
/// tests pass `tauri::test::mock_context(noop_assets())` and run setup end to end.
pub fn build<R: tauri::Runtime>(context: tauri::Context<R>) -> tauri::App<R> {
    tauri::Builder::<R>::new()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        // The OS-level global hotkey plugin is deliberately **not** attached here: its setup
        // creates the platform hotkey manager, which fails on headless Linux and would take the
        // whole build down with it. It is loaded at runtime inside setup instead
        // (quick_access::install_plugin), where a failure only records state. Claiming the
        // bindings isn't done here either — the source of truth is the workspace settings, and
        // `commands::apply_quick_access` pushes them from the DB once unlocked
        .manage(AppState {
            service: Arc::new(Mutex::new(None)),
            db_path: Mutex::new(None),
            agent_handle: Mutex::new(None),
            auto_lock_registered: std::sync::atomic::AtomicBool::new(false),
            passkey_server_started: std::sync::atomic::AtomicBool::new(false),
            passkey_server_shutdown: Mutex::new(None),
            ssh_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
            passkey_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
            sync_emitter: Mutex::new(None),
            token_store: Arc::new(token_store::OsKeyringTokenStore::new(
                token_store::SYNC_SERVICE,
            )),
            biometric_provider: Arc::new(biometric::OsBiometricProvider),
            biometric_store: Arc::new(token_store::OsKeyringTokenStore::new(
                token_store::BIOMETRIC_SERVICE,
            )),
            biometric_wrapper: biometric::key_wrapper(),
            biometric_wrap_store: Arc::new(token_store::OsKeyringTokenStore::new(
                token_store::BIOMETRIC_WRAP_SERVICE,
            )),
            device_store: Arc::new(token_store::OsKeyringTokenStore::new(
                token_store::DEVICE_SERVICE,
            )),
            account_token_store: Arc::new(token_store::OsKeyringTokenStore::new(
                token_store::ACCOUNT_SERVICE,
            )),
            connect_server: Mutex::new(None),
            quick_access: std::sync::Mutex::new(quick_access::QuickAccessRuntime::default()),
            fill_target: std::sync::Mutex::new(None),
            pairing_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            sync_group_store: Arc::new(token_store::OsKeyringTokenStore::new(
                token_store::SYNC_GROUP_SERVICE,
            )),
        })
        .setup(|app| {
            // Logging first: every later tracing event (including the tray fallback notice) has
            // a sink
            init_desktop_logging(app);
            // Global hotkey plugin loaded at runtime (a failure doesn't block startup; the reason
            // is kept in the runtime state for the settings page to show — see the quick_access
            // module docs)
            if let Err(e) = quick_access::install_plugin(app.handle()) {
                tracing::warn!("global shortcut plugin unavailable: {}", e);
                let state = app.state::<AppState>();
                let mut runtime = state.quick_access.lock().unwrap_or_else(|p| p.into_inner());
                runtime.install_error = Some(e);
            }
            // System tray: approval popups must still be deliverable after the main window is
            // closed, and the tray is the resident entry point. Without a display session
            // (CI/container/ssh-only) the muda menu panics outright, so skip the tray and run
            // degraded — the approval chain doesn't depend on the tray being alive.
            if display_session_available() {
                setup_tray(app)?;
            } else {
                tracing::info!("no display session; running headless without tray");
            }
            // Cloud drive sync watcher: when transport is cloud and the directory is configured,
            // remote changes in the cloud drive directory trigger a sync cycle on their own
            // (notify primary, with an mtime polling fallback). Switching back to server
            // transport stops it automatically; when locked or not in a group, the
            // sync_cycle_once gate provides the fallback.
            sync_watcher::spawn_sync_watcher(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the main window = hide to tray (passkey/SSH approvals keep working); only
            // the tray Quit exits
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            // Quick Access and the generator popups: they self-dismiss on focus loss (the same
            // behaviour as 1Password — a popup is a "grab it quickly" surface, and one sitting in
            // the middle of the screen after focus moves to another app is just in the way).
            // CloseRequested is likewise turned into hide rather than a real close: the popups
            // are resident (visible:false initially, summoned by hotkey/tray at any time), and
            // being truly closed by Alt+F4 / cmd-W would make them impossible to summon again
            if window.label() == quick_access::WINDOW_LABEL
                || window.label() == quick_access::GENERATOR_WINDOW_LABEL
            {
                if let tauri::WindowEvent::Focused(false) = event {
                    let _ = window.hide();
                }
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::init_service,
            commands::lock_service,
            commands::is_service_unlocked,
            commands::create_identity,
            commands::get_identities,
            commands::get_identity,
            commands::get_active_identity,
            commands::set_active_identity,
            commands::clear_active_identity,
            commands::get_workspace_settings,
            commands::backup_export_to_file,
            commands::backup_restore_from_file,
            commands::backup_push_to_server,
            commands::backup_list_server_versions,
            commands::backup_restore_from_server,
            commands::backup_delete_server_version,
            commands::set_feature_flags,
            commands::set_password_expiry,
            commands::set_locale,
            commands::set_tray_locale,
            commands::quick_access_status,
            commands::quick_access_set,
            commands::quick_access_open,
            commands::quick_access_open_credential,
            commands::fill_target_status,
            commands::desktop_fill_credential,
            commands::generator_status,
            commands::generator_set,
            commands::generator_open,
            commands::focus_main_window,
            commands::change_master_password,
            commands::connect_server_start,
            commands::connect_server_stop,
            commands::connect_server_status,
            commands::connect_token_create,
            commands::connect_token_list,
            commands::connect_token_revoke,
            commands::get_travel_status,
            commands::set_travel_marked,
            commands::enter_travel_mode,
            commands::exit_travel_mode,
            commands::biometric_status,
            commands::biometric_enable,
            commands::biometric_disable,
            commands::biometric_unlock,
            commands::biometric_wrap_spike,
            commands::biometric_tpm_spike,
            commands::set_sync_config,
            commands::set_sync_methods,
            commands::set_sync_transport,
            commands::sync_token_present,
            commands::sync_device_status,
            commands::sync_join,
            commands::sync_leave,
            commands::sync_list_devices,
            commands::sync_set_device_remark,
            commands::sync_authorize,
            commands::sync_revoke,
            commands::sync_now,
            commands::sync_status,
            commands::sync_rotate,
            commands::sync_conflicts_list,
            commands::sync_conflict_resolve,
            commands::sync_group_status,
            commands::sync_group_pairing_create,
            commands::sync_group_pairing_poll,
            commands::sync_group_pairing_cancel,
            commands::sync_group_join_begin,
            commands::sync_group_join_confirm,
            commands::sync_group_join_cancel,
            commands::account_register,
            commands::set_account_binding,
            commands::account_passkey_create_options,
            commands::account_passkey_register,
            commands::account_passkey_login_options,
            commands::account_srp_register,
            commands::account_srp_challenge,
            commands::account_srp_verify,
            commands::account_srp_register_with_password,
            commands::account_srp_login,
            commands::account_exchange_session,
            commands::account_sign_out,
            commands::account_generate_recovery_codes,
            commands::account_verify_recovery_code,
            commands::account_authorize_device,
            commands::account_list_devices,
            commands::account_revoke_device,
            commands::account_create_session,
            commands::account_revoke_session,
            commands::update_identity,
            commands::delete_identity,
            commands::create_credential,
            commands::update_credential,
            commands::update_credential_data,
            commands::get_credentials_for_identity,
            commands::get_credential_data,
            commands::get_credential_custom_fields,
            commands::set_credential_custom_fields,
            commands::get_credential_history,
            commands::restore_credential_version,
            commands::get_totp_code,
            commands::list_attachments,
            commands::attach_file_to_credential,
            commands::save_attachment_to_file,
            commands::delete_attachment,
            commands::search_credentials,
            commands::generate_password,
            commands::generate_password_advanced,
            commands::get_statistics,
            commands::toggle_credential_favorite,
            commands::fetch_credential_favicon,
            commands::get_favicons,
            commands::delete_credential,
            commands::get_ssh_agent_status,
            commands::start_ssh_agent,
            commands::stop_ssh_agent,
            commands::ssh_agent_integration_status,
            commands::ssh_agent_integration_enable,
            commands::ssh_agent_integration_disable,
            commands::ssh_agent_config_analysis,
            commands::ssh_approval_respond,
            commands::passkey_approval_respond,
            commands::inspect_ssh_key_file,
            commands::import_ssh_key,
            commands::generate_ssh_key,
            commands::get_ssh_keys,
            commands::wallet_generate_mnemonic,
            commands::wallet_list,
            commands::wallet_list_addresses,
            commands::wallet_validate_mnemonic,
            commands::wallet_set_item_password,
            commands::wallet_clear_item_password,
            commands::wallet_generate,
            commands::wallet_import,
            commands::wallet_add_address,
            commands::wallet_delete,
            commands::wallet_export,
            commands::wallet_create_transaction,
            commands::wallet_pending_transactions,
            commands::wallet_sign_transaction,
            commands::configure_auto_lock,
            commands::get_auto_lock_status,
            commands::touch_activity,
            commands::start_auto_lock_monitoring,
            commands::stop_auto_lock_monitoring,
            commands::audit_query,
            commands::audit_statistics,
            commands::audit_cleanup,
            commands::health_scan,
            commands::passkey_list,
            commands::passkey_list_by_rp,
            commands::passkey_get,
            commands::passkey_delete,
            commands::passkey_create,
            commands::passkey_self_test,
            commands::passkey_export_private_key,
            commands::export_identity,
            commands::reveal_credential_secret,
            commands::reauth_verify,
            commands::report_frontend_error,
        ])
        .build(context)
        .expect("error while building tauri application")
}

/// Assemble and run the application (called from the process entry point; the event loop does
/// not return until Quit).
pub fn run() {
    let app = build::<tauri::Wry>(tauri::generate_context!());
    app.run(|app_handle, event| {
        // RunEvent::Exit is the last callback before the process exits (tray Quit ->
        // app.exit(0) is the only exit path, and it lands here after ExitRequested); the main
        // thread is still alive, so block_on does a best-effort flush of the sync emitter's
        // queue (same semantics as the stop at the end of the CLI).
        if let tauri::RunEvent::Exit = event {
            tauri::async_runtime::block_on(async {
                let emitter = app_handle
                    .state::<AppState>()
                    .sync_emitter
                    .lock()
                    .await
                    .take();
                if let Some(emitter) = emitter {
                    emitter.stop().await;
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    /// Coexistence probe between mock_app's mock runtime and the test tokio reactor: if sqlx
    /// hangs after mock_app, this fails before every command-level test and pinpoints the root
    /// cause (see the FakeSink comment in passkey_bridge.rs).
    #[tokio::test]
    async fn sqlite_works_after_mock_app_creation() {
        let _app = tauri::test::mock_app();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("smoke.db");
        let db = persona_core::storage::Database::from_file(db_path.to_str().unwrap())
            .await
            .unwrap();

        let migrated = tokio::time::timeout(std::time::Duration::from_secs(20), db.migrate())
            .await
            .expect("sqlx never completed under mock_app — reactor poisoned");
        migrated.unwrap();

        // One real query plus one real write, to confirm the reactor interference isn't limited
        // to migrate.
        use persona_core::storage::Repository;
        let repo = persona_core::storage::IdentityRepository::new(db);
        let identity = persona_core::models::Identity::new(
            "Smoke".to_string(),
            persona_core::models::IdentityType::Personal,
        );
        let created = repo.create(&identity).await.unwrap();
        let fetched = repo.find_by_id(&created.id).await.unwrap();
        assert!(fetched.is_some());
    }
}
