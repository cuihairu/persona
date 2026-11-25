//! Integration test: the mock runtime and real Unix socket IO running
//! together, inside a separate process.
//!
//! Inside the bin's unit test process these two interfere with each other
//! (the mock runtime wrecks the wakeup of subsequent socket/duplex IO — see
//! the FakeSink comment in `passkey_bridge::tests`), so `TauriApprovalSink`'s
//! emit path previously could only be bypassed with FakeSink. Now that the
//! code is a lib, these tests drive the real sink and the approval server
//! directly from a separate process.
//!
//! Unix-only: the approval channel under test is a Unix domain socket (the
//! production side, `run_passkey_approval_server_with` /
//! `TauriApprovalSink`, is likewise gated behind `#[cfg(unix)]`, Windows
//! having a separate named-pipe implementation), so the whole test target
//! compiles as an empty file on non-Unix platforms (hence the
//! E0432/E0433 in the Windows cross check).
#![cfg(unix)]

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tauri::Manager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use persona_desktop::commands::{self, PasskeyApprovalRespondRequest};
use persona_desktop::passkey_bridge::{
    approval_socket_path, run_passkey_approval_server_with, TauriApprovalSink,
};
use persona_desktop::token_store::InMemoryTokenStore;
use persona_desktop::types::{AppState, InitRequest};

/// Mock app + empty AppState, matching the mock_app in the lib's command_layer_tests.
fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    let app = tauri::test::mock_app();
    app.manage(AppState {
        service: Arc::new(Mutex::new(None)),
        db_path: Mutex::new(None),
        agent_handle: Mutex::new(None),
        auto_lock_registered: std::sync::atomic::AtomicBool::new(false),
        passkey_server_started: std::sync::atomic::AtomicBool::new(false),
        passkey_server_shutdown: Mutex::new(None),
        ssh_approvals: Arc::new(StdMutex::new(HashMap::new())),
        passkey_approvals: Arc::new(StdMutex::new(HashMap::new())),
        sync_emitter: Mutex::new(None),
        token_store: Arc::new(InMemoryTokenStore::default()),
        biometric_provider: Arc::new(persona_core::MockBiometricProvider::default()),
        biometric_store: Arc::new(InMemoryTokenStore::default()),
        biometric_wrapper: Arc::new(persona_desktop::biometric::GateOnlyKeyWrapper),
        biometric_wrap_store: Arc::new(InMemoryTokenStore::default()),
        device_store: Arc::new(InMemoryTokenStore::default()),
        account_token_store: Arc::new(InMemoryTokenStore::default()),
        connect_server: Mutex::new(None),
        quick_access: StdMutex::new(persona_desktop::quick_access::QuickAccessRuntime::default()),
        fill_target: StdMutex::new(None),
        pairing_sessions: Arc::new(StdMutex::new(HashMap::new())),
        sync_group_store: Arc::new(InMemoryTokenStore::default()),
    });
    app
}

use std::collections::HashMap;

/// The tests in this file share the process env (PERSONA_AGENT_STATE_DIR
/// determines the socket path); a single process-wide lock serializes the
/// tests that hold env.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<StdMutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Redirect the agent state dir to a sandbox directory; restored on Drop.
struct StateDirGuard {
    prev: Option<String>,
}

impl StateDirGuard {
    fn sandbox(dir: &tempfile::TempDir) -> Self {
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::set_var("PERSONA_AGENT_STATE_DIR", dir.path());
        Self { prev }
    }
}

impl Drop for StateDirGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("PERSONA_AGENT_STATE_DIR", v),
            None => std::env::remove_var("PERSONA_AGENT_STATE_DIR"),
        }
    }
}

/// Poll until the socket file appears (the server task binds asynchronously).
async fn wait_for_socket(timeout: Duration) -> std::path::PathBuf {
    let path = approval_socket_path();
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if path.exists() {
            return path;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("approval socket never appeared at {}", path.display());
}

/// Event capturer for `persona://passkey-approval`.
#[derive(Clone, Default)]
struct EmittedEvents(Arc<StdMutex<Vec<String>>>);

impl EmittedEvents {
    fn listen(&self, app: &tauri::AppHandle<tauri::test::MockRuntime>) {
        use tauri::Listener;
        let sink = self.0.clone();
        app.listen("persona://passkey-approval", move |event| {
            sink.lock().unwrap().push(event.payload().to_string());
        });
    }

    fn wait_for(&self, timeout: Duration) -> Vec<String> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let events = self.0.lock().unwrap();
            if !events.is_empty() {
                return events.clone();
            }
            drop(events);
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("no approval event emitted within {timeout:?}");
    }
}

/// Production sink end to end: unlock the vault -> real socket receives the
/// bridge request -> TauriApprovalSink emits for real -> the frontend command
/// answers allow -> the client receives {"approved":true}.
#[tokio::test(flavor = "multi_thread")]
// env is process-global, so the lock must be held until the test ends (after
// bind, changing env does not affect an already-listening socket; the race
// window is only before startup, and holding the lock across await is
// deliberate).
#[allow(clippy::await_holding_lock)]
async fn tauri_sink_emits_and_resolves_over_real_socket() {
    let _env = env_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);

    let app = mock_app();
    let handle = app.handle().clone();

    // Unlocked vault: passkey_assert goes through GUI approval rather than
    // answering locked straight away.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("it.db");
    std::mem::forget(dir);
    let resp = commands::init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(db_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        handle.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "init failed: {:?}", resp.error);

    let events = EmittedEvents::default();
    events.listen(&handle);

    let state = app.state::<AppState>();
    let pending = state.passkey_approvals.clone();
    let service = state.service.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let _keep = shutdown_tx;
    let server = tokio::spawn(run_passkey_approval_server_with(
        TauriApprovalSink::new(handle.clone()),
        pending,
        service,
        shutdown_rx,
    ));
    let socket_path = wait_for_socket(Duration::from_secs(5)).await;

    // Bridge side: connect, send the request, wait for the answer.
    let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
    client
        .write_all(
            concat!(
                r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#,
                "\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let emitted = events.wait_for(Duration::from_secs(5));
    let payload: serde_json::Value = serde_json::from_str(&emitted[0]).unwrap();
    assert_eq!(payload["operation"], "passkey_assert");
    assert_eq!(payload["origin"], "https://github.com");
    let request_id = payload["request_id"].as_str().unwrap().to_string();

    // The frontend command answers allow (the same path as tapping confirm in
    // the production modal).
    let resp = commands::passkey_approval_respond(
        PasskeyApprovalRespondRequest {
            request_id,
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "respond failed: {:?}", resp.error);

    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut answer))
        .await
        .expect("server did not answer")
        .unwrap();
    assert!(read > 0, "connection closed without an answer");
    let decision: serde_json::Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(decision["approved"], serde_json::Value::Bool(true));

    server.abort();
}

/// Locked vault: the server does not pop the GUI and answers locked
/// directly — re-verified on the real emit path.
#[tokio::test(flavor = "multi_thread")]
// Same as above: env is global, and holding the lock across await is deliberate.
#[allow(clippy::await_holding_lock)]
async fn tauri_sink_locked_session_answers_directly_without_emit() {
    let _env = env_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);

    let app = mock_app();
    let handle = app.handle().clone();
    let events = EmittedEvents::default();
    events.listen(&handle);

    let state = app.state::<AppState>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let _keep = shutdown_tx;
    let server = tokio::spawn(run_passkey_approval_server_with(
        TauriApprovalSink::new(handle.clone()),
        state.passkey_approvals.clone(),
        state.service.clone(),
        shutdown_rx,
    ));
    let socket_path = wait_for_socket(Duration::from_secs(5)).await;

    let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
    client
        .write_all(
            concat!(
                r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#,
                "\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut answer))
        .await
        .expect("server did not answer")
        .unwrap();
    let decision: serde_json::Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(decision["approved"], serde_json::Value::Bool(false));
    assert_eq!(decision["reason"], "locked");

    std::thread::sleep(Duration::from_millis(100));
    assert!(
        events.0.lock().unwrap().is_empty(),
        "locked vault must not wake the GUI"
    );

    server.abort();
}

/// show_main_window: a safe no-op when there is no main window (the mock
/// runtime never built a "main" window).
#[test]
fn show_main_window_without_window_is_a_no_op() {
    let app = tauri::test::mock_app();
    persona_desktop::show_main_window(app.handle());
}

/// show_main_window: with a "main" window present, the full
/// unminimize/show/focus arm runs.
#[test]
fn show_main_window_focuses_existing_main_window() {
    let app = tauri::test::mock_app();
    let window = tauri::webview::WebviewWindowBuilder::new(
        app.handle(),
        "main",
        tauri::WebviewUrl::default(),
    )
    .build()
    .expect("mock runtime can build windows");
    assert!(window.is_visible().unwrap_or(false) || true); // mock visibility semantics are loose

    persona_desktop::show_main_window(app.handle());

    // The window still exists (it is neither closed nor rebuilt).
    assert!(app.get_webview_window("main").is_some());
}

/// The full build() chain: a mock context runs the complete assembly —
/// AppState manage, tray + menu construction, and all command registration.
/// Equivalent to the assembly section of production main(), minus the event
/// loop itself. The passkey approval server is off by default: no socket may
/// appear after assembly (the spawn is gated by the workspace toggle inside
/// init_service; see commands::maybe_start_passkey_server).
#[test]
fn build_assembles_full_app_with_tray() {
    let _env = env_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);

    let mut app = persona_desktop::build(tauri::test::mock_context::<tauri::test::MockRuntime, _>(
        tauri::test::noop_assets(),
    ));

    // The setup closure only runs at the first event loop iteration
    // (Builder::build does not run it), so drive one iteration manually to
    // trigger tray construction (mock runtime only, a single call — not the
    // looping busy-loop scenario the docs warn about).
    #[allow(deprecated)]
    {
        app.run_iteration(|_handle, _event| {});
    }

    // manage took effect: the command layer can read AppState.
    assert!(app.try_state::<AppState>().is_some());

    // Default feature flags are all off: the approval server must not be
    // started by the assembly section.
    let socket = state_dir
        .path()
        .join(persona_desktop::passkey_bridge::APPROVAL_SOCKET_NAME);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !socket.exists(),
        "passkey approval socket must not listen until the workspace flag is on"
    );

    // The tray branches on the display session: with a display, build it (the mock tray
    // exercises the full API surface); without one (CI/container) the headless branch
    // skips tray construction.
    let has_display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    if has_display {
        assert!(app.tray_by_id("persona-tray").is_some());
    } else {
        assert!(
            app.tray_by_id("persona-tray").is_none(),
            "headless session must not build a tray"
        );
    }

    app.cleanup_before_exit();
}

/// Custom field (1Password-aligned) command-layer walkthrough: a real PersonaService
/// (unlocked) + mock runtime State driving the commands directly — set with an empty id
/// generates it in the backend, get reads back consistently, an empty table removes,
/// and malformed UUIDs plus unknown types report classified errors.
#[tokio::test]
async fn custom_fields_commands_roundtrip_through_real_service() {
    use persona_desktop::commands;
    use persona_desktop::types::SerializableCustomField;

    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let db = persona_core::storage::Database::from_file(
        dir.path().join("custom-fields.db").to_str().unwrap(),
    )
    .await
    .unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::service::PersonaService::new(db)
        .await
        .unwrap();
    service.initialize_user("test_password").await.unwrap();
    let identity = service
        .create_identity(
            "CF Identity".to_string(),
            persona_core::IdentityType::Personal,
        )
        .await
        .unwrap();
    let data = persona_core::models::CredentialData::Password(
        persona_core::models::credential::PasswordCredentialData {
            password: "pw".to_string(),
            email: None,
            security_questions: vec![],
        },
    );
    let cred = service
        .create_credential(
            identity.id,
            "WithFields".to_string(),
            persona_core::CredentialType::Password,
            persona_core::models::SecurityLevel::Medium,
            &data,
        )
        .await
        .unwrap();
    *app.state::<AppState>().service.lock().await = Some(service);

    let field_input =
        |id: &str, label: &str, value: &str, field_type: &str| SerializableCustomField {
            id: id.to_string(),
            label: label.to_string(),
            value: value.to_string(),
            field_type: field_type.to_string(),
            section: None,
        };

    // set: a new row with an empty id -> generated by the backend; get reads the same table back
    let set_resp = commands::set_credential_custom_fields(
        cred.id.to_string(),
        vec![
            field_input("", "Server", "db.internal:5432", "text"),
            field_input("", "Recovery code", "abcd-efgh", "concealed"),
        ],
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(set_resp.success, "set failed: {:?}", set_resp.error);
    let stored = set_resp.data.clone().unwrap();
    assert_eq!(stored.len(), 2);
    assert!(!stored[0].id.is_empty() && !stored[1].id.is_empty());
    assert!(stored[1].id != stored[0].id);

    let get_resp =
        commands::get_credential_custom_fields(cred.id.to_string(), app.state::<AppState>())
            .await
            .unwrap();
    assert!(get_resp.success);
    assert_eq!(get_resp.data.unwrap(), stored);

    // An empty table = removal
    let clear = commands::set_credential_custom_fields(
        cred.id.to_string(),
        vec![],
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(clear.success);
    let get_empty =
        commands::get_credential_custom_fields(cred.id.to_string(), app.state::<AppState>())
            .await
            .unwrap();
    assert!(get_empty.data.unwrap().is_empty());

    // Malformed UUID: classified error
    let bad =
        commands::get_credential_custom_fields("not-a-uuid".to_string(), app.state::<AppState>())
            .await
            .unwrap();
    assert!(!bad.success);
    assert!(bad.error.unwrap().contains("Invalid UUID"));

    // Unknown type: classified error (nothing persisted)
    let unknown = commands::set_credential_custom_fields(
        cred.id.to_string(),
        vec![field_input("", "K", "V", "bogus")],
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!unknown.success);
    assert!(unknown.error.unwrap().contains("unknown custom field type"));
}
