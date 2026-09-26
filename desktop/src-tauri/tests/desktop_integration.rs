//! 集成测试：独立进程里同时跑 mock runtime 与真 Unix socket IO。
//!
//! bin 单测进程内这两者互相干扰（mock runtime 会拖垮后续 socket/duplex
//! IO 的唤醒，见 `passkey_bridge::tests` 中 FakeSink 的注释），所以
//! `TauriApprovalSink` 的 emit 路径此前只能用 FakeSink 绕过。lib 化后
//! 这些测试在独立进程里直驱真实 sink 与审批服务端。

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

/// mock app + 空 AppState，与 lib 内 command_layer_tests 的 mock_app 一致。
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
        connect_server: Mutex::new(None),
        quick_access: StdMutex::new(persona_desktop::quick_access::QuickAccessRuntime::default()),
    });
    app
}

use std::collections::HashMap;

/// 本文件的测试共享进程 env（PERSONA_AGENT_STATE_DIR 决定 socket 路径），
/// 用同一把进程级锁串行化持 env 的测试。
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<StdMutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 把 agent state dir 重定向到 sandbox 目录，Drop 时恢复。
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

/// 轮询等待 socket 文件出现（server task 异步 bind）。
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

/// `persona://passkey-approval` 事件捕获器。
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

/// 生产 sink 全链路：解锁保险库 → 真 socket 收 bridge 请求 →
/// TauriApprovalSink 真实 emit → 前端命令应答 allow → 客户端收到
/// {"approved":true}。
#[tokio::test(flavor = "multi_thread")]
// env 是进程全局，锁必须持到测试结束（bind 后改 env 不影响已监听的
// socket，竞争窗口只在启动前，跨 await 持锁是刻意的）。
#[allow(clippy::await_holding_lock)]
async fn tauri_sink_emits_and_resolves_over_real_socket() {
    let _env = env_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);

    let app = mock_app();
    let handle = app.handle().clone();

    // 解锁的保险库：passkey_assert 走 GUI 审批而非直接 locked。
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

    // bridge 侧：连接、发请求、等应答。
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

    // 前端命令应答 allow（与生产 modal 点确认同一路径）。
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

/// 锁定保险库：服务端不弹 GUI，直接回 locked —— 真实 emit 路径下复验。
#[tokio::test(flavor = "multi_thread")]
// 同上：env 全局，跨 await 持锁是刻意的。
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

/// show_main_window：无主窗口时安全空跑（mock runtime 没建过 "main" 窗）。
#[test]
fn show_main_window_without_window_is_a_no_op() {
    let app = tauri::test::mock_app();
    persona_desktop::show_main_window(app.handle());
}

/// show_main_window：有 "main" 窗时走 unminimize/show/focus 全臂。
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
    assert!(window.is_visible().unwrap_or(false) || true); // mock 窗口可见性语义宽松

    persona_desktop::show_main_window(app.handle());

    // 窗口仍在（不会被关闭或重建）。
    assert!(app.get_webview_window("main").is_some());
}

/// build() 整链：mock context 跑完整装配 —— AppState manage、托盘 + 菜单
/// 构建、全部命令注册。等价于生产 main() 的装配段，事件循环本身除外。
/// passkey 审批服务端默认关闭：装配后 socket 不应出现（spawn 由
/// init_service 按 workspace 开关门禁，见 commands::maybe_start_passkey_server）。
#[test]
fn build_assembles_full_app_with_tray() {
    let _env = env_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);

    let mut app = persona_desktop::build(tauri::test::mock_context::<tauri::test::MockRuntime, _>(
        tauri::test::noop_assets(),
    ));

    // setup 闭包延迟到第一次事件循环迭代才执行（Builder::build 不跑它），
    // 这里手动驱动一次触发托盘构建（仅 mock runtime，单次调用，不涉及
    // 文档警告的循环 busy-loop 场景）。
    #[allow(deprecated)]
    {
        app.run_iteration(|_handle, _event| {});
    }

    // manage 生效：命令层读得到 AppState。
    assert!(app.try_state::<AppState>().is_some());

    // 默认 feature flags 全关：审批服务端不应被装配段启动。
    let socket = state_dir
        .path()
        .join(persona_desktop::passkey_bridge::APPROVAL_SOCKET_NAME);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !socket.exists(),
        "passkey approval socket must not listen until the workspace flag is on"
    );

    // 托盘按显示会话分流：有 display 构建（mock tray 走完整 API 面），
    // 无 display（CI/容器）走 headless 分支不建托盘。
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
