//! 桌面填充的**真实命令层**取消时序套件（第五轮收口）。第四轮的取消时序
//! 用例（desktop_fill.rs win_tests）直测注入引擎层 `execute_fill`，重查闭
//! 包是测试自己注入的——命令层（`desktop_fill_credential`）自建的
//! `slot_recheck_for` 闭包从未被真命令路径执行过。本套件补上这一层：
//! **端到端驱动真命令**（mock runtime `State<AppState>` + 真服务解密 +
//! 真实跨进程靶窗），取消由宿主进程的**暂停钩子**确定性插桩——
//!
//! 1. 注入线程在 username 的跨进程 `SendMessageW` 上阻塞；
//! 2. 宿主在 username 写入完成的消息处理里停住（`HOOK_PAUSED`），
//!    此刻注入流程被物理挂起——旧实现（绑定比较后锁释放、无字段级重查）
//!    与新实现（逐字段写入前重查）在此分岔；
//! 3. 测试侧在 `HOOK_PAUSED` 与 `hook-go` 之间改动
//!    `AppState.fill_target`（清槽 / 换新快照）——时序严格落在第一字段
//!    写入完成之后、密码写入之前，不靠轮询碰运气；
//! 4. 放行后：新实现必须中止剩余写入并如实报
//!    `FILL_TARGET_DISCARDED` / `FILL_TARGET_CHANGED`（部分完成）；
//!    **旧实现则会把密码写进框里并报成功**——因此这两个用例在旧实现上
//!    必红（真机红跑见 docs/review/evidence/openclaw-2026-11-06-desktop-fill/
//!    run7-red-cmdcancel-old-impl/）。
//!
//! 密码残留断言用靶进程**同进程**读回（READBACK 长度前缀协议）：Windows
//! 跨进程 `WM_GETTEXT` 读 ES_PASSWORD 恒返回空（平台限制，见 xproc 套件头
//! 注释），长度前缀保证「username 非空 + password 空」的单字段残留不会被
//! 吞成双空。
//!
//! 运行条件：Windows + `--features fill-test-host` + 交互式桌面会话
//! （SSH 会话不可用，理由同 xproc 套件）：
//!   cargo test -p persona-fill-test --test desktop_fill_command_cancel

#![cfg(all(target_os = "windows", feature = "fill-test-host"))]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use persona_desktop::commands::{
    create_credential, create_identity, desktop_fill_credential, init_service,
};
use persona_desktop::desktop_fill::win::{process_image_path, window_class_name};
use persona_desktop::desktop_fill::FillTarget;
use persona_desktop::token_store::InMemoryTokenStore;
use persona_desktop::types::{
    AppState, CreateCredentialRequest, CreateIdentityRequest, CredentialDataRequest,
    InitRequest, SecurityQuestionRequest,
};
use tauri::Manager;

const HOST_EXE: &str = env!("CARGO_BIN_EXE_fill-test-host");

const USERNAME: &str = "alice@example.com";
const PASSWORD: &str = "s3cret-Пароль⚡";

// ---------------------------------------------------------------------------
// mock runtime + 真服务夹具（与包内 command_layer_tests 同构；集成测试在
// persona-fill-test crate 里，无法复用包内私有 fixture，按同一形状重建）
// ---------------------------------------------------------------------------

fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    let app = tauri::test::mock_app();
    app.manage(AppState {
        service: Arc::new(tokio::sync::Mutex::new(None)),
        db_path: tokio::sync::Mutex::new(None),
        agent_handle: tokio::sync::Mutex::new(None),
        auto_lock_registered: AtomicBool::new(false),
        passkey_server_started: AtomicBool::new(false),
        passkey_server_shutdown: tokio::sync::Mutex::new(None),
        ssh_approvals: Arc::new(Mutex::new(HashMap::new())),
        passkey_approvals: Arc::new(Mutex::new(HashMap::new())),
        sync_emitter: tokio::sync::Mutex::new(None),
        // CI/headless 没有 secret service——测试一律走内存 fake
        token_store: Arc::new(InMemoryTokenStore::default()),
        biometric_provider: Arc::new(persona_core::MockBiometricProvider::default()),
        biometric_store: Arc::new(InMemoryTokenStore::default()),
        // 默认门禁档桩（= CI/headless 的生产装配）
        biometric_wrapper: Arc::new(persona_desktop::biometric::GateOnlyKeyWrapper),
        biometric_wrap_store: Arc::new(InMemoryTokenStore::default()),
        device_store: Arc::new(InMemoryTokenStore::default()),
        account_token_store: Arc::new(InMemoryTokenStore::default()),
        connect_server: tokio::sync::Mutex::new(None),
        quick_access: std::sync::Mutex::new(
            persona_desktop::quick_access::QuickAccessRuntime::default(),
        ),
        // 桌面填充注入目标槽：命令层取消时序套件直接读写这个槽位
        fill_target: std::sync::Mutex::new(None),
        pairing_sessions: Arc::new(Mutex::new(HashMap::new())),
        sync_group_store: Arc::new(InMemoryTokenStore::default()),
    });
    app
}

async fn init_service_ok(app: &tauri::App<tauri::test::MockRuntime>, password: &str) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cmd-cancel.db");
    // Leak the TempDir: the service keeps the file open for the whole test.
    std::mem::forget(dir);
    let resp = init_service(
        InitRequest {
            master_password: password.to_string(),
            db_path: Some(db_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "init failed: {:?}", resp.error);
}

/// 已初始化服务 + 一条 Password 凭据（username/password 恒为
/// USERNAME / PASSWORD），返回 app + 凭据 id。取消时序用例的插桩线程
/// 通过 `slot_addr_of` 拿槽位地址，不需要跨线程持有 App。
async fn app_with_password_credential() -> (tauri::App<tauri::test::MockRuntime>, String) {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    let resp = create_identity(
        CreateIdentityRequest {
            name: "Cmd Cancel Holder".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let identity = resp.data.expect("identity created");

    let resp = create_credential(
        CreateCredentialRequest {
            identity_id: identity.id,
            name: "Example Login".to_string(),
            credential_type: "Password".to_string(),
            security_level: "High".to_string(),
            url: Some("https://example.com".to_string()),
            username: Some(USERNAME.to_string()),
            notes: None,
            tags: None,
            credential_data: CredentialDataRequest::Password {
                password: PASSWORD.to_string(),
                email: None,
                security_questions: vec![SecurityQuestionRequest {
                    question: "pet?".to_string(),
                    answer: "cat".to_string(),
                }],
            },
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "credential create failed: {:?}", resp.error);
    let cred = resp.data.expect("credential created");
    (app, cred.id)
}

// ---------------------------------------------------------------------------
// 靶进程驱动（与 desktop_fill_cross_process.rs 同构；HostProcess 的 stdin
// 用 Arc<Mutex<>> 包裹：取消插桩线程要和主线程共享它发 hook-go）
// ---------------------------------------------------------------------------

/// stdout 行的双订阅：同一行同时进主通道与取消插桩通道（HOST_PAUSED 只
/// 由插桩线程消费，其余行留给主线程的应答循环跳过）
fn forward_both(line: Result<String, std::io::Error>, txs: &[&std::sync::mpsc::Sender<String>]) {
    let Ok(line) = line else { return };
    for tx in txs {
        let _ = tx.send(line.clone());
    }
}

struct HostProcess {
    child: Child,
    stdin: Arc<Mutex<std::process::ChildStdin>>,
    lines: Receiver<String>,
    /// 取消插桩线程专用的行通道（HOOK_PAUSED 消费方）
    hook_lines: Receiver<String>,
}

impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl HostProcess {
    fn spawn(title: &str, password_style: bool) -> Self {
        let mut child = Command::new(HOST_EXE)
            .args([
                "--title",
                title,
                "--password-style",
                if password_style { "1" } else { "0" },
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn fill-test-host");
        let stdin = child.stdin.take().expect("host stdin");
        let stdout = child.stdout.take().expect("host stdout");
        let (tx_main, rx_main) = channel();
        let (tx_hook, rx_hook) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                forward_both(line, &[&tx_main, &tx_hook]);
            }
        });
        let host = Self {
            child,
            stdin: Arc::new(Mutex::new(stdin)),
            lines: rx_main,
            hook_lines: rx_hook,
        };
        host.wait_ready();
        host
    }

    /// 取出取消插桩线程专用的行通道（HOOK_PAUSED 消费方）；主线程之后
    /// 只再用 `lines`（应答循环）
    fn take_hook_lines(&mut self) -> Receiver<String> {
        std::mem::replace(
            &mut self.hook_lines,
            channel().1,
        )
    }

    fn wait_ready(&self) {
        loop {
            match self.lines.recv_timeout(Duration::from_secs(10)) {
                Ok(line) if line.starts_with("READY") => return,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("fill-test-host not ready in 10s"),
                Err(RecvTimeoutError::Disconnected) => panic!("fill-test-host died at startup"),
            }
        }
    }

    fn send(&self, cmd: &str) {
        let mut stdin = self.stdin.lock().expect("host stdin lock");
        writeln!(stdin, "{cmd}").expect("write host stdin");
        stdin.flush().expect("flush host stdin");
    }

    /// 挂暂停钩子（等 PAUSE_ARMED）
    fn arm_pause_hook(&self) {
        self.send("arm-pause-hook");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) if line.starts_with("PAUSE_ARMED") => return,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("host did not arm pause hook in time"),
                Err(RecvTimeoutError::Disconnected) => panic!("host died while arming pause hook"),
            }
        }
    }

    fn quit(&mut self) {
        self.send("quit");
        let _ = self.child.wait();
    }

    /// 靶进程**同进程**读回两个 Edit 的文本（长度前缀协议帧 → 解码）。
    /// 密码残留断言的唯一可靠通道（Windows 跨进程 WM_GETTEXT 读
    /// ES_PASSWORD 恒返回空；长度前缀保住单字段残留信息）。
    fn readback(&self) -> (String, String) {
        self.send("readback");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) if line.starts_with("READBACK") => {
                    return persona_fill_test::parse_readback_frame(&line)
                        .expect("well-formed READBACK frame");
                }
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("host did not answer readback in time"),
                Err(RecvTimeoutError::Disconnected) => panic!("host died during readback"),
            }
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

/// 按标题查找顶层窗口（轮询等待宿主窗口就绪）
fn find_window_by_title(title: &str) -> isize {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;
    let title_h = HSTRING::from(title);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let hwnd =
            unsafe { FindWindowW(PCWSTR::null(), PCWSTR(title_h.as_ptr())).unwrap_or_default() };
        if !hwnd.is_invalid() {
            return hwnd.0 as isize;
        }
        if Instant::now() > deadline {
            panic!("host window with title {title:?} not found in 10s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 真实指纹快照（与 xproc 套件同源：类名/进程路径用同一批 helper 查询；
/// snapshot_id 现造——命令层按 id 做确认绑定）
fn snapshot_for(hwnd: isize, title: &str, pid: u32, snapshot_id: &str) -> FillTarget {
    FillTarget {
        hwnd,
        title: title.to_string(),
        pid,
        window_class: window_class_name(hwnd),
        exe_path: process_image_path(pid),
        snapshot_id: snapshot_id.to_string(),
    }
}

/// 槽位指针的跨线程传递：`App<MockRuntime>` 内含 mock runtime 的
/// `Receiver<Message>`（!Send/!Sync），整个 App 无法跨线程——但命令必须
/// 在创建 mock_app 的主线程上跑。插桩线程只需要 `AppState.fill_target`
/// 这一个 `Mutex<Option<FillTarget>>`（Sync），主线程把它的地址装进
/// AtomicIsize 交给插桩线程；指向的 Mutex 由 App 的 state map 持有，
/// 寿命覆盖插桩线程（mutator join 早于 app 离开作用域）。仅测试插桩用。
type SlotAddr = Arc<std::sync::atomic::AtomicIsize>;

fn slot_addr_of(app: &tauri::App<tauri::test::MockRuntime>) -> SlotAddr {
    SlotAddr::new(std::sync::atomic::AtomicIsize::new(
        &app.state::<AppState>().fill_target as *const std::sync::Mutex<Option<FillTarget>>
            as isize,
    ))
}

/// 取消插桩线程：等 `HOOK_PAUSED`（此刻 username 已真实落值、注入线程被
/// 挂起），执行测试给定的槽位改动，然后发 `hook-go` 放行注入流程。
fn spawn_slot_mutator(
    hook_lines: Receiver<String>,
    stdin: Arc<Mutex<std::process::ChildStdin>>,
    slot_addr: SlotAddr,
    mutate: impl FnOnce(&mut Option<FillTarget>) + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || loop {
        match hook_lines.recv_timeout(Duration::from_secs(30)) {
            Ok(line) if line.starts_with("HOOK_PAUSED") => {
                let slot_mutex = unsafe {
                    &*(slot_addr.load(std::sync::atomic::Ordering::Acquire)
                        as *const std::sync::Mutex<Option<FillTarget>>)
                };
                let mut slot = slot_mutex.lock().expect("fill_target lock");
                mutate(&mut slot);
                drop(slot);
                let mut s = stdin.lock().expect("host stdin lock");
                writeln!(s, "hook-go").expect("write hook-go");
                s.flush().expect("flush hook-go");
                return;
            }
            Ok(_) => continue,
            Err(RecvTimeoutError::Timeout) => panic!("host never reported HOOK_PAUSED in 30s"),
            Err(RecvTimeoutError::Disconnected) => panic!("host died before HOOK_PAUSED"),
        }
    })
}

// ---------------------------------------------------------------------------
// 绑定门（无需靶进程：拒绝发生在任何注入之前）
// ---------------------------------------------------------------------------

/// 确认面硬门经真命令：`confirmed=false` 一律拒绝，不存在静默注入路径。
#[tokio::test]
async fn command_layer_rejects_unconfirmed_fill() {
    let app = mock_app();
    let resp = desktop_fill_credential(
        "00000000-0000-0000-0000-000000000000".to_string(),
        false,
        None,
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "unconfirmed fill must be rejected");
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("requires explicit user confirmation"),
        "rejection must name the confirmation gate: {:?}",
        resp.error
    );
}

/// 确认必须携带捕获时的 snapshot_id：缺 id 的请求在解密完成后按协议错
/// 拒绝（`FILL_TARGET_SNAPSHOT_REQUIRED`），绝不落到「此刻槽位里的目标」。
#[tokio::test]
async fn command_layer_requires_snapshot_id() {
    let (app, cred_id) = app_with_password_credential().await;
    let hwnd = 0isize; // 绑定拒绝先于任何指纹验证，占位目标即可
    let slot_target = snapshot_for(hwnd, "unused", std::process::id(), "captured-A");
    {
        let state = app.state::<AppState>();
        *state.fill_target.lock().unwrap() = Some(slot_target);
    }
    let resp = desktop_fill_credential(cred_id, true, None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "missing snapshot_id must be rejected");
    assert_eq!(resp.error_code.as_deref(), Some("FILL_TARGET_SNAPSHOT_REQUIRED"));
}

/// 槽位已空（浮窗收起清槽）：携旧 snapshot_id 的在途请求在解密完成后的
/// 锁内比对被拒（`FILL_TARGET_DISCARDED`）——注入根本不会启动。
#[tokio::test]
async fn command_layer_rejects_inflight_request_after_slot_clear() {
    let (app, cred_id) = app_with_password_credential().await;
    let resp = desktop_fill_credential(
        cred_id,
        true,
        Some("stale-captured-id".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error_code.as_deref(), Some("FILL_TARGET_DISCARDED"));
}

// ---------------------------------------------------------------------------
// 取消时序（真命令 + 真跨进程靶窗 + 暂停钩子确定性插桩）
// ---------------------------------------------------------------------------

/// **清槽**落在第一字段写入之后：命令层必须中止剩余写入并如实报
/// `FILL_TARGET_DISCARDED`（部分完成 username=true / password=false），
/// 密码框零残留。**旧实现（绑定比较后锁释放、无字段级重查）下此用例
/// 必红**：密码会被写进框里且命令报成功。
#[tokio::test]
async fn command_layer_mid_fill_slot_clear_aborts_remaining_write() {
    let title = "persona cmd cancel clear";
    let mut host = HostProcess::spawn(title, true);
    let hwnd = find_window_by_title(title);
    let snapshot_id = format!("cmd-cancel-{}", uuid::Uuid::new_v4());
    let snapshot = snapshot_for(hwnd, title, host.pid(), &snapshot_id);

    let (app, cred_id) = app_with_password_credential().await;
    {
        let state = app.state::<AppState>();
        *state.fill_target.lock().unwrap() = Some(snapshot.clone());
    }
    host.arm_pause_hook();
    let hook_lines = host.take_hook_lines();

    // 插桩线程：HOOK_PAUSED（username 已落值、注入线程挂起）时清槽再放行
    let mutator = spawn_slot_mutator(
        hook_lines,
        Arc::clone(&host.stdin),
        slot_addr_of(&app),
        |slot| {
            *slot = None;
        },
    );

    let resp = desktop_fill_credential(
        cred_id,
        true,
        Some(snapshot_id.clone()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    mutator.join().expect("slot mutator thread");

    assert!(
        !resp.success,
        "mid-fill slot clear must abort the fill (old implementation would report success here)"
    );
    assert_eq!(
        resp.error_code.as_deref(),
        Some("FILL_TARGET_DISCARDED"),
        "unexpected response: {:?}",
        resp.error
    );
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("mid-fill")
            && msg.contains("username_filled=true")
            && msg.contains("password_filled=false"),
        "rejection must report partial completion honestly: {msg}"
    );

    // 决定性零残留断言：username 已写入（插桩点在它之后），密码一个字
    // 都不能落——靶进程同进程读回（长度前缀协议保住单字段残留）
    let (host_user, host_pwd) = host.readback();
    assert_eq!(host_user, USERNAME, "username write must have landed");
    assert_eq!(
        host_pwd, "",
        "password write must be aborted after the mid-fill slot clear"
    );
    host.quit();
}

/// **换目标**落在第一字段写入之后（确认 A 后浮窗重新捕获了 B）：命令层
/// 必须以 `FILL_TARGET_CHANGED` 中止剩余写入，绝不把剩余字段写进新目标。
/// **旧实现下必红**（密码照写、命令报成功）。
#[tokio::test]
async fn command_layer_mid_fill_target_swap_aborts_remaining_write() {
    let title = "persona cmd cancel swap";
    let mut host = HostProcess::spawn(title, true);
    let hwnd = find_window_by_title(title);
    let snapshot_id = format!("cmd-swap-{}", uuid::Uuid::new_v4());
    let snapshot = snapshot_for(hwnd, title, host.pid(), &snapshot_id);

    let (app, cred_id) = app_with_password_credential().await;
    {
        let state = app.state::<AppState>();
        *state.fill_target.lock().unwrap() = Some(snapshot.clone());
    }
    host.arm_pause_hook();
    let hook_lines = host.take_hook_lines();

    // 插桩线程：HOOK_PAUSED 时把槽位换成新一轮捕获的 B（不同 snapshot_id）
    let mutator = spawn_slot_mutator(
        hook_lines,
        Arc::clone(&host.stdin),
        slot_addr_of(&app),
        |slot| {
            let mut replacement = slot.clone().expect("slot still holds the confirmed target");
            replacement.snapshot_id = "re-captured-target-B".to_string();
            *slot = Some(replacement);
        },
    );

    let resp = desktop_fill_credential(
        cred_id,
        true,
        Some(snapshot_id.clone()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    mutator.join().expect("slot mutator thread");

    assert!(
        !resp.success,
        "mid-fill target swap must abort the fill (old implementation would report success here)"
    );
    assert_eq!(
        resp.error_code.as_deref(),
        Some("FILL_TARGET_CHANGED"),
        "unexpected response: {:?}",
        resp.error
    );
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("refusing to write remaining fields")
            && msg.contains("username_filled=true")
            && msg.contains("password_filled=false"),
        "rejection must report partial completion honestly: {msg}"
    );

    // 靶进程同进程读回：username 已落值，密码不落（不注入 B 的语义在
    // 单进程靶窗上表现为「密码框零残留」）
    let (host_user, host_pwd) = host.readback();
    assert_eq!(host_user, USERNAME, "username write must have landed");
    assert_eq!(
        host_pwd, "",
        "password must never land after the mid-fill target swap"
    );
    host.quit();
}
