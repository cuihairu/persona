//! **Real command-layer** cancellation timing suite for desktop fill (closed
//! out in round five). The round-four cancellation timing case (desktop_fill.rs
//! win_tests) tested the injection engine layer `execute_fill` directly, with the
//! recheck closure injected by the test itself — the `slot_recheck_for` closure
//! built by the command layer (`desktop_fill_credential`) had never been executed
//! by the real command path. This suite covers that layer: **it drives the real
//! command end to end** (mock runtime `State<AppState>` + real service decryption
//! + a real cross-process target window), with cancellation instrumented
//! deterministically via the host process's **pause hook** —
//!
//! 1. the injection thread blocks on the cross-process `SendMessageW` for
//!    username;
//! 2. the host stops inside the message handling that completed the username
//!    write (`HOOK_PAUSED`), at which point the injection flow is physically
//!    suspended — this is where the old implementation (release the lock after
//!    the binding comparison, no field-level recheck) and the new one (recheck
//!    before each field write) diverge;
//! 3. the test side mutates `AppState.fill_target` between `HOOK_PAUSED` and
//!    `hook-go` (clear the slot / swap in a new snapshot) — the timing lands
//!    strictly after the first field write completes and before the password
//!    write, without depending on lucky polling;
//! 4. after release: the new implementation must abort the remaining writes and
//!    honestly report `FILL_TARGET_DISCARDED` / `FILL_TARGET_CHANGED` (partial
//!    completion); **the old implementation would write the password into the
//!    box and report success** — so both cases must fail on the old
//!    implementation (see the red run on real hardware in
//!    docs/evidence/openclaw-2026-11-06-desktop-fill/
//!    run7-red-cmdcancel-old-impl/).
//!
//! The password-residue assertion uses the target process's **same-process**
//! readback (the READBACK length-prefixed protocol): cross-process
//! `WM_GETTEXT` on ES_PASSWORD always returns empty on Windows (a platform
//! limitation, see the xproc suite's header comment), and the length prefix
//! ensures a single-field residue of "username non-empty + password empty" is
//! not swallowed into double empty.
//!
//! Run requirements: Windows + `--features fill-test-host` + an interactive
//! desktop session (SSH sessions do not work, for the same reason as the xproc
//! suite):
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
    AppState, CreateCredentialRequest, CreateIdentityRequest, CredentialDataRequest, InitRequest,
    SecurityQuestionRequest,
};
use tauri::Manager;

const HOST_EXE: &str = env!("CARGO_BIN_EXE_fill-test-host");

const USERNAME: &str = "alice@example.com";
const PASSWORD: &str = "s3cret-Пароль⚡";

// ---------------------------------------------------------------------------
// mock runtime + real-service fixture (same shape as the in-package
// command_layer_tests; the integration tests live in the persona-fill-test
// crate and cannot reuse the package's private fixtures, so they are rebuilt
// with the same shape)
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
        // CI/headless has no secret service — tests always use the in-memory fake
        token_store: Arc::new(InMemoryTokenStore::default()),
        biometric_provider: Arc::new(persona_core::MockBiometricProvider::default()),
        biometric_store: Arc::new(InMemoryTokenStore::default()),
        // Default gate-tier stub (= the production wiring on CI/headless)
        biometric_wrapper: Arc::new(persona_desktop::biometric::GateOnlyKeyWrapper),
        biometric_wrap_store: Arc::new(InMemoryTokenStore::default()),
        device_store: Arc::new(InMemoryTokenStore::default()),
        account_token_store: Arc::new(InMemoryTokenStore::default()),
        connect_server: tokio::sync::Mutex::new(None),
        quick_access: std::sync::Mutex::new(
            persona_desktop::quick_access::QuickAccessRuntime::default(),
        ),
        // Desktop fill injection target slot: the command-layer cancellation timing suite reads and writes this slot directly
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

/// Initialized service + one Password credential (username/password are always
/// USERNAME / PASSWORD), returning the app and the credential id. The
/// instrumentation thread of the cancellation timing cases gets the slot
/// address via `slot_addr_of`, so it does not need to hold the App across
/// threads.
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
// Target-process driver (same shape as desktop_fill_cross_process.rs; the
// HostProcess stdin is wrapped in Arc<Mutex<>>: the cancellation
// instrumentation thread must share it with the main thread to send hook-go)
// ---------------------------------------------------------------------------

/// Double subscription of stdout lines: each line goes to both the main channel
/// and the cancellation instrumentation channel (HOST_PAUSED is consumed only by
/// the instrumentation thread; the remaining lines are left for the main thread's
/// reply loop to skip)
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
    /// Line channel dedicated to the cancellation instrumentation thread (the HOOK_PAUSED consumer)
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

    /// Take out the line channel dedicated to the cancellation instrumentation
    /// thread (the HOOK_PAUSED consumer); afterwards the main thread only uses
    /// `lines` (the reply loop)
    fn take_hook_lines(&mut self) -> Receiver<String> {
        std::mem::replace(&mut self.hook_lines, channel().1)
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

    /// Arm the pause hook (waits for PAUSE_ARMED)
    fn arm_pause_hook(&self) {
        self.send("arm-pause-hook");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
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

    /// Read back the text of the two Edit controls **in the target process**
    /// (length-prefixed protocol frame -> decoded). The only reliable channel for
    /// the password-residue assertion (cross-process WM_GETTEXT on ES_PASSWORD
    /// always returns empty on Windows; the length prefix preserves the
    /// single-field residue information).
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

/// Find a top-level window by title (polls until the host window is ready)
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

/// A real fingerprint snapshot (same source as the xproc suite: the class name /
/// process path are queried with the same helpers; the snapshot_id is made up on
/// the spot — the command layer binds confirmation by id)
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

/// Cross-thread hand-off of the slot pointer: `App<MockRuntime>` contains the
/// mock runtime's `Receiver<Message>` (!Send/!Sync), so the whole App cannot
/// cross threads — yet the command must run on the main thread that created
/// mock_app. The instrumentation thread only needs the single
/// `Mutex<Option<FillTarget>>` of `AppState.fill_target` (Sync); the main thread
/// packs its address into an AtomicIsize and hands it to the instrumentation
/// thread; the Mutex it points at is held by the App's state map, so it outlives
/// the instrumentation thread (the mutator is joined before the app leaves
/// scope). For test instrumentation only.
type SlotAddr = Arc<std::sync::atomic::AtomicIsize>;

fn slot_addr_of(app: &tauri::App<tauri::test::MockRuntime>) -> SlotAddr {
    SlotAddr::new(std::sync::atomic::AtomicIsize::new(
        &app.state::<AppState>().fill_target as *const std::sync::Mutex<Option<FillTarget>>
            as isize,
    ))
}

/// Cancellation instrumentation thread: waits for `HOOK_PAUSED` (at which point
/// username has really landed and the injection thread is suspended), performs the
/// slot mutation given by the test, then sends `hook-go` to release the
/// injection flow.
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
// Binding gate (no target process needed: the rejection happens before any
// injection)
// ---------------------------------------------------------------------------

/// The confirmation-plane hard gate through the real command:
/// `confirmed=false` is always rejected; there is no silent injection path.
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

/// Confirmation must carry the snapshot_id captured at the time: a request
/// missing the id is rejected as a protocol error after decryption completes
/// (`FILL_TARGET_SNAPSHOT_REQUIRED`) and never falls back to "whatever target
/// happens to be in the slot right now".
#[tokio::test]
async fn command_layer_requires_snapshot_id() {
    let (app, cred_id) = app_with_password_credential().await;
    let hwnd = 0isize; // Binding rejection precedes any fingerprint verification, so a placeholder target is fine
    let slot_target = snapshot_for(hwnd, "unused", std::process::id(), "captured-A");
    {
        let state = app.state::<AppState>();
        *state.fill_target.lock().unwrap() = Some(slot_target);
    }
    let resp = desktop_fill_credential(cred_id, true, None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "missing snapshot_id must be rejected");
    assert_eq!(
        resp.error_code.as_deref(),
        Some("FILL_TARGET_SNAPSHOT_REQUIRED")
    );
}

/// The slot is already empty (the popover collapsed and cleared the slot): an
/// in-flight request carrying a stale snapshot_id is rejected by the
/// in-lock comparison after decryption completes (`FILL_TARGET_DISCARDED`) —
/// the injection never even starts.
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
// Cancellation timing (real command + real cross-process target window +
// deterministic pause-hook instrumentation)
// ---------------------------------------------------------------------------

/// **Slot clear** landing after the first field write: the command layer must
/// abort the remaining writes and honestly report `FILL_TARGET_DISCARDED`
/// (partial completion username=true / password=false), with the password box
/// left with zero residue. **This case must fail under the old implementation
/// (release the lock after the binding comparison, no field-level recheck)**:
/// the password would be written into the box and the command would report
/// success.
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

    // Instrumentation thread: at HOOK_PAUSED (username has landed, injection thread
    // suspended) clear the slot, then release
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

    // Decisive zero-residue assertion: username has been written (the instrumentation
    // point is after it) and not a single character of the password may land —
    // read back in the target process (the length-prefixed protocol preserves the
    // single-field residue)
    let (host_user, host_pwd) = host.readback();
    assert_eq!(host_user, USERNAME, "username write must have landed");
    assert_eq!(
        host_pwd, "",
        "password write must be aborted after the mid-fill slot clear"
    );
    host.quit();
}

/// **Target swap** landing after the first field write (after confirming A the
/// popover re-captured B): the command layer must abort the remaining writes
/// with `FILL_TARGET_CHANGED` and must never write the remaining fields into the
/// new target. **This case must fail under the old implementation** (the
/// password is still written and the command reports success).
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

    // Instrumentation thread: at HOOK_PAUSED swap the slot for a freshly captured
    // B (different snapshot_id)
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

    // Readback in the target process: username has landed, the password does not
    // land (the semantics of "do not inject B" show up on the single-process
    // target window as "the password box has zero residue")
    let (host_user, host_pwd) = host.readback();
    assert_eq!(host_user, USERNAME, "username write must have landed");
    assert_eq!(
        host_pwd, "",
        "password must never land after the mid-fill target swap"
    );
    host.quit();
}
