//! 桌面填充注入的**跨进程**集成测试（安全评审 codex-2026-11-05 P1 修复
//! 验收）。单测（desktop_fill.rs win_tests）在测试进程内造窗，验证的是
//! 注入链路本身；这里用独立靶进程（`fill-test-host` bin）验证真正的
//! 跨进程语义：
//!
//! 1. ES_PASSWORD 框注入成功（真目标进程）；
//! 2. 两个普通 Edit 的进程被拒绝（不再猜"第二个框"）；
//! 3. 同标题伪装进程拒绝（pid/进程指纹不换不放行）；
//! 4. HWND 销毁重建（注入前完成）拒绝 + 同进程同指纹复用限制如实断言；
//! 5. 注入请求**在途**时销毁重建（竞态钩子）整体拒绝，密文不落新窗口。
//!
//! 运行条件：Windows + `--features fill-test-host`（bin 挂 feature 门禁，
//! 正常构建不产出）。真机验收（openclaw Windows Server 2022，需**交互式
//! 桌面会话**——SSH 会话里 IsWindowVisible 恒 false、GetForegroundWindow
//! 恒 null，本套件的资格校验与目标捕获依赖真实桌面）跑本套件：
//!   cargo test --features fill-test-host --test desktop_fill_cross_process
//! （套件放在独立 test-only crate，原因见 ../Cargo.toml 头注释；运行
//! 命令 `cargo test --features fill-test-host -p persona-fill-test
//! --test desktop_fill_cross_process`。）

#![cfg(all(target_os = "windows", feature = "fill-test-host"))]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use persona_desktop::desktop_fill::{execute_fill, FillError};
use persona_desktop::desktop_fill::win::{
    enumerate_edit_fields, process_image_path, read_field_text, validate_target, window_class_name,
};
use persona_desktop::desktop_fill::FillTarget;

const HOST_EXE: &str = env!("CARGO_BIN_EXE_fill-test-host");

/// 本套件直测注入引擎层（不经过命令层的确认绑定），槽位重查恒放行；
/// 取消边界（清槽/换目标的在途中止）由 desktop_fill.rs win_tests 的
/// 可控时序用例覆盖。错误侧只关心常规拒绝（Rejected 原文透传）。
fn no_slot_check() -> Result<(), persona_desktop::desktop_fill::ConfirmBindRejection> {
    Ok(())
}

/// 解包常规拒绝的原文（历史 String 错误形态）；引擎在中途快照失效时
/// 返回 Aborted——本套件不绑定槽位，不会出现，出现即断言失败。
fn rejected_of(err: FillError) -> String {
    match err {
        FillError::Rejected(msg) => msg,
        other => panic!("expected Rejected, got {other:?}"),
    }
}

/// 靶进程句柄：Drop 时保证进程被回收（测试 panic 也不留孤儿窗口）
struct HostProcess {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout_lines: Receiver<String>,
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
            .args(["--title", title, "--password-style", if password_style { "1" } else { "0" }])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn fill-test-host");
        let stdin = child.stdin.take().expect("host stdin");
        let stdout = child.stdout.take().expect("host stdout");
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.expect("read host stdout")).is_err() {
                    break;
                }
            }
        });
        let host = Self { child, stdin, stdout_lines: rx };
        host.wait_ready();
        host
    }

    fn wait_ready(&self) {
        loop {
            match self.stdout_lines.recv_timeout(Duration::from_secs(10)) {
                Ok(line) if line.starts_with("READY") => return,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("fill-test-host not ready in 10s"),
                Err(RecvTimeoutError::Disconnected) => panic!("fill-test-host died at startup"),
            }
        }
    }

    /// 销毁并同标题重建窗口，返回新 hwnd
    fn destroy_recreate(&mut self) -> isize {
        writeln!(self.stdin, "destroy-recreate").expect("write destroy-recreate");
        self.stdin.flush().expect("flush stdin");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.stdout_lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) if line.starts_with("RECREATED") => {
                    return line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .expect("RECREATED <hwnd>");
                }
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("host did not recreate in time"),
                Err(RecvTimeoutError::Disconnected) => panic!("host died during recreate"),
            }
        }
    }

    fn quit(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }

    /// 在 username 框上挂竞态钩子：下一次 WM_SETTEXT（注入在途）完成写入
    /// 后，宿主在同一消息处理内同步销毁重建顶层窗口（RACE_TRIGGERED）。
    fn arm_race_hook(&mut self) {
        writeln!(self.stdin, "arm-race-hook").expect("write arm-race-hook");
        self.stdin.flush().expect("flush stdin");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.stdout_lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) if line.starts_with("RACE_ARMED") => return,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("host did not arm race hook in time"),
                Err(RecvTimeoutError::Disconnected) => panic!("host died while arming race hook"),
            }
        }
    }

    /// 靶进程**同进程**读回两个 Edit 的文本（长度前缀协议帧 → 解码）。
    /// 密码断言的唯一可靠通道：Windows 跨进程 WM_GETTEXT 读 ES_PASSWORD
    /// 控件恒返回空串（平台限制，见套件头注释）。帧协议保证空字段被
    /// 长度前缀如实携带（`0:`）——单字段残留不会被吞成双空；帧残缺/
    /// 前缀非法直接报协议错，绝不静默当全空。
    fn readback(&mut self) -> (String, String) {
        writeln!(self.stdin, "readback").expect("write readback");
        self.stdin.flush().expect("flush stdin");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self
                .stdout_lines
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
        let hwnd = unsafe { FindWindowW(PCWSTR::null(), PCWSTR(title_h.as_ptr())).unwrap_or_default() };
        if !hwnd.is_invalid() {
            return hwnd.0 as isize;
        }
        if Instant::now() > deadline {
            panic!("host window with title {title:?} not found in 10s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 真实指纹快照（与产品 capture_foreground 同源：类名/进程路径用同一批
/// helper 查询；snapshot_id 由测试侧现造——本套件直测注入引擎层，不经过
/// 命令层的确认绑定，引擎只按指纹说话）
fn snapshot_for(hwnd: isize, title: &str, pid: u32) -> FillTarget {
    FillTarget {
        hwnd,
        title: title.to_string(),
        pid,
        window_class: window_class_name(hwnd),
        exe_path: process_image_path(pid),
        snapshot_id: format!("xproc-test-{hwnd}"),
    }
}

/// 跨进程 EM_GETPASSWORDCHAR（掩码字符元数据，非敏感、允许跨进程读）。
/// 返回 0 = 无掩码（普通框）。
fn password_char(field_hwnd: isize) -> u32 {
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::UI::Controls::EM_GETPASSWORDCHAR;
    use windows::Win32::UI::WindowsAndMessaging::SendMessageW;
    unsafe {
        SendMessageW(
            HWND(field_hwnd as *mut _),
            EM_GETPASSWORDCHAR,
            Some(WPARAM(0)),
            Some(LPARAM(0)),
        )
        .0 as u32
    }
}

/// 真机验收核心：跨进程对独立靶进程的 ES_PASSWORD 框注入成功，普通框
/// 一个字符都不落。
#[test]
fn cross_process_password_field_injection_succeeds() {
    let mut host = HostProcess::spawn("persona xproc login", true);
    let hwnd = find_window_by_title("persona xproc login");
    let snapshot = snapshot_for(hwnd, "persona xproc login", host.pid());
    assert!(validate_target(&snapshot, std::process::id()), "fresh cross-process snapshot must validate");

    let (user_filled, pwd_filled, title) =
        execute_fill(
            &snapshot,
            "alice@example.com",
            "s3cret-Пароль⚡",
            std::process::id(),
            &no_slot_check,
        )
        .expect("cross-process fill into ES_PASSWORD field");
    assert!(user_filled, "username must be injected");
    assert!(pwd_filled, "password must be injected");
    assert_eq!(title, "persona xproc login");

    let fields = enumerate_edit_fields(hwnd);
    assert_eq!(fields.len(), 2);

    // 普通框（跨进程 WM_GETTEXT 不受限）：值必须原样落在框里
    assert!(!fields[0].is_password, "first edit must be plain");
    assert_eq!(password_char(fields[0].hwnd), 0, "plain edit must have no password char");
    assert_eq!(read_field_text(fields[0].hwnd), "alice@example.com");

    // ES_PASSWORD 框：样式与掩码字符跨进程可验证（写入本身由 execute_fill
    // 的 WM_SETTEXT 返回值担保——非零即写入成功）
    assert!(fields[1].is_password, "second edit must carry ES_PASSWORD");
    assert_ne!(
        password_char(fields[1].hwnd),
        0,
        "ES_PASSWORD edit must report a password char"
    );

    // 平台行为实录（2026-11-06 openclaw Windows Server 2022 实测观察）：
    // 跨进程 WM_GETTEXT 读 ES_PASSWORD 控件在该系统上返回空串
    //（WM_GETTEXTLENGTH 同理返回 0）——WM_SETTEXT 写入成功但读被系统隐藏。
    // **不作为通用断言**（未在其他 Windows 版本验证是否恒然），只记录本次
    // 实测观察值；注入成功的判据不依赖跨进程读密码框，见下方靶进程
    // 同进程读回断言。
    let cross_read = read_field_text(fields[1].hwnd);
    eprintln!(
        "observed: cross-process WM_GETTEXT on ES_PASSWORD read {cross_read:?} \
         after successful WM_SETTEXT (measured empty on Windows Server 2022; \
         recorded as observation, not asserted as a universal invariant)"
    );

    // 密码注入成功的决定性断言：靶进程**同进程**读回两个框——用户名与
    // 密码都必须与注入值逐字符一致（读回在宿主进程内完成，绕开平台对
    // 跨进程读密码框的隐藏，不构成对注入语义的削弱）
    let (host_user, host_pwd) = host.readback();
    assert_eq!(host_user, "alice@example.com", "same-process read-back: username");
    assert_eq!(host_pwd, "s3cret-Пароль⚡", "same-process read-back: password");
    host.quit();
}

/// 恶意形态一：目标进程只有两个普通 Edit（无 ES_PASSWORD）→ 整体拒绝，
/// 任何框都不落值（历史"第二个框"启发式的攻击面已移除）。
#[test]
fn cross_process_plain_edit_window_rejected() {
    let mut host = HostProcess::spawn("persona xproc plain trap", false);
    let hwnd = find_window_by_title("persona xproc plain trap");
    let snapshot = snapshot_for(hwnd, "persona xproc plain trap", host.pid());
    let err = rejected_of(
        execute_fill(
            &snapshot,
            "victim@example.com",
            "hunter2",
            std::process::id(),
            &no_slot_check,
        )
        .expect_err("plain-edit-only window must be rejected"),
    );
    assert!(err.contains("ES_PASSWORD"), "rejection must name ES_PASSWORD: {err}");
    let fields = enumerate_edit_fields(hwnd);
    for f in &fields {
        assert_eq!(read_field_text(f.hwnd), "", "no value may land in a plain edit: field {f:?}");
    }
    host.quit();
}

/// 恶意形态二：同标题伪装进程拒绝。靶 A 销毁后，另一个进程（同 exe、
/// 同窗口类、同标题，只有 pid/进程身份不同）顶上来——快照仍指向 A，
/// 注入必须拒绝。
#[test]
fn cross_process_spoofed_title_process_rejected() {
    let mut host_a = HostProcess::spawn("persona xproc spoof target", true);
    let hwnd_a = find_window_by_title("persona xproc spoof target");
    let snapshot_a = snapshot_for(hwnd_a, "persona xproc spoof target", host_a.pid());
    host_a.quit();

    let mut host_b = HostProcess::spawn("persona xproc spoof target", true);
    let hwnd_b = find_window_by_title("persona xproc spoof target");
    assert_ne!(host_b.pid(), snapshot_a.pid, "decoy must be a different process");

    // 快照指向已死的 A：hwnd 失效（或值复用但 pid 不符）→ 注入拒绝
    let err = rejected_of(
        execute_fill(
            &snapshot_a,
            "victim@example.com",
            "hunter2",
            std::process::id(),
            &no_slot_check,
        )
        .expect_err("fill must be rejected against the dead/spoofed snapshot"),
    );
    assert_eq!(err, "CAPTURED_TARGET_INVALID");
    assert!(!validate_target(&snapshot_a, std::process::id()));

    // B 自己的窗口作为独立目标是合法的（验证拒绝不是因为窗口形态问题）
    let snapshot_b = snapshot_for(hwnd_b, "persona xproc spoof target", host_b.pid());
    assert!(validate_target(&snapshot_b, std::process::id()));
    host_b.quit();
}

/// 恶意形态三：HWND 销毁重建（注入**前**完成）。快照后窗口被销毁重建
///（同进程同标题），随后另一进程顶上同标题——旧快照在任何一步都不得把
/// 密码写进错误目标：
/// - 进程内重建后旧快照若已失效 → 注入拒绝；
/// - **同进程同指纹 HWND 值复用限制（如实描述，不声称拒绝）**：若 hwnd
///   值被同进程同标题窗口复用（全指纹仍指向同一进程同一标题，平台层面
///   无法区分），注入会写入**同一靶进程的同标题窗口**——语义上仍在快照
///   声明的宿主进程内，非跨进程劫持；此平台固有限制由确认面（目标应用
///   名展示）与 snapshot_id 确认绑定兜底，测试如实断言两种结局且值只落
///   在宿主进程内。
///
/// 真正的**在途**竞态（注入请求跑到一半目标被销毁重建）由
/// `cross_process_inflight_destroy_rebuild_rejected` 覆盖。
#[test]
fn cross_process_destroy_recreate_race_rejected() {
    let mut host = HostProcess::spawn("persona xproc race", true);
    let hwnd_old = find_window_by_title("persona xproc race");
    let snapshot = snapshot_for(hwnd_old, "persona xproc race", host.pid());

    let hwnd_new = host.destroy_recreate();
    // 进程内重建后：旧快照要么失效（hwnd 不同/已死）→ 拒绝；
    // 要么 hwnd 值被同进程同标题窗口复用 → 填的仍是宿主自己的窗口。
    if hwnd_new != hwnd_old {
        let err = rejected_of(
            execute_fill(
                &snapshot,
                "victim@example.com",
                "hunter2",
                std::process::id(),
                &no_slot_check,
            )
            .expect_err("stale snapshot hwnd must be rejected after destroy+recreate"),
        );
        assert_eq!(err, "CAPTURED_TARGET_INVALID");
        assert!(!validate_target(&snapshot, std::process::id()));
    } else {
        // hwnd 值复用路径：注入只允许落在宿主进程（pid 校验保证），且
        // 值必须出现在宿主当前窗口的控件里
        let (_, _, _) = execute_fill(
            &snapshot,
            "race@example.com",
            "hunter2",
            std::process::id(),
            &no_slot_check,
        )
        .expect("hwnd reuse within the same process+title is semantically the same target");
        let fields = enumerate_edit_fields(hwnd_new);
        let texts: Vec<String> = fields.iter().map(|f| read_field_text(f.hwnd)).collect();
        assert!(
            texts.contains(&"race@example.com".to_string()),
            "value must land in the recreated host window: {texts:?}"
        );
    }

    // 决定性拒绝场景：宿主退出后另一个进程用同标题顶上（销毁+重建的
    // 跨进程形态）——旧快照注入必须拒绝
    host.quit();
    let mut decoy = HostProcess::spawn("persona xproc race", true);
    let err = rejected_of(
        execute_fill(
            &snapshot,
            "victim@example.com",
            "hunter2",
            std::process::id(),
            &no_slot_check,
        )
        .expect_err("snapshot of destroyed window must not fill into a decoy process"),
    );
    assert_eq!(err, "CAPTURED_TARGET_INVALID");
    assert!(!validate_target(&snapshot, std::process::id()));
    decoy.quit();
}

/// 恶意形态四（真竞态）：**注入请求在途时**目标被销毁重建。竞态钩子挂在
/// username 框上：execute_fill 的第一条 WM_SETTEXT（username 写入）完成
/// 后、密码写入前，宿主在同一消息处理内同步销毁并重建顶层窗口——测试
/// 线程此刻还阻塞在 username 的 SendMessageW 上，属于真正的在途换目标。
/// 注入必须整体拒绝（密码不得落进任何窗口）；重建出的同标题新窗口是
/// 销毁后的新目标，不是快照声明的目标——密文一个字符都不能落进去。
#[test]
fn cross_process_inflight_destroy_rebuild_rejected() {
    let mut host = HostProcess::spawn("persona xproc inflight race", true);
    let hwnd_old = find_window_by_title("persona xproc inflight race");
    let snapshot = snapshot_for(hwnd_old, "persona xproc inflight race", host.pid());
    assert!(validate_target(&snapshot, std::process::id()));

    // 挂钩：下一次 WM_SETTEXT 完成写入后，宿主就地销毁重建
    host.arm_race_hook();

    let err = rejected_of(
        execute_fill(
            &snapshot,
            "race@example.com",
            "hunter2",
            std::process::id(),
            &no_slot_check,
        )
        .expect_err("in-flight destroy+rebuild must reject the fill"),
    );
    // 拒绝点：username 写完后销毁重建，密码写入前的逐控件重验证失败
    //（或旧 hwnd 彻底失效时的 CAPTURED_TARGET_INVALID——两种拒绝都算）
    assert!(
        err == "CAPTURED_TARGET_INVALID" || err.contains("gone") || err.contains("no longer"),
        "rejection must come from target/field invalidation: {err}"
    );

    // 决定性断言：销毁后重建的同标题新窗口里，密文一个字符都不能落
    let fields_new = enumerate_edit_fields(find_window_by_title("persona xproc inflight race"));
    assert_eq!(fields_new.len(), 2, "recreated window must have both edits");
    assert_eq!(
        read_field_text(fields_new[0].hwnd),
        "",
        "recreated username field must be empty (no cross-target replay)"
    );
    assert_eq!(
        read_field_text(fields_new[1].hwnd),
        "",
        "recreated password field must be empty — the password write must never happen after the in-flight destroy"
    );
    // 宿主进程同进程读回交叉确认（绕开跨进程读限制，直接问宿主）。
    // 长度前缀协议下空字段被如实携带（`0:`）——这里的两个断空是决定性
    // 的零残留证明：任何单字段残留（哪怕 username 空 + password 非空）
    // 都会如实在帧里出现并被断言拦下，不会被旧协议的「不足 3 段按双空」
    // 吞掉。
    let (host_user, host_pwd) = host.readback();
    assert_eq!(
        host_user, "",
        "recreated window must not carry the injected username (decisive zero-residue)"
    );
    assert_eq!(
        host_pwd, "",
        "recreated window must not carry the injected password (decisive zero-residue)"
    );
    host.quit();
}
