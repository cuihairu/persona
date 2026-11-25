//! **Cross-process** integration test for desktop fill injection (acceptance
//! for the security review codex-2026-11-05 P1 fix). The unit tests
//! (desktop_fill.rs win_tests) create windows inside the test process and verify
//! the injection pipeline itself; this suite uses a separate target process (the
//! `fill-test-host` bin) to verify true cross-process semantics:
//!
//! 1. ES_PASSWORD box injection succeeds (a real target process);
//! 2. a process with two plain Edit controls is rejected (no more guessing "the
//!    second box");
//! 3. a same-title impostor process is rejected (pid/process fingerprint must
//!    not have changed to allow the fill);
//! 4. HWND destroy/recreate (completed before injection) is rejected, plus an
//!    honest assertion of the same-process same-fingerprint reuse restriction;
//! 5. destroy/recreate while the injection request is **in flight** (race hook)
//!    rejects the whole injection and no ciphertext lands in the new window.
//!
//! Run requirements: Windows + `--features fill-test-host` (the bin sits behind
//! a feature gate; normal builds produce nothing). Acceptance on real hardware
//! (openclaw Windows Server 2022, which needs an **interactive desktop
//! session** — in an SSH session IsWindowVisible is always false and
//! GetForegroundWindow always null, and this suite's eligibility checks and
//! target capture depend on a real desktop):
//!   cargo test --features fill-test-host --test desktop_fill_cross_process
//! (The suite lives in a separate test-only crate; see the ../Cargo.toml header
//! comment for why. Run command: `cargo test --features fill-test-host -p
//! persona-fill-test --test desktop_fill_cross_process`.)

#![cfg(all(target_os = "windows", feature = "fill-test-host"))]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use persona_desktop::desktop_fill::win::{
    enumerate_edit_fields, process_image_path, read_field_text, validate_target, window_class_name,
};
use persona_desktop::desktop_fill::FillTarget;
use persona_desktop::desktop_fill::{execute_fill, FillError};

const HOST_EXE: &str = env!("CARGO_BIN_EXE_fill-test-host");

/// This suite tests the injection engine layer directly (bypassing the command
/// layer's confirmation binding), so the slot recheck always passes; the
/// cancellation boundary (in-flight abort on slot clear / target swap) is
/// covered by the controlled-timing cases in desktop_fill.rs win_tests. On the
/// error side only regular rejections matter (the Rejected message passes
/// through verbatim).
fn no_slot_check() -> Result<(), persona_desktop::desktop_fill::ConfirmBindRejection> {
    Ok(())
}

/// Unwrap the raw message of a regular rejection (the historical String error
/// shape); the engine returns Aborted when the snapshot becomes invalid
/// mid-fill — this suite does not bind a slot, so that must not happen, and any
/// occurrence is an assertion failure.
fn rejected_of(err: FillError) -> String {
    match err {
        FillError::Rejected(msg) => msg,
        other => panic!("expected Rejected, got {other:?}"),
    }
}

/// Handle to the target process: Drop guarantees the process is reaped (a test
/// panic must not leave an orphan window behind)
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
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.expect("read host stdout")).is_err() {
                    break;
                }
            }
        });
        let host = Self {
            child,
            stdin,
            stdout_lines: rx,
        };
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

    /// Destroy the window and recreate it with the same title, returning the new hwnd
    fn destroy_recreate(&mut self) -> isize {
        writeln!(self.stdin, "destroy-recreate").expect("write destroy-recreate");
        self.stdin.flush().expect("flush stdin");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self
                .stdout_lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
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

    /// Arm the race hook on the username box: after the next WM_SETTEXT (injection
    /// in flight) completes its write, the host synchronously destroys and
    /// recreates the top-level window inside the same message handling
    /// (RACE_TRIGGERED).
    fn arm_race_hook(&mut self) {
        writeln!(self.stdin, "arm-race-hook").expect("write arm-race-hook");
        self.stdin.flush().expect("flush stdin");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self
                .stdout_lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) if line.starts_with("RACE_ARMED") => return,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("host did not arm race hook in time"),
                Err(RecvTimeoutError::Disconnected) => panic!("host died while arming race hook"),
            }
        }
    }

    /// Read back the text of the two Edit controls **in the target process**
    /// (length-prefixed protocol frame -> decoded). The only reliable channel for
    /// the password assertion: cross-process WM_GETTEXT on an ES_PASSWORD
    /// control always returns an empty string on Windows (a platform limitation,
    /// see the suite's header comment). The frame protocol guarantees an empty
    /// field is carried faithfully by the length prefix (`0:`) — a single-field
    /// residue is not swallowed into double empty; a truncated frame or invalid
    /// prefix reports a protocol error directly, never silently treated as
    /// all-empty.
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

/// A real fingerprint snapshot (same source as the product's
/// capture_foreground: the class name / process path are queried with the same
/// helpers; the snapshot_id is made up by the test side — this suite tests the
/// injection engine layer directly, bypassing the command layer's confirmation
/// binding, so the engine speaks only by fingerprint)
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

/// Cross-process EM_GETPASSWORDCHAR (mask-character metadata, non-sensitive and
/// allowed to be read across processes). Returns 0 = no mask (a plain box).
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

/// The core of the acceptance on real hardware: cross-process injection into
/// the ES_PASSWORD box of a separate target process succeeds, and not a single
/// character lands in the plain box.
#[test]
fn cross_process_password_field_injection_succeeds() {
    let mut host = HostProcess::spawn("persona xproc login", true);
    let hwnd = find_window_by_title("persona xproc login");
    let snapshot = snapshot_for(hwnd, "persona xproc login", host.pid());
    assert!(
        validate_target(&snapshot, std::process::id()),
        "fresh cross-process snapshot must validate"
    );

    let (user_filled, pwd_filled, title) = execute_fill(
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

    // Plain box (cross-process WM_GETTEXT is unrestricted): the value must land in the box verbatim
    assert!(!fields[0].is_password, "first edit must be plain");
    assert_eq!(
        password_char(fields[0].hwnd),
        0,
        "plain edit must have no password char"
    );
    assert_eq!(read_field_text(fields[0].hwnd), "alice@example.com");

    // ES_PASSWORD box: style and mask char are verifiable across processes (the
    // write itself is guaranteed by execute_fill's WM_SETTEXT return value —
    // non-zero means the write succeeded)
    assert!(fields[1].is_password, "second edit must carry ES_PASSWORD");
    assert_ne!(
        password_char(fields[1].hwnd),
        0,
        "ES_PASSWORD edit must report a password char"
    );

    // Platform behavior record (measured 2026-11-06 on openclaw Windows Server 2022):
    // cross-process WM_GETTEXT on an ES_PASSWORD control returned an empty
    // string on that system (WM_GETTEXTLENGTH likewise returned 0) — the
    // WM_SETTEXT write succeeded but the read was hidden by the system. **Not
    // asserted as a universal invariant** (it has not been verified whether this
    // holds on other Windows versions); only this measured observation is
    // recorded. The injection-success criterion does not depend on
    // cross-process password reading, see the target process's same-process
    // readback assertion below.
    let cross_read = read_field_text(fields[1].hwnd);
    eprintln!(
        "observed: cross-process WM_GETTEXT on ES_PASSWORD read {cross_read:?} \
         after successful WM_SETTEXT (measured empty on Windows Server 2022; \
         recorded as observation, not asserted as a universal invariant)"
    );

    // Decisive assertion of successful password injection: read back both boxes
    // **in the target process** — username and password must each match the
    // injected value character for character (the readback happens inside the
    // host process, bypassing the platform's hiding of cross-process password
    // reads, which does not weaken the injection semantics)
    let (host_user, host_pwd) = host.readback();
    assert_eq!(
        host_user, "alice@example.com",
        "same-process read-back: username"
    );
    assert_eq!(
        host_pwd, "s3cret-Пароль⚡",
        "same-process read-back: password"
    );
    host.quit();
}

/// Malicious shape one: the target process has only two plain Edits (no
/// ES_PASSWORD) -> the whole injection is rejected and no box gets any value
/// (the historical "second box" heuristic attack surface has been removed).
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
    assert!(
        err.contains("ES_PASSWORD"),
        "rejection must name ES_PASSWORD: {err}"
    );
    let fields = enumerate_edit_fields(hwnd);
    for f in &fields {
        assert_eq!(
            read_field_text(f.hwnd),
            "",
            "no value may land in a plain edit: field {f:?}"
        );
    }
    host.quit();
}

/// Malicious shape two: same-title impostor process rejection. After target A
/// is destroyed, another process (same exe, same window class, same title, only
/// the pid/process identity differs) takes its place — the snapshot still points
/// at A, and the injection must be rejected.
#[test]
fn cross_process_spoofed_title_process_rejected() {
    let mut host_a = HostProcess::spawn("persona xproc spoof target", true);
    let hwnd_a = find_window_by_title("persona xproc spoof target");
    let snapshot_a = snapshot_for(hwnd_a, "persona xproc spoof target", host_a.pid());
    host_a.quit();

    let mut host_b = HostProcess::spawn("persona xproc spoof target", true);
    let hwnd_b = find_window_by_title("persona xproc spoof target");
    assert_ne!(
        host_b.pid(),
        snapshot_a.pid,
        "decoy must be a different process"
    );

    // Snapshot points at the now-dead A: hwnd is invalid (or the value is reused
    // but the pid does not match) -> injection rejected
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

    // B's own window is a legitimate independent target (verifies the rejection is not caused by window-shape issues)
    let snapshot_b = snapshot_for(hwnd_b, "persona xproc spoof target", host_b.pid());
    assert!(validate_target(&snapshot_b, std::process::id()));
    host_b.quit();
}

/// Malicious shape three: HWND destroy/recreate (completed **before**
/// injection). After the snapshot the window is destroyed and recreated (same
/// process, same title), then another process takes over the same title — the
/// old snapshot must never write the password into the wrong target at any
/// step:
/// - if the old snapshot became invalid after the in-process recreate ->
///   injection rejected;
/// - **same-process same-fingerprint HWND value reuse limitation (described
///   honestly, not claimed to be rejected)**: if the hwnd value is reused by a
///   same-process same-title window (the full fingerprint still points to the
///   same process and title, indistinguishable at platform level), the
///   injection writes into **the same-title window of the same target process**
///   — semantically still within the host process declared by the snapshot, not
///   a cross-process hijack; this platform-inherent limitation is backstopped by
///   the confirmation plane (target app name display) and snapshot_id
///   confirmation binding. The test honestly asserts both outcomes, and the
///   value only ever lands inside the host process.
///
/// The true **in-flight** race (the injection request is half done when the
/// target is destroyed and recreated) is covered by
/// `cross_process_inflight_destroy_rebuild_rejected`.
#[test]
fn cross_process_destroy_recreate_race_rejected() {
    let mut host = HostProcess::spawn("persona xproc race", true);
    let hwnd_old = find_window_by_title("persona xproc race");
    let snapshot = snapshot_for(hwnd_old, "persona xproc race", host.pid());

    let hwnd_new = host.destroy_recreate();
    // After the in-process recreate: either the old snapshot is invalid (different
    // hwnd / already dead) -> rejected; or the hwnd value is reused by a
    // same-process same-title window -> what gets filled is still the host's own
    // window.
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
        // hwnd value-reuse path: injection is only allowed to land in the host process
        // (guaranteed by the pid check), and the value must appear in a control
        // of the host's current window
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

    // Decisive rejection scenario: after the host exits, another process takes the
    // same title (the cross-process flavor of destroy + recreate) — injection
    // with the old snapshot must be rejected
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

/// Malicious shape four (the real race): the target is destroyed and
/// recreated **while the injection request is in flight**. The race hook sits on
/// the username box: after execute_fill's first WM_SETTEXT (the username write)
/// completes and before the password write, the host synchronously destroys and
/// recreates the top-level window inside the same message handling — the test
/// thread is still blocked on the username SendMessageW at that moment, which is
/// a genuine in-flight target swap. The injection must be rejected as a whole
/// (the password must not land in any window); the recreated same-title window
/// is a new target after the destruction, not the target the snapshot declared —
/// not a single character of ciphertext may land in it.
#[test]
fn cross_process_inflight_destroy_rebuild_rejected() {
    let mut host = HostProcess::spawn("persona xproc inflight race", true);
    let hwnd_old = find_window_by_title("persona xproc inflight race");
    let snapshot = snapshot_for(hwnd_old, "persona xproc inflight race", host.pid());
    assert!(validate_target(&snapshot, std::process::id()));

    // Arm the hook: after the next WM_SETTEXT completes its write, the host destroys
    // and recreates the window in place
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
    // Rejection point: destroy/recreate after the username write, so the
    // per-control re-verification before the password write fails (or
    // CAPTURED_TARGET_INVALID when the old hwnd is entirely invalid — either
    // rejection counts)
    assert!(
        err == "CAPTURED_TARGET_INVALID" || err.contains("gone") || err.contains("no longer"),
        "rejection must come from target/field invalidation: {err}"
    );

    // Decisive assertion: not a single character of ciphertext may land in the
    // recreated same-title window
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
    // Cross-check by reading back in the host process (bypassing the cross-process
    // read restriction and asking the host directly). Under the length-prefixed
    // protocol empty fields are carried faithfully (`0:`) — so the two
    // empty-assertions here are decisive proof of zero residue: any single-field
    // residue (even empty username + non-empty password) appears faithfully in
    // the frame and is caught by the assertions, instead of being swallowed by
    // the old protocol's "fewer than 3 segments means double empty".
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
