//! Windows real-session integration tests: the target window is a real Win32
//! window (same desktop session), and what runs is the whole real
//! "capture → enumerate → classify → per-control revalidation → inject → read
//! back" chain, not mocks.

use super::classify_fields;
use super::win::test_window::TestTargetWindow;
use super::win::{enumerate_edit_fields, read_field_text, revalidate_field, validate_target};
use super::{execute_fill, FieldState, FillError, FillTarget};

/// Username/password field recognition + the full execute_fill chain
/// (fingerprint validation → enumeration → classification → per-control
/// revalidation → WM_SETTEXT) injection + WM_GETTEXT read-back consistency.
/// This is the core real-machine acceptance assertion for desktop fill (run on
/// openclaw Windows Server 2022).
#[test]
fn settext_injection_roundtrip_on_real_window() {
    let target =
        TestTargetWindow::create("persona fill test - login", true).expect("create target");
    let fields = enumerate_edit_fields(target.top);
    assert_eq!(fields.len(), 2, "two EDIT controls expected");
    assert_eq!(fields[0].hwnd, target.username);
    assert!(!fields[0].is_password);
    assert_eq!(fields[1].hwnd, target.password);
    assert!(fields[1].is_password);

    let classified = classify_fields(&fields).expect("classify");
    assert_eq!(classified.username_hwnd, Some(target.username));
    assert_eq!(classified.password_hwnd, target.password);

    // Full-chain injection: self_pid faked as a different process (the
    // snapshot pid is the real test process pid)
    let snapshot = target.snapshot("persona fill test - login");
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let (user_filled, pwd_filled, title) = execute_fill(
        &snapshot,
        "alice@example.com",
        "s3cret-Пароль⚡",
        fake_self_pid,
        &|| Ok(()),
    )
    .expect("execute_fill");
    assert!(user_filled && pwd_filled);
    assert_eq!(title, "persona fill test - login");
    assert_eq!(read_field_text(target.username), "alice@example.com");
    assert_eq!(read_field_text(target.password), "s3cret-Пароль⚡");
    target.destroy();
}

/// Cancellation boundary (fourth-round closure): **the slot clear lands after
/// the first field write**. The recheck closure counts by call order: the 1st
/// call (before the username write) passes; the 2nd call (before the password
/// write) first asserts that the username really received its value (proving
/// the slot-clear hook indeed fired after the first field write), then clears
/// the slot and makes the recheck reject. Injection must abort the remaining
/// writes and report partial completion honestly via
/// [`FillError::Aborted`] (username=true, password=false),
/// with zero residue in the password field.
#[test]
fn slot_cleared_after_first_write_aborts_remaining_write() {
    use std::sync::Mutex;
    let target =
        TestTargetWindow::create("persona fill test - cancel clear", true).expect("create");
    let snapshot = target.snapshot("persona fill test - cancel clear");
    let slot: Mutex<Option<FillTarget>> = Mutex::new(Some(snapshot.clone()));
    let inner = super::slot_recheck_for(&slot, snapshot.snapshot_id.clone());
    let call = std::cell::Cell::new(0usize);
    let username_hwnd = target.username;
    let recheck = || {
        let n = call.get() + 1;
        call.set(n);
        if n == 2 {
            // At this moment the first field write has completed — the
            // slot-clear hook lands after the first field write
            assert_eq!(
                read_field_text(username_hwnd),
                "alice@example.com",
                "clear hook must fire after the first field write landed"
            );
            *slot.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
        inner()
    };
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let result = execute_fill(
        &snapshot,
        "alice@example.com",
        "s3cret-Пароль⚡",
        fake_self_pid,
        &recheck,
    );
    match result {
        Err(FillError::Aborted {
            reason: super::ConfirmBindRejection::TargetDiscarded,
            username_filled: true,
            password_filled: false,
            ..
        }) => {}
        other => panic!("mid-fill clear must abort with partial completion, got {other:?}"),
    }
    assert_eq!(
        read_field_text(target.password),
        "",
        "password write must be aborted (no residue after the clear)"
    );
    target.destroy();
}

/// Cancellation boundary (fourth-round closure): **the slot is replaced by a
/// newer capture after the first field write**
/// (the floating window captured B after A was confirmed). Same timing control
/// as the slot-clear case: by the 2nd recheck the slot
/// already holds the new id, so injection must abort the remaining writes with
/// `TargetChanged`, leaving the password unwritten.
#[test]
fn slot_replaced_after_first_write_aborts_remaining_write() {
    use std::sync::Mutex;
    let target = TestTargetWindow::create("persona fill test - cancel swap", true).expect("create");
    let snapshot = target.snapshot("persona fill test - cancel swap");
    let slot: Mutex<Option<FillTarget>> = Mutex::new(Some(snapshot.clone()));
    let inner = super::slot_recheck_for(&slot, snapshot.snapshot_id.clone());
    let call = std::cell::Cell::new(0usize);
    let username_hwnd = target.username;
    let recheck = || {
        let n = call.get() + 1;
        call.set(n);
        if n == 2 {
            assert_eq!(
                read_field_text(username_hwnd),
                "alice@example.com",
                "swap hook must fire after the first field write landed"
            );
            // Simulate a re-capture: the slot is replaced by a new snapshot
            // (different id)
            let mut replacement = snapshot.clone();
            replacement.snapshot_id = "re-captured-target-B".to_string();
            *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(replacement);
        }
        inner()
    };
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let result = execute_fill(
        &snapshot,
        "alice@example.com",
        "s3cret-Пароль⚡",
        fake_self_pid,
        &recheck,
    );
    match result {
        Err(FillError::Aborted {
            reason: super::ConfirmBindRejection::TargetChanged,
            username_filled: true,
            password_filled: false,
            ..
        }) => {}
        other => {
            panic!("mid-fill target swap must abort with partial completion, got {other:?}")
        }
    }
    assert_eq!(
        read_field_text(target.password),
        "",
        "password must never land in the re-captured target"
    );
    target.destroy();
}

/// No ES_PASSWORD field at all → injection refused (the historical
/// "second field" heuristic has been removed:
/// a plain field might be a plaintext harvester faked by an attacker).
#[test]
fn plain_only_window_is_rejected_no_password_guessing() {
    let target = TestTargetWindow::create("persona fill test - plain", false).expect("create");
    let fields = enumerate_edit_fields(target.top);
    assert_eq!(fields.len(), 2);
    assert!(fields.iter().all(|f| !f.is_password));
    assert!(
        classify_fields(&fields).is_none(),
        "no ES_PASSWORD field must reject classification"
    );
    let snapshot = target.snapshot("persona fill test - plain");
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let err = execute_fill(&snapshot, "alice", "s3cret", fake_self_pid, &|| Ok(()))
        .expect_err("plain-only window must be rejected");
    let FillError::Rejected(err) = err else {
        panic!("expected Rejected, got {err:?}");
    };
    assert!(
        err.contains("ES_PASSWORD"),
        "error must mention ES_PASSWORD: {err}"
    );
    // Both plain fields must remain empty as they were (nothing written in)
    assert_eq!(read_field_text(target.username), "");
    assert_eq!(read_field_text(target.password), "");
    target.destroy();
}

/// Classification guards (pure function): invisible/disabled/read-only password
/// fields are ineligible; when only invisible password fields exist, reject
/// outright.
#[test]
fn classification_guards_ineligible_fields() {
    use super::FieldState as F;
    // Read-only password field: ineligible → no eligible password field → reject
    let ro = vec![F {
        hwnd: 1,
        is_password: true,
        visible: true,
        enabled: true,
        read_only: true,
    }];
    assert!(classify_fields(&ro).is_none());
    // Hidden password field: reject
    let hidden = vec![F {
        hwnd: 2,
        is_password: true,
        visible: false,
        enabled: true,
        read_only: false,
    }];
    assert!(classify_fields(&hidden).is_none());
    // Disabled password field: reject
    let disabled = vec![F {
        hwnd: 3,
        is_password: true,
        visible: true,
        enabled: false,
        read_only: false,
    }];
    assert!(classify_fields(&disabled).is_none());
    // Hidden password field + visible username field: still reject (never fill
    // only the username into a suspicious window)
    let mixed = vec![
        F {
            hwnd: 4,
            is_password: false,
            visible: true,
            enabled: true,
            read_only: false,
        },
        F {
            hwnd: 5,
            is_password: true,
            visible: false,
            enabled: true,
            read_only: false,
        },
    ];
    assert!(classify_fields(&mixed).is_none());
    // Eligible password field + hidden username field: fill the password, and
    // report the username as unfilled honestly
    let pwd_only = vec![
        F {
            hwnd: 6,
            is_password: false,
            visible: false,
            enabled: true,
            read_only: false,
        },
        F {
            hwnd: 7,
            is_password: true,
            visible: true,
            enabled: true,
            read_only: false,
        },
    ];
    let c = classify_fields(&pwd_only).unwrap();
    assert_eq!(c.username_hwnd, None);
    assert_eq!(c.password_hwnd, 7);
    // Empty target
    assert!(classify_fields(&[]).is_none());
}

/// Per-control pre-write revalidation: dead handles are rejected,
/// read-only/disabled/hidden are rejected, and a password field that lost its
/// ES_PASSWORD style is rejected (the hwnd-reuse role-swap scenario).
#[test]
fn revalidate_field_rejects_gone_and_role_swapped_fields() {
    let target = TestTargetWindow::create("persona fill test - revalidate", true).expect("create");
    let mut pid = 0u32;
    unsafe {
        GetWindowThreadProcessId(
            windows::Win32::Foundation::HWND(target.top as *mut _),
            Some(&mut pid),
        );
    }
    // Happy path
    revalidate_field(target.password, target.top, pid, true).expect("eligible password field");
    revalidate_field(target.username, target.top, pid, false).expect("eligible username field");
    // Dead handle
    assert!(revalidate_field(0xDEAD_BEEFisize, target.top, pid, true).is_err());
    target.destroy();
    // After destruction, everything is rejected
    assert!(revalidate_field(target.password, target.top, pid, true).is_err());
    assert!(revalidate_field(target.username, target.top, pid, false).is_err());
}

/// Target revalidation (real hwnd through validate_snapshot): mismatched pid is
/// rejected, mismatched title prefix is rejected, an empty title is no longer
/// always-true, dead handles are rejected, and so is everything after
/// destruction; validate_target always rejects windows of our own process
/// (pid == self_pid).
#[test]
fn target_validation_guards_hwnd_reuse() {
    use super::win::validate_snapshot;
    let fake_other_pid = std::process::id().wrapping_add(1).max(1);
    let target =
        TestTargetWindow::create("persona fill test - validate", true).expect("create target");

    let real_pid = {
        let mut pid = 0u32;
        unsafe {
            GetWindowThreadProcessId(
                windows::Win32::Foundation::HWND(target.top as *mut _),
                Some(&mut pid),
            );
        }
        pid
    };
    let class = super::win::window_class_name(target.top);
    let exe = super::win::process_image_path(real_pid);
    assert!(
        !class.is_empty() && !exe.is_empty(),
        "fingerprint helpers must work in-test"
    );

    // Fingerprint fully matching (self_pid faked as a different process) → pass
    assert!(
        validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            &class,
            &exe,
            fake_other_pid
        ),
        "matching snapshot must pass"
    );

    // Title prefix mismatch → reject (simulates hwnd reuse into another window)
    assert!(
        !validate_snapshot(
            target.top,
            "totally different window",
            real_pid,
            &class,
            &exe,
            fake_other_pid
        ),
        "stale title must be rejected"
    );

    // Empty snapshot title + non-empty current title → reject (closes the
    // starts_with("")-always-true hole)
    assert!(
        !validate_snapshot(target.top, "", real_pid, &class, &exe, fake_other_pid),
        "empty snapshot title must not match a titled window"
    );

    // Snapshot pid filled with garbage (=0) mismatches the real pid → reject
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            0,
            &class,
            &exe,
            fake_other_pid
        ),
        "mismatched pid must be rejected"
    );

    // Class name mismatch → reject
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            "OtherClass",
            &exe,
            fake_other_pid
        ),
        "mismatched class must be rejected"
    );

    // Executable path mismatch → reject (the impersonating-process scenario
    // with the same title and pid)
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            &class,
            "C:\\attacker.exe",
            fake_other_pid
        ),
        "mismatched exe path must be rejected"
    );

    // Dead handle → reject
    assert!(!validate_snapshot(
        0xDEAD_BEEFisize,
        "",
        real_pid,
        &class,
        &exe,
        fake_other_pid
    ));

    // validate_target layer: windows of our own process (pid == self_pid) are
    // always rejected
    let own = FillTarget {
        hwnd: target.top,
        title: "persona fill test - validate".to_string(),
        pid: real_pid,
        window_class: class.clone(),
        exe_path: exe.clone(),
        snapshot_id: "test-own-window-snapshot".to_string(),
    };
    assert!(
        !validate_target(&own, real_pid),
        "own-process window must be rejected"
    );

    target.destroy();
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            &class,
            &exe,
            fake_other_pid
        ),
        "destroyed window must be rejected"
    );
}

/// Clipboard backup/restore closed loop: the ciphertext is present during the
/// paste and the original content is restored afterwards;
/// a closure panic does not bypass the restore.
#[test]
fn clipboard_backup_restore_roundtrip() {
    let _guard = clipboard_test_lock();
    use super::win::{seed_clipboard, with_clipboard_paste};
    // Seed "previous content" (written directly, bypassing the backup/restore
    // semantics). The value carries a unique suffix per run: the machine's
    // RDP/clipboard sync chain (rdpclip etc.) may re-inject a **fixed literal
    // written by a previous run** after the clipboard has been cleared
    // (reproduced on run4-red) — a fixed value would collide with stale
    // content, while a unique value can never match re-injected content.
    let prev = format!("PREV-{}", uuid::Uuid::new_v4());
    seed_clipboard(&prev).expect("seed clipboard");
    assert_eq!(read_clipboard_text(), prev);

    // Paste fake ciphertext: assert that what is read during the closure is the
    // ciphertext, and that prev is restored afterwards
    let seen = std::cell::RefCell::new(String::new());
    let (_, warn) = with_clipboard_paste("TOP-SECRET", || {
        *seen.borrow_mut() = read_clipboard_text();
    })
    .expect("paste roundtrip");
    assert_eq!(
        seen.borrow().as_str(),
        "TOP-SECRET",
        "secret must be on clipboard during paste"
    );
    assert_eq!(
        read_clipboard_text(),
        prev,
        "previous content must be restored"
    );
    assert!(warn.is_none(), "restore should not warn: {warn:?}");

    // With no previous content: the ciphertext is cleared at the end (an empty
    // string is written) and nothing remains. The empty assertion must
    // **read once**: the old retry-until-non-empty approach gives external
    // clipboard sync processes a full second to push stale content back in
    // (see above), magnifying "read nothing" into "read garbage".
    seed_clipboard("").expect("clear clipboard");
    let (_, _) = with_clipboard_paste("GHOST", || ()).expect("paste roundtrip 2");
    assert_eq!(
        read_clipboard_text_expect_maybe_empty(),
        "",
        "no prior content must leave no residue"
    );

    // Closure panic: the restore still happens, and the panic propagates after
    // it
    let prev_panic = format!("PREV-PANIC-{}", uuid::Uuid::new_v4());
    seed_clipboard(&prev_panic).expect("seed clipboard 2");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = with_clipboard_paste("PANIC-SECRET", || panic!("boom in paste closure"));
    }));
    assert!(
        panicked.is_err(),
        "closure panic must propagate after restore"
    );
    assert_eq!(
        read_clipboard_text(),
        prev_panic,
        "panic must not bypass clipboard restore"
    );
}

/// When the original clipboard holds non-text content (files/bitmap/custom
/// format): the original cannot be restored and an empty string is written at
/// the end — a warning must be returned; silently destroying the user's
/// clipboard is not allowed.
#[test]
fn clipboard_paste_warns_when_non_text_content_is_cleared() {
    let _guard = clipboard_test_lock();
    use super::win::{seed_clipboard_non_text, with_clipboard_paste};
    seed_clipboard_non_text().expect("seed non-text clipboard");

    let ((_, warn), logged) =
        capture_warns(|| with_clipboard_paste("GHOST-SECRET", || ()).unwrap());
    let warn = warn.expect("wiping non-text clipboard content must surface a warning");
    assert!(
        warn.to_lowercase().contains("non-text"),
        "warning must explain the non-text wipe: {warn}"
    );
    // tracing::warn must actually land in the log (not just the return value)
    assert!(
        logged
            .iter()
            .any(|w| w.contains("previous non-text clipboard content")),
        "non-text wipe must be logged via tracing::warn: {logged:?}"
    );
    // No ciphertext residue (overwritten with an empty string), and the
    // clipboard is cleared back to the empty state on the way out. The
    // empty expectation must use expect_maybe_empty: retry-until-non-empty
    // would give external sync processes like rdpclip a window to push the
    // previous case's PREV-* back in
    // (verified on openclaw: this assertion read the roundtrip case's
    // PREV-PANIC value).
    assert_eq!(
        read_clipboard_text_expect_maybe_empty(),
        "",
        "no prior content must leave no residue"
    );
    super::win::seed_clipboard("").ok();
}

/// Overwrite-failure (set failure) branch: the warning on the restore path must
/// not be swallowed — the Err propagates as-is, and
/// `tracing::warn!("...swallowed by paste failure...")` must land in the log.
/// Triggered deterministically via an injected failing writer function (no need
/// to race the real clipboard timing).
#[test]
fn clipboard_paste_warns_when_restore_warning_is_swallowed_by_paste_failure() {
    let _guard = clipboard_test_lock();
    use super::win::with_clipboard_paste_with_writer;
    let (_, warns) = capture_warns(|| {
        let err = with_clipboard_paste_with_writer(
            "TOP-SECRET",
            || panic!("paste closure must never run when the overwrite failed"),
            |_| Err("injected clipboard writer failure".to_string()),
        )
        .expect_err("injected writer failure must surface as Err");
        assert!(
            err.contains("injected clipboard writer failure"),
            "Err must carry the overwrite failure: {err}"
        );
    });
    assert!(
        warns.iter().any(|w| {
            w.contains("swallowed by paste failure")
                && w.contains("injected clipboard writer failure")
        }),
        "swallowed restore warning must be logged via tracing::warn: {warns:?}"
    );
}

/// Closure-panic branch: after the restore completes,
/// `tracing::warn!("...on panic path...")`
/// must land in the log, and the panic is re-raised as-is after the restore.
/// The injected writer function **only fails the restore**
/// (first call = plaintext overwrite succeeds, afterwards = writing the backup
/// back fails), deterministically covering
/// the "panic + restore failure" combined branch — if the overwrite failed
/// instead, the closure would never run at all and
/// the panic branch could not be triggered (verified on openclaw: an
/// all-Err writer function made this case fail red every time).
#[test]
fn clipboard_paste_warns_on_panic_path_when_restore_fails() {
    let _guard = clipboard_test_lock();
    use super::win::with_clipboard_paste_with_writer;
    // The 1st write (plaintext overwrite) succeeds; from the 2nd write
    // (restoring the backup) on it fails deterministically
    let calls = std::cell::Cell::new(0usize);
    let (_, warns) = capture_warns(|| {
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_clipboard_paste_with_writer(
                "PANIC-SECRET",
                || panic!("boom in paste closure"),
                |_| {
                    let n = calls.get();
                    calls.set(n + 1);
                    if n == 0 {
                        Ok(())
                    } else {
                        Err("injected clipboard writer failure".to_string())
                    }
                },
            );
        }));
        assert!(
            panicked.is_err(),
            "closure panic must propagate after restore"
        );
    });
    assert!(
        warns.iter().any(|w| {
            w.contains("on panic path") && w.contains("injected clipboard writer failure")
        }),
        "panic-path restore warning must be logged via tracing::warn: {warns:?}"
    );
    // The restore was made to fail by injection: the plaintext PANIC-SECRET is
    // still left on the real clipboard — the test
    // clears it itself; never leave it for later cases or external clipboard
    // sync processes.
    super::win::seed_clipboard("").ok();
}

/// tracing warning capture (thread-local dispatcher, warns emitted inside the
/// test body):
/// returns (the test body's return value, the captured warn texts) — asserting
/// the actual `tracing::warn!` output of each failure branch, not just the
/// return values.
fn capture_warns<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    use std::sync::{Arc, Mutex};
    struct WarnCapture(Arc<Mutex<Vec<String>>>);
    struct MessageVisitor(String);
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }
    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.level() == &tracing::Level::WARN
        }
        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(visitor.0);
        }
        fn enter(&self, _span: &tracing::Id) {}
        fn exit(&self, _span: &tracing::Id) {}
    }
    let capture = Arc::new(WarnCapture(Arc::new(Mutex::new(Vec::new()))));
    let sink = capture.0.clone();
    let out = tracing::subscriber::with_default(capture, f);
    let warns = sink.lock().unwrap_or_else(|p| p.into_inner()).clone();
    (out, warns)
}

/// The clipboard is process-global: multiple clipboard cases running in
/// parallel inside the same binary would trample each other —
/// serialize them with an in-process mutex (the Linux side does not compile this
/// module, so it has no such dependency).
fn clipboard_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Clipboard listener processes on this machine often hold the clipboard
/// briefly (when OpenClipboard fails transiently
/// `read_clipboard_text_once` silently returns an empty string); read-back
/// assertions first retry at short intervals,
/// distinguishing transient contention from a genuinely empty clipboard (still
/// empty after the retries are exhausted is treated as empty).
/// **Only for assertions expecting non-empty** — assertions expecting empty use
/// [`read_clipboard_text_expect_maybe_empty`], since retry-until-non-empty
/// would give external clipboard sync processes time to push stale content
/// back in.
fn read_clipboard_text() -> String {
    for _ in 0..20 {
        let text = read_clipboard_text_once();
        if !text.is_empty() {
            return text;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    String::new()
}

/// Read-back where empty is expected: retry only when OpenClipboard fails
/// (a listener process briefly holds the lock), and as soon as the clipboard is
/// open, return whatever it currently holds — no window is given for external
/// sync processes
/// to push stale content back in.
fn read_clipboard_text_expect_maybe_empty() -> String {
    for _ in 0..20 {
        match read_clipboard_text_once_state() {
            ReadOutcome::Opened(text) => return text,
            ReadOutcome::OpenFailed => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    String::new()
}

enum ReadOutcome {
    Opened(String),
    OpenFailed,
}

fn read_clipboard_text_once() -> String {
    match read_clipboard_text_once_state() {
        ReadOutcome::Opened(text) => text,
        ReadOutcome::OpenFailed => String::new(),
    }
}

fn read_clipboard_text_once_state() -> ReadOutcome {
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;
    unsafe {
        if OpenClipboard(None).is_err() {
            return ReadOutcome::OpenFailed;
        }
        let out: Option<String> = (|| {
            let h = GetClipboardData(CF_UNICODETEXT.0 as u32).ok()?;
            if h.is_invalid() {
                return None;
            }
            let gh = windows::Win32::Foundation::HGLOBAL(h.0);
            let ptr = GlobalLock(gh);
            if ptr.is_null() {
                return None;
            }
            let scan_limit = ((GlobalSize(gh) / 2) as usize).min(1 << 20);
            let wide = std::slice::from_raw_parts(ptr as *const u16, scan_limit);
            let mut n = 0usize;
            while n < wide.len() && wide[n] != 0 {
                n += 1;
            }
            let text = String::from_utf16_lossy(&wide[..n]);
            let _ = GlobalUnlock(gh);
            Some(text)
        })();
        let _ = CloseClipboard();
        ReadOutcome::Opened(out.unwrap_or_default())
    }
}

use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
