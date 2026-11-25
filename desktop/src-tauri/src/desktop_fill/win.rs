//! Win32 implementation. Every function returns Err with the original text on
//! failure — never panics, never fails silently.

use windows::core::BOOL;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HWND, LPARAM, WPARAM};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    IsWindowEnabled, SendInput, SetFocus, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
    KEYEVENTF_KEYUP, VIRTUAL_KEY, VK_CONTROL, VK_V,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, GetAncestor, GetClassNameW, GetForegroundWindow, GetWindowLongPtrW,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindow, IsWindowVisible,
    SendMessageW, SetForegroundWindow, ES_PASSWORD, ES_READONLY, GA_ROOT, GWL_STYLE, WM_GETTEXT,
    WM_GETTEXTLENGTH, WM_SETTEXT,
};

use super::FieldState;
use super::FillTarget;

/// Window class name of the classic Win32 edit control
const EDIT_CLASS: &str = "Edit";

/// Captures the current foreground window (called before the floating window
/// shows). Returns None for this process's own windows (the floating/main
/// window must not become an injection target); also returns None when the
/// fingerprint cannot be fully queried (class name / executable path) — no
/// fingerprint, no trusted injection.
pub fn capture_foreground(self_pid: u32) -> Option<FillTarget> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == self_pid {
            return None;
        }
        let title = window_text(hwnd);
        let window_class = window_class_name(hwnd.0 as isize);
        if window_class.is_empty() {
            return None;
        }
        let exe_path = process_image_path(pid);
        if exe_path.is_empty() {
            return None;
        }
        Some(FillTarget {
            hwnd: hwnd.0 as isize,
            title,
            pid,
            window_class,
            exe_path,
            snapshot_id: super::new_snapshot_id(),
        })
    }
}

/// Revalidation before injection: the three fingerprint factors + process
/// identity (see the "target trust model" in the module header).
pub fn validate_target(target: &FillTarget, self_pid: u32) -> bool {
    validate_snapshot(
        target.hwnd,
        &target.title,
        target.pid,
        &target.window_class,
        &target.exe_path,
        self_pid,
    )
}

/// Snapshot validation semantics (the expanded form of [`validate_target`],
/// pure parameters for ease of testing):
/// - hwnd is alive;
/// - owning process == expected_pid and != self_pid (this process's windows are
///   never injected);
/// - current top-level class name == snapshot class name;
/// - current process executable path == snapshot path (case-insensitive, NTFS
///   semantics);
/// - title: a non-empty snapshot is compared by prefix (login dialog titles
///   change with state, e.g. "Log on - Disconnected"); **an empty snapshot
///   requires the current title to also be empty** — closing the historical
///   `starts_with("")`-always-true vulnerability.
pub fn validate_snapshot(
    hwnd: isize,
    expected_title: &str,
    expected_pid: u32,
    expected_class: &str,
    expected_exe: &str,
    self_pid: u32,
) -> bool {
    unsafe {
        let hwnd = HWND(hwnd as *mut _);
        if !IsWindow(Some(hwnd)).as_bool() {
            return false;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid != expected_pid || pid == self_pid {
            return false;
        }
        if window_class_name(hwnd.0 as isize) != expected_class {
            return false;
        }
        let current_exe = process_image_path(pid);
        if !current_exe.eq_ignore_ascii_case(expected_exe) {
            return false;
        }
        let current = window_text(hwnd);
        if expected_title.is_empty() {
            current.is_empty()
        } else {
            current.starts_with(expected_title)
        }
    }
}

/// Per-control revalidation before writing: hwnd alive, GA_ROOT ownership of
/// the target top-level window, pid, class name Edit, visible/enabled/not
/// read-only; with `require_password`, the control must still carry the
/// ES_PASSWORD style (otherwise it must **not** carry it — to prevent field
/// roles from being swapped after hwnd reuse). Any mismatch returns Err and the
/// caller refuses to inject.
pub fn revalidate_field(
    field_hwnd: isize,
    target_hwnd: isize,
    expected_pid: u32,
    require_password: bool,
) -> Result<(), String> {
    let state = field_state(field_hwnd).ok_or_else(|| "target field window is gone".to_string())?;
    unsafe {
        let root = GetAncestor(HWND(field_hwnd as *mut _), GA_ROOT);
        if root.0 as isize != target_hwnd {
            return Err("target field no longer belongs to the captured window".to_string());
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(HWND(field_hwnd as *mut _), Some(&mut pid));
        if pid != expected_pid {
            return Err("target field changed process".to_string());
        }
    }
    if !state.eligible() {
        return Err("target field is not visible/enabled or is read-only".to_string());
    }
    if require_password && !state.is_password {
        return Err("password field lost its ES_PASSWORD style; refusing to fill".to_string());
    }
    if !require_password && state.is_password {
        return Err("username field changed to a password field; refusing to fill".to_string());
    }
    Ok(())
}

/// Enumerates the classic EDIT child controls of the target window (Z order),
/// producing the full state of each field.
pub fn enumerate_edit_fields(top_hwnd: isize) -> Vec<FieldState> {
    struct CollectCtx<'a> {
        out: &'a mut Vec<FieldState>,
    }
    unsafe extern "system" fn enum_proc(child: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam.0 as *mut CollectCtx);
        // Only accept child windows whose class name is exactly "Edit"; always
        // skip ones whose class name cannot be queried
        let mut buf = [0u16; 64];
        let n = GetClassNameW(child, &mut buf);
        if n <= 0 {
            return BOOL(1);
        }
        let class = String::from_utf16_lossy(&buf[..n as usize]);
        if class != EDIT_CLASS {
            return BOOL(1); // continue enumeration
        }
        if let Some(state) = field_state(child.0 as isize) {
            ctx.out.push(state);
        }
        BOOL(1)
    }
    unsafe {
        let mut found: Vec<FieldState> = Vec::new();
        let mut collector = CollectCtx { out: &mut found };
        let lparam = LPARAM(&mut collector as *mut CollectCtx as isize);
        let _ = EnumChildWindows(Some(HWND(top_hwnd as *mut _)), Some(enum_proc), lparam);
        found
    }
}

/// Reads the field state of a single hwnd; returns None if the hwnd is dead or
/// its class name is not Edit.
fn field_state(hwnd: isize) -> Option<FieldState> {
    unsafe {
        let handle = HWND(hwnd as *mut _);
        if !IsWindow(Some(handle)).as_bool() {
            return None;
        }
        let mut buf = [0u16; 64];
        let n = GetClassNameW(handle, &mut buf);
        if n <= 0 {
            return None;
        }
        let class = String::from_utf16_lossy(&buf[..n as usize]);
        if class != EDIT_CLASS {
            return None;
        }
        let style = GetWindowLongPtrW(handle, GWL_STYLE);
        Some(FieldState {
            hwnd,
            is_password: style & ES_PASSWORD as isize != 0,
            visible: IsWindowVisible(handle).as_bool(),
            enabled: IsWindowEnabled(handle).as_bool(),
            read_only: style & ES_READONLY as isize != 0,
        })
    }
}

/// Writes directly into an input field with WM_SETTEXT. Cross-process safe
/// (within the same desktop session) and does not depend on focus.
/// The caller ([`execute_fill`]) is responsible for running
/// [`revalidate_field`] first.
pub fn inject_settext(field_hwnd: isize, value: &str) -> Result<(), String> {
    unsafe {
        let hwnd = HWND(field_hwnd as *mut _);
        if !IsWindow(Some(hwnd)).as_bool() {
            return Err("target field window is gone".to_string());
        }
        let mut wide: Vec<u16> = value.encode_utf16().collect();
        wide.push(0);
        let res = SendMessageW(
            hwnd,
            WM_SETTEXT,
            Some(WPARAM(0)),
            Some(LPARAM(wide.as_ptr() as isize)),
        );
        // A nonzero WM_SETTEXT return value means success
        if res.0 == 0 {
            return Err(format!("WM_SETTEXT rejected (lresult={})", res.0));
        }
        Ok(())
    }
}

/// Reads back the current text of an input field (for post-injection
/// verification and testing; not part of the product's echo surface).
///
/// **Platform limitation (verified on openclaw Server 2022)**: when
/// `field_hwnd` belongs to another process and the control carries
/// `ES_PASSWORD`, cross-process `WM_GETTEXT`/`WM_GETTEXTLENGTH` always
/// return empty/0 — even when the cross-process `WM_SETTEXT` write
/// succeeded. The system hides password fields from cross-process reads, so
/// this function cannot be used to verify cross-process password injection;
/// verification must be done by the target process reading back itself (see
/// the `readback` command of fill-test-host) or by falling back to asserting
/// `EM_GETPASSWORDCHAR`/style. Same-process calls are unaffected.
pub fn read_field_text(field_hwnd: isize) -> String {
    unsafe {
        let hwnd = HWND(field_hwnd as *mut _);
        let len = SendMessageW(hwnd, WM_GETTEXTLENGTH, Some(WPARAM(0)), Some(LPARAM(0))).0;
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; (len + 1) as usize];
        let got = SendMessageW(
            hwnd,
            WM_GETTEXT,
            Some(WPARAM(buf.len())),
            Some(LPARAM(buf.as_mut_ptr() as isize)),
        )
        .0;
        if got <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..got as usize])
    }
}

/// Top-level window class name (fingerprint factor). Returns an empty string
/// on query failure.
pub fn window_class_name(hwnd: isize) -> String {
    unsafe {
        let mut buf = [0u16; 256];
        let n = GetClassNameW(HWND(hwnd as *mut _), &mut buf);
        if n <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

/// Full executable path of the process (fingerprint factor). Returns an empty
/// string if OpenProcess/the query fails (insufficient permissions or the
/// process has exited).
pub fn process_image_path(pid: u32) -> String {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        let Ok(handle) = handle else {
            return String::new();
        };
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = windows::Win32::System::Threading::QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(handle);
        if !ok {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

/// Backs up the clipboard → overwrites with the plaintext → runs the `paste`
/// closure → restores the backup.
///
/// **Confidentiality boundary (stated honestly)**: `value` is plaintext; the
/// system clipboard is globally shared within the same desktop session, and
/// any process can read it while it is resident. This function only shrinks
/// the exposure window and provides no confidentiality guarantee. A restore
/// failure is returned honestly as a warning (not silently — leaving a
/// password in the user's clipboard is an incident). Non-text clipboard
/// content before the backup (files/bitmap): the original cannot be restored,
/// so it is overwritten with an empty string at the end and explained by the
/// warning in the return value. A closure panic likewise restores the
/// clipboard first and then propagates (wrapped in catch_unwind).
///
/// Currently **not wired into the production path** (production uses
/// WM_SETTEXT only); before enabling, the boundary above must be disclosed
/// explicitly in UI/docs.
pub fn with_clipboard_paste<T>(
    value: &str,
    paste: impl FnOnce() -> T,
) -> Result<(T, Option<String>), String> {
    with_clipboard_paste_with_writer(value, paste, set_clipboard_text)
}

/// Implementation body of [`with_clipboard_paste`]; the clipboard write
/// function (shared by the plaintext overwrite and the restore) is injectable
/// — tests use it to deterministically trigger the "overwrite failed →
/// restore also failed" warning branch, without racing the real clipboard's
/// open/close timing.
pub(crate) fn with_clipboard_paste_with_writer<T>(
    value: &str,
    paste: impl FnOnce() -> T,
    set_text: impl Fn(&str) -> Result<(), String>,
) -> Result<(T, Option<String>), String> {
    unsafe {
        open_clipboard_with_retry()?;
        // Back up the current text clipboard (store it if present; non-text
        // content cannot be restored to its original — at the end it is
        // overwritten with an empty string and **warned about honestly**;
        // silently destroying the user's clipboard is not allowed)
        let had_text = IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok();
        let had_non_text = if had_text {
            false
        } else {
            clipboard_has_any_format()
        };
        let backup = if had_text {
            GetClipboardData(CF_UNICODETEXT.0 as u32)
                .ok()
                .filter(|h| !h.is_invalid())
                .and_then(|h| {
                    let gh = windows::Win32::Foundation::HGLOBAL(h.0);
                    let ptr = GlobalLock(gh);
                    if ptr.is_null() {
                        return None;
                    }
                    // CF_UNICODETEXT is NUL-terminated UTF-16. The allocation
                    // boundary is measured with GlobalSize (historical
                    // versions blindly sliced 1M characters, risking an out-of-
                    // bounds read); the NUL scan is capped at 1M characters to
                    // prevent runaway.
                    let total_chars = (GlobalSize(gh) / 2) as usize;
                    let scan_limit = total_chars.min(1 << 20);
                    let wide = std::slice::from_raw_parts(ptr as *const u16, scan_limit);
                    let mut n = 0usize;
                    while n < wide.len() && wide[n] != 0 {
                        n += 1;
                    }
                    let text = String::from_utf16_lossy(&wide[..n]);
                    let _ = GlobalUnlock(gh);
                    Some(text)
                })
        } else {
            None
        };
        let _ = EmptyClipboard();
        let closed = CloseClipboard().map_err(|e| format!("CloseClipboard failed: {e}"));
        let set = closed.and_then(|()| set_text(value));

        // catch_unwind: a closure panic must not bypass the clipboard restore
        // (the panic payload is re-raised after the restore, following
        // ResumeUnwind semantics)
        let paste_result =
            set.map(|()| std::panic::catch_unwind(std::panic::AssertUnwindSafe(paste)));

        // Restore: write the backup back (with no text backup, write an empty
        // string to clear the ciphertext)
        let mut restore_warning = set_text(backup.as_deref().unwrap_or("")).err();
        // Non-text content (files/bitmap/custom format) cannot be restored to its
        // original — after overwriting with an empty string a warning must be
        // returned (silently destroying the user's clipboard is not allowed)
        if restore_warning.is_none() && had_non_text {
            let msg = "previous non-text clipboard content was cleared and could not be restored"
                .to_string();
            tracing::warn!("clipboard paste: {msg}");
            restore_warning = Some(msg);
        }

        match paste_result {
            // set_clipboard_text failed (String): the warning on the restore
            // path must not be swallowed
            Err(e) => {
                if let Some(w) = &restore_warning {
                    tracing::warn!("clipboard restore warning swallowed by paste failure: {w}");
                }
                Err(e)
            }
            // Closure panic: the restore has completed, the warning is logged,
            // and the panic payload is re-raised as-is
            Ok(Err(payload)) => {
                if let Some(w) = &restore_warning {
                    tracing::warn!("clipboard restore warning on panic path: {w}");
                }
                std::panic::resume_unwind(payload)
            }
            Ok(Ok(v)) => match restore_warning {
                None => Ok((v, None)),
                Some(w) => Ok((v, Some(w))),
            },
        }
    }
}

/// Whether the clipboard holds any format (call while the clipboard is open).
/// Used to distinguish "empty clipboard" from "has non-text content" — the
/// latter must be warned about when overwritten and cleared.
fn clipboard_has_any_format() -> bool {
    unsafe { windows::Win32::System::DataExchange::EnumClipboardFormats(0) != 0 }
}

/// Test-only: writes clipboard text directly (bypassing the backup/restore
/// semantics, to fabricate "previous content" for the closed-loop tests of
/// [`with_clipboard_paste`]).
#[cfg(test)]
pub(crate) fn seed_clipboard(value: &str) -> Result<(), String> {
    set_clipboard_text(value)
}

/// Test-only: writes a **non-text** clipboard content (custom format), used to
/// verify [`with_clipboard_paste`]'s warning path for "non-text content was
/// cleared".
#[cfg(test)]
pub(crate) fn seed_clipboard_non_text() -> Result<(), String> {
    use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, SetClipboardData};
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    unsafe {
        open_clipboard_with_retry()?;
        let result = (|| {
            let _ = EmptyClipboard();
            let fmt = windows::Win32::System::DataExchange::RegisterClipboardFormatW(
                windows::core::PCWSTR(
                    windows::core::HSTRING::from("PersonaTestNonTextFormat").as_ptr(),
                ),
            );
            let fmt = if fmt == 0 {
                return Err("RegisterClipboardFormatW failed".to_string());
            } else {
                fmt
            };
            let h = GlobalAlloc(GMEM_MOVEABLE, 16).map_err(|e| format!("GlobalAlloc: {e}"))?;
            let ptr = GlobalLock(h);
            if ptr.is_null() {
                let _ = windows::Win32::Foundation::GlobalFree(Some(h));
                return Err("GlobalLock failed".to_string());
            }
            std::ptr::write_bytes(ptr as *mut u8, 0xAB, 16);
            let _ = GlobalUnlock(h);
            if SetClipboardData(fmt, Some(windows::Win32::Foundation::HANDLE(h.0))).is_err() {
                let _ = windows::Win32::Foundation::GlobalFree(Some(h));
                return Err("SetClipboardData(non-text) failed".to_string());
            }
            Ok(())
        })();
        let _ = CloseClipboard();
        result
    }
}

/// Opens the clipboard (with retries). OpenClipboard can fail because another
/// process briefly holds the clipboard (clipboard listeners/rdpclip scenarios
/// are common); following Win32 convention, retry a few times at short
/// intervals before giving up, so transient contention is not mistaken for a
/// hard error.
fn open_clipboard_with_retry() -> Result<(), String> {
    for attempt in 0u32..10 {
        if unsafe { OpenClipboard(None) }.is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(
            20 * u64::from(attempt + 1),
        ));
    }
    Err("cannot open clipboard".to_string())
}

/// Writes text to the clipboard (internally opens/closes; can be called
/// standalone). The Err text returned can be used directly as a "restore
/// failed" warning.
fn set_clipboard_text(value: &str) -> Result<(), String> {
    unsafe {
        open_clipboard_with_retry().map_err(|_| "cannot reopen clipboard".to_string())?;
        let result = (|| {
            let _ = EmptyClipboard();
            let mut wide: Vec<u16> = value.encode_utf16().collect();
            wide.push(0);
            let bytes = wide.len() * 2;
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(|e| format!("GlobalAlloc: {e}"))?;
            let ptr = GlobalLock(h);
            if ptr.is_null() {
                let _ = GlobalFree(Some(h));
                return Err("GlobalLock failed".to_string());
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr as *mut u16, wide.len());
            let _ = GlobalUnlock(h);
            // Once SetClipboardData succeeds, the clipboard takes ownership of h
            // (it must not be GlobalFree'd anymore)
            if SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(h.0))).is_err() {
                let _ = GlobalFree(Some(h));
                return Err("SetClipboardData failed".to_string());
            }
            Ok(())
        })();
        let _ = CloseClipboard();
        result
    }
}

/// Focuses the target input field and simulates Ctrl+V (used together with
/// [`with_clipboard_paste`]).
/// Focus transfer uses AttachThreadInput to briefly attach our input queue to
/// the target thread — under the Windows foreground lock policy, this is the
/// standard way to focus across processes.
pub fn paste_into_focused(field_hwnd: isize) -> Result<(), String> {
    unsafe {
        let hwnd = HWND(field_hwnd as *mut _);
        if !IsWindow(Some(hwnd)).as_bool() {
            return Err("target field window is gone".to_string());
        }
        let target_thread = GetWindowThreadProcessId(hwnd, None);
        let self_thread = GetCurrentThreadId();
        let attached = AttachThreadInput(self_thread, target_thread, true).as_bool();
        let _ = SetForegroundWindow(GetAncestor(hwnd, GA_ROOT));
        let _ = SetFocus(Some(hwnd));
        let sent = send_ctrl_v();
        if attached {
            let _ = AttachThreadInput(self_thread, target_thread, false);
        }
        if !sent {
            return Err("SendInput failed".to_string());
        }
        Ok(())
    }
}

fn send_ctrl_v() -> bool {
    unsafe {
        let mk = |vk: VIRTUAL_KEY, keyup: bool| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: if keyup {
                        KEYEVENTF_KEYUP
                    } else {
                        Default::default()
                    },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let seq = [
            mk(VK_CONTROL, false),
            mk(VK_V, false),
            mk(VK_V, true),
            mk(VK_CONTROL, true),
        ];
        SendInput(&seq, std::mem::size_of::<INPUT>() as i32) == seq.len() as u32
    }
}

fn window_text(hwnd: HWND) -> String {
    unsafe {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; (len + 1) as usize];
        let got = GetWindowTextW(hwnd, &mut buf);
        if got <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..got as usize])
    }
}

#[cfg(test)]
pub(crate) mod test_window {
    //! Lets tests in this module create target windows (the cross-process suite
    //! lives in the separate ../fill-test crate).
    //! The test windows are real top-level windows: what is verified is the whole
    //! "enumerate child controls → classify → per-control revalidation →
    //! WM_SETTEXT → read back" chain.
    //!
    //! Test target window: one real top-level window plus two EDIT controls
    //! (username/password). Created inside the test process (same desktop
    //! session) and destroyed when the test finishes.

    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, ES_AUTOHSCROLL, ES_PASSWORD, WINDOW_EX_STYLE, WINDOW_STYLE,
        WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    use super::*;

    fn pcw(s: &HSTRING) -> PCWSTR {
        PCWSTR(s.as_ptr())
    }

    pub struct TestTargetWindow {
        pub top: isize,
        pub username: isize,
        pub password: isize,
    }

    impl TestTargetWindow {
        /// title becomes the window title verbatim (the revalidation assertion
        /// uses the same string);
        /// `password_style` = attach the ES_PASSWORD style to the second field.
        pub fn create(title: &str, password_style: bool) -> Result<Self, String> {
            unsafe {
                let title_h = HSTRING::from(title);
                let top = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    pcw(&HSTRING::from("static")),
                    pcw(&title_h),
                    WINDOW_STYLE(WS_OVERLAPPEDWINDOW.0 | WS_VISIBLE.0),
                    0x8000_0000u32 as i32, // CW_USEDEFAULT
                    0x8000_0000u32 as i32,
                    0x8000_0000u32 as i32,
                    0x8000_0000u32 as i32,
                    None,
                    None,
                    None,
                    None,
                )
                .map_err(|e| format!("CreateWindowExW(top): {e}"))?;
                let mk_edit = |pwd: bool| -> Result<isize, String> {
                    let mut style = WS_CHILD.0 | WS_VISIBLE.0 | ES_AUTOHSCROLL as u32;
                    if pwd {
                        style |= ES_PASSWORD as u32;
                    }
                    let edit = CreateWindowExW(
                        WINDOW_EX_STYLE::default(),
                        pcw(&HSTRING::from("edit")),
                        pcw(&HSTRING::from("")),
                        WINDOW_STYLE(style),
                        8,
                        8,
                        160,
                        24,
                        Some(top),
                        None,
                        None,
                        None,
                    )
                    .map_err(|e| format!("CreateWindowExW(edit): {e}"))?;
                    Ok(edit.0 as isize)
                };
                let username = mk_edit(false)?;
                let password = mk_edit(password_style)?;
                Ok(Self {
                    top: top.0 as isize,
                    username,
                    password,
                })
            }
        }

        pub fn destroy(&self) {
            unsafe {
                let _ = DestroyWindow(HWND(self.top as *mut _));
            }
        }

        /// Assembles a trusted snapshot from the real pid + class name +
        /// executable path (test use).
        pub fn snapshot(&self, title: &str) -> super::super::FillTarget {
            let mut pid = 0u32;
            unsafe {
                GetWindowThreadProcessId(HWND(self.top as *mut _), Some(&mut pid));
            }
            super::super::FillTarget {
                hwnd: self.top,
                title: title.to_string(),
                pid,
                window_class: window_class_name(self.top),
                exe_path: process_image_path(pid),
                snapshot_id: super::super::new_snapshot_id(),
            }
        }
    }
}
