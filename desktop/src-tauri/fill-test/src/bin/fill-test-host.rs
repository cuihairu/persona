//! fill-test-host: the cross-process target process for the desktop fill
//! injection tests (the acceptance tool for the security review
//! codex-2026-11-05 P1 fix, **test builds only** — the bin sits behind the
//! `fill-test-host` feature, so a normal `cargo build`/`tauri build` does not
//! produce this binary).
//!
//! Responsibilities: create a real top-level window plus two EDIT child
//! controls in its own process (the first a plain box, the second with
//! ES_PASSWORD applied according to `--password-style`), then run a message
//! loop waiting for commands. The integration test
//! `tests/desktop_fill_cross_process.rs` uses it to verify: cross-process
//! injection success/rejection, same-title impostor process rejection, HWND
//! destroy/recreate race rejection — these are true cross-process semantics
//! that creating windows inside the test process cannot cover.
//!
//! stdin commands (one per line):
//! - `readback`: read back the current text of the two Edit controls **in this
//!   process** (WM_GETTEXTLENGTH + WM_GETTEXT) and reply with a length-prefixed
//!   `READBACK <unit-count>:<hex> <unit-count>:<hex>` frame (UTF-16 hex, 4
//!   lowercase digits per unit, empty field = `0:`; the length prefix preserves
//!   empty-field information, see fill-test/lib.rs). Why it exists: a Windows
//!   platform limitation — cross-process WM_GETTEXT on an ES_PASSWORD control
//!   always returns an empty string (measured 2026-11-06 on openclaw Server 2022),
//!   so the injected-password assertion can only be read back by the host
//!   process itself;
//! - `destroy-recreate`: destroy the current top-level window and recreate it
//!   with the **same title and style** (the HWND reuse/recreate race case),
//!   printing `RECREATED <hwnd>` to stdout when done;
//! - `arm-race-hook`: arm a race hook on the username box (classic subclassing):
//!   the next time `WM_SETTEXT` arrives (i.e. the injection request is
//!   **in flight**), let the original procedure write first, then
//!   **synchronously destroy and recreate** the top-level window inside the same
//!   message handling — the target swaps out from under the half-finished
//!   injection request, replying `RACE_ARMED` / `RACE_TRIGGERED <hwnd>`;
//! - `arm-pause-hook`: arm a **pause hook** on the username box (classic
//!   subclassing): after the next `WM_SETTEXT` completes its write through the
//!   original procedure, the host **stops inside the same message handling** (the
//!   injection thread is still blocked on that cross-process SendMessageW),
//!   replying `PAUSE_ARMED` / `HOOK_PAUSED`; it is released only on the stdin
//!   command `hook-go`, replying `HOOK_RESUMED`. This gives the command-layer
//!   cancellation timing suite (tests/desktop_fill_command_cancel.rs) a
//!   **deterministic** instrumentation point after the first field write
//!   completes: the test side mutates the slot between `HOOK_PAUSED` and
//!   `hook-go`, so the timing does not depend on lucky polling;
//! - `quit`: clean exit (destroy the window, EXIT 0).
//!
//! Non-Windows platforms: the entry point exits 0 directly (takes part in no
//! tests).

#[cfg(not(target_os = "windows"))]
fn main() {
    // Linux/macOS CI: this bin is only built under an explicit feature and has no behavior at all
    std::process::exit(0);
}

#[cfg(target_os = "windows")]
fn main() {
    use std::io::{BufRead, Write};
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::sync::OnceLock;

    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CallWindowProcW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        GetMessageW, PostMessageW, PostQuitMessage, RegisterClassW, SendMessageW,
        SetWindowLongPtrW, ES_AUTOHSCROLL, ES_PASSWORD, GWLP_WNDPROC, MSG, WINDOW_EX_STYLE,
        WINDOW_STYLE, WM_APP, WM_DESTROY, WM_GETTEXT, WM_GETTEXTLENGTH, WM_SETTEXT, WNDCLASSW,
        WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    static TITLE: OnceLock<String> = OnceLock::new();
    static PASSWORD_STYLE: AtomicIsize = AtomicIsize::new(0);
    static TOP_HWND: AtomicIsize = AtomicIsize::new(0);
    static USERNAME_HWND: AtomicIsize = AtomicIsize::new(0);
    static PASSWORD_HWND: AtomicIsize = AtomicIsize::new(0);
    /// PostQuitMessage is only posted from WM_DESTROY once the quit command has
    /// been set — destroy-recreate also triggers WM_DESTROY, but in that case
    /// the message loop must stay alive
    static QUITTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    /// Custom message: destroy and recreate the top-level window from the
    /// wndproc thread (DestroyWindow must be called from the creating thread;
    /// the stdin thread can only post)
    const WM_DESTROY_RECREATE: u32 = WM_APP + 1;
    /// Custom message: arm the race hook on the username box (must likewise be
    /// done on the creating thread)
    const WM_ARM_RACE_HOOK: u32 = WM_APP + 2;
    /// Custom message: arm the pause hook on the username box (must likewise be
    /// done on the creating thread)
    const WM_ARM_PAUSE_HOOK: u32 = WM_APP + 3;
    /// Original wndproc of the username box (procedure pointer before the race
    /// hook subclasses it; 0 = not hooked)
    static ORIG_USERNAME_PROC: AtomicIsize = AtomicIsize::new(0);
    /// Race hook has fired (destroy/recreate after the first WM_SETTEXT) —
    /// fires only once
    static RACE_TRIGGERED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// Original wndproc of the username box (procedure pointer before the pause
    /// hook subclasses it; 0 = not hooked. Stored separately from the race
    /// hook: each hook has its own host instance and they are never armed at
    /// the same time)
    static ORIG_PAUSE_PROC: AtomicIsize = AtomicIsize::new(0);
    /// Pause hook has fired (stopped after the first WM_SETTEXT) — fires only
    /// once
    static PAUSE_TRIGGERED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// Release switch for the pause hook (set by the stdin `hook-go`; it also
    /// releases itself after a 60s fallback timeout, so a dead test process
    /// does not leave a deadlocked window)
    static PAUSE_GO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn pcw(s: &HSTRING) -> PCWSTR {
        PCWSTR(s.as_ptr())
    }

    /// Read back an Edit's text in this process and encode it as UTF-16 hex (4
    /// lowercase digits per unit, independent of pipe/console encoding). Returns
    /// an empty string when hwnd is 0 or the text cannot be read.
    unsafe fn control_text_hex(hwnd_value: isize) -> String {
        if hwnd_value == 0 {
            return String::new();
        }
        let hwnd = HWND(hwnd_value as *mut _);
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
        buf[..got as usize]
            .iter()
            .map(|u| format!("{u:04x}"))
            .collect()
    }

    /// Read back the two Edit controls' text in this process and reply with a
    /// READBACK frame using the **length-prefixed protocol**
    /// (`READBACK <unit-count>:<hex> <unit-count>:<hex>`, empty field = `0:`).
    /// The length prefix preserves empty-field information: under the old
    /// space-separated protocol a "empty username + non-empty password" frame had
    /// only 2 segments and was misjudged as double empty by the parser, so a
    /// single-field residue could not be detected.
    unsafe fn readback_frame() -> String {
        let user = control_text_hex(USERNAME_HWND.load(Ordering::Acquire));
        let pwd = control_text_hex(PASSWORD_HWND.load(Ordering::Acquire));
        persona_fill_test::encode_readback_frame(&user, &pwd)
    }

    unsafe fn create_target_window() -> isize {
        let hinstance = GetModuleHandleW(None).expect("GetModuleHandleW");
        let title_h = HSTRING::from(
            TITLE
                .get()
                .map(|s| s.as_str())
                .unwrap_or("persona fill test host"),
        );
        let top = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            pcw(&HSTRING::from("PersonaFillTestHostClass")),
            pcw(&title_h),
            WINDOW_STYLE(WS_OVERLAPPEDWINDOW.0 | WS_VISIBLE.0),
            0x8000_0000u32 as i32,
            0x8000_0000u32 as i32,
            0x8000_0000u32 as i32,
            0x8000_0000u32 as i32,
            None,
            None,
            Some(windows::Win32::Foundation::HINSTANCE(hinstance.0)),
            None,
        )
        .expect("CreateWindowExW(top)");
        let mk_edit = |pwd: bool| -> HWND {
            let mut style = WS_CHILD.0 | WS_VISIBLE.0 | ES_AUTOHSCROLL as u32;
            if pwd {
                style |= ES_PASSWORD as u32;
            }
            CreateWindowExW(
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
            .expect("CreateWindowExW(edit)")
        };
        let username = mk_edit(false);
        let password = mk_edit(PASSWORD_STYLE.load(Ordering::Relaxed) != 0);
        TOP_HWND.store(top.0 as isize, Ordering::Release);
        USERNAME_HWND.store(username.0 as isize, Ordering::Release);
        PASSWORD_HWND.store(password.0 as isize, Ordering::Release);
        top.0 as isize
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_DESTROY {
            // Only the quit flow exits the message loop (destroy-recreate's WM_DESTROY
            // must keep pumping messages, otherwise the host hangs and the test
            // process's wait() blocks forever)
            if QUITTING.load(Ordering::Acquire) {
                PostQuitMessage(0);
            }
            return LRESULT(0);
        }
        if msg == WM_DESTROY_RECREATE {
            let _ = DestroyWindow(hwnd);
            let new_top = create_target_window();
            println!("RECREATED {new_top}");
            let _ = std::io::stdout().flush();
            return LRESULT(0);
        }
        if msg == WM_ARM_RACE_HOOK {
            let username = USERNAME_HWND.load(Ordering::Acquire);
            if username == 0 {
                println!("RACE_ARM_FAILED no-username");
            } else {
                unsafe {
                    let hook_fn: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
                        race_proc;
                    let proc_ptr = hook_fn as *const () as isize;
                    let prev = SetWindowLongPtrW(HWND(username as *mut _), GWLP_WNDPROC, proc_ptr);
                    ORIG_USERNAME_PROC.store(prev, Ordering::Release);
                }
                println!("RACE_ARMED");
            }
            let _ = std::io::stdout().flush();
            return LRESULT(0);
        }
        if msg == WM_ARM_PAUSE_HOOK {
            let username = USERNAME_HWND.load(Ordering::Acquire);
            if username == 0 {
                println!("PAUSE_ARM_FAILED no-username");
            } else {
                unsafe {
                    let hook_fn: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
                        pause_proc;
                    let proc_ptr = hook_fn as *const () as isize;
                    let prev = SetWindowLongPtrW(HWND(username as *mut _), GWLP_WNDPROC, proc_ptr);
                    ORIG_PAUSE_PROC.store(prev, Ordering::Release);
                }
                println!("PAUSE_ARMED");
            }
            let _ = std::io::stdout().flush();
            return LRESULT(0);
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    /// Race hook procedure (classic subclassing of the username box): normal
    /// messages are forwarded to the original procedure; on the first
    /// `WM_SETTEXT` (the injection request in flight), after the original
    /// procedure writes, the top-level window is **synchronously destroyed and
    /// recreated inside the same message handling** — the test thread is still
    /// blocked on that SendMessageW at that moment, and on return it faces a
    /// world where "the password box is gone and the window is new".
    unsafe extern "system" fn race_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let orig = ORIG_USERNAME_PROC.load(Ordering::Acquire);
        let result = if orig != 0 {
            let proc_fn: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
                std::mem::transmute(orig);
            CallWindowProcW(Some(proc_fn), hwnd, msg, wparam, lparam)
        } else {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        };
        if msg == WM_SETTEXT && !RACE_TRIGGERED.swap(true, Ordering::AcqRel) {
            // The injected value has landed in the old window (still a legal target
            // per the snapshot at this moment); immediately after, the window is
            // destroyed and recreated inside the message handling that completed
            // the write — the second half of the in-flight request (the password
            // write) will face destroyed fields
            let top = TOP_HWND.load(Ordering::Acquire);
            if top != 0 {
                let _ = DestroyWindow(HWND(top as *mut _));
            }
            let new_top = create_target_window();
            println!("RACE_TRIGGERED {new_top}");
            let _ = std::io::stdout().flush();
        }
        result
    }

    /// Pause hook procedure (classic subclassing of the username box): normal
    /// messages are forwarded to the original procedure; after the first
    /// `WM_SETTEXT` completes its write through the original procedure, the
    /// process **stops inside that same message handling** — the injection
    /// thread is still blocked on that cross-process SendMessageW until the test
    /// process observes `HOOK_PAUSED`, mutates the slot, and sends `hook-go` to
    /// release it. This gives the command-layer cancellation timing suite a
    /// deterministic instrumentation point: clearing the slot / switching the
    /// target lands strictly after the first field write completes and before
    /// the injection flow resumes, without relying on lucky poll timing.
    unsafe extern "system" fn pause_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let orig = ORIG_PAUSE_PROC.load(Ordering::Acquire);
        let result = if orig != 0 {
            let proc_fn: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
                std::mem::transmute(orig);
            CallWindowProcW(Some(proc_fn), hwnd, msg, wparam, lparam)
        } else {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        };
        if msg == WM_SETTEXT && !PAUSE_TRIGGERED.swap(true, Ordering::AcqRel) {
            // The injected value has landed in the username box (the injection thread
            // is still blocked on this message); stop and wait for hook-go (60s
            // fallback: an unexpected death of the test process must not hang
            // this forever)
            println!("HOOK_PAUSED");
            let _ = std::io::stdout().flush();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !PAUSE_GO.load(Ordering::Acquire) {
                if std::time::Instant::now() >= deadline {
                    println!("HOOK_TIMEOUT");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            println!("HOOK_RESUMED");
            let _ = std::io::stdout().flush();
        }
        result
    }

    fn parse_args() {
        let args: Vec<String> = std::env::args().collect();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--title" => {
                    i += 1;
                    let _ = TITLE.set(args.get(i).cloned().unwrap_or_default());
                }
                "--password-style" => {
                    i += 1;
                    let on = args.get(i).map(|v| v != "0").unwrap_or(false);
                    PASSWORD_STYLE.store(if on { 1 } else { 0 }, Ordering::Relaxed);
                }
                _ => {}
            }
            i += 1;
        }
    }

    parse_args();
    let class_name = HSTRING::from("PersonaFillTestHostClass");
    unsafe {
        let hinstance = GetModuleHandleW(None).expect("GetModuleHandleW");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance.into(),
            lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        RegisterClassW(&wc);
        create_target_window();
        println!("READY {}", std::process::id());
        let _ = std::io::stdout().flush();
    }

    // stdin command thread: dispatches destroy-recreate / quit
    let stdin = std::thread::spawn(|| {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            match line.trim() {
                "readback" => unsafe {
                    let frame = readback_frame();
                    println!("{frame}");
                    let _ = std::io::stdout().flush();
                },
                "destroy-recreate" => unsafe {
                    let top = TOP_HWND.load(Ordering::Acquire);
                    if top != 0 {
                        let _ = PostMessageW(
                            Some(HWND(top as *mut _)),
                            WM_DESTROY_RECREATE,
                            WPARAM(0),
                            LPARAM(0),
                        );
                    }
                },
                "arm-race-hook" => unsafe {
                    let top = TOP_HWND.load(Ordering::Acquire);
                    if top != 0 {
                        let _ = PostMessageW(
                            Some(HWND(top as *mut _)),
                            WM_ARM_RACE_HOOK,
                            WPARAM(0),
                            LPARAM(0),
                        );
                    }
                },
                "arm-pause-hook" => unsafe {
                    PAUSE_GO.store(false, Ordering::Release);
                    let top = TOP_HWND.load(Ordering::Acquire);
                    if top != 0 {
                        let _ = PostMessageW(
                            Some(HWND(top as *mut _)),
                            WM_ARM_PAUSE_HOOK,
                            WPARAM(0),
                            LPARAM(0),
                        );
                    }
                },
                "hook-go" => {
                    PAUSE_GO.store(true, Ordering::Release);
                }
                "quit" => {
                    QUITTING.store(true, Ordering::Release);
                    unsafe {
                        let top = TOP_HWND.load(Ordering::Acquire);
                        if top != 0 {
                            let _ = PostMessageW(
                                Some(HWND(top as *mut _)),
                                windows::Win32::UI::WindowsAndMessaging::WM_CLOSE,
                                WPARAM(0),
                                LPARAM(0),
                            );
                        }
                        return;
                    }
                }
                _ => {}
            }
        }
    });

    unsafe {
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = DispatchMessageW(&msg);
        }
    }
    let _ = stdin.join();
}
