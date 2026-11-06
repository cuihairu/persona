//! fill-test-host：桌面填充注入的跨进程测试靶进程（安全评审
//! codex-2026-11-05 P1 修复的验收工具，**仅测试构建**——bin 挂在
//! `fill-test-host` feature 后面，正常 `cargo build`/`tauri build`
//! 不产出该二进制）。
//!
//! 职责：在自己的进程里创建一个真实顶层窗口 + 两个 EDIT 子控件
//!（第一个普通框，第二个按 `--password-style` 决定是否挂 ES_PASSWORD），
//! 跑消息循环等命令。集成测试 `tests/desktop_fill_cross_process.rs`
//! 用它验证：跨进程注入成功/拒绝、同标题伪装进程拒绝、HWND 销毁
//! 重建竞态拒绝——这些是测试进程内造窗覆盖不到的真跨进程语义。
//!
//! stdin 命令（按行）：
//! - `readback`：**同进程**读回两个 Edit 的当前文本（WM_GETTEXTLENGTH +
//!   WM_GETTEXT），按长度前缀协议打回
//!   `READBACK <unit-count>:<hex> <unit-count>:<hex>`（UTF-16 hex 每单元
//!   4 位小写，空字段 = `0:`；长度前缀保住空字段信息，见 fill-test/lib.rs）。
//!   存在的原因：Windows 平台限制——跨进程 WM_GETTEXT 读 ES_PASSWORD
//!   控件恒返回空串（2026-11-06 openclaw Server 2022 实测），注入成功的
//!   密码断言只能由宿主进程自己读回；
//! - `destroy-recreate`：销毁当前顶层窗口并**同标题同样式**重建
//!   （HWND 复用/重建竞态用例），完成后向 stdout 打 `RECREATED <hwnd>`；
//! - `arm-race-hook`：在 username 框上挂竞态钩子（旧式子类化）：下一次
//!   收到 `WM_SETTEXT`（即注入请求**在途**）时，先让原过程写入、随后在
//!   同一消息处理内**同步销毁并重建**顶层窗口——注入请求跑到一半目标
//!   就地换人，打回 `RACE_ARMED` / `RACE_TRIGGERED <hwnd>`；
//! - `arm-pause-hook`：在 username 框上挂**暂停钩子**（旧式子类化）：
//!   下一次 `WM_SETTEXT` 在原过程写入完成后，宿主**在同一消息处理内停住**
//!   （注入线程仍阻塞在这条跨进程 SendMessageW 上），打回 `PAUSE_ARMED` /
//!   `HOOK_PAUSED`；收到 stdin 命令 `hook-go` 才放行，打回 `HOOK_RESUMED`。
//!   给命令层取消时序套件（tests/desktop_fill_command_cancel.rs）提供
//!   **确定性**的第一字段写入完成后的插桩点：测试侧在 `HOOK_PAUSED` 与
//!   `hook-go` 之间改动槽位，时序不是靠轮询碰运气；
//! - `quit`：干净退出（销毁窗口，EXIT 0）。
//!
//! 非 Windows 平台：入口直接退出 0（不参与任何测试）。

#[cfg(not(target_os = "windows"))]
fn main() {
    // Linux/macOS CI：该 bin 仅在显式 feature 下构建，无任何行为
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
    /// quit 命令置位后才在 WM_DESTROY 里投递 PostQuitMessage——destroy-
    /// rebuild 同样会触发 WM_DESTROY，但那个场景消息循环必须活下去
    static QUITTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    /// 自定义消息：wndproc 线程内销毁并重建顶层窗口（DestroyWindow 必须在
    /// 创建线程调用，stdin 线程只能投递）
    const WM_DESTROY_RECREATE: u32 = WM_APP + 1;
    /// 自定义消息：在 username 框上挂竞态钩子（同样必须在创建线程做）
    const WM_ARM_RACE_HOOK: u32 = WM_APP + 2;
    /// 自定义消息：在 username 框上挂暂停钩子（同样必须在创建线程做）
    const WM_ARM_PAUSE_HOOK: u32 = WM_APP + 3;
    /// username 框的原 wndproc（竞态钩子子类化前的过程指针；0 = 未挂钩）
    static ORIG_USERNAME_PROC: AtomicIsize = AtomicIsize::new(0);
    /// 竞态钩子已触发（首次 WM_SETTEXT 后销毁重建）——只触发一次
    static RACE_TRIGGERED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// username 框的原 wndproc（暂停钩子子类化前的过程指针；0 = 未挂钩。
    /// 与竞态钩子分开存：两个钩子各自一个宿主实例，互不同时挂）
    static ORIG_PAUSE_PROC: AtomicIsize = AtomicIsize::new(0);
    /// 暂停钩子已触发（首次 WM_SETTEXT 后停住）——只触发一次
    static PAUSE_TRIGGERED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// 暂停钩子的放行开关（stdin `hook-go` 置位；60 秒兜底超时后自行放行，
    /// 测试进程崩了也不留死锁的窗口）
    static PAUSE_GO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn pcw(s: &HSTRING) -> PCWSTR {
        PCWSTR(s.as_ptr())
    }

    /// 同进程读回一个 Edit 的文本并按 UTF-16 hex 编码（每单元 4 位小写，
    /// 管道/console 编码无关）。hwnd 为 0 或读不到时返回空串。
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
        buf[..got as usize].iter().map(|u| format!("{u:04x}")).collect()
    }

    /// 同进程读回两个 Edit 的文本并按**长度前缀协议**打回 READBACK 帧
    ///（`READBACK <unit-count>:<hex> <unit-count>:<hex>`，空字段 = `0:`）。
    /// 长度前缀保住空字段信息：旧空格分隔协议下「username 空 + password
    /// 非空」的帧只剩 2 段，被解析端误判双空，单字段残留无法检出。
    unsafe fn readback_frame() -> String {
        let user = control_text_hex(USERNAME_HWND.load(Ordering::Acquire));
        let pwd = control_text_hex(PASSWORD_HWND.load(Ordering::Acquire));
        persona_fill_test::encode_readback_frame(&user, &pwd)
    }

    unsafe fn create_target_window() -> isize {
        let hinstance = GetModuleHandleW(None).expect("GetModuleHandleW");
        let title_h = HSTRING::from(TITLE.get().map(|s| s.as_str()).unwrap_or("persona fill test host"));
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
            // 只有 quit 流程才退出消息循环（destroy-recreate 的 WM_DESTROY
            // 必须继续泵消息，否则宿主假死、测试进程 wait() 永久阻塞）
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

    /// 竞态钩子过程（旧式子类化 username 框）：正常消息全部转交原过程；
    /// 首次 `WM_SETTEXT`（注入请求在途）在原过程写入后，**同一消息处理内**
    /// 同步销毁并重建顶层窗口——测试线程此刻仍阻塞在这条 SendMessageW 上，
    /// 返回后它面对的已是「密码框销毁、窗口换新」的世界。
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
            // 注入值已落进旧窗口（此刻它仍是快照声明的合法目标）；
            // 紧接着在写入完成的消息处理内销毁重建——在途请求的后半段
            // （密码写入）将面对已销毁的字段
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

    /// 暂停钩子过程（旧式子类化 username 框）：正常消息全部转交原过程；
    /// 首次 `WM_SETTEXT` 在原过程写入完成后**停在同一消息处理里**——注入
    /// 线程此刻仍阻塞在这条跨进程 SendMessageW 上，直到测试进程观察到
    /// `HOOK_PAUSED`、改完槽位并发来 `hook-go` 才放行。这给命令层取消时序
    /// 套件一个确定性的插桩点：清槽/换目标严格落在第一字段写入完成之后、
    /// 注入流程恢复之前，不靠轮询时序碰运气。
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
            // 注入值已落进 username 框（注入线程还阻塞在这条消息上）；
            // 停住等 hook-go（60 秒兜底：测试进程意外死亡也不永久挂死）
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

    // stdin 命令线程：解析 destroy-recreate / quit
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
                },
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
                },
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
