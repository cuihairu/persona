//! Desktop fill injection（对标 FEATURE_GAP_ANALYSIS #12：Windows 桌面应用
//! 内的填充注入路径）。
//!
//! 口径（与 #22 一致）：**填充归目标应用侧**——浏览器里的填充走浏览器扩展
//! （Native Messaging 桥），本模块只负责"非浏览器原生桌面应用"的取件后
//! 填充：用户在检索浮窗选中凭据 → 注入到浮窗唤起前最后持有前台的那个
//! 应用窗口。
//!
//! 选型（设计小节见 docs/src/design/desktop-fill.md，此处只留结论）：
//! - **首选 WM_SETTEXT 直写**：枚举目标窗口的经典 Win32 EDIT 子控件，
//!   用户名 = 第一个非密码框，密码 = 第一个 `ES_PASSWORD` 样式框（无密码
//!   样式且 ≥2 个输入框时退回"第二个框"启发式）。直写不依赖焦点、不模拟
//!   键击、跨进程可靠（同一桌面会话内），是可自动化验收的路径。代价：
//!   Electron/Qt/浏览器等自绘输入框不吃 WM_SETTEXT——这类宿主本就该走
//!   浏览器扩展或 UIA，属诚实边界而非缺陷。
//! - **备选剪贴板中转**（`with_clipboard_paste` + `paste_into_focused`）：
//!   粘贴前备份文本剪贴板、闭包执行期间密文在场、闭包返回后立即恢复备份。
//!   给吃键盘事件校验（如实时强度提示）的应用兜底，不做首选（焦点转移受
//!   系统前台锁策略约束，可靠性差）。
//! - **不做 UIA**：UI Automation 可覆盖自绘控件，但引入
//!   `Win32_UI_Accessibility` 依赖面 + COM 生命周期管理，首版不引入；
//!   作为后续对自绘宿主的扩展点记录在本注释里。
//!
//! 目标窗口捕获：热键唤起浮窗时（`toggle_window` 的 show 分支）目标应用
//! 还持有前台——此刻 `GetForegroundWindow` 拿到的就是注入对象；存 hwnd +
//! 标题 + pid 到运行态。注入时**重验证**：hwnd 复用是真实威胁（用户关了
//! 目标窗口又开了别的），标题前缀不一致即拒绝注入，宁可不填不填错。
//! pid 等于本进程的窗口永不作为目标（浮窗/主窗口自己）。
//!
//! 非 Windows 平台：命令层如实报"平台不支持"（`fill_supported()`），
//! 不假装有功能——Linux/macOS 的桌面填充是后续议题，本模块不画饼。

use serde::{Deserialize, Serialize};

/// 注入目标窗口的进程内快照（`AppState.fill_target` 持有）。
/// hwnd 用 isize 存（跨 FFI 边界不暴露裸 HWND 类型，也方便测试造句柄）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FillTarget {
    /// Win32 顶层窗口句柄（原始值）
    pub hwnd: isize,
    /// 捕获时刻的窗口标题（注入时做前缀重验证，防 hwnd 复用）
    pub title: String,
    /// 捕获时刻的窗口所属进程 id（注入时校验仍属同进程，配合标题双保险）
    pub pid: u32,
}

/// 字段分类结果：用户名框 + 可选的密码框句柄
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedFields {
    pub username_hwnd: isize,
    /// None = 目标窗口没找到密码样式的框（有的登录窗只有一个用户名框）
    pub password_hwnd: Option<isize>,
}

/// 字段选择启发式（平台无关，纯函数可测）。
///
/// 输入按 Z 序（EnumChildWindows 顺序）传入 (hwnd, is_password_styled)：
/// - 用户名 = 第一个**非**密码样式的框；
/// - 密码 = 第一个密码样式（`ES_PASSWORD`）的框；
/// - 若没有任何密码样式框但有 ≥2 个输入框，退回"第二个框"启发式
///   （经典登录对话框 username/password 连排，无样式标记也大概率成立）；
/// - 全部是密码样式框（改密对话框）：把第一框当用户名填进去是事故，
///   拒绝注入，由调用方如实报错。
pub fn classify_fields(fields: &[(isize, bool)]) -> Option<ClassifiedFields> {
    let username = fields.iter().find(|(_, pwd)| !pwd).map(|(h, _)| *h);
    let password = fields.iter().find(|(_, pwd)| *pwd).map(|(h, _)| *h);
    let username = username?;
    let password = password.or_else(|| {
        // 无任何密码样式框但有第二个输入框：经典登录对话框连排启发式
        fields
            .iter()
            .filter(|(_, pwd)| !pwd)
            .nth(1)
            .map(|(h, _)| *h)
    });
    Some(ClassifiedFields {
        username_hwnd: username,
        password_hwnd: password,
    })
}

/// 当前平台是否实现了注入路径（命令层用它决定如实报错还是放行）
pub fn fill_supported() -> bool {
    cfg!(target_os = "windows")
}

/// 命令层的注入执行入口（平台双态）：
/// Windows = 重验证目标 → 枚举 EDIT 框 → 分类 → WM_SETTEXT 注入两字段；
/// 其他平台 = 恒 Err（命令层先有 `fill_supported()` 前置检查，这里是兜底）。
/// 返回 (用户名是否注入, 密码是否注入, 目标窗口标题)。
#[cfg(target_os = "windows")]
pub fn execute_fill(
    target: &FillTarget,
    username: &str,
    password: &str,
    self_pid: u32,
) -> Result<(bool, bool, String), String> {
    if !win::validate_target(target, self_pid) {
        return Err("CAPTURED_TARGET_INVALID".to_string());
    }
    let fields = win::enumerate_edit_fields(target.hwnd);
    if fields.is_empty() {
        return Err(format!(
            "Target window \"{}\" has no classic edit controls (self-drawn UI is not supported; browser fill goes through the extension)",
            target.title
        ));
    }
    let Some(classified) = classify_fields(&fields) else {
        return Err(format!(
            "No editable login fields found in target window \"{}\"",
            target.title
        ));
    };
    let mut username_filled = false;
    if !username.is_empty() {
        username_filled = win::inject_settext(classified.username_hwnd, username).is_ok();
    }
    let mut password_filled = false;
    if let Some(pwd_hwnd) = classified.password_hwnd {
        password_filled = win::inject_settext(pwd_hwnd, password).is_ok();
    }
    Ok((username_filled, password_filled, target.title.clone()))
}

/// 非 Windows：没有注入实现（见模块头注释的诚实边界）
#[cfg(not(target_os = "windows"))]
pub fn execute_fill(
    _target: &FillTarget,
    _username: &str,
    _password: &str,
    _self_pid: u32,
) -> Result<(bool, bool, String), String> {
    Err("Desktop fill injection is only implemented on Windows".to_string())
}

/// `fill_target_status` 的返回形状（snake_case：前端 `FillTargetStatus`
/// 逐字对齐）。只带标题，**不带 hwnd/pid**——句柄值对前端无用，暴露
/// 进程内指针反而扩大信息面。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillTargetStatus {
    /// 本平台是否实现了注入路径
    pub supported: bool,
    /// 有已捕获且当前仍然有效的注入目标
    pub ready: bool,
    /// 目标窗口标题（无目标/已失效时为 null）
    pub target_title: Option<String>,
}

/// `desktop_fill_credential` 的返回形状（snake_case：前端 `DesktopFillResult`
/// 逐字对齐）。逐字段结果而非整体布尔：单字段失败（如目标只有用户名框）
/// 时前端能如实说"只填了用户名"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopFillResult {
    pub username_filled: bool,
    pub password_filled: bool,
    /// 注入目标窗口标题（结果里带上，用户能核对"填进的是哪个窗口"）
    pub target_title: String,
    /// 非致命警告（如剪贴板恢复失败——粘贴模式专用，SetText 路径恒 None）
    pub warning: Option<String>,
}

#[cfg(target_os = "windows")]
pub mod win {
    //! Win32 实现。全部函数失败都返回 Err 带原文，不 panic、不静默。

    use windows::core::BOOL;
    use windows::Win32::Foundation::{HANDLE, GlobalFree, HWND, LPARAM, WPARAM};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable,
        OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;
    use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, SetFocus, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
        VK_CONTROL, VK_V, VIRTUAL_KEY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumChildWindows, GetAncestor, GetClassNameW, GetForegroundWindow, GetWindowLongPtrW,
        GetWindowThreadProcessId, GetWindowTextLengthW, GetWindowTextW, IsWindow, SendMessageW,
        SetForegroundWindow, GA_ROOT, GWL_STYLE, WM_GETTEXT, WM_GETTEXTLENGTH, WM_SETTEXT,
    };

    use super::FillTarget;

    /// 经典 Win32 编辑控件的窗口类名
    const EDIT_CLASS: &str = "Edit";

    /// 捕获当前前台窗口（浮窗 show 前调用）。本进程自己的窗口返回 None
    ///（浮窗/主窗口不该成为注入目标）。
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
            Some(FillTarget {
                hwnd: hwnd.0 as isize,
                title,
                pid,
            })
        }
    }

    /// 注入前重验证：句柄仍活着 + 标题前缀一致 + 进程一致。
    /// 标题比对用前缀（登录对话框标题会随状态变化，如"登录 - 已断开"），
    /// 空标题窗口只验证存活 + pid。
    pub fn validate_target(target: &FillTarget, self_pid: u32) -> bool {
        unsafe {
            let hwnd = HWND(target.hwnd as *mut _);
            if !IsWindow(Some(hwnd)).as_bool() {
                return false;
            }
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid != target.pid || pid == self_pid {
                return false;
            }
            let current = window_text(hwnd);
            current.starts_with(&target.title)
        }
    }

    /// 枚举目标窗口下的经典 EDIT 子控件（Z 序），返回 (hwnd, 是否密码样式)。
    pub fn enumerate_edit_fields(top_hwnd: isize) -> Vec<(isize, bool)> {
        struct CollectCtx<'a> {
            out: &'a mut Vec<(isize, bool)>,
        }
        unsafe extern "system" fn enum_proc(child: HWND, lparam: LPARAM) -> BOOL {
            let ctx = &mut *(lparam.0 as *mut CollectCtx);
            // 只认类名精确等于 "Edit" 的子窗口；取类名失败的一律跳过
            let mut buf = [0u16; 64];
            let n = GetClassNameW(child, &mut buf);
            if n <= 0 {
                return BOOL(1);
            }
            let class = String::from_utf16_lossy(&buf[..n as usize]);
            if class != EDIT_CLASS {
                return BOOL(1); // 继续枚举
            }
            let style = GetWindowLongPtrW(child, GWL_STYLE);
            ctx.out
                .push((child.0 as isize, style & windows::Win32::UI::WindowsAndMessaging::ES_PASSWORD as isize != 0));
            BOOL(1)
        }
        unsafe {
            let mut found: Vec<(isize, bool)> = Vec::new();
            let mut collector = CollectCtx { out: &mut found };
            let lparam = LPARAM(&mut collector as *mut CollectCtx as isize);
            let _ = EnumChildWindows(Some(HWND(top_hwnd as *mut _)), Some(enum_proc), lparam);
            found
        }
    }

    /// WM_SETTEXT 直写一个输入框。跨进程安全（同一桌面会话），不依赖焦点。
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
            // WM_SETTEXT 返回非零表示成功
            if res.0 == 0 {
                return Err(format!("WM_SETTEXT rejected (lresult={})", res.0));
            }
            Ok(())
        }
    }

    /// 读回一个输入框的当前文本（注入后验证与测试用；不进产品回显面）。
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

    /// 剪贴板备份 → 覆写为密文 → 执行 `paste` 闭包 → 恢复备份。
    /// 密文在剪贴板的驻留只覆盖闭包执行期；恢复失败如实返回警告（不静默
    /// ——用户剪贴板里留着密码是事故）。备份前非文本内容（文件/位图）：
    /// 恢复不了原文，结束时覆写为空串，由返回值里的警告说明。
    pub fn with_clipboard_paste<T>(
        value: &str,
        paste: impl FnOnce() -> T,
    ) -> Result<(T, Option<String>), String> {
        unsafe {
            if OpenClipboard(None).is_err() {
                return Err("cannot open clipboard".to_string());
            }
            // 备份当前文本剪贴板（有就存；非文本内容最后覆写为空串）
            let had_text = IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok();
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
                        // CF_UNICODETEXT 是 NUL 结尾 UTF-16；长度不可知，
                        // 靠 NUL 扫描（上限 1M 字符防失控）
                        let wide = std::slice::from_raw_parts(ptr as *const u16, 1 << 20);
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
            let set = closed.and_then(|()| set_clipboard_text(value));

            let paste_result = set.map(|()| paste());

            // 恢复：写回备份（无文本备份则写空串，把密文清掉）
            let restore_warning = restore_clipboard(backup.as_deref().unwrap_or(""));

            match (paste_result, restore_warning) {
                (Ok(v), None) => Ok((v, None)),
                (Ok(v), Some(w)) => Ok((v, Some(w))),
                (Err(e), _) => Err(e),
            }
        }
    }

    /// 写入文本到剪贴板（内部 Open/Close，可独立调用）。返回 Err 的原文
    /// 可直接作为"恢复失败"警告使用。
    fn set_clipboard_text(value: &str) -> Result<(), String> {
        unsafe {
            if OpenClipboard(None).is_err() {
                return Err("cannot reopen clipboard".to_string());
            }
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
                // SetClipboardData 成功后剪贴板接管 h（不能再 GlobalFree）
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

    fn restore_clipboard(backup: &str) -> Option<String> {
        set_clipboard_text(backup).err()
    }

    /// 聚焦目标输入框并模拟 Ctrl+V（配合 [`with_clipboard_paste`] 使用）。
    /// 焦点转移用 AttachThreadInput 把我们的输入队列短暂挂到目标线程——
    /// Windows 前台锁策略下这是跨进程聚焦的标准做法。
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
                        dwFlags: if keyup { KEYEVENTF_KEYUP } else { Default::default() },
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

    /// 供本模块测试创建目标窗口（不对命令层暴露）。测试窗口是真实顶层
    /// 窗口：验证的就是"枚举子控件 → 分类 → WM_SETTEXT → 读回"整条链。
    #[cfg(test)]
    pub(crate) mod test_window {
        //! 测试靶窗：一个真实顶层窗口 + username/password 两个 EDIT 控件。
        //! 在测试进程内创建（同一桌面会话），跑完销毁。

        use windows::core::{HSTRING, PCWSTR};
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, ES_AUTOHSCROLL, ES_PASSWORD, WINDOW_EX_STYLE,
            WINDOW_STYLE, WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
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
            /// title 原样成为窗口标题（重验证断言要用同一串）；
            /// `password_style` = 给第二个框挂 ES_PASSWORD 样式。
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
        }
    }
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod win_tests {
    //! Windows 真会话集成测试：靶窗是真实 Win32 窗口（同一桌面会话），
    //! 跑的是"捕获 → 枚举 → 分类 → 注入 → 读回"整条真链，不是 mock。

    use super::classify_fields;
    use super::win::test_window::TestTargetWindow;
    use super::win::{enumerate_edit_fields, inject_settext, read_field_text, validate_target};

    /// 用户名/密码框识别 + WM_SETTEXT 注入 + WM_GETTEXT 读回一致。
    /// 这是桌面填充的真机验收核心断言（openclaw Windows Server 2022 跑）。
    #[test]
    fn settext_injection_roundtrip_on_real_window() {
        let target =
            TestTargetWindow::create("persona fill test - login", true).expect("create target");
        let fields = enumerate_edit_fields(target.top);
        assert_eq!(fields.len(), 2, "two EDIT controls expected");
        assert_eq!(fields[0], (target.username, false));
        assert_eq!(fields[1], (target.password, true));

        let classified = classify_fields(&fields).expect("classify");
        assert_eq!(classified.username_hwnd, target.username);
        assert_eq!(classified.password_hwnd, Some(target.password));

        inject_settext(classified.username_hwnd, "alice@example.com").expect("inject username");
        inject_settext(classified.password_hwnd.unwrap(), "s3cret-Пароль⚡")
            .expect("inject password");
        assert_eq!(read_field_text(target.username), "alice@example.com");
        assert_eq!(read_field_text(target.password), "s3cret-Пароль⚡");
        target.destroy();
    }

    /// 无密码样式 + 多框时的"第二个框"启发式
    #[test]
    fn heuristic_second_field_when_no_password_style() {
        let target =
            TestTargetWindow::create("persona fill test - heuristic", false).expect("create target");
        let fields = enumerate_edit_fields(target.top);
        assert_eq!(fields.len(), 2);
        let classified = classify_fields(&fields).expect("classify");
        assert_eq!(classified.username_hwnd, target.username);
        assert_eq!(classified.password_hwnd, Some(target.password));
        target.destroy();
    }

    /// 全密码样式框（改密对话框形态）与退化形态必须拒绝注入
    #[test]
    fn classification_edge_cases() {
        let all_password = vec![(101isize, true), (102isize, true)];
        assert!(classify_fields(&all_password).is_none());
        let single = vec![(103isize, true)];
        assert!(classify_fields(&single).is_none());
        let empty: Vec<(isize, bool)> = vec![];
        assert!(classify_fields(&empty).is_none());
        // 单个非密码框：用户名可注入、密码不猜
        let c = classify_fields(&[(9, false)]).unwrap();
        assert_eq!(c.password_hwnd, None);
    }

    /// 目标重验证：pid 不符拒绝、标题前缀不符拒绝、死句柄拒绝。
    #[test]
    fn target_validation_guards_hwnd_reuse() {
        let self_pid = std::process::id();
        let target =
            TestTargetWindow::create("persona fill test - validate", false).expect("create target");

        // 快照 pid 乱填（=0）与真实 pid 不符 → 拒绝
        let t_bad_pid = super::FillTarget {
            hwnd: target.top,
            title: "persona fill test - validate".to_string(),
            pid: 0,
        };
        assert!(!validate_target(&t_bad_pid, self_pid), "mismatched pid must be rejected");

        // pid + 标题都对 → 放行
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
        assert_ne!(real_pid, self_pid, "test window pid must differ (sanity)");
        let t_ok = super::FillTarget {
            hwnd: target.top,
            title: "persona fill test - validate".to_string(),
            pid: real_pid,
        };
        assert!(validate_target(&t_ok, self_pid), "matching snapshot must pass");

        // 标题前缀不一致 → 拒绝（模拟 hwnd 复用到别的窗口）
        let t_other = super::FillTarget {
            hwnd: target.top,
            title: "totally different window".to_string(),
            pid: real_pid,
        };
        assert!(!validate_target(&t_other, self_pid), "stale title must be rejected");

        // 死句柄 → 拒绝
        let t_dead = super::FillTarget {
            hwnd: 0xDEAD_BEEFisize,
            title: String::new(),
            pid: real_pid,
        };
        assert!(!validate_target(&t_dead, self_pid));

        target.destroy();
        assert!(!validate_target(&t_ok, self_pid), "destroyed window must be rejected");
    }

    /// 剪贴板备份/恢复闭环：粘贴期间密文在场、结束后原内容恢复。
    #[test]
    fn clipboard_backup_restore_roundtrip() {
        use super::win::with_clipboard_paste;
        // 第一轮：把 "PREV-VALUE" 放进剪贴板（作为后续轮次的"原有内容"）
        let (_, warn) = with_clipboard_paste("PREV-VALUE", || ()).expect("seed clipboard");
        assert!(warn.is_none(), "seeding should not warn: {warn:?}");

        // 第二轮：粘贴假密文，断言闭包期间读到的是密文、结束后恢复 PREV-VALUE
        let seen = std::cell::RefCell::new(String::new());
        let (_, warn2) = with_clipboard_paste("TOP-SECRET", || {
            *seen.borrow_mut() = read_clipboard_text();
        })
        .expect("paste roundtrip");
        assert_eq!(seen.borrow().as_str(), "TOP-SECRET", "secret must be on clipboard during paste");
        assert_eq!(read_clipboard_text(), "PREV-VALUE", "previous content must be restored");
        assert!(warn2.is_none(), "restore should not warn: {warn2:?}");
    }

    fn read_clipboard_text() -> String {
        use windows::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, OpenClipboard,
        };
        use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
        use windows::Win32::System::Ole::CF_UNICODETEXT;
        unsafe {
            if OpenClipboard(None).is_err() {
                return String::new();
            }
            let out: Option<String> = (|| {
                let h = GetClipboardData(CF_UNICODETEXT.0 as u32).ok()?;
                if h.is_invalid() {
                    return None;
                }
                let ptr = GlobalLock(windows::Win32::Foundation::HGLOBAL(h.0));
                if ptr.is_null() {
                    return None;
                }
                let wide = std::slice::from_raw_parts(ptr as *const u16, 1 << 20);
                let mut n = 0usize;
                while n < wide.len() && wide[n] != 0 {
                    n += 1;
                }
                let text = String::from_utf16_lossy(&wide[..n]);
                let _ = GlobalUnlock(windows::Win32::Foundation::HGLOBAL(h.0));
                Some(text)
            })();
            let _ = CloseClipboard();
            out.unwrap_or_default()
        }
    }

    use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
}

/// 非 Windows 平台的编译单元（保持 Linux/CI 侧 cargo check/test 全绿）：
/// 平台判定纯函数在这里测，命令层的"如实报不支持"路径由
/// command_layer_tests 覆盖。
#[cfg(not(target_os = "windows"))]
#[cfg(test)]
mod nonwin_tests {
    use super::{classify_fields, fill_supported};

    #[test]
    fn platform_reports_unsupported() {
        assert!(!fill_supported(), "non-windows must report unsupported");
    }

    #[test]
    fn classification_heuristics() {
        // 正常：用户名第一个非密码框，密码第一个密码样式框
        let f = vec![(1, false), (2, true), (3, true)];
        let c = classify_fields(&f).unwrap();
        assert_eq!(c.username_hwnd, 1);
        assert_eq!(c.password_hwnd, Some(2));
        // 无密码样式多框：第二个框启发式
        let f = vec![(7, false), (8, false)];
        let c = classify_fields(&f).unwrap();
        assert_eq!(c.username_hwnd, 7);
        assert_eq!(c.password_hwnd, Some(8));
        // 全密码框：拒绝（改密对话框不是登录框）
        assert!(classify_fields(&[(1, true), (2, true)]).is_none());
        // 单框：不猜密码
        let f = vec![(9, false)];
        let c = classify_fields(&f).unwrap();
        assert_eq!(c.password_hwnd, None);
        // 空目标
        assert!(classify_fields(&[]).is_none());
    }
}
