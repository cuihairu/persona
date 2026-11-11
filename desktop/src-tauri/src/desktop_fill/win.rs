pub mod win {
    //! Win32 实现。全部函数失败都返回 Err 带原文，不 panic、不静默。

    use windows::core::BOOL;
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HWND, LPARAM, WPARAM};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable,
        OpenClipboard, SetClipboardData,
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
        SendMessageW, SetForegroundWindow, ES_PASSWORD, ES_READONLY, GA_ROOT, GWL_STYLE,
        WM_GETTEXT, WM_GETTEXTLENGTH, WM_SETTEXT,
    };

    use super::FieldState;
    use super::FillTarget;

    /// 经典 Win32 编辑控件的窗口类名
    const EDIT_CLASS: &str = "Edit";

    /// 捕获当前前台窗口（浮窗 show 前调用）。本进程自己的窗口返回 None
    ///（浮窗/主窗口不该成为注入目标）；指纹查不全（类名/可执行文件路径）
    /// 也返回 None——没有指纹就没有可信注入。
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

    /// 注入前重验证：指纹三要素 + 进程一致性（见模块头"目标可信模型"）。
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

    /// 验证快照语义（[`validate_target`] 的展开形态，纯参数便于测试）：
    /// - hwnd 存活；
    /// - 所属进程 == expected_pid 且 != self_pid（本进程窗口永不注入）；
    /// - 当前顶层类名 == 快照类名；
    /// - 当前进程可执行文件路径 == 快照路径（大小写不敏感，NTFS 语义）；
    /// - 标题：非空快照按前缀比对（登录对话框标题会随状态变化，如
    ///   "登录 - 已断开"）；**空快照标题要求当前标题也为空**——堵住
    ///   `starts_with("")` 恒真的历史漏洞。
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

    /// 逐控件写入前重验证：hwnd 存活、GA_ROOT 归属目标顶层窗口、pid、
    /// 类名 Edit、可见/启用/非只读；`require_password` 时必须仍带
    /// ES_PASSWORD 样式（否则必须**不带**——防止 hwnd 复用后字段角色
    /// 对调）。任一不满足返回 Err，调用方拒绝注入。
    pub fn revalidate_field(
        field_hwnd: isize,
        target_hwnd: isize,
        expected_pid: u32,
        require_password: bool,
    ) -> Result<(), String> {
        let state =
            field_state(field_hwnd).ok_or_else(|| "target field window is gone".to_string())?;
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

    /// 枚举目标窗口下的经典 EDIT 子控件（Z 序），产出各框完整状态。
    pub fn enumerate_edit_fields(top_hwnd: isize) -> Vec<FieldState> {
        struct CollectCtx<'a> {
            out: &'a mut Vec<FieldState>,
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

    /// 读取单个 hwnd 的字段状态；hwnd 已死或类名不是 Edit 返回 None。
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

    /// WM_SETTEXT 直写一个输入框。跨进程安全（同一桌面会话），不依赖焦点。
    /// 调用方（[`execute_fill`]）负责先做 [`revalidate_field`]。
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
    ///
    /// **平台限制（openclaw Server 2022 实测）**：`field_hwnd` 属于其他
    /// 进程且控件带 `ES_PASSWORD` 时，跨进程 `WM_GETTEXT`/`WM_GETTEXTLENGTH`
    /// 恒返回空/0——即使跨进程 `WM_SETTEXT` 写入成功。系统对密码框做了
    /// 跨进程读隐藏，本函数不能用于验证跨进程密码注入；验证须由目标进程
    /// 自己读回（见 fill-test-host 的 `readback` 命令）或退而断言
    /// `EM_GETPASSWORDCHAR`/样式。同进程调用不受影响。
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

    /// 顶层窗口类名（指纹要素）。查询失败返回空串。
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

    /// 进程可执行文件完整路径（指纹要素）。OpenProcess/查询失败返回空串
    ///（权限不足或进程已退出）。
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

    /// 剪贴板备份 → 覆写为明文 → 执行 `paste` 闭包 → 恢复备份。
    ///
    /// **保密边界（如实声明）**：`value` 是明文；系统剪贴板是同桌面会话
    /// 全局共享的，驻留期间任何进程都可读取，本函数只缩短暴露窗口，
    /// 不提供保密保证。恢复失败如实返回警告（不静默——用户剪贴板里
    /// 留着密码是事故）。备份前非文本内容（文件/位图）：恢复不了原文，
    /// 结束时覆写为空串，由返回值里的警告说明。闭包 panic 同样先恢复
    /// 剪贴板再传播（catch_unwind 包裹）。
    ///
    /// 当前**未接入生产路径**（生产只走 WM_SETTEXT）；启用前须在 UI/文档
    /// 明确披露上述边界。
    pub fn with_clipboard_paste<T>(
        value: &str,
        paste: impl FnOnce() -> T,
    ) -> Result<(T, Option<String>), String> {
        with_clipboard_paste_with_writer(value, paste, set_clipboard_text)
    }

    /// [`with_clipboard_paste`] 的实现体，剪贴板写入函数（明文覆写与恢复
    /// 复用同一支）可注入——测试用它确定性触发「覆写失败 → 恢复也失败」
    /// 的告警分支，不必与真实剪贴板的打开/关闭时序赛跑。
    pub(crate) fn with_clipboard_paste_with_writer<T>(
        value: &str,
        paste: impl FnOnce() -> T,
        set_text: impl Fn(&str) -> Result<(), String>,
    ) -> Result<(T, Option<String>), String> {
        unsafe {
            open_clipboard_with_retry()?;
            // 备份当前文本剪贴板（有就存；非文本内容恢复不了原文——结束
            // 时覆写为空串并**如实告警**，不许静默销毁用户剪贴板）
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
                        // CF_UNICODETEXT 是 NUL 结尾 UTF-16。分配边界以
                        // GlobalSize 实测为准（历史版本盲取 1M 字符切片，
                        // 存在越界读风险），NUL 扫描上限 1M 字符防失控。
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

            // catch_unwind：闭包 panic 不能绕过剪贴板恢复（panic 信息在
            // 恢复之后按 ResumeUnwind 语义重新抛出）
            let paste_result =
                set.map(|()| std::panic::catch_unwind(std::panic::AssertUnwindSafe(paste)));

            // 恢复：写回备份（无文本备份则写空串，把密文清掉）
            let mut restore_warning = set_text(backup.as_deref().unwrap_or("")).err();
            // 非文本内容（文件/位图/自定义格式）恢复不了原文——覆写为空串
            // 后必须返回告警（不能静默销毁用户剪贴板）
            if restore_warning.is_none() && had_non_text {
                let msg =
                    "previous non-text clipboard content was cleared and could not be restored"
                        .to_string();
                tracing::warn!("clipboard paste: {msg}");
                restore_warning = Some(msg);
            }

            match paste_result {
                // set_clipboard_text 失败（String）：恢复路径的告警不能被吞
                Err(e) => {
                    if let Some(w) = &restore_warning {
                        tracing::warn!("clipboard restore warning swallowed by paste failure: {w}");
                    }
                    Err(e)
                }
                // 闭包 panic：恢复已完成，告警落日志后再原样重抛
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

    /// 剪贴板是否装有任何格式（剪贴板处于打开状态时调用）。用于区分
    /// 「空剪贴板」与「有非文本内容」——后者被覆写清空时必须告警。
    fn clipboard_has_any_format() -> bool {
        unsafe { windows::Win32::System::DataExchange::EnumClipboardFormats(0) != 0 }
    }

    /// 测试专用：直接写入剪贴板文本（绕过备份/恢复语义，用于给
    /// [`with_clipboard_paste`] 的闭环测试造"原有内容"）。
    #[cfg(test)]
    pub(crate) fn seed_clipboard(value: &str) -> Result<(), String> {
        set_clipboard_text(value)
    }

    /// 测试专用：写入一个**非文本**剪贴板内容（自定义格式），用于验证
    /// [`with_clipboard_paste`] 对"非文本内容被清空"的告警路径。
    #[cfg(test)]
    pub(crate) fn seed_clipboard_non_text() -> Result<(), String> {
        use windows::Win32::System::DataExchange::{
            CloseClipboard, EmptyClipboard, SetClipboardData,
        };
        use windows::Win32::System::Memory::{
            GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
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

    /// 打开剪贴板（带重试）。OpenClipboard 会因其他进程短暂持有剪贴板
    /// 而失败（剪贴板监听器/rdpclip 场景很常见）；按 Win32 惯例小间隔
    /// 重试若干次再放弃，避免把瞬时竞争当成硬错误。
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

    /// 写入文本到剪贴板（内部 Open/Close，可独立调用）。返回 Err 的原文
    /// 可直接作为"恢复失败"警告使用。
    fn set_clipboard_text(value: &str) -> Result<(), String> {
        unsafe {
            open_clipboard_with_retry().map_err(|_| "cannot reopen clipboard".to_string())?;
            let result = (|| {
                let _ = EmptyClipboard();
                let mut wide: Vec<u16> = value.encode_utf16().collect();
                wide.push(0);
                let bytes = wide.len() * 2;
                let h =
                    GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(|e| format!("GlobalAlloc: {e}"))?;
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
        //! 供本模块测试创建目标窗口（跨进程套件在 ../fill-test 独立 crate）。
        //! 测试窗口是真实顶层窗口：验证的就是"枚举子控件 → 分类 → 逐控件
        //! 重验证 → WM_SETTEXT → 读回"整条链。
        //!
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

            /// 真实 pid + 类名 + 可执行文件路径组装可信快照（测试用）。
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
}
