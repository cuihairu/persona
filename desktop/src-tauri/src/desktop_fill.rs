//! Desktop fill injection（对标 FEATURE_GAP_ANALYSIS #12：Windows 桌面应用
//! 内的填充注入路径）。
//!
//! 口径（与 #22 一致）：**浮窗负责取件与确认目标，注入由桌面端安全路径
//! 执行**——浏览器里的填充走浏览器扩展（Native Messaging 桥），本模块只
//! 负责"非浏览器原生桌面应用"的取件后填充：用户在检索浮窗选中凭据 →
//! **明确确认注入目标（目标应用可执行文件名 + 窗口标题）** → 注入。
//!
//! 选型（设计小节见 docs/src/design/desktop-fill.md，此处只留结论）：
//! - **首选 WM_SETTEXT 直写**：枚举目标窗口的经典 Win32 EDIT 子控件，
//!   用户名 = 第一个可用的非密码框，密码 = 第一个可用（可见/启用/非只读）
//!   的 `ES_PASSWORD` 样式框。**没有密码样式框就拒绝注入**——历史版本曾
//!   退回"第二个框"启发式，已在安全评审（codex 2026-11-05）后移除：任意
//!   前台进程布置两个普通 Edit 就能伪装登录框骗取密码，启发式是漏洞不是
//!   兜底。直写不依赖焦点、不模拟键击、跨进程可靠（同一桌面会话内）。
//!   代价：Electron/Qt/浏览器等自绘输入框不吃 WM_SETTEXT——这类宿主本就
//!   该走浏览器扩展或 UIA，属诚实边界而非缺陷。
//! - **备选剪贴板中转**（`with_clipboard_paste` + `paste_into_focused`）：
//!   目前**未接入生产路径**（生产只走 WM_SETTEXT）。且须如实说明：系统
//!   剪贴板是全会话共享的，驻留期间任何同桌面进程都可读取，本模块的
//!   备份/恢复只缩短暴露窗口，不提供保密保证。启用前须明确披露该边界。
//! - **不做 UIA**：UI Automation 可覆盖自绘控件，但引入
//!   `Win32_UI_Accessibility` 依赖面 + COM 生命周期管理，首版不引入；
//!   作为后续对自绘宿主的扩展点记录在本注释里。
//!
//! 目标可信模型（安全评审后收紧）：
//! 1. **指纹三要素快照**：热键唤起浮窗时（`toggle_window` 的 show 分支）
//!    目标应用还持有前台——此刻 `GetForegroundWindow` 拿到的就是注入对象；
//!    存 hwnd + 标题 + pid + **顶层窗口类名 + 进程可执行文件完整路径**
//!    到运行态。可执行文件路径查不到（权限/进程已退出）就**不建立目标**
//!    ——没有指纹就没有可信注入。
//! 2. **注入前重验证三要素**：hwnd 存活、pid 未换、类名一致、可执行文件
//!    一致；标题按快照前缀比对（非空快照才启用前缀；空标题必须仍为空，
//!    堵住历史版本 `starts_with("")` 恒真的洞）。pid 等于本进程的窗口
//!    永不作为目标（浮窗/主窗口自己）。
//! 3. **逐控件写入前重验证**：枚举结果到 SendMessageW 之间子 HWND 可被
//!    销毁复用——每个字段写入前重核验 IsWindow、GA_ROOT 归属目标窗口、
//!    pid、类名 Edit、样式（密码框必须仍带 ES_PASSWORD）、可见/启用/
//!    非只读。Win32 校验非原子，校验与写入之间仍有极小竞态窗口——这是
//!    平台固有剩余风险，由第 4 条的用户显式确认面兜底（用户看得到目标
//!    应用名，填错窗可即时察觉）。
//! 4. **注入前用户确认**：浮窗展示目标应用名（可执行文件名）与窗口标题，
//!    用户显式确认后命令层才放行（`desktop_fill_credential` 的
//!    `confirmed` 参数），不存在静默直写路径。
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
    /// 捕获时刻的窗口标题（注入时按前缀重验证，防 hwnd 复用；空标题只有
    /// 在当前标题也为空时才放行）
    pub title: String,
    /// 捕获时刻的窗口所属进程 id（注入时校验仍属同进程）
    pub pid: u32,
    /// 捕获时刻的顶层窗口类名（指纹三要素之二）
    pub window_class: String,
    /// 捕获时刻目标进程可执行文件完整路径（指纹三要素之三；查不到就不建目标）
    pub exe_path: String,
}

/// 单个候选输入框的状态（枚举产出，分类与逐控件重验证共用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldState {
    pub hwnd: isize,
    /// 控件带 `ES_PASSWORD` 样式
    pub is_password: bool,
    /// IsWindowVisible
    pub visible: bool,
    /// IsWindowEnabled
    pub enabled: bool,
    /// 带 `ES_READONLY` 样式（只读框不可注入）
    pub read_only: bool,
}

impl FieldState {
    /// 可注入资格：可见、启用、非只读。密码框另需 ES_PASSWORD 样式。
    pub fn eligible(&self) -> bool {
        self.visible && self.enabled && !self.read_only
    }
}

/// 字段分类结果：可选的用户名框 + 必须存在的密码框句柄
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedFields {
    /// None = 目标窗口没有可用的用户名框（只填密码，结果里如实回报）
    pub username_hwnd: Option<isize>,
    /// 必填：没有合格的 ES_PASSWORD 框时 `classify_fields` 整体返回 None
    pub password_hwnd: isize,
}

/// 字段分类（平台无关，纯函数可测）。
///
/// 输入按 Z 序（EnumChildWindows 顺序）传入各框状态：
/// - 密码 = 第一个**合格**（可见/启用/非只读）的 `ES_PASSWORD` 框；
///   **找不到密码样式框 → 整体拒绝**（None）。不再猜"第二个框"：
///   普通框可能是攻击者伪装的明文收集器。
/// - 用户名 = 第一个合格的非密码框；没有合格用户名框时允许只填密码。
/// - 全部是密码样式框（改密对话框）：没有用户名框，只填密码——改密
///   对话框不是本功能的目标形态，密码写入由确认面提示用户核对目标。
pub fn classify_fields(fields: &[FieldState]) -> Option<ClassifiedFields> {
    let password = fields
        .iter()
        .find(|f| f.is_password && f.eligible())
        .map(|f| f.hwnd)?;
    let username = fields
        .iter()
        .find(|f| !f.is_password && f.eligible())
        .map(|f| f.hwnd);
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
/// Windows = 重验证指纹三要素 → 枚举 EDIT 框 → 分类（必须有合格密码框）
/// → 逐控件写入前重验证 → WM_SETTEXT 注入；
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
            "Target window \"{}\" has no eligible ES_PASSWORD field; refusing to fill (plain edit controls are never treated as password fields)",
            target.title
        ));
    };
    let mut username_filled = false;
    if let Some(user_hwnd) = classified.username_hwnd {
        if !username.is_empty() {
            win::revalidate_field(user_hwnd, target.hwnd, target.pid, false)?;
            username_filled = win::inject_settext(user_hwnd, username).is_ok();
        }
    }
    // 密码框写入前再做一次逐控件重验证：枚举到写入之间子 HWND 可被
    // 销毁复用，样式/归属可能已变（见模块头"目标可信模型"第 3 条）。
    win::revalidate_field(classified.password_hwnd, target.hwnd, target.pid, true)?;
    let password_filled = win::inject_settext(classified.password_hwnd, password).is_ok();
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
/// 逐字对齐）。只带标题与应用名，**不带 hwnd/pid/可执行文件完整路径**
/// ——句柄与路径对前端无用，暴露进程内指针反而扩大信息面。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillTargetStatus {
    /// 本平台是否实现了注入路径
    pub supported: bool,
    /// 有已捕获且**当前仍然有效**的注入目标（失效目标即时清槽）
    pub ready: bool,
    /// 目标窗口标题（无目标/已失效时为 null）
    pub target_title: Option<String>,
    /// 目标应用可执行文件名（如 "notepad.exe"；确认面展示用）
    pub target_app: Option<String>,
}


/// 目标应用可执行文件名（确认面展示用，如 "notepad.exe"）。平台无关的
/// 纯字符串处理（路径分隔符按 Win32/Unix 两种都切）。
pub fn exe_file_name(exe_path: &str) -> String {
    exe_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe_path)
        .to_string()
}

/// `desktop_fill_credential` 的返回形状（snake_case：前端 `DesktopFillResult`
/// 逐字对齐）。逐字段结果而非整体布尔：单字段失败（如目标只有密码框）
/// 时前端能如实说"只填了密码"。
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
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;
    use windows::Win32::System::Threading::{
        AttachThreadInput, GetCurrentThreadId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        IsWindowEnabled, SendInput, SetFocus, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
        KEYEVENTF_KEYUP, VK_CONTROL, VK_V, VIRTUAL_KEY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumChildWindows, GetAncestor, GetClassNameW, GetForegroundWindow, GetWindowLongPtrW,
        GetWindowThreadProcessId, GetWindowTextLengthW, GetWindowTextW, IsWindow,
        IsWindowVisible, SendMessageW, SetForegroundWindow, GA_ROOT, GWL_STYLE, WM_GETTEXT,
        WM_GETTEXTLENGTH, WM_SETTEXT, ES_PASSWORD, ES_READONLY,
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
        unsafe {
            open_clipboard_with_retry()?;
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
            let set = closed.and_then(|()| set_clipboard_text(value));

            // catch_unwind：闭包 panic 不能绕过剪贴板恢复（panic 信息在
            // 恢复之后按 ResumeUnwind 语义重新抛出）
            let paste_result = set.map(|()| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(paste))
            });

            // 恢复：写回备份（无文本备份则写空串，把密文清掉）
            let restore_warning = restore_clipboard(backup.as_deref().unwrap_or(""));

            match paste_result {
                // set_clipboard_text 失败（String）
                Err(e) => Err(e),
                // 闭包 panic：恢复已完成，原样重抛
                Ok(Err(payload)) => std::panic::resume_unwind(payload),
                Ok(Ok(v)) => match restore_warning {
                    None => Ok((v, None)),
                    Some(w) => Ok((v, Some(w))),
                },
            }
        }
    }

    /// 测试专用：直接写入剪贴板文本（绕过备份/恢复语义，用于给
    /// [`with_clipboard_paste`] 的闭环测试造"原有内容"）。
    #[cfg(test)]
    pub(crate) fn seed_clipboard(value: &str) -> Result<(), String> {
        set_clipboard_text(value)
    }

    /// 打开剪贴板（带重试）。OpenClipboard 会因其他进程短暂持有剪贴板
    /// 而失败（剪贴板监听器/rdpclip 场景很常见）；按 Win32 惯例小间隔
    /// 重试若干次再放弃，避免把瞬时竞争当成硬错误。
    fn open_clipboard_with_retry() -> Result<(), String> {
        for attempt in 0u32..10 {
            if unsafe { OpenClipboard(None) }.is_ok() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(20 * u64::from(attempt + 1)));
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

    /// 供本模块测试创建目标窗口（跨进程套件在 ../fill-test 独立 crate）。
    /// 测试窗口是真实顶层窗口：验证的就是"枚举子控件 → 分类 → 逐控件
    /// 重验证 → WM_SETTEXT → 读回"整条链。
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
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod win_tests {
    //! Windows 真会话集成测试：靶窗是真实 Win32 窗口（同一桌面会话），
    //! 跑的是"捕获 → 枚举 → 分类 → 逐控件重验证 → 注入 → 读回"整条真链，
    //! 不是 mock。

    use super::classify_fields;
    use super::win::test_window::TestTargetWindow;
    use super::win::{enumerate_edit_fields, read_field_text, revalidate_field, validate_target};
    use super::{execute_fill, FillTarget};

    /// 用户名/密码框识别 + execute_fill 全链（指纹验证 → 枚举 → 分类 →
    /// 逐控件重验证 → WM_SETTEXT）注入 + WM_GETTEXT 读回一致。
    /// 这是桌面填充的真机验收核心断言（openclaw Windows Server 2022 跑）。
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

        // 全链注入：self_pid 伪造成别的进程（快照 pid 是真实测试进程 pid）
        let snapshot = target.snapshot("persona fill test - login");
        let fake_self_pid = std::process::id().wrapping_add(1).max(1);
        let (user_filled, pwd_filled, title) =
            execute_fill(&snapshot, "alice@example.com", "s3cret-Пароль⚡", fake_self_pid)
                .expect("execute_fill");
        assert!(user_filled && pwd_filled);
        assert_eq!(title, "persona fill test - login");
        assert_eq!(read_field_text(target.username), "alice@example.com");
        assert_eq!(read_field_text(target.password), "s3cret-Пароль⚡");
        target.destroy();
    }

    /// 无任何 ES_PASSWORD 框 → 拒绝注入（历史"第二个框"启发式已移除：
    /// 普通框可能是攻击者伪装的明文收集器）。
    #[test]
    fn plain_only_window_is_rejected_no_password_guessing() {
        let target = TestTargetWindow::create("persona fill test - plain", false).expect("create");
        let fields = enumerate_edit_fields(target.top);
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().all(|f| !f.is_password));
        assert!(classify_fields(&fields).is_none(), "no ES_PASSWORD field must reject classification");
        let snapshot = target.snapshot("persona fill test - plain");
        let fake_self_pid = std::process::id().wrapping_add(1).max(1);
        let err = execute_fill(&snapshot, "alice", "s3cret", fake_self_pid)
            .expect_err("plain-only window must be rejected");
        assert!(err.contains("ES_PASSWORD"), "error must mention ES_PASSWORD: {err}");
        // 两个普通框都必须原样为空（没写进去任何东西）
        assert_eq!(read_field_text(target.username), "");
        assert_eq!(read_field_text(target.password), "");
        target.destroy();
    }

    /// 分类守卫（纯函数）：不可见/禁用/只读的密码框不合格；只有不可见
    /// 密码框时整体拒绝。
    #[test]
    fn classification_guards_ineligible_fields() {
        use super::FieldState as F;
        // 只读密码框：不合格 → 无合格密码框 → 拒绝
        let ro = vec![F { hwnd: 1, is_password: true, visible: true, enabled: true, read_only: true }];
        assert!(classify_fields(&ro).is_none());
        // 隐藏密码框：拒绝
        let hidden = vec![F { hwnd: 2, is_password: true, visible: false, enabled: true, read_only: false }];
        assert!(classify_fields(&hidden).is_none());
        // 禁用密码框：拒绝
        let disabled = vec![F { hwnd: 3, is_password: true, visible: true, enabled: false, read_only: false }];
        assert!(classify_fields(&disabled).is_none());
        // 隐藏密码框 + 可见用户名框：仍然拒绝（不能只填用户名进可疑窗口）
        let mixed = vec![
            F { hwnd: 4, is_password: false, visible: true, enabled: true, read_only: false },
            F { hwnd: 5, is_password: true, visible: false, enabled: true, read_only: false },
        ];
        assert!(classify_fields(&mixed).is_none());
        // 合格密码框 + 隐藏用户名框：填密码，用户名如实报未填
        let pwd_only = vec![
            F { hwnd: 6, is_password: false, visible: false, enabled: true, read_only: false },
            F { hwnd: 7, is_password: true, visible: true, enabled: true, read_only: false },
        ];
        let c = classify_fields(&pwd_only).unwrap();
        assert_eq!(c.username_hwnd, None);
        assert_eq!(c.password_hwnd, 7);
        // 空目标
        assert!(classify_fields(&[]).is_none());
    }

    /// 逐控件写入前重验证：死句柄拒绝、只读/禁用/隐藏拒绝、密码框丢失
    /// ES_PASSWORD 样式拒绝（hwnd 复用字段角色对调的场景）。
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
        // 好路径
        revalidate_field(target.password, target.top, pid, true).expect("eligible password field");
        revalidate_field(target.username, target.top, pid, false).expect("eligible username field");
        // 死句柄
        assert!(revalidate_field(0xDEAD_BEEFisize, target.top, pid, true).is_err());
        target.destroy();
        // 销毁后全部拒绝
        assert!(revalidate_field(target.password, target.top, pid, true).is_err());
        assert!(revalidate_field(target.username, target.top, pid, false).is_err());
    }

    /// 目标重验证（真 hwnd 走 validate_snapshot）：pid 不符拒绝、标题前缀
    /// 不符拒绝、空标题不再恒真、死句柄拒绝、销毁后拒绝；validate_target
    /// 对本进程窗口（pid == self_pid）恒拒绝。
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
        assert!(!class.is_empty() && !exe.is_empty(), "fingerprint helpers must work in-test");

        // 指纹全对（self_pid 伪造成别的进程）→ 放行
        assert!(
            validate_snapshot(target.top, "persona fill test - validate", real_pid, &class, &exe, fake_other_pid),
            "matching snapshot must pass"
        );

        // 标题前缀不一致 → 拒绝（模拟 hwnd 复用到别的窗口）
        assert!(
            !validate_snapshot(target.top, "totally different window", real_pid, &class, &exe, fake_other_pid),
            "stale title must be rejected"
        );

        // 空快照标题 + 非空当前标题 → 拒绝（堵 starts_with("") 恒真的洞）
        assert!(
            !validate_snapshot(target.top, "", real_pid, &class, &exe, fake_other_pid),
            "empty snapshot title must not match a titled window"
        );

        // 快照 pid 乱填（=0）与真实 pid 不符 → 拒绝
        assert!(
            !validate_snapshot(target.top, "persona fill test - validate", 0, &class, &exe, fake_other_pid),
            "mismatched pid must be rejected"
        );

        // 类名不符 → 拒绝
        assert!(
            !validate_snapshot(target.top, "persona fill test - validate", real_pid, "OtherClass", &exe, fake_other_pid),
            "mismatched class must be rejected"
        );

        // 可执行文件路径不符 → 拒绝（同标题同 pid 的伪装进程场景）
        assert!(
            !validate_snapshot(target.top, "persona fill test - validate", real_pid, &class, "C:\\attacker.exe", fake_other_pid),
            "mismatched exe path must be rejected"
        );

        // 死句柄 → 拒绝
        assert!(!validate_snapshot(0xDEAD_BEEFisize, "", real_pid, &class, &exe, fake_other_pid));

        // validate_target 层：本进程窗口（pid == self_pid）恒拒绝
        let own = FillTarget {
            hwnd: target.top,
            title: "persona fill test - validate".to_string(),
            pid: real_pid,
            window_class: class.clone(),
            exe_path: exe.clone(),
        };
        assert!(!validate_target(&own, real_pid), "own-process window must be rejected");

        target.destroy();
        assert!(
            !validate_snapshot(target.top, "persona fill test - validate", real_pid, &class, &exe, fake_other_pid),
            "destroyed window must be rejected"
        );
    }

    /// 剪贴板备份/恢复闭环：粘贴期间密文在场、结束后原内容恢复；
    /// 闭包 panic 不绕过恢复。
    #[test]
    fn clipboard_backup_restore_roundtrip() {
        use super::win::{seed_clipboard, with_clipboard_paste};
        // 预置"原有内容"（直接写，不走备份/恢复语义）
        seed_clipboard("PREV-VALUE").expect("seed clipboard");
        assert_eq!(read_clipboard_text(), "PREV-VALUE");

        // 粘贴假密文：断言闭包期间读到的是密文、结束后恢复 PREV-VALUE
        let seen = std::cell::RefCell::new(String::new());
        let (_, warn) = with_clipboard_paste("TOP-SECRET", || {
            *seen.borrow_mut() = read_clipboard_text();
        })
        .expect("paste roundtrip");
        assert_eq!(seen.borrow().as_str(), "TOP-SECRET", "secret must be on clipboard during paste");
        assert_eq!(read_clipboard_text(), "PREV-VALUE", "previous content must be restored");
        assert!(warn.is_none(), "restore should not warn: {warn:?}");

        // 无原有内容时：结束后密文被清掉（写空串），不残留
        seed_clipboard("").expect("clear clipboard");
        let (_, _) = with_clipboard_paste("GHOST", || ()).expect("paste roundtrip 2");
        assert_eq!(read_clipboard_text(), "", "no prior content must leave no residue");

        // 闭包 panic：恢复仍要发生，panic 在恢复之后传播
        seed_clipboard("PREV-PANIC").expect("seed clipboard 2");
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_clipboard_paste("PANIC-SECRET", || panic!("boom in paste closure"));
        }));
        assert!(panicked.is_err(), "closure panic must propagate after restore");
        assert_eq!(read_clipboard_text(), "PREV-PANIC", "panic must not bypass clipboard restore");
    }

    /// 本机常有剪贴板监听进程短暂持有剪贴板（OpenClipboard 瞬时失败时
    /// `read_clipboard_text_once` 静默返回空串）；读回断言先小间隔重试，
    /// 把瞬时竞争与真实空剪贴板区分开（重试耗尽仍为空按空处理）。
    fn read_clipboard_text() -> String {
        let mut last = String::new();
        for _ in 0..20 {
            let text = read_clipboard_text_once();
            if !text.is_empty() {
                return text;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        last
    }

    fn read_clipboard_text_once() -> String {
        use windows::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, OpenClipboard,
        };
        use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
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
    use super::{classify_fields, fill_supported, FieldState};

    #[test]
    fn platform_reports_unsupported() {
        assert!(!fill_supported(), "non-windows must report unsupported");
    }

    #[test]
    fn classification_requires_eligible_es_password_field() {
        let f = |hwnd: isize, pwd: bool, vis: bool, en: bool, ro: bool| FieldState {
            hwnd,
            is_password: pwd,
            visible: vis,
            enabled: en,
            read_only: ro,
        };
        // 正常：用户名第一个合格非密码框，密码第一个合格密码样式框
        let ok = vec![f(1, false, true, true, false), f(2, true, true, true, false), f(3, true, true, true, false)];
        let c = classify_fields(&ok).unwrap();
        assert_eq!(c.username_hwnd, Some(1));
        assert_eq!(c.password_hwnd, 2);
        // 没有任何密码样式框：**整体拒绝**（不再猜"第二个框"）
        let plain_only = vec![f(7, false, true, true, false), f(8, false, true, true, false)];
        assert!(classify_fields(&plain_only).is_none());
        // 全密码框：没有用户名框，只填密码
        let all_pwd = vec![f(1, true, true, true, false), f(2, true, true, true, false)];
        let c = classify_fields(&all_pwd).unwrap();
        assert_eq!(c.username_hwnd, None);
        assert_eq!(c.password_hwnd, 1);
        // 只读密码框不合格 → 拒绝
        let ro = vec![f(9, true, true, true, true)];
        assert!(classify_fields(&ro).is_none());
        // 隐藏密码框不合格 → 拒绝
        let hidden = vec![f(10, true, false, true, false)];
        assert!(classify_fields(&hidden).is_none());
        // 禁用密码框不合格 → 拒绝
        let disabled = vec![f(11, true, true, false, false)];
        assert!(classify_fields(&disabled).is_none());
        // 密码框合格但用户名框全部不合格：只填密码
        let pwd_only = vec![f(12, false, false, true, true), f(13, true, true, true, false)];
        let c = classify_fields(&pwd_only).unwrap();
        assert_eq!(c.username_hwnd, None);
        assert_eq!(c.password_hwnd, 13);
        // 空目标
        assert!(classify_fields(&[]).is_none());
    }
}
