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
    /// 捕获时生成的快照标识（P1 确认绑定）：用户确认时前端携带此 id，
    /// 注入命令在异步解密（在途窗口）完成后按 id 与当前槽位比对——
    /// 不一致/槽位已空一律拒绝，在途请求绝不转投重新捕获的新目标。
    pub snapshot_id: String,
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

/// 确认绑定拒绝原因（P1 收紧：确认绑定到具体快照，在途请求不得转投新目标）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmBindRejection {
    /// 请求未携带 snapshot_id（协议不符/旧前端）——确认面协议错误优先报出
    SnapshotRequired,
    /// 槽位为空：浮窗已收起/目标已被清（隐藏即丢弃）——携旧 id 的在途请求如实拒绝
    TargetDiscarded,
    /// 槽位已被新一轮捕获替换：确认 A 之后浮窗重新捕获了 B——携 A 的 id 拒绝，不注入 B
    TargetChanged,
}

/// 把「用户确认」绑定到具体快照（P1 收紧，平台无关纯函数）。
///
/// 命令层在异步解密（在途窗口）完成后、注入前调用：请求必须携带捕获时
/// 生成的 `snapshot_id`，且与**当前槽位**一致才放行。绑定成功返回的是被
/// 确认的那份快照的克隆（命令层随后对该快照做指纹重验证后注入——注入
/// 目标因此与用户确认的目标一一对应，而不是「解密完成那一刻的槽位」）：
/// - `requested` 缺失 → [`ConfirmBindRejection::SnapshotRequired`]；
/// - 槽位已空（浮窗收起清槽/失效清槽）→ [`ConfirmBindRejection::TargetDiscarded`]；
/// - 槽位已是别的快照（确认后重新唤起浮窗捕获了新目标）→
///   [`ConfirmBindRejection::TargetChanged`]——绝不转投新目标。
pub fn bind_confirmed_snapshot(
    slot: Option<&FillTarget>,
    requested_snapshot_id: Option<&str>,
) -> Result<FillTarget, ConfirmBindRejection> {
    let Some(requested) = requested_snapshot_id else {
        return Err(ConfirmBindRejection::SnapshotRequired);
    };
    let Some(target) = slot else {
        return Err(ConfirmBindRejection::TargetDiscarded);
    };
    if target.snapshot_id != requested {
        return Err(ConfirmBindRejection::TargetChanged);
    }
    Ok(target.clone())
}

/// 捕获时生成快照标识（P1 确认绑定）：UUID v4，唯一标识一份捕获。
/// 非 Windows 编译单元里没有捕获路径（槽位恒空），保留此函数供平台
/// 无关的绑定语义测试与未来平台实现使用。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn new_snapshot_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// 注入失败/中止的**如实形态**（第四轮取消边界收口）：命令层据此区分
/// 「常规拒绝（什么都没写）」与「注入中途快照失效（已写入的字段如实
/// 携带部分完成结果）」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillError {
    /// 常规拒绝：目标指纹不符（`CAPTURED_TARGET_INVALID`）、无合格
    /// ES_PASSWORD 框、逐控件重验证失败等——原文透传，与历史 String
    /// 错误一致，此形态下未发生任何字段写入。
    Rejected(String),
    /// 注入中途快照失效：槽位在字段写入之间被清（浮窗收起，
    /// [`ConfirmBindRejection::TargetDiscarded`]）或被新一轮捕获替换
    ///（确认 A 后捕获了 B，[`ConfirmBindRejection::TargetChanged`]）。
    /// **已写入的字段如实携带**（部分完成），剩余写入全部中止——
    /// 注入目标与用户确认的快照一一对应，绝不把剩余字段写进新目标。
    Aborted {
        reason: ConfirmBindRejection,
        username_filled: bool,
        password_filled: bool,
        title: String,
    },
}

/// 命令层的槽位重查闭包工厂：绑定比较（解密完成后锁内）与注入循环
/// 逐字段写入前的重查**共用同一语义**——按 snapshot_id 与当前槽位比对，
/// 槽位为空 → [`ConfirmBindRejection::TargetDiscarded`]，槽位已被新快照
/// 替换 → [`ConfirmBindRejection::TargetChanged`]。返回的闭包只做锁内
/// 比对（不克隆），可在注入循环内反复调用。
pub(crate) fn slot_recheck_for(
    slot: &std::sync::Mutex<Option<FillTarget>>,
    snapshot_id: String,
) -> impl Fn() -> Result<(), ConfirmBindRejection> + '_ {
    move || {
        let guard = slot.lock().unwrap_or_else(|p| p.into_inner());
        // 恒携带 Some(id)，SnapshotRequired 分支不可达；防御性按通过处理
        bind_confirmed_snapshot(guard.as_ref(), Some(&snapshot_id)).map(|_| ())
    }
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
/// → 逐控件写入前重验证 + 快照有效性重查 → WM_SETTEXT 注入；
/// 其他平台 = 恒 Err（命令层先有 `fill_supported()` 前置检查，这里是兜底）。
/// 返回 (用户名是否注入, 密码是否注入, 目标窗口标题)。
///
/// `slot_recheck`：注入循环内**每个字段写入前**的快照有效性重查（第四轮
/// 取消边界收口）——绑定比较在锁内完成后注入锁外执行，期间浮窗可能收起
/// 清槽或重新捕获了别的目标；每个字段写入前经此闭包重查「快照 id 仍是
/// 当前绑定且未被清/换」，失效即中止剩余写入，已写入的字段以
/// [`FillError::Aborted`] 如实报部分完成。
#[cfg(target_os = "windows")]
pub fn execute_fill(
    target: &FillTarget,
    username: &str,
    password: &str,
    self_pid: u32,
    slot_recheck: &dyn Fn() -> Result<(), ConfirmBindRejection>,
) -> Result<(bool, bool, String), FillError> {
    if !win::validate_target(target, self_pid) {
        return Err(FillError::Rejected("CAPTURED_TARGET_INVALID".to_string()));
    }
    let fields = win::enumerate_edit_fields(target.hwnd);
    if fields.is_empty() {
        return Err(FillError::Rejected(format!(
            "Target window \"{}\" has no classic edit controls (self-drawn UI is not supported; browser fill goes through the extension)",
            target.title
        )));
    }
    let Some(classified) = classify_fields(&fields) else {
        return Err(FillError::Rejected(format!(
            "Target window \"{}\" has no eligible ES_PASSWORD field; refusing to fill (plain edit controls are never treated as password fields)",
            target.title
        )));
    };
    let aborted = |reason, username_filled: bool, password_filled: bool| FillError::Aborted {
        reason,
        username_filled,
        password_filled,
        title: target.title.clone(),
    };
    let mut username_filled = false;
    if let Some(user_hwnd) = classified.username_hwnd {
        if !username.is_empty() {
            // 快照有效性重查：绑定比较之后注入在锁外执行，username 写入前
            // 槽位可能已被清（浮窗收起）或被新一轮捕获替换——失效即中止，
            // 不把已确认的凭据写进非确认目标
            slot_recheck().map_err(|reason| aborted(reason, false, false))?;
            win::revalidate_field(user_hwnd, target.hwnd, target.pid, false)
                .map_err(FillError::Rejected)?;
            username_filled = win::inject_settext(user_hwnd, username).is_ok();
        }
    }
    // 密码框写入前再做一次逐控件重验证：枚举到写入之间子 HWND 可被
    // 销毁复用，样式/归属可能已变（见模块头"目标可信模型"第 3 条）。
    // 同样先重查快照有效性：第一字段写入完成到此刻之间槽位仍可能被清/换
    //（可控制时序的真机用例：清槽钩子落在第一字段写入之后）——失效即
    // 中止剩余写入，已写入的字段以 Aborted 如实报部分完成。
    slot_recheck().map_err(|reason| aborted(reason, username_filled, false))?;
    win::revalidate_field(classified.password_hwnd, target.hwnd, target.pid, true)
        .map_err(FillError::Rejected)?;
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
    _slot_recheck: &dyn Fn() -> Result<(), ConfirmBindRejection>,
) -> Result<(bool, bool, String), FillError> {
    Err(FillError::Rejected(
        "Desktop fill injection is only implemented on Windows".to_string(),
    ))
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
    /// 当前有效快照的标识（P1 确认绑定）：确认面捕获此 id，注入请求
    /// 必须原样带回——后端按它把确认绑定到具体快照（无目标/已失效为 null）
    pub snapshot_id: Option<String>,
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
pub mod win;

#[cfg(test)]
mod tests;
