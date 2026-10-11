//! Quick Access：OS 级全局热键唤出的浮窗（对标矩阵 #22）。
//!
//! 机制分层：
//! - **装载面**：global-shortcut 插件在 `setup` 里**运行时装载**
//!   （[`install_plugin`]，不用 `Builder::plugin`）。原因是它的 `setup`
//!   会建 X11/平台热键管理器，失败即 Err——走 Builder 链的话这个 Err 会
//!   让整个 app 构建失败（`.expect` 直接 panic），一个"锦上添花的全局热键
//!   不该让密码管理器起不来"。headless Linux/无 XWayland 正是这条路径。
//! - **注册面**（本模块其余部分）：两个独立绑定各自抢注——Quick Access
//!   检索浮窗（对标矩阵 #22）与密码生成器浮窗（#9 余项）。成功才把
//!   `registered` 记为 Some。**抢注失败不静默**：原因进 `last_error`，
//!   设置页如实显示（被别的应用/WM 占用、平台不支持都会走到这里）。
//!   改绑**只注销自己的旧键**（`unregister` 单个），不动另一个绑定。
//! - **浮窗面**：`quick-access` / `generator-panel` 两个无边框置顶小窗
//!   （tauri.conf.json 声明，初始 `visible: false`）。热键是 toggle：
//!   已显示则隐藏（把焦点还给原应用），未显示则 show + focus + emit
//!   该窗口的 OPENED 事件让前端重置状态。
//!
//! 真值源纪律：绑定与开关的**持久化真值**在 workspace settings
//! （`quick_access_enabled` / `quick_access_hotkey`，见
//! `core::models::WorkspaceSettings`）。本模块只持进程内运行态；解锁成功后
//! 由 `commands::apply_quick_access` 从 DB 重新下发（[`apply_from_settings`]），
//! 改绑走 `commands::quick_access_set`（先落库再重注册）。前端不参与决定
//! 抢注什么键。
//!
//! 已知边界（诚实记录，不在文档里吹）：
//! - Linux 只走 X11（global-hotkey 用 x11-dl 运行时 dlopen，不链 X 库）；
//!   Wayland 需 XWayland，无则抢注失败并如实上报。
//! - 浮窗内的检索/复制全部经已解锁的 service；锁定态唤起只显示"需先解锁"
//!   并把主窗口拉到前台（不在浮窗里复刻解锁流，见 THREAT_MODEL 登记）。

use std::str::FromStr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_global_shortcut::{GlobalShortcut, ShortcutState};

use persona_core::models::WorkspaceSettings;

/// 浮窗标签（tauri.conf.json 里 windows[1].label 必须一致）
pub const WINDOW_LABEL: &str = "quick-access";

/// 生成器浮窗标签（tauri.conf.json 里同名 window 的 label 必须一致）
pub const GENERATOR_WINDOW_LABEL: &str = "generator-panel";

/// 浮窗被热键唤起时向自身 webview 发的事件：前端据此清空上一次查询、
/// 聚焦输入框（同一进程内多窗口的 wake 通道，不用轮询）
pub const OPENED_EVENT: &str = "persona://quick-access-opened";

/// 生成器浮窗的唤醒事件（同 [`OPENED_EVENT`] 语义，各自的 webview 各听各的）
pub const GENERATOR_OPENED_EVENT: &str = "persona://generator-panel-opened";

/// 浮窗里"在 Persona 中打开"→ 主窗口：事件 + 载荷（跨 webview 唯一通道，
/// 两个窗口各有独立的 JS store，不能靠前端内存互传）
pub const OPEN_CREDENTIAL_EVENT: &str = "persona://quick-access-open-credential";

/// 主窗口标签（tauri.conf.json windows[0].label）
pub const MAIN_WINDOW_LABEL: &str = "main";

/// 浮窗不存在时的失败原因（热键的作用对象都没了，抢注无意义）
const ERR_WINDOW_MISSING: &str = "quick-access window is not available";

/// [`OPEN_CREDENTIAL_EVENT`] 的载荷（snake_case：与仓库既有 DTO 口径一致，
/// 前端 `types/index.ts` 的 `QuickAccessOpenCredential` 逐字对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCredentialPayload {
    pub identity_id: String,
    pub credential_id: String,
}

/// 进程内运行态（`AppState` 持有）。`registered` 与 DB 里的
/// `quick_access_hotkey` 不一定一致——抢注失败时前者为 None、后者保留，
/// 设置页据此显示"绑定为 X，实际未生效（原因）"
#[derive(Debug, Default)]
pub struct QuickAccessRuntime {
    /// 当前真正抢注成功的加速键（None = 未注册：关闭、抢注失败或未下发）
    pub registered: Option<String>,
    /// 最近一次抢注失败的原文（设置页展示；成功/关闭时清空）
    pub last_error: Option<String>,
    /// 生成器热键的抢注结果（语义同 `registered`，槽位独立互不影响）
    pub generator_registered: Option<String>,
    /// 生成器热键最近一次抢注失败的原文（语义同 `last_error`）
    pub generator_last_error: Option<String>,
    /// 插件装载失败原因（headless 会话 / 平台不支持）。与 `last_error` 分开
    /// 记：一个是"这台机器上全局热键根本起不来"，一个是"键被占用了"。
    /// 装载失败对两个绑定一视同仁（同一个插件实例）
    pub install_error: Option<String>,
}

impl QuickAccessRuntime {
    /// 收口成可序列化的状态面（`quick_access_status` 命令返回）
    pub fn snapshot(&self, settings: &WorkspaceSettings) -> QuickAccessStatus {
        let enabled = settings.quick_access_enabled;
        let configured = settings
            .quick_access_hotkey
            .clone()
            .unwrap_or_else(|| default_accelerator().to_string());
        QuickAccessStatus {
            enabled,
            // 设置页展示的绑定（DB 真值，未设置时是平台默认值）
            configured_accelerator: configured,
            // 实际生效的绑定（抢注成功才 Some）
            registered_accelerator: self.registered.clone(),
            // 一个就够 UI 说的失败原因：本次抢注失败优先于装载失败
            error: self
                .last_error
                .clone()
                .or_else(|| self.install_error.clone()),
        }
    }
}

/// `generator_status` 的返回形状（与 [`QuickAccessStatus`] 同构，字段
/// snake_case：前端 `GeneratorStatus` 逐字对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorStatus {
    /// 用户开关（DB 真值）
    pub enabled: bool,
    /// 设置页展示的绑定
    pub configured_accelerator: String,
    /// 实际抢注成功的绑定（None = 未生效）
    pub registered_accelerator: Option<String>,
    /// 未生效原因（抢注失败或插件装载失败）
    pub error: Option<String>,
}

impl GeneratorStatus {
    /// 从运行态 + 设置收口（与 [`QuickAccessRuntime::snapshot`] 同构）
    pub fn snapshot(runtime: &QuickAccessRuntime, settings: &WorkspaceSettings) -> Self {
        let enabled = settings.generator_panel_enabled;
        let configured = settings
            .generator_panel_hotkey
            .clone()
            .unwrap_or_else(|| default_generator_accelerator().to_string());
        GeneratorStatus {
            enabled,
            configured_accelerator: configured,
            registered_accelerator: runtime.generator_registered.clone(),
            error: runtime
                .generator_last_error
                .clone()
                .or_else(|| runtime.install_error.clone()),
        }
    }
}

/// `quick_access_status` 的返回形状（snake_case：命令响应面与仓库既有 DTO
/// 同口径，前端 `QuickAccessStatus` 逐字对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickAccessStatus {
    /// 用户开关（DB 真值）
    pub enabled: bool,
    /// 设置页展示的绑定
    pub configured_accelerator: String,
    /// 实际抢注成功的绑定（None = 未生效）
    pub registered_accelerator: Option<String>,
    /// 未生效原因（抢注失败或插件装载失败）
    pub error: Option<String>,
}

/// 平台默认绑定。macOS 用 ⌘⇧Space（与 Spotlight 习惯同构、且避开系统
/// 常用的 ⌘Space），Win/Linux 用 Ctrl+Shift+Space——**不用** Ctrl+Alt+\
/// 之类的低频键位：这类键在部分发行版/WM 已被窗口管理器占用，抢注失败率
/// 高，而失败只会被用户读成"功能坏了"。
#[cfg(target_os = "macos")]
pub const fn default_accelerator() -> &'static str {
    "Command+Shift+Space"
}

#[cfg(not(target_os = "macos"))]
pub const fn default_accelerator() -> &'static str {
    "Control+Shift+Space"
}

/// 生成器热键的平台默认绑定。macOS 用 ⌘⇧G（与 Finder「前往文件夹」重叠，
/// 全局注册后生成器优先——介意可在设置页改绑），Win/Linux 用
/// Ctrl+Shift+G（避开 WM 高频占用键位，与检索浮窗默认键同构好记）
#[cfg(target_os = "macos")]
pub const fn default_generator_accelerator() -> &'static str {
    "Command+Shift+G"
}

#[cfg(not(target_os = "macos"))]
pub const fn default_generator_accelerator() -> &'static str {
    "Control+Shift+G"
}

/// 校验并解析加速键串（tauri global-shortcut 语法）。空串与空白按"恢复
/// 平台默认"处理由调用方决定，这里只做语法判定
pub fn parse_accelerator(raw: &str) -> Result<tauri_plugin_global_shortcut::Shortcut, String> {
    tauri_plugin_global_shortcut::Shortcut::from_str(raw.trim())
        .map_err(|e| format!("invalid accelerator: {e}"))
}

/// 归一化（仅去空白）。**刻意不用 `Shortcut` 的 `Display`**：它会把
/// "Ctrl+Shift+Space" 改写成 "shift+control+Space"（小写修饰键 + 固定
/// 顺序），展示与回显都用原文更符合"设置页显示的就是我填的"
pub fn normalize_accelerator(raw: &str) -> String {
    raw.trim().to_string()
}

/// 装载 global-shortcut 插件（`setup` 调用；幂等）。
///
/// 运行时装载而非 `Builder::plugin`：插件 setup 里的
/// `GlobalHotKeyManager::new()` 在 headless Linux / 无 XWayland 的
/// Wayland 上会返回 Err，走 Builder 链这个 Err 会让 `build()` 失败、
/// `.expect` 直接 panic——全局热键不可用不该让整个密码管理器起不来。
/// 失败原因存进运行态，设置页能如实显示。
///
/// **必须挂 `with_handler`**（2026-09-28 修复"热键不生效"的根因）：
/// 插件的事件分发只有两路——`register()` 存的 per-shortcut handler
/// （Rust 侧 `register` 恒为 None）和 Builder 级 handler。此前两路
/// 都是 None：OS 抢注成功（无冲突报错）、`registered` 也记为 Some，
/// 但按键事件分发给空 handler，什么都不发生。挂在 Builder 级对
/// 本应用注册的任何加速键都生效（检索 + 生成器两个绑定）；只在
/// `Pressed` 沿触发——global-hotkey 的 Pressed/Released 都会上报，
/// 不过滤会 show 完立刻 hide。哪个键按下由运行态里的注册串反查
/// （[`dispatch_shortcut`]）：两个绑定抢到同一个加速键只可能有一个
/// 真注册成功（第二个 register 必撞 OS 冲突），不会双触发。
pub fn install_plugin<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    if app.try_state::<GlobalShortcut<R>>().is_some() {
        return Ok(());
    }
    app.plugin(
        tauri_plugin_global_shortcut::Builder::new()
            .with_handler(|app, shortcut, event| {
                if event.state == ShortcutState::Pressed {
                    dispatch_shortcut(app, shortcut);
                }
            })
            .build(),
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// 一次抢注的结果
enum Registration {
    /// 抢注成功，存的是**配置串**（不是 `Display` 归一化串）
    Registered(String),
    /// 开关关闭：主动释放本绑定的旧键（不动另一个绑定）
    Disabled,
    /// 没抢上，原因原样带给设置页
    Failed(String),
}

/// 按窗口标签定位该绑定在运行态里的槽位对（生成器与检索各一组字段）
fn slots_for<'a>(
    guard: &'a mut QuickAccessRuntime,
    window_label: &str,
) -> (&'a mut Option<String>, &'a mut Option<String>) {
    if window_label == GENERATOR_WINDOW_LABEL {
        (
            &mut guard.generator_registered,
            &mut guard.generator_last_error,
        )
    } else {
        (&mut guard.registered, &mut guard.last_error)
    }
}

/// 同步 OS 抢注状态并返回结果（不改运行态，由调用方统一落盘——避免
/// "先改状态后抢注失败"留下半截状态）。`previous` 是该绑定当前已注册
/// 的加速键串：改绑/关闭时**只注销自己这一个旧键**——`unregister_all`
/// 会把另一个绑定的键一起杀掉，两绑定并存后不能再全局清。
fn compute_registration<R: tauri::Runtime>(
    app: &AppHandle<R>,
    window_label: &str,
    accelerator: Option<&str>,
    previous: Option<String>,
) -> Registration {
    // 开关关闭最先判：关闭 = 用户明确不要热键，**不是失败**——浮窗缺失
    // /headless 等环境问题不该给关着的开关记一条错误原因（设置页会把
    // "已关闭"误渲染成"未生效（原因）"）。能拿到插件就只注销自己的旧键；
    // 拿不到（mock / 未装载）说明本来就没注册过，无需清理。
    let Some(raw) = accelerator else {
        if let (Some(plugin), Some(prev)) =
            (app.try_state::<GlobalShortcut<R>>(), previous.as_deref())
        {
            if let Ok(old) = parse_accelerator(prev) {
                let _ = plugin.unregister(old);
            }
        }
        return Registration::Disabled;
    };
    // 热键唯一作用是唤出浮窗：浮窗不在（集成测试的 mock context 就是
    // 没有窗口）就没什么可绑的，直接短路。顺带避开一个测试隐患——
    // mock runtime 的 run_on_main_thread 只排队不执行，插件 register 里
    // 的阻塞 recv 会把测试挂死。
    if app.get_webview_window(window_label).is_none() {
        return Registration::Failed(ERR_WINDOW_MISSING.to_string());
    }
    // 插件装载失败（headless / 平台不支持）：如实报，不 panic
    let Some(plugin) = app.try_state::<GlobalShortcut<R>>() else {
        return Registration::Failed(
            "global shortcut support is unavailable on this session".to_string(),
        );
    };
    // 先释放自己绑定的旧键：改绑时旧键必须先让位，否则新旧两键同时响应。
    // 只动自己的——另一个绑定的键不归这里管
    if let Some(prev) = previous.as_deref() {
        if let Ok(old) = parse_accelerator(prev) {
            let _ = plugin.unregister(old);
        }
    }

    let shortcut = match parse_accelerator(raw) {
        Ok(shortcut) => shortcut,
        Err(err) => return Registration::Failed(err),
    };
    match plugin.register(shortcut) {
        Ok(()) => Registration::Registered(normalize_accelerator(raw)),
        Err(err) => Registration::Failed(err.to_string()),
    }
}

/// 把抢注结果写回运行态（按 `window_label` 选边）
fn store_registration(
    runtime: &Mutex<QuickAccessRuntime>,
    window_label: &str,
    outcome: Registration,
) {
    let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    let (registered, last_error) = slots_for(&mut guard, window_label);
    match outcome {
        Registration::Registered(accelerator) => {
            *registered = Some(accelerator);
            *last_error = None;
        }
        Registration::Disabled => {
            *registered = None;
            *last_error = None;
        }
        Registration::Failed(reason) => {
            tracing::warn!("hotkey registration failed for {window_label}: {reason}");
            *registered = None;
            *last_error = Some(reason);
        }
    }
}

/// 读取该绑定当前已注册的加速键串（`compute_registration` 的 `previous`）
fn current_registration(runtime: &Mutex<QuickAccessRuntime>, window_label: &str) -> Option<String> {
    let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    slots_for(&mut guard, window_label).0.clone()
}

/// 单个绑定的"开关+绑定串"下发（检索与生成器共用，窗口标签区分）。
fn apply_binding<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    window_label: &str,
    enabled: bool,
    accelerator: Option<&str>,
    fallback_default: &str,
) {
    let effective = enabled.then(|| {
        accelerator
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback_default.to_string())
    });
    let previous = current_registration(runtime, window_label);
    let outcome = compute_registration(app, window_label, effective.as_deref(), previous);
    store_registration(runtime, window_label, outcome);
}

/// 按 workspace settings 下发两个绑定（解锁成功后调用；开关关 = 注销
/// 该绑定自己的旧键）。
///
/// DB 是真值源，所以这里不做"是否与当前一致"的短路判断——每次解锁都重放
/// 一遍，代价是至多两次 unregister + 两次 register，收益是任何一端的
/// 改绑（包括 CLI 手改 settings JSON）都在下次解锁时收敛。
pub fn apply_from_settings<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    settings: &WorkspaceSettings,
) {
    apply_binding(
        app,
        runtime,
        WINDOW_LABEL,
        settings.quick_access_enabled,
        settings.quick_access_hotkey.as_deref(),
        default_accelerator(),
    );
    apply_binding(
        app,
        runtime,
        GENERATOR_WINDOW_LABEL,
        settings.generator_panel_enabled,
        settings.generator_panel_hotkey.as_deref(),
        default_generator_accelerator(),
    );
}

/// 显式下发检索绑定（设置页改开关/改绑后调用，与 [`apply_from_settings`]
/// 同一套抢注逻辑，区别只是绑定串由调用方给定而非从 DB 读）
pub fn apply_explicit<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    enabled: bool,
    accelerator: Option<&str>,
) -> QuickAccessStatus {
    apply_binding(
        app,
        runtime,
        WINDOW_LABEL,
        enabled,
        accelerator,
        default_accelerator(),
    );

    let guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    QuickAccessStatus {
        enabled,
        configured_accelerator: if enabled {
            accelerator
                .map(|s| s.to_string())
                .unwrap_or_else(|| default_accelerator().to_string())
        } else {
            Default::default()
        },
        registered_accelerator: guard.registered.clone(),
        error: guard
            .last_error
            .clone()
            .or_else(|| guard.install_error.clone()),
    }
}

/// 显式下发生成器绑定（语义同 [`apply_explicit`]，窗口与槽位独立）
pub fn apply_explicit_generator<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    enabled: bool,
    accelerator: Option<&str>,
) -> GeneratorStatus {
    apply_binding(
        app,
        runtime,
        GENERATOR_WINDOW_LABEL,
        enabled,
        accelerator,
        default_generator_accelerator(),
    );

    let guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    GeneratorStatus {
        enabled,
        configured_accelerator: if enabled {
            accelerator
                .map(|s| s.to_string())
                .unwrap_or_else(|| default_generator_accelerator().to_string())
        } else {
            Default::default()
        },
        registered_accelerator: guard.generator_registered.clone(),
        error: guard
            .generator_last_error
            .clone()
            .or_else(|| guard.install_error.clone()),
    }
}

/// 热键回调体：toggle 浮窗。抽成独立函数便于托盘、命令与插件回调共用。
/// `window_label`/`opened_event` 成对传（检索与生成器各一套，语义一致）
fn toggle_window<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str, opened_event: &str) {
    let Some(window) = app.get_webview_window(window_label) else {
        return;
    };
    match window.is_visible() {
        Ok(true) => {
            let _ = window.hide();
        }
        _ => {
            let _ = window.show();
            let _ = window.set_focus();
            // 唤醒事件：前端清查询 + 聚焦输入框（浮窗复用上次结果会很迷惑）
            let _ = window.emit(opened_event, ());
        }
    }
}

/// 拉起浮窗（托盘菜单 / 设置页按钮用；已显示时只聚焦）
fn open_window<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str, opened_event: &str) {
    let Some(window) = app.get_webview_window(window_label) else {
        return;
    };
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.emit(opened_event, ());
}

/// 收回浮窗（前端 Esc / 失焦自收尾都走它，避免两处各写一遍 hide）
fn close_window<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str) {
    if let Some(window) = app.get_webview_window(window_label) {
        let _ = window.hide();
    }
}

/// 检索浮窗热键回调（toggle）
pub fn toggle<R: tauri::Runtime>(app: &AppHandle<R>) {
    toggle_window(app, WINDOW_LABEL, OPENED_EVENT);
}

/// 生成器浮窗热键回调（toggle）
pub fn toggle_generator<R: tauri::Runtime>(app: &AppHandle<R>) {
    toggle_window(app, GENERATOR_WINDOW_LABEL, GENERATOR_OPENED_EVENT);
}

/// 拉起检索浮窗（托盘菜单 / 设置页按钮用）
pub fn open<R: tauri::Runtime>(app: &AppHandle<R>) {
    open_window(app, WINDOW_LABEL, OPENED_EVENT);
}

/// 拉起生成器浮窗（托盘菜单入口，语义同 [`open`]）
pub fn open_generator<R: tauri::Runtime>(app: &AppHandle<R>) {
    open_window(app, GENERATOR_WINDOW_LABEL, GENERATOR_OPENED_EVENT);
}

/// 收回检索浮窗
pub fn close<R: tauri::Runtime>(app: &AppHandle<R>) {
    close_window(app, WINDOW_LABEL);
}

/// 收回生成器浮窗。生成结果虽非库内密文，但用户可能刚复制走要用的密码，
/// 锁户时同样不该留在屏幕上（与 [`close`] 同一数据暴露面论据）
pub fn close_generator<R: tauri::Runtime>(app: &AppHandle<R>) {
    close_window(app, GENERATOR_WINDOW_LABEL);
}

/// 锁户时两个浮窗一起收（托盘 lock 菜单 / 前端锁屏动作共用）
pub fn close_all<R: tauri::Runtime>(app: &AppHandle<R>) {
    close(app);
    close_generator(app);
}

/// Builder 级 handler 的分发体：反查运行态里哪个绑定注册了这枚按键。
/// 配置串解析失败的槽位跳过（不该发生——注册成功时存的就是合法串）；
/// 两个绑定都没命中就忽略（理论不可达，防御式不 panic）。
fn dispatch_shortcut<R: tauri::Runtime>(
    app: &AppHandle<R>,
    fired: &tauri_plugin_global_shortcut::Shortcut,
) {
    use crate::AppState;
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let guard = state.quick_access.lock().unwrap_or_else(|p| p.into_inner());
    let search_hit = guard
        .registered
        .as_deref()
        .and_then(|raw| parse_accelerator(raw).ok())
        .is_some_and(|s| s == *fired);
    let generator_hit = guard
        .generator_registered
        .as_deref()
        .and_then(|raw| parse_accelerator(raw).ok())
        .is_some_and(|s| s == *fired);
    drop(guard);
    if search_hit {
        toggle(app);
    }
    if generator_hit {
        toggle_generator(app);
    }
}

/// 浮窗里选中某条凭据 → 主窗口切到该身份并打开详情。
///
/// 事件用 `emit_to(MAIN_WINDOW_LABEL)` 定向投递：广播会让浮窗自己也收到
/// 一份，白跑一轮副作用。返回 false = 主窗口不存在（不该发生，报给前端
/// 做错误提示而不是静默）。
pub fn open_credential_in_main<R: tauri::Runtime>(
    app: &AppHandle<R>,
    identity_id: &str,
    credential_id: &str,
) -> bool {
    let Some(main) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        return false;
    };
    let payload = OpenCredentialPayload {
        identity_id: identity_id.to_string(),
        credential_id: credential_id.to_string(),
    };
    if main
        .emit_to(MAIN_WINDOW_LABEL, OPEN_CREDENTIAL_EVENT, payload)
        .is_err()
    {
        return false;
    }
    let _ = main.unminimize();
    let _ = main.show();
    let _ = main.set_focus();
    close(app);
    true
}

/// 把主窗口拉到前台（浮窗的"锁定态"出口：不在浮窗里复刻解锁流，
/// 统一回主窗口的解锁屏——见模块注释的已知边界）
pub fn focus_main_window<R: tauri::Runtime>(app: &AppHandle<R>) -> bool {
    match app.get_webview_window(MAIN_WINDOW_LABEL) {
        Some(main) => {
            let _ = main.unminimize();
            let _ = main.show();
            let _ = main.set_focus();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_accelerator_parses() {
        assert!(
            parse_accelerator(default_accelerator()).is_ok(),
            "默认绑定必须是合法加速键串"
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_accelerator("").is_err());
        assert!(parse_accelerator("Ctrl+").is_err());
        assert!(parse_accelerator("NotAKey").is_err());
    }

    #[test]
    fn normalize_trims_only() {
        // 不改写大小写/顺序（与 Shortcut::Display 的归一化刻意不同）
        assert_eq!(
            normalize_accelerator("  Ctrl+Shift+Space  "),
            "Ctrl+Shift+Space"
        );
    }

    #[test]
    fn snapshot_maps_settings_to_status() {
        let runtime = QuickAccessRuntime {
            registered: Some("Ctrl+Shift+Space".to_string()),
            last_error: None,
            ..QuickAccessRuntime::default()
        };
        // 开启态（默认已改关，2026-09-28）：未自定义绑定 → configured 落到
        // 平台默认值
        let settings = WorkspaceSettings {
            quick_access_enabled: true,
            ..WorkspaceSettings::default()
        };
        let status = runtime.snapshot(&settings);
        assert!(status.enabled);
        assert_eq!(status.configured_accelerator, default_accelerator());
        assert_eq!(
            status.registered_accelerator.as_deref(),
            Some("Ctrl+Shift+Space")
        );
        assert!(status.error.is_none());
    }

    #[test]
    fn snapshot_surfaces_registration_failure() {
        // 抢注失败：configured 仍是 DB 里的绑定，registered 空、error 有值
        let runtime = QuickAccessRuntime {
            registered: None,
            last_error: Some("Another process has already registered".to_string()),
            ..QuickAccessRuntime::default()
        };
        let settings = WorkspaceSettings {
            quick_access_hotkey: Some("Control+Alt+K".to_string()),
            ..WorkspaceSettings::default()
        };
        let status = runtime.snapshot(&settings);
        assert_eq!(status.configured_accelerator, "Control+Alt+K");
        assert!(status.registered_accelerator.is_none());
        assert!(status.error.is_some());
    }

    #[test]
    fn snapshot_prefers_registration_error_over_install_error() {
        // 两个错误同时存在时给更具体的那个（本次抢注失败 > 装载失败）
        let runtime = QuickAccessRuntime {
            registered: None,
            last_error: Some("hotkey taken".to_string()),
            install_error: Some("no display".to_string()),
            ..QuickAccessRuntime::default()
        };
        let status = runtime.snapshot(&WorkspaceSettings::default());
        assert_eq!(status.error.as_deref(), Some("hotkey taken"));
    }

    #[test]
    fn snapshot_falls_back_to_install_error() {
        let runtime = QuickAccessRuntime {
            registered: None,
            last_error: None,
            install_error: Some("no display".to_string()),
            ..QuickAccessRuntime::default()
        };
        let status = runtime.snapshot(&WorkspaceSettings::default());
        assert_eq!(status.error.as_deref(), Some("no display"));
    }

    #[test]
    fn snapshot_disabled_when_setting_off() {
        let settings = WorkspaceSettings {
            quick_access_enabled: false,
            ..WorkspaceSettings::default()
        };
        let status = QuickAccessRuntime::default().snapshot(&settings);
        assert!(!status.enabled);
        // 关掉时 configured 仍展示绑定串（设置页要能看见"当前配置"）
        assert_eq!(status.configured_accelerator, default_accelerator());
        assert!(status.registered_accelerator.is_none());
    }

    #[test]
    fn generator_default_accelerator_parses() {
        assert!(
            parse_accelerator(default_generator_accelerator()).is_ok(),
            "生成器默认绑定必须是合法加速键串"
        );
    }

    #[test]
    fn generator_snapshot_maps_settings_to_status() {
        let runtime = QuickAccessRuntime {
            generator_registered: Some("Ctrl+Shift+G".to_string()),
            ..QuickAccessRuntime::default()
        };
        let settings = WorkspaceSettings {
            generator_panel_enabled: true,
            ..WorkspaceSettings::default()
        };
        let status = GeneratorStatus::snapshot(&runtime, &settings);
        assert!(status.enabled);
        assert_eq!(
            status.configured_accelerator,
            default_generator_accelerator()
        );
        assert_eq!(
            status.registered_accelerator.as_deref(),
            Some("Ctrl+Shift+G")
        );
        assert!(status.error.is_none());
    }

    #[test]
    fn generator_snapshot_surfaces_registration_failure() {
        // 抢注失败：configured 保留 DB 里的绑定，registered 空、error 有值
        let runtime = QuickAccessRuntime {
            generator_last_error: Some("Another process has already registered".to_string()),
            ..QuickAccessRuntime::default()
        };
        let settings = WorkspaceSettings {
            generator_panel_hotkey: Some("Control+Alt+P".to_string()),
            ..WorkspaceSettings::default()
        };
        let status = GeneratorStatus::snapshot(&runtime, &settings);
        assert_eq!(status.configured_accelerator, "Control+Alt+P");
        assert!(status.registered_accelerator.is_none());
        assert_eq!(
            status.error.as_deref(),
            Some("Another process has already registered")
        );
    }

    #[test]
    fn generator_snapshot_disabled_shows_configured_only() {
        let settings = WorkspaceSettings {
            generator_panel_enabled: false,
            ..WorkspaceSettings::default()
        };
        let status = GeneratorStatus::snapshot(&QuickAccessRuntime::default(), &settings);
        assert!(!status.enabled);
        assert_eq!(
            status.configured_accelerator,
            default_generator_accelerator()
        );
        assert!(status.registered_accelerator.is_none());
        assert!(status.error.is_none());
    }

    #[test]
    fn generator_status_serializes_snake_case_keys() {
        let json = serde_json::to_value(GeneratorStatus::snapshot(
            &QuickAccessRuntime::default(),
            &WorkspaceSettings::default(),
        ))
        .unwrap();
        for key in [
            "enabled",
            "configured_accelerator",
            "registered_accelerator",
            "error",
        ] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
        assert!(json.get("configuredAccelerator").is_none());
    }

    // 抢注路径（compute_registration / apply_*）需要 AppHandle，其"浮窗
    // 不存在 → 明确失败"的分支由 command_layer_tests 的 quick_access_*
    // 用例覆盖（那里 mock_app 是既有惯例）。**不要**在本模块的单元测试里
    // 造 mock app：`tauri::test::mock_app()` 的 mock runtime 会毒化本进程
    // 的 tokio socket IO 探测，同进程并跑的 sqlx 用例会随机 disk I/O error
    // （见 lib.rs 模块注释与 sqlite_works_after_mock_app_creation 探针）。

    /// 线格式锁：状态面字段名是前端 `QuickAccessStatus` 的契约，改了这里
    /// 必须同步改 TS，否则 UI 静默读到 undefined（比编译错误更难查）
    #[test]
    fn status_serializes_snake_case_keys() {
        let json = serde_json::to_value(
            QuickAccessRuntime::default().snapshot(&WorkspaceSettings::default()),
        )
        .unwrap();
        for key in [
            "enabled",
            "configured_accelerator",
            "registered_accelerator",
            "error",
        ] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
        assert!(json.get("configuredAccelerator").is_none());
    }

    /// 同上，跨窗事件载荷
    #[test]
    fn open_credential_payload_serializes_snake_case_keys() {
        let json = serde_json::to_value(OpenCredentialPayload {
            identity_id: "i1".to_string(),
            credential_id: "c1".to_string(),
        })
        .unwrap();
        assert_eq!(json["identity_id"], "i1");
        assert_eq!(json["credential_id"], "c1");
        assert!(json.get("identityId").is_none());
    }
}
