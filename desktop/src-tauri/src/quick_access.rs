//! Quick Access：OS 级全局热键唤出的浮窗（对标矩阵 #22）。
//!
//! 机制分层：
//! - **装载面**：global-shortcut 插件在 `setup` 里**运行时装载**
//!   （[`install_plugin`]，不用 `Builder::plugin`）。原因是它的 `setup`
//!   会建 X11/平台热键管理器，失败即 Err——走 Builder 链的话这个 Err 会
//!   让整个 app 构建失败（`.expect` 直接 panic），一个"锦上添花的全局热键
//!   不该让密码管理器起不来"。headless Linux/无 XWayland 正是这条路径。
//! - **注册面**（本模块其余部分）：抢注一个加速键，成功才把 `registered`
//!   记为 Some。**抢注失败不静默**：原因进 `last_error`，设置页如实显示
//!   （被别的应用/WM 占用、平台不支持都会走到这里）。
//! - **浮窗面**：`quick-access` 标签的无边框置顶小窗（tauri.conf.json 声明，
//!   初始 `visible: false`）。热键是 toggle：已显示则隐藏（把焦点还给原
//!   应用），未显示则 show + focus + emit [`OPENED_EVENT`] 让前端重置搜索态。
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
use tauri_plugin_global_shortcut::GlobalShortcut;

use persona_core::models::WorkspaceSettings;

/// 浮窗标签（tauri.conf.json 里 windows[1].label 必须一致）
pub const WINDOW_LABEL: &str = "quick-access";

/// 浮窗被热键唤起时向自身 webview 发的事件：前端据此清空上一次查询、
/// 聚焦输入框（同一进程内多窗口的 wake 通道，不用轮询）
pub const OPENED_EVENT: &str = "persona://quick-access-opened";

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
    /// 插件装载失败原因（headless 会话 / 平台不支持）。与 `last_error` 分开
    /// 记：一个是"这台机器上全局热键根本起不来"，一个是"键被占用了"
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
pub fn install_plugin<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    if app.try_state::<GlobalShortcut<R>>().is_some() {
        return Ok(());
    }
    app.plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// 一次抢注的结果
enum Registration {
    /// 抢注成功，存的是**配置串**（不是 `Display` 归一化串）
    Registered(String),
    /// 开关关闭：主动释放全部绑定
    Disabled,
    /// 没抢上，原因原样带给设置页
    Failed(String),
}

/// 同步 OS 抢注状态并返回结果（不改运行态，由调用方统一落盘——避免
/// "先改状态后抢注失败"留下半截状态）。
fn compute_registration<R: tauri::Runtime>(
    app: &AppHandle<R>,
    accelerator: Option<&str>,
) -> Registration {
    // 热键唯一作用是唤出浮窗：浮窗不在（集成测试的 mock context 就是
    // 没有窗口）就没什么可绑的，直接短路。顺带避开一个测试隐患——
    // mock runtime 的 run_on_main_thread 只排队不执行，插件 register 里
    // 的阻塞 recv 会把测试挂死。
    if app.get_webview_window(WINDOW_LABEL).is_none() {
        return Registration::Failed(ERR_WINDOW_MISSING.to_string());
    }
    // 插件装载失败（headless / 平台不支持）：如实报，不 panic
    let Some(plugin) = app.try_state::<GlobalShortcut<R>>() else {
        return Registration::Failed(
            "global shortcut support is unavailable on this session".to_string(),
        );
    };
    // 先释放旧绑定：改绑时旧键必须先让位，否则新旧两键同时响应
    let _ = plugin.unregister_all();

    let Some(raw) = accelerator else {
        return Registration::Disabled;
    };
    let shortcut = match parse_accelerator(raw) {
        Ok(shortcut) => shortcut,
        Err(err) => return Registration::Failed(err),
    };
    match plugin.register(shortcut) {
        Ok(()) => Registration::Registered(normalize_accelerator(raw)),
        Err(err) => Registration::Failed(err.to_string()),
    }
}

/// 把抢注结果写回运行态
fn store_registration(runtime: &Mutex<QuickAccessRuntime>, outcome: Registration) {
    let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    match outcome {
        Registration::Registered(accelerator) => {
            guard.registered = Some(accelerator);
            guard.last_error = None;
        }
        Registration::Disabled => {
            guard.registered = None;
            guard.last_error = None;
        }
        Registration::Failed(reason) => {
            guard.registered = None;
            guard.last_error = Some(reason);
        }
    }
}

/// 按 workspace settings 下发绑定（解锁成功后调用；开关关 = 注销全部）。
///
/// DB 是真值源，所以这里不做"是否与当前一致"的短路判断——每次解锁都重放
/// 一遍，代价是一次 unregister_all + 一次 register，收益是任何一端的
/// 改绑（包括 CLI 手改 settings JSON）都在下次解锁时收敛。
pub fn apply_from_settings<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    settings: &WorkspaceSettings,
) {
    let accelerator = settings.quick_access_enabled.then(|| {
        settings
            .quick_access_hotkey
            .clone()
            .unwrap_or_else(|| default_accelerator().to_string())
    });
    store_registration(runtime, compute_registration(app, accelerator.as_deref()));
}

/// 显式下发（设置页改开关/改绑后调用，与 [`apply_from_settings`] 同一套
/// 抢注逻辑，区别只是绑定串由调用方给定而非从 DB 读）
pub fn apply_explicit<R: tauri::Runtime>(
    app: &AppHandle<R>,
    runtime: &Mutex<QuickAccessRuntime>,
    enabled: bool,
    accelerator: Option<&str>,
) -> QuickAccessStatus {
    let effective = enabled.then(|| {
        accelerator
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_accelerator().to_string())
    });
    store_registration(runtime, compute_registration(app, effective.as_deref()));

    let guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
    QuickAccessStatus {
        enabled,
        configured_accelerator: effective.unwrap_or_default(),
        registered_accelerator: guard.registered.clone(),
        error: guard
            .last_error
            .clone()
            .or_else(|| guard.install_error.clone()),
    }
}

/// 热键回调体：toggle 浮窗。抽成独立函数便于托盘、命令与插件回调共用
pub fn toggle<R: tauri::Runtime>(app: &AppHandle<R>) {
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
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
            let _ = window.emit(OPENED_EVENT, ());
        }
    }
}

/// 拉起浮窗（托盘菜单 / 设置页按钮用；已显示时只聚焦）
pub fn open<R: tauri::Runtime>(app: &AppHandle<R>) {
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        return;
    };
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.emit(OPENED_EVENT, ());
}

/// 收回浮窗（前端 Esc / 失焦自收尾都走它，避免两处各写一遍 hide）
pub fn close<R: tauri::Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
        let _ = window.hide();
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
            install_error: None,
        };
        // 未自定义绑定 → configured 落到平台默认值
        let status = runtime.snapshot(&WorkspaceSettings::default());
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
            install_error: None,
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
