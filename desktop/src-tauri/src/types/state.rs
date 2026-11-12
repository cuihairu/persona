//! `AppState` 与 `PairingSession`：Tauri 全局状态与同步组配对会话（内存态）。

use persona_core::*;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::async_runtime::JoinHandle;
use tokio::sync::Mutex;

/// Application state that holds the Persona service
///
/// `service` 用 `Arc` 包裹：auto-lock 回调在独立任务里触发落锁，
/// 需要在不经过 Tauri `State` 的情况下持有同一份引用。
pub struct AppState {
    pub service: Arc<Mutex<Option<PersonaService>>>,
    pub db_path: Mutex<Option<String>>,
    pub agent_handle: Mutex<Option<JoinHandle<()>>>,
    /// auto-lock 回调只注册一次（多次 init_service 时防重复）
    pub auto_lock_registered: std::sync::atomic::AtomicBool,
    /// passkey 审批服务端本会话已启动（workspace 开关门禁的幂等标记）
    pub passkey_server_started: std::sync::atomic::AtomicBool,
    /// passkey 审批服务端的关停通道（maybe_start 填充、关 flag 时消费发送；
    /// None = 本会话未启动或已关停）
    pub passkey_server_shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// 待应答的 SSH 签名审批（request_id → oneshot），由
    /// DesktopApprovalHandler 写入、ssh_approval_respond 命令取出
    pub ssh_approvals: Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
    /// 待应答的 bridge passkey 审批（request_id → oneshot），由
    /// passkey_bridge 服务端写入、passkey_approval_respond 命令取出
    pub passkey_approvals:
        Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
    /// 审计事件同步上报器（settings.sync 配置驱动；None = 未启用）。
    /// 槽位即真相源：重挂时先 stop 旧的再换新，防止双任务。注意这里
    /// 用全路径——`tauri::Emitter`（事件 emit trait）占用了 `Emitter` 名。
    pub sync_emitter: Mutex<Option<persona_core::events::Emitter>>,
    /// sync token 的字段级加密存储（生产 = OS keyring，测试 = 内存
    /// fake）。vault settings JSON 里的 `server_token` 恒为空串占位，
    /// 真值只存在这里。
    pub token_store: Arc<dyn crate::token_store::TokenStore>,
    /// OS 级 biometric provider（Touch ID / Windows Hello / polkit）。
    /// 解锁屏 ceremony 没有活的 PersonaService，provider 挂在这里；
    /// init_service 建服务后把它注入 PersonaService（SSH agent 的
    /// require_biometric 策略同一份）。
    pub biometric_provider: Arc<dyn BiometricProvider>,
    /// 硬件绑定的密钥包裹器（`biometric_wrap` 模块 trait）。生产装配按
    /// 平台选择：macOS 上 PERSONA_BIOMETRIC_SE_SPIKE=1 时为 Secure
    /// Enclave 路线 B' 实现，其余平台/默认为 gate-only 桩（capability
    /// OsGateOnly → enable 恒走门禁层密码托管，行为与历史版本一致）。
    pub biometric_wrapper: Arc<dyn persona_core::BiometricKeyWrapper>,
    /// biometric 托管主密码的 keyring 存储（service "persona-biometric"、
    /// 键 = vault db_path）。条目存在与否 = biometric unlock 是否启用
    /// （单一真相源，settings 不存开关——vault 文件拷机后 keyring 无
    /// 条目，功能自然回到未启用）。
    pub biometric_store: Arc<dyn crate::token_store::TokenStore>,
    /// 硬件绑定包裹 blob 的 keyring 存储（service
    /// "persona-biometric-wrap"）。与 biometric_store 一样只存密文：
    /// blob 是被平台硬件密钥包裹的主密钥，同用户进程读到了也打不开。
    pub biometric_wrap_store: Arc<dyn crate::token_store::TokenStore>,
    /// Connect 本机自动化 listener 句柄（端口 + 关停通道）；None = 未
    /// 启动（DR-4 默认关闭 = 不创建 listener）。槽位即真相源，start/stop
    /// 换槽防双 listener。
    pub connect_server: Mutex<Option<crate::connect_server::ConnectServerHandle>>,
    /// E2EE sync 设备身份存储（生产 = OS keyring service `persona-device`，
    /// 测试 = 内存 fake）。值 = `DeviceIdentity::to_stored_json`，键同
    /// token_store = vault db_path。条目存在与否 = 本 vault 是否已加入
    /// 同步（单一真相源，settings 不存开关）。
    pub device_store: Arc<dyn crate::token_store::TokenStore>,
    /// 账号域 bearer 的 keyring 存储（service `persona-account`，键同
    /// token_store = vault db_path）。`account_srp_verify` /
    /// `account_create_session` 成功后写入，`account_revoke_session`
    /// 自吊销时清除；Bearer 门禁的账号命令从这里解析（fail-closed）。
    pub account_token_store: Arc<dyn crate::token_store::TokenStore>,
    /// Quick Access 全局热键的进程内运行态（实际抢注结果 + 失败原因）。
    /// 绑定与开关的持久化真值在 workspace settings，本字段只反映"这一
    /// 进程里 OS 抢注成功没有"——见 `quick_access` 模块注释。用 std Mutex
    /// （同 ssh_approvals 槽位）：锁内只做字段读写，从不跨 await。
    pub quick_access: std::sync::Mutex<crate::quick_access::QuickAccessRuntime>,
    /// 桌面填充注入目标（FEATURE_GAP_ANALYSIS #12）：热键唤起检索浮窗时
    /// 捕获的前台窗口快照（`desktop_fill::FillTarget`）。None = 尚未捕获/
    /// 目标已失效/平台不支持。std Mutex：锁内只做快照读写，从不跨 await。
    pub fill_target: std::sync::Mutex<Option<crate::desktop_fill::FillTarget>>,
    /// 同步组配对进行中的会话（session_id → 会话态）。host 出码、guest
    /// 输码各存一条；完成/取消即移除。动态密码派生值与 SRP 私有份额只在
    /// 这里存活（内存态，不落盘）——见 `core/src/sync/pairing.rs` 模块
    /// 注释。锁内只做 take/put，从不跨 await 持锁（drive/join 的网络等待
    /// 都在锁外）。
    pub pairing_sessions: Arc<std::sync::Mutex<HashMap<String, crate::types::PairingSession>>>,
    /// 同步组组密钥的 keyring 存储（service `persona-sync-group`，键 =
    /// vault db_path，值 = hex）。条目存在与否 = 本 vault 是否已加入同步
    /// 组（单一真相源）；配对完成时写入，S2 指令流从这里读。
    pub sync_group_store: Arc<dyn crate::token_store::TokenStore>,
}

/// 同步组配对会话（host 出码 / guest 输码两种角色，内存态）。
pub enum PairingSession {
    /// 邀请端：动态密码握手现场 + 待递交的组密钥（完成时落
    /// sync_group_store）。GroupKey 带内存清零（Drop/ZeroizeOnDrop）。
    Host {
        host: persona_core::sync::pairing::PairingHost,
        group_key: persona_core::sync::keys::GroupKey,
        relay_url: String,
    },
    /// 加入端：join_begin 与 join_confirm 之间持有（指纹比对通过后 confirm）。
    Guest {
        guest: persona_core::sync::pairing::PairingGuest,
        relay_url: String,
    },
}
