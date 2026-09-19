//! 全局宿主状态槽位（对齐 desktop AppState 的"槽位即真相"模型）。
//!
//! 所有 PersonaService/Emitter 状态留在 Rust 侧，Dart 层只拿
//! PersonaResult/bool——无裸指针句柄跨 FFI，密钥材料不越界。
//! 槽位解耦：`persona_configure_sync` 可先于/后于 `persona_service_init`
//! 调用，两侧在任一时机把既有值注入对方。

use std::sync::OnceLock;
use tokio::sync::Mutex;

use persona_core::events::Emitter;
use persona_core::PersonaService;

/// 唯一的 PersonaService 实例（None = 未初始化）。mobile 单 vault 单用户，
/// 全局单例足够——与 desktop 的 `Arc<Mutex<Option<PersonaService>>>` 同型。
static SERVICE: OnceLock<Mutex<Option<PersonaService>>> = OnceLock::new();

/// 审计事件上报器（None = 未启用）。换新停旧的顺序与 desktop
/// `attach_sync_emitter` 一致：先替换槽位，旧 emitter 锁外 stop。
static EMITTER: OnceLock<Mutex<Option<Emitter>>> = OnceLock::new();

pub(crate) fn service_slot() -> &'static Mutex<Option<PersonaService>> {
    SERVICE.get_or_init(|| Mutex::new(None))
}

pub(crate) fn emitter_slot() -> &'static Mutex<Option<Emitter>> {
    EMITTER.get_or_init(|| Mutex::new(None))
}
