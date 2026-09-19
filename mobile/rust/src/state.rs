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

// ---------------------------------------------------------------------------
// 测试助手（lib.rs 与 business.rs 的测试模块共用：全局槽位是进程内单例，
// 两处测试必须经同一把锁串行，否则互相踢掉对方的服务状态）
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 每个生命周期/业务测试开头复位全局槽位。
#[cfg(test)]
pub(crate) fn reset_state() {
    assert!(crate::persona_shutdown().success);
}

#[cfg(test)]
pub(crate) fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}

/// 就绪的临时 vault 路径（TempDir 泄漏到测试结束，进程退出回收）。
#[cfg(test)]
pub(crate) fn temp_db_path(tag: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{}.db", tag));
    // 泄漏目录：service 的 sqlx 池在 shutdown 后仍可能短暂触碰文件
    std::mem::forget(dir);
    path.to_string_lossy().to_string()
}
