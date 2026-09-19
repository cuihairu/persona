//! Persona mobile bindings。
//!
//! 手写 extern "C" FFI：把 core 的 [`PersonaService`] 与审计事件上报器
//! （[`Emitter`] + [`ServerEventSink`]）接进移动宿主。宿主接线语义对齐
//! desktop/CLI：config 一半即 fail-closed（url+token 都非空才启用）、
//! 先写本地审计库后尽力上报、shutdown 尽力最终 flush。
//!
//! 内存约定：字符串经 `CString::into_raw` 传出，由调用方用
//! `persona_free_string`/`persona_free_result` 归还；所有服务状态留在
//! Rust 侧全局槽位（`state.rs`），指针参数仅限入参且本函数内借用。

mod runtime;
mod state;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;

use persona_core::events::Emitter;
use persona_core::storage::Database;
use persona_core::{AuthResult, PersonaService, ServerEventSink};

/// Initialize the mobile library
#[no_mangle]
pub extern "C" fn persona_init() -> i32 {
    // Initialize logging or other setup
    0 // Success
}

/// Get version string
#[no_mangle]
pub extern "C" fn persona_version() -> *mut c_char {
    let version = env!("CARGO_PKG_VERSION");
    match CString::new(version) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string allocated by this library
/// # Safety
/// Caller must pass a pointer returned by this library (e.g., from `persona_version`)
/// and ensure it is not used after freeing. Passing any other pointer is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn persona_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = CString::from_raw(s);
}

/// Error handling
#[repr(C)]
pub struct PersonaResult {
    pub success: bool,
    pub error_message: *mut c_char,
}

impl PersonaResult {
    fn success() -> Self {
        Self {
            success: true,
            error_message: std::ptr::null_mut(),
        }
    }

    fn error(message: &str) -> Self {
        let error_message = match CString::new(message) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => std::ptr::null_mut(),
        };

        Self {
            success: false,
            error_message,
        }
    }
}

/// Free a PersonaResult
/// # Safety
/// The `error_message` pointer inside `PersonaResult` must either be null or allocated
/// by this library. Caller must ensure it will not be reused after freeing.
#[no_mangle]
pub unsafe extern "C" fn persona_free_result(result: PersonaResult) {
    if !result.error_message.is_null() {
        let _ = CString::from_raw(result.error_message);
    }
}

/// 借用调用方传入的 C 字符串（null / 非 UTF-8 统一报错）。
///
/// # Safety
/// `ptr` 必须指向有效的 null 结尾字符串（或为 null——返回 Err 而非 UB）。
fn ptr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null argument".to_string());
    }
    // SAFETY: 调用方契约保证指针有效（或 null 已在上方拦截）
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map_err(|_| "invalid UTF-8 in argument".to_string())
}

// ---------------------------------------------------------------------------
// PersonaService 生命周期宿主接线
// ---------------------------------------------------------------------------

/// 初始化（或重复初始化）Persona service：打开 vault 文件 → 迁移 →
/// 建户（首次）或认证（既有用户，语义对齐 desktop `init_service`）。
/// 成功即解锁态。若 `persona_configure_sync` 已先行配置，此处把既有
/// emitter 注入 service。
/// # Safety
/// `db_path`/`master_password` 必须是有效的 null 结尾 UTF-8 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_service_init(
    db_path: *const c_char,
    master_password: *const c_char,
) -> PersonaResult {
    let result = (|| {
        let db_path = ptr_to_str(db_path)?;
        let master_password = ptr_to_str(master_password)?;
        Ok::<_, String>((db_path.to_string(), master_password.to_string()))
    })();
    let (db_path, master_password) = match result {
        Ok(v) => v,
        Err(e) => return PersonaResult::error(&e),
    };
    runtime::block_on(async move {
        match init_service_inner(&db_path, &master_password).await {
            Ok(()) => PersonaResult::success(),
            Err(e) => PersonaResult::error(&e),
        }
    })
}

async fn init_service_inner(db_path: &str, master_password: &str) -> Result<(), String> {
    let db = Database::from_file(db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;

    let mut service = PersonaService::new(db)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    if !service
        .has_users()
        .await
        .map_err(|e| format!("Failed to query users: {}", e))?
    {
        service
            .initialize_user(master_password)
            .await
            .map_err(|e| format!("Failed to initialize user: {}", e))?;
    } else {
        match service
            .authenticate_user(master_password)
            .await
            .map_err(|e| format!("Authentication error: {}", e))?
        {
            AuthResult::Success => {}
            AuthResult::InvalidCredentials => return Err("Invalid master password".to_string()),
            AuthResult::AccountLocked => {
                return Err("Account is locked due to too many failed attempts".to_string())
            }
            AuthResult::PasswordChangeRequired => {
                return Err("Password change required".to_string())
            }
            _ => return Err("Authentication failed".to_string()),
        }
    }

    // 先 configure 后 init 的顺序：把 emitter 槽位既有值注入 service
    let emitter = state::emitter_slot().lock().await.clone();
    if emitter.is_some() {
        service.set_event_emitter(emitter);
    }
    *state::service_slot().lock().await = Some(service);
    Ok(())
}

/// 用主密码解锁既有会话（`authenticate_user`；未初始化时拒绝）。
/// # Safety
/// `master_password` 必须是有效的 null 结尾 UTF-8 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_service_unlock(master_password: *const c_char) -> PersonaResult {
    let master_password = match ptr_to_str(master_password) {
        Ok(s) => s.to_string(),
        Err(e) => return PersonaResult::error(&e),
    };
    runtime::block_on(async move {
        let mut guard = state::service_slot().lock().await;
        match guard.as_mut() {
            Some(service) => {
                match service
                    .authenticate_user(&master_password)
                    .await
                    .map_err(|e| format!("Authentication error: {}", e))
                {
                    Ok(AuthResult::Success) => PersonaResult::success(),
                    Ok(AuthResult::InvalidCredentials) => {
                        PersonaResult::error("Invalid master password")
                    }
                    Ok(AuthResult::AccountLocked) => {
                        PersonaResult::error("Account is locked due to too many failed attempts")
                    }
                    Ok(AuthResult::PasswordChangeRequired) => {
                        PersonaResult::error("Password change required")
                    }
                    Ok(_) => PersonaResult::error("Authentication failed"),
                    Err(e) => PersonaResult::error(&e),
                }
            }
            None => PersonaResult::error("Service not initialized"),
        }
    })
}

/// 立即落锁（清内存主密钥；语义对齐 desktop 托盘 Lock）。
#[no_mangle]
pub extern "C" fn persona_service_lock() -> PersonaResult {
    runtime::block_on(async {
        let mut guard = state::service_slot().lock().await;
        match guard.as_mut() {
            Some(service) => {
                service.lock();
                PersonaResult::success()
            }
            None => PersonaResult::error("Service not initialized"),
        }
    })
}

/// 当前会话是否处于解锁态（service 未初始化视为锁定）。
#[no_mangle]
pub extern "C" fn persona_service_is_unlocked() -> bool {
    runtime::block_on(async {
        state::service_slot()
            .lock()
            .await
            .as_ref()
            .is_some_and(|s| s.is_unlocked())
    })
}

// ---------------------------------------------------------------------------
// 审计事件上报接线
// ---------------------------------------------------------------------------

/// 配置/关闭审计事件上报（mobile 宿主的 `attach_sync_emitter` 对应物）。
///
/// url 与 token 都非空（trim 后）→ 构造 `ServerEventSink` + `Emitter`
/// 并启用；任一空白 → 摘除既有上报器（fail-closed，对齐 CLI
/// "都非空才启用"语义）。URL 不做格式预校验（与 desktop attach 一致，
/// 格式错误在发送期暴露并按退避重试）；构造失败（如 TLS 初始化）报错。
///
/// 先于 `persona_service_init` 调用时仅存槽位，init 时注入；
/// service 已初始化时立即同步注入。换新停旧（旧 emitter 锁外 stop）。
///
/// # Safety
/// `server_url`/`token` 必须是有效的 null 结尾 UTF-8 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_configure_sync(
    server_url: *const c_char,
    token: *const c_char,
) -> PersonaResult {
    let result = (|| {
        let url = ptr_to_str(server_url)?;
        let token = ptr_to_str(token)?;
        Ok::<_, String>((url.trim().to_string(), token.trim().to_string()))
    })();
    let (url, token) = match result {
        Ok(v) => v,
        Err(e) => return PersonaResult::error(&e),
    };
    runtime::block_on(async move {
        let new_emitter = if !url.is_empty() && !token.is_empty() {
            match ServerEventSink::new(&url, token) {
                Ok(sink) => {
                    let emitter = Emitter::new(Arc::new(sink));
                    emitter.start();
                    Some(emitter)
                }
                Err(e) => return PersonaResult::error(&format!("Invalid sync server_url: {}", e)),
            }
        } else {
            None
        };

        // 锁顺序固定 emitter → service（与 desktop attach_sync_emitter 一致）；
        // 旧 emitter 在槽位替换后、锁外 stop（flush 可能走网络）
        let old = {
            let mut slot = state::emitter_slot().lock().await;
            let old = slot.take();
            *slot = new_emitter.clone();
            old
        };
        if let Some(old) = old {
            old.stop().await;
        }

        let mut guard = state::service_slot().lock().await;
        if let Some(service) = guard.as_mut() {
            service.set_event_emitter(new_emitter);
        }
        PersonaResult::success()
    })
}

/// 关闭宿主：service 落锁清内存主密钥、上报器尽力最终 flush、
/// 双槽位清空（对齐 CLI main 尾部的 stop 语义）。之后可重新 init。
#[no_mangle]
pub extern "C" fn persona_shutdown() -> PersonaResult {
    runtime::block_on(async {
        {
            let mut guard = state::service_slot().lock().await;
            if let Some(service) = guard.as_mut() {
                service.lock();
            }
            *guard = None;
        }
        let emitter = state::emitter_slot().lock().await.take();
        if let Some(emitter) = emitter {
            emitter.stop().await;
        }
        PersonaResult::success()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::sync::Mutex as StdMutex;

    /// 全局槽位跨测试共享（进程内单例），全部生命周期测试串行执行。
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: StdMutex<()> = StdMutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 每个生命周期测试开头复位全局槽位。
    fn reset_state() {
        assert!(persona_shutdown().success);
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// 就绪的临时 vault 路径（TempDir 泄漏到测试结束，进程退出回收）。
    fn temp_db_path(tag: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{}.db", tag));
        // 泄漏目录：service 的 sqlx 池在 shutdown 后仍可能短暂触碰文件
        std::mem::forget(dir);
        path.to_string_lossy().to_string()
    }

    /// 断言 result 成功；失败时带出错误消息。
    fn assert_ok(result: PersonaResult, context: &str) {
        assert!(
            result.success,
            "{} failed: {:?}",
            context,
            (unsafe {
                if result.error_message.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(result.error_message).to_str().unwrap())
                }
            })
        );
        unsafe { persona_free_result(result) };
    }

    /// 断言 result 失败并返回错误消息。
    fn assert_err(result: PersonaResult) -> String {
        assert!(!result.success, "expected error, got success");
        let msg = unsafe {
            CStr::from_ptr(result.error_message)
                .to_str()
                .unwrap()
                .to_string()
        };
        unsafe { persona_free_result(result) };
        msg
    }

    #[test]
    fn init_returns_success_code() {
        assert_eq!(persona_init(), 0);
    }

    #[test]
    fn version_returns_package_version_and_frees_cleanly() {
        let ptr = persona_version();
        assert!(!ptr.is_null());
        unsafe {
            let version = CStr::from_ptr(ptr).to_str().unwrap();
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
            persona_free_string(ptr);
        }
    }

    #[test]
    fn free_string_accepts_null() {
        unsafe { persona_free_string(std::ptr::null_mut()) };
    }

    #[test]
    fn result_helpers_round_trip_error_messages() {
        let ok = PersonaResult::success();
        assert!(ok.success);
        assert!(ok.error_message.is_null());

        let err = PersonaResult::error("boom");
        assert!(!err.success);
        unsafe {
            let msg = CStr::from_ptr(err.error_message).to_str().unwrap();
            assert_eq!(msg, "boom");
            persona_free_result(err);
        }
    }

    /// 宿主接线全链路：未初始化门禁 → init 建户 → 锁/解锁 →
    /// configure_sync 启停 → shutdown 复位 → 重复 init（认证分支）。
    /// 全局槽位串行，单测试函数内顺序覆盖（见 test_lock 注释）。
    #[test]
    fn service_lifecycle_unlock_sync_and_shutdown() {
        let _guard = test_lock();
        reset_state();

        // 未初始化：unlock/lock/configure_sync 的 service 侧拒绝
        let pw = cstr("master-pin");
        assert_eq!(
            assert_err(unsafe { persona_service_unlock(pw.as_ptr()) }),
            "Service not initialized"
        );
        assert!(!persona_service_lock().success);
        assert!(!persona_service_is_unlocked());

        // null 指针安全拒绝（UB 防线）
        assert_eq!(
            assert_err(unsafe { persona_service_init(std::ptr::null(), pw.as_ptr()) }),
            "null argument"
        );
        assert_eq!(
            assert_err(unsafe { persona_configure_sync(std::ptr::null(), pw.as_ptr()) }),
            "null argument"
        );

        // init：首次建户即解锁
        let db_path = temp_db_path("lifecycle");
        let db = cstr(&db_path);
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "first-time init",
        );
        assert!(persona_service_is_unlocked());

        // lock → unlock（错误密码拒绝且不改变状态）→ 解锁恢复
        assert_ok(persona_service_lock(), "lock");
        assert!(!persona_service_is_unlocked());
        let wrong = cstr("wrong-pin");
        assert_eq!(
            assert_err(unsafe { persona_service_unlock(wrong.as_ptr()) }),
            "Invalid master password"
        );
        assert!(!persona_service_is_unlocked());
        assert_ok(unsafe { persona_service_unlock(pw.as_ptr()) }, "unlock");
        assert!(persona_service_is_unlocked());

        // configure_sync：启用 → 审计动作入队 → 空白摘除 → 不再入队
        let url = cstr("http://127.0.0.1:1");
        let token = cstr("tok-1");
        assert_ok(
            unsafe { persona_configure_sync(url.as_ptr(), token.as_ptr()) },
            "configure sync on",
        );
        assert_ok(persona_service_lock(), "lock for audit");
        // unlock 是审计动作（login），emitter 已注入则入队（FFI 调用须在
        // block_on 外——内部会 block_on 同一全局 runtime，嵌套即 panic）
        assert_ok(
            unsafe { persona_service_unlock(pw.as_ptr()) },
            "unlock for audit",
        );
        let queued_with_sync = runtime::block_on(async {
            state::emitter_slot()
                .lock()
                .await
                .as_ref()
                .map(|e| e.queued())
        });
        assert!(
            queued_with_sync.unwrap_or(0) >= 1,
            "audit event should be queued while sync enabled"
        );

        assert_ok(
            unsafe { persona_configure_sync(cstr("  ").as_ptr(), token.as_ptr()) },
            "configure sync off",
        );
        assert_ok(persona_service_lock(), "lock again");
        assert_ok(
            unsafe { persona_service_unlock(pw.as_ptr()) },
            "unlock again",
        );
        let queued_after_detach = runtime::block_on(async {
            state::emitter_slot()
                .lock()
                .await
                .as_ref()
                .map(|e| e.queued())
        });
        assert_eq!(
            queued_after_detach, None,
            "no emitter after blank reconfigure"
        );

        // shutdown 复位 → 重复 init 走 authenticate 分支
        assert_ok(persona_shutdown(), "shutdown");
        assert!(!persona_service_is_unlocked());
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "re-init with correct password",
        );
        assert!(persona_service_is_unlocked());
        let wrong_again = cstr("nope");
        assert_eq!(
            assert_err(unsafe { persona_service_init(db.as_ptr(), wrong_again.as_ptr()) }),
            "Invalid master password"
        );
        assert_ok(persona_shutdown(), "final shutdown");
    }

    /// 先 configure 后 init 的注入顺序（槽位解耦）。
    #[test]
    fn configure_sync_before_init_injects_on_init() {
        let _guard = test_lock();
        reset_state();

        let url = cstr("http://127.0.0.1:1");
        let token = cstr("tok-early");
        assert_ok(
            unsafe { persona_configure_sync(url.as_ptr(), token.as_ptr()) },
            "configure before init",
        );

        let db_path = temp_db_path("early-configure");
        let db = cstr(&db_path);
        let pw = cstr("master-pin");
        assert_ok(
            unsafe { persona_service_init(db.as_ptr(), pw.as_ptr()) },
            "init after configure",
        );
        // lock 本身不写审计（只清密钥），unlock（login）才产生审计事件
        assert_ok(persona_service_lock(), "lock");
        assert_ok(unsafe { persona_service_unlock(pw.as_ptr()) }, "unlock");
        let queued = runtime::block_on(async {
            state::emitter_slot()
                .lock()
                .await
                .as_ref()
                .map(|e| e.queued())
        });
        assert!(
            queued.unwrap_or(0) >= 1,
            "emitter configured before init should be injected"
        );
        assert_ok(persona_shutdown(), "cleanup shutdown");
    }

    /// 与 desktop `attach_sync_emitter` 一致：不做 URL 格式预校验
    /// （`ServerEventSink::new` 恒可构造，格式错误在发送期暴露并退避），
    /// 非法 URL 的重配置同样替换槽位、不 panic。
    #[test]
    fn configure_sync_accepts_malformed_url_like_desktop() {
        let _guard = test_lock();
        reset_state();

        let url = cstr("http://127.0.0.1:1");
        let token = cstr("tok");
        assert_ok(
            unsafe { persona_configure_sync(url.as_ptr(), token.as_ptr()) },
            "enable sync",
        );
        let emitter_before =
            runtime::block_on(async { state::emitter_slot().lock().await.as_ref().is_some() });
        assert!(emitter_before, "emitter should be set after enable");

        let bad_url = cstr("::::not-a-url::::");
        assert_ok(
            unsafe { persona_configure_sync(bad_url.as_ptr(), token.as_ptr()) },
            "malformed url accepted like desktop",
        );
        let emitter_after =
            runtime::block_on(async { state::emitter_slot().lock().await.as_ref().is_some() });
        assert!(
            emitter_after,
            "slot replaced with the new (malformed-url) emitter"
        );
        assert_ok(persona_shutdown(), "cleanup shutdown");
    }
}
