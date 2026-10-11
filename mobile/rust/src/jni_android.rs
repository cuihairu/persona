//! Android JNI 导出层：把同 crate 的 C ABI 桥以平台标准 JNI 符号暴露给
//! Kotlin（`com.persona.mobile.PersonaBridge`，`System.loadLibrary`）。
//!
//! 出参一律打平为 JSON 字符串 `{"success":bool,"error":string|null}`，
//! Kotlin 侧用 org.json 解析——不在 JNI 边界传递 C 结构体，免除调用方
//! `persona_free_result` 的跨语言归还负担；`error_message` 在本层消费后
//! 即归还（`CString::from_raw`），不泄漏。
//!
//! 符号命名对应：`Java_com_persona_mobile_PersonaBridge_<method>`。
//!
//! 导出签名铁律（2026-10-11 实机走查实锤，String 出参曾恒为 null——NPE 崩溃
//! aa771f4 只治了症状）：`JNIEnv` 是 `#[repr(transparent)]` 裸指针包装，
//! 导出函数必须**按值**收 `JNIEnv`（写 `&mut JNIEnv` 会变成双重间接，一切
//! 经 env 的出参都废）；内部 helper 收 `&mut JNIEnv` 引用则没问题。

use std::ffi::{CStr, CString};

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;

use super::PersonaResult;

/// new_string 失败（JVM 已损坏）时的降级出参：宁可给一条可解析的
/// 失败 JSON，也不返回 null（Kotlin 侧 parseResult 对 null 只能当未知
/// 错误，2026-10-03 走查实锤的崩溃路径之一）。
const JNI_DEGRADED_JSON: &str = "{\"success\":false,\"error\":\"jni bridge degraded\"}";

/// 把 PersonaResult 转成 JSON jstring；error_message 消费后归还。
fn result_to_json(env: &mut JNIEnv, result: PersonaResult) -> jstring {
    let error = if result.error_message.is_null() {
        None
    } else {
        // SAFETY: error_message 由 PersonaResult::error 经 CString::into_raw
        // 分配，契约保证此处取走字符串后立刻归还所有权。
        let owned = unsafe {
            let s = CStr::from_ptr(result.error_message)
                .to_string_lossy()
                .into_owned();
            let _ = CString::from_raw(result.error_message);
            s
        };
        Some(owned)
    };
    let json = match error {
        Some(e) => format!(
            "{{\"success\":{},\"error\":{}}}",
            result.success,
            serde_json::to_string(&e).unwrap_or_else(|_| "\"\"".to_string())
        ),
        None => format!("{{\"success\":{},\"error\":null}}", result.success),
    };
    // JVM 字符串只能含有效 UTF-8，new_string 失败即宿主已损坏——退化为
    // 固定失败 JSON（再失败才 null，两层都挂说明 JVM 无从谈返回值）
    env.new_string(&json)
        .or_else(|_| env.new_string(JNI_DEGRADED_JSON))
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// 入参 jstring → CString（拷出 owned），失败时返回 None 并记错误消息。
fn jstring_to_cstring(env: &mut JNIEnv, input: &JString) -> Result<CString, String> {
    let owned = env
        .get_string(input)
        .map_err(|_| "failed to read JNI string argument".to_string())?
        .to_string_lossy()
        .into_owned();
    CString::new(owned).map_err(|_| "argument contains interior NUL".to_string())
}

/// 入参非法时的统一 JSON 错误出参。
fn arg_error(env: &mut JNIEnv, message: &str) -> jstring {
    let result = PersonaResult::error(message);
    result_to_json(env, result)
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaInit(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    super::persona_init()
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    // SAFETY: persona_version 返回本库分配的 CString 指针，取值后立即归还。
    let version = unsafe {
        let ptr = super::persona_version();
        let owned = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        let _ = CString::from_raw(ptr);
        owned
    };
    env.new_string(&version)
        .or_else(|_| env.new_string("unknown"))
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceInit(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
) -> jstring {
    let (db_path, master_password) = match (
        jstring_to_cstring(&mut env, &db_path),
        jstring_to_cstring(&mut env, &master_password),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return arg_error(&mut env, &e),
    };
    // SAFETY: 两个 CString 保活到调用结束，指针在 persona_service_init 内有效。
    let result = unsafe { super::persona_service_init(db_path.as_ptr(), master_password.as_ptr()) };
    result_to_json(&mut env, result)
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceUnlock(
    mut env: JNIEnv,
    _class: JClass,
    master_password: JString,
) -> jstring {
    let master_password = match jstring_to_cstring(&mut env, &master_password) {
        Ok(s) => s,
        Err(e) => return arg_error(&mut env, &e),
    };
    // SAFETY: CString 保活到调用结束，指针在 persona_service_unlock 内有效。
    let result = unsafe { super::persona_service_unlock(master_password.as_ptr()) };
    result_to_json(&mut env, result)
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceLock(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    result_to_json(&mut env, super::persona_service_lock())
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceIsUnlocked(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    super::persona_service_is_unlocked() as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaShutdown(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    result_to_json(&mut env, super::persona_shutdown())
}

// ---------------------------------------------------------------------------
// 业务 FFI 转发（business 层 JSON 包络 {"ok":bool,"error"?,"data"?}，与上面
// 生命周期层的 {"success":bool,"error"} 键名不同，Kotlin 侧分别解析）
// ---------------------------------------------------------------------------

/// business C ABI 出参（owned CString JSON）→ jstring；取值后归还所有权。
/// null（两层全挂）降级为可解析失败包络，不把 null 递给 Kotlin。
fn business_json_to_jstring(env: &mut JNIEnv, json: *mut std::os::raw::c_char) -> jstring {
    const BUSINESS_DEGRADED: &str = "{\"ok\":false,\"error\":\"jni bridge degraded\"}";
    let owned = if json.is_null() {
        BUSINESS_DEGRADED.to_string()
    } else {
        // SAFETY: 指针由 business 层 CString::into_raw 分配，取值后立刻归还。
        unsafe {
            let s = CStr::from_ptr(json).to_string_lossy().into_owned();
            let _ = CString::from_raw(json);
            s
        }
    };
    env.new_string(&owned)
        .or_else(|_| env.new_string(BUSINESS_DEGRADED))
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaCredentialSearch(
    mut env: JNIEnv,
    _class: JClass,
    query: JString,
) -> jstring {
    let query = match jstring_to_cstring(&mut env, &query) {
        Ok(s) => s,
        Err(e) => {
            // 入参非法也走 business 包络语义，Kotlin 只需解析一种业务格式
            let degraded = format!(
                "{{\"ok\":false,\"error\":{}}}",
                serde_json::to_string(&e).unwrap_or_else(|_| "\"error\"".to_string())
            );
            return env
                .new_string(&degraded)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut());
        }
    };
    // SAFETY: CString 保活到调用结束，指针在 persona_credential_search 内有效。
    let json = unsafe { super::business::persona_credential_search(query.as_ptr()) };
    business_json_to_jstring(&mut env, json)
}
