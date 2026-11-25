//! Android JNI export layer: exposes this crate's C ABI bridge to Kotlin as
//! platform-standard JNI symbols (`com.persona.mobile.PersonaBridge`,
//! `System.loadLibrary`).
//!
//! Out parameters are always flattened into a JSON string
//! `{"success":bool,"error":string|null}` that Kotlin parses with org.json — no
//! C structs cross the JNI boundary, so the caller is spared the
//! `persona_free_result` cross-language deallocation burden; `error_message`
//! is returned (via `CString::from_raw`) as soon as it is consumed here, with no
//! leak.
//!
//! Symbol naming: `Java_com_persona_mobile_PersonaBridge_<method>`.
//!
//! Export signature rule (confirmed on device on 2026-10-11, when String out
//! parameters were always null — aa771f4 only patched the NPE symptom):
//! `EnvUnowned` is a `#[repr(transparent)]` raw-pointer wrapper, so exported
//! functions must take `EnvUnowned` **by value** (writing `&mut EnvUnowned`
//! introduces double indirection and breaks every out parameter that flows
//! through env); internal helpers may take a `&mut Env` reference instead.
//!
//! jni 0.22 splits the old `JNIEnv` into `Env` (the environment handle) and
//! `EnvUnowned` (the raw pointer; the old name is now a deprecated alias):
//! `new_string`/`try_to_string` live only on `Env`. Exported function bodies
//! must switch to `&mut Env` via `EnvUnowned::with_env` — no new JNI stack
//! frame is created, and the closure is wrapped by `catch_unwind` so it cannot
//! unwind into the JVM. `run_in_env` absorbs this boilerplate, and errors inside
//! the closure are not lost (they map to a parseable degraded JSON instead of
//! handing null to Kotlin).
use std::ffi::{CStr, CString};

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::{Env, EnvUnowned};

use super::PersonaResult;

/// Degraded out parameter used when new_string fails (JVM already corrupted):
/// prefer returning a parseable failure JSON over null (Kotlin's parseResult
/// can only treat null as an unknown error — one of the crash paths confirmed
/// during the 2026-10-03 walkthrough).
const JNI_DEGRADED_JSON: &str = "{\"success\":false,\"error\":\"jni bridge degraded\"}";

/// Obtain `&mut Env` inside the JNI stack frame and run the closure (see the
/// jni 0.22 note in the module docs). The closure itself returns no error —
/// the string degradation path is completed inside the closure; this only
/// transports the value.
fn run_in_env(env: &mut EnvUnowned, f: impl FnOnce(&mut Env) -> jstring) -> jstring {
    match env
        .with_env(|e: &mut Env| -> Result<jstring, jni::errors::Error> {
            let value = f(e);
            Ok(value)
        })
        .into_outcome()
    {
        jni::Outcome::Ok(value) => value,
        _ => std::ptr::null_mut(),
    }
}

/// Convert a PersonaResult into a JSON jstring; error_message is returned after being consumed.
fn result_to_json(env: &mut Env, result: PersonaResult) -> jstring {
    let error = if result.error_message.is_null() {
        None
    } else {
        // SAFETY: error_message was allocated by PersonaResult::error via
        // CString::into_raw; the contract guarantees ownership is returned
        // here immediately after the string is taken.
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
    // JVM strings may only contain valid UTF-8, so a new_string failure means
    // the host is already corrupted — degrade to the fixed failure JSON
    // (null only if that also fails: both layers down means the JVM can offer
    // no return value at all)
    env.new_string(&json)
        .or_else(|_| env.new_string(JNI_DEGRADED_JSON))
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Inbound jstring → CString (copies out an owned value); returns None with an error message on failure.
fn jstring_to_cstring(env: &mut Env, input: &JString) -> Result<CString, String> {
    let owned = input
        .try_to_string(env)
        .map_err(|_| "failed to read JNI string argument".to_string())?;
    CString::new(owned).map_err(|_| "argument contains interior NUL".to_string())
}

/// Unified JSON error out parameter for invalid arguments.
fn arg_error(env: &mut Env, message: &str) -> jstring {
    let result = PersonaResult::error(message);
    result_to_json(env, result)
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaInit(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    super::persona_init()
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaVersion(
    mut env: EnvUnowned,
    _class: JClass,
) -> jstring {
    // SAFETY: persona_version returns a CString pointer allocated by this library; ownership is returned immediately after the value is read.
    let version = unsafe {
        let ptr = super::persona_version();
        let owned = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        let _ = CString::from_raw(ptr);
        owned
    };
    run_in_env(&mut env, |env| {
        env.new_string(&version)
            .or_else(|_| env.new_string("unknown"))
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceInit(
    mut env: EnvUnowned,
    _class: JClass,
    db_path: JString,
    master_password: JString,
) -> jstring {
    run_in_env(&mut env, |env| {
        let (db_path, master_password) = match (
            jstring_to_cstring(env, &db_path),
            jstring_to_cstring(env, &master_password),
        ) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return arg_error(env, &e),
        };
        // SAFETY: both CStrings live to the end of the call; the pointers are valid inside persona_service_init.
        let result =
            unsafe { super::persona_service_init(db_path.as_ptr(), master_password.as_ptr()) };
        result_to_json(env, result)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceUnlock(
    mut env: EnvUnowned,
    _class: JClass,
    master_password: JString,
) -> jstring {
    run_in_env(&mut env, |env| {
        let master_password = match jstring_to_cstring(env, &master_password) {
            Ok(s) => s,
            Err(e) => return arg_error(env, &e),
        };
        // SAFETY: the CString lives to the end of the call; the pointer is valid inside persona_service_unlock.
        let result = unsafe { super::persona_service_unlock(master_password.as_ptr()) };
        result_to_json(env, result)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceLock(
    mut env: EnvUnowned,
    _class: JClass,
) -> jstring {
    run_in_env(&mut env, |env| {
        result_to_json(env, super::persona_service_lock())
    })
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaServiceIsUnlocked(
    _env: EnvUnowned,
    _class: JClass,
) -> jboolean {
    super::persona_service_is_unlocked() as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_persona_mobile_PersonaBridge_personaShutdown(
    mut env: EnvUnowned,
    _class: JClass,
) -> jstring {
    run_in_env(&mut env, |env| {
        result_to_json(env, super::persona_shutdown())
    })
}

// ---------------------------------------------------------------------------
// Business FFI forwarding (the business layer's JSON envelope {"ok":bool,"error"?,"data"?}
// uses different key names from the lifecycle layer's {"success":bool,"error"} above;
// Kotlin parses them separately)
// ---------------------------------------------------------------------------

/// business C ABI out parameter (owned CString JSON) → jstring; ownership is returned after the value is read.
/// null (both layers down) degrades to a parseable failure envelope — never hand null to Kotlin.
fn business_json_to_jstring(env: &mut Env, json: *mut std::os::raw::c_char) -> jstring {
    const BUSINESS_DEGRADED: &str = "{\"ok\":false,\"error\":\"jni bridge degraded\"}";
    let owned = if json.is_null() {
        BUSINESS_DEGRADED.to_string()
    } else {
        // SAFETY: the pointer was allocated by the business layer via CString::into_raw; ownership is returned immediately after the value is read.
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
    mut env: EnvUnowned,
    _class: JClass,
    query: JString,
) -> jstring {
    run_in_env(&mut env, |env| {
        let query = match jstring_to_cstring(env, &query) {
            Ok(s) => s,
            Err(e) => {
                // Invalid input also follows the business envelope semantics so Kotlin only needs to parse one business format
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
        // SAFETY: the CString lives to the end of the call; the pointer is valid inside persona_credential_search.
        let json = unsafe { super::business::persona_credential_search(query.as_ptr()) };
        business_json_to_jstring(env, json)
    })
}
