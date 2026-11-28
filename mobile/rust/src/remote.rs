//! Remote-auth bridge: SRP device login against a persona-server plus the
//! login-awareness device registry reader — the mobile side of the server's
//! PERSONA-DEVALERT-001 surface. The `device_name` passed here is the device
//! fingerprint the server ledger keys on (device + peer IP + time), so the
//! host should default it to something identifiable (e.g. `android-<model>`).
//!
//! Same JSON envelope as the business layer (`{"ok","error"?,"data"?}`), the
//! same `block_on` bridge, and the same memory contract (out strings via
//! `CString::into_raw`; input pointers borrowed for the call). These entry
//! points intentionally do not touch the local vault service — a locked
//! vault can still log in remotely, and a remote login never unlocks
//! anything locally.

use std::ffi::c_char;
use std::future::Future;

use persona_core::auth::remote_http::HttpRemoteAuthProvider;

use crate::business::{err_envelope, ok_envelope};
use crate::runtime;

/// Builds the provider (fail-closed on a malformed base URL), runs `f` on it
/// and pins the shared error mapping: every failure lands in the
/// `{"ok":false,"error"}` envelope with the step name in the message. The
/// error type matches the core remote-auth client's anyhow-flavored returns;
/// the `?`s inside the closures convert `PersonaError` into it.
async fn with_provider<T, Fut, F>(base_url: &str, step: &str, f: F) -> Result<T, String>
where
    F: FnOnce(HttpRemoteAuthProvider) -> Fut,
    Fut: Future<Output = Result<T, anyhow::Error>>,
{
    let provider = HttpRemoteAuthProvider::new(base_url)
        .map_err(|e| format!("Failed to init remote auth client: {}", e))?;
    f(provider)
        .await
        .map_err(|e| format!("{} failed: {}", step, e))
}

/// Bootstrap registration of this device with the server: generates the SRP
/// salt/verifier locally and posts it under the operator's bootstrap Bearer.
/// The password chosen here is the one future `persona_remote_login` calls
/// verify against.
///
/// # Safety
/// All four pointers must be valid null-terminated UTF-8 string pointers.
#[no_mangle]
pub unsafe extern "C" fn persona_remote_register_device(
    base_url: *const c_char,
    bearer: *const c_char,
    device_name: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    let args = match parse_args4(base_url, bearer, device_name, password) {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    let data = runtime::block_on(async {
        with_provider(&args.0, "register", move |provider| async move {
            provider
                .register_device(&args.1, &args.2, &args.3)
                .await
                .map(|_| serde_json::json!({ "device": args.2 }))
        })
        .await
    });
    match data {
        Ok(v) => ok_envelope(&v),
        Err(e) => err_envelope(&e),
    }
}

/// SRP login against the server: `device_name` doubles as the fingerprint the
/// server's login-awareness ledger records (device, peer IP, time, outcome).
/// Returns the short-lived Bearer token (server TTL 15 minutes — the host
/// holds it in memory and re-logs in before expiry) plus the session key
/// fingerprint; the raw session key never crosses the bridge.
///
/// # Safety
/// All three pointers must be valid null-terminated UTF-8 string pointers.
#[no_mangle]
pub unsafe extern "C" fn persona_remote_login(
    base_url: *const c_char,
    device_name: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    let args = match parse_args3(base_url, device_name, password) {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    let data = runtime::block_on(async {
        with_provider(&args.0, "login", move |provider| async move {
            let outcome = provider.begin_login(&args.1).await?.finish(&args.2).await?;
            Ok(serde_json::json!({
                "device": args.1,
                "token": outcome.token,
                "expires_in_secs": outcome.expires_in_secs,
                "session_key_fingerprint": outcome.session_key_fingerprint,
            }))
        })
        .await
    });
    match data {
        Ok(v) => ok_envelope(&v),
        Err(e) => err_envelope(&e),
    }
}

/// Reads the server's login-awareness device registry
/// (`GET /api/v1/auth/devices`) with a Bearer from `persona_remote_login`.
/// The server's JSON (`{"devices":[...]}`) is passed through verbatim — the
/// shape is the server's contract.
///
/// # Safety
/// Both pointers must be valid null-terminated UTF-8 string pointers.
#[no_mangle]
pub unsafe extern "C" fn persona_remote_devices(
    base_url: *const c_char,
    token: *const c_char,
) -> *mut c_char {
    let (base, token) = match parse_args2(base_url, token) {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    let data = runtime::block_on(async {
        with_provider(&base, "devices", move |provider| async move {
            provider.devices(&token).await
        })
        .await
    });
    match data {
        Ok(v) => ok_envelope(&v),
        Err(e) => err_envelope(&e),
    }
}

// --- borrowed-string parsing (null / non-UTF-8 land in the error envelope) ---

struct Args4(String, String, String, String);
struct Args3(String, String, String);
type Args2 = (String, String);

unsafe fn parse_args4(
    a: *const c_char,
    b: *const c_char,
    c: *const c_char,
    d: *const c_char,
) -> Result<Args4, String> {
    Ok(Args4(
        crate::ptr_to_str(a)?.to_string(),
        crate::ptr_to_str(b)?.to_string(),
        crate::ptr_to_str(c)?.to_string(),
        crate::ptr_to_str(d)?.to_string(),
    ))
}

unsafe fn parse_args3(
    a: *const c_char,
    b: *const c_char,
    c: *const c_char,
) -> Result<Args3, String> {
    Ok(Args3(
        crate::ptr_to_str(a)?.to_string(),
        crate::ptr_to_str(b)?.to_string(),
        crate::ptr_to_str(c)?.to_string(),
    ))
}

unsafe fn parse_args2(a: *const c_char, b: *const c_char) -> Result<Args2, String> {
    Ok((
        crate::ptr_to_str(a)?.to_string(),
        crate::ptr_to_str(b)?.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn take(ptr: *mut c_char) -> serde_json::Value {
        let s = unsafe { CString::from_raw(ptr) }.into_string().unwrap();
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn null_argument_lands_in_error_envelope() {
        let out = unsafe {
            persona_remote_login(
                CString::new("http://127.0.0.1:1").unwrap().into_raw(),
                std::ptr::null(),
                CString::new("pw").unwrap().into_raw(),
            )
        };
        let v = take(out);
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "null argument", "{v}");
    }

    #[test]
    fn unreachable_server_lands_in_error_envelope() {
        // Port 1 on loopback: nothing listens, the client must fail closed
        // into the envelope instead of panicking across the FFI boundary.
        let out = unsafe {
            persona_remote_login(
                CString::new("http://127.0.0.1:1").unwrap().into_raw(),
                CString::new("phone").unwrap().into_raw(),
                CString::new("pw").unwrap().into_raw(),
            )
        };
        let v = take(out);
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("login failed"), "{v}");
    }
}
