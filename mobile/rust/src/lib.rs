use std::ffi::{CStr, CString};
use std::os::raw::c_char;

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

// Placeholder functions for mobile integration
// These would be implemented based on specific mobile platform needs

/// Create a new identity (placeholder)
/// # Safety
/// `name` must be a valid null-terminated UTF-8 string pointer. Caller retains ownership
/// of the pointer and must not pass null.
#[no_mangle]
pub unsafe extern "C" fn persona_create_identity(name: *const c_char) -> PersonaResult {
    if name.is_null() {
        return PersonaResult::error("Name cannot be null");
    }

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return PersonaResult::error("Invalid UTF-8 in name"),
    };

    // TODO: Implement actual identity creation
    println!("Creating identity: {}", name_str);
    PersonaResult::success()
}

/// List identities (placeholder)
#[no_mangle]
pub extern "C" fn persona_list_identities() -> *mut c_char {
    // TODO: Implement actual identity listing
    let json = r#"[]"#;
    match CString::new(json) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

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
    fn create_identity_rejects_null_and_accepts_valid_names() {
        let result = unsafe { persona_create_identity(std::ptr::null()) };
        assert!(!result.success);

        let name = CString::new("mobile-alice").unwrap();
        let result = unsafe { persona_create_identity(name.as_ptr()) };
        assert!(result.success);
        assert!(result.error_message.is_null());
        unsafe { persona_free_result(result) };
    }

    #[test]
    fn create_identity_rejects_non_utf8_names() {
        let name = CString::new(&[0xff, 0xfe][..]).unwrap();
        let result = unsafe { persona_create_identity(name.as_ptr()) };
        assert!(!result.success);
        unsafe {
            let msg = CStr::from_ptr(result.error_message).to_str().unwrap();
            assert_eq!(msg, "Invalid UTF-8 in name");
            persona_free_result(result);
        }
    }

    #[test]
    fn list_identities_returns_empty_json_array() {
        let ptr = persona_list_identities();
        assert!(!ptr.is_null());
        unsafe {
            let json = CStr::from_ptr(ptr).to_str().unwrap();
            assert_eq!(json, "[]");
            persona_free_string(ptr);
        }
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
}
