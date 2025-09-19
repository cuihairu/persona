use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use persona_core::{Result, PersonaError};

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
#[no_mangle]
pub extern "C" fn persona_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
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
#[no_mangle]
pub extern "C" fn persona_free_result(result: PersonaResult) {
    if !result.error_message.is_null() {
        unsafe {
            let _ = CString::from_raw(result.error_message);
        }
    }
}

// Placeholder functions for mobile integration
// These would be implemented based on specific mobile platform needs

/// Create a new identity (placeholder)
#[no_mangle]
pub extern "C" fn persona_create_identity(name: *const c_char) -> PersonaResult {
    if name.is_null() {
        return PersonaResult::error("Name cannot be null");
    }
    
    let name_str = unsafe {
        match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return PersonaResult::error("Invalid UTF-8 in name"),
        }
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