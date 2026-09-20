//! 非三大桌面平台：一律不可用（fail-closed）。

pub fn platform_name() -> &'static str {
    "unsupported"
}

pub fn available() -> bool {
    false
}

pub fn ceremony(_reason: &str) -> Result<(), String> {
    Err("biometric unlock unsupported on this platform".to_string())
}
