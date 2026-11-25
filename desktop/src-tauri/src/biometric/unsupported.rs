//! Any platform outside the three major desktops: always unavailable (fail-closed).

pub fn platform_name() -> &'static str {
    "unsupported"
}

pub fn available() -> bool {
    false
}

pub fn ceremony(_reason: &str) -> Result<(), String> {
    Err("biometric unlock unsupported on this platform".to_string())
}
