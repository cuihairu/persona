//! 工具函数模块

use wasm_bindgen::prelude::*;

/// 设置panic hook以获得更好的错误信息
pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Base64编码
#[wasm_bindgen]
pub fn base64_encode(data: &[u8]) -> String {
    base64::encode(data)
}

/// Base64解码
#[wasm_bindgen]
pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, JsValue> {
    base64::decode(encoded).map_err(|e| JsValue::from_str(&format!("Decode failed: {}", e)))
}

/// Hex编码
#[wasm_bindgen]
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Hex解码
#[wasm_bindgen]
pub fn hex_decode(encoded: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(encoded).map_err(|e| JsValue::from_str(&format!("Decode failed: {}", e)))
}

/// 安全比较两个字符串(防止时序攻击)
#[wasm_bindgen]
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_base64() {
        let data = b"hello world";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[wasm_bindgen_test]
    fn test_hex() {
        let data = b"hello";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "68656c6c6f");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[wasm_bindgen_test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("secret", "secret"));
        assert!(!constant_time_compare("secret", "SECRET"));
        assert!(!constant_time_compare("secret", "secre"));
    }
}
