//! Persona WASM Crypto Module
//!
//! 为浏览器扩展提供加密操作的WebAssembly模块
//! 支持密码哈希、密钥派生、对称加密等功能

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

mod crypto;
mod utils;

pub use crypto::*;
pub use utils::*;

/// 初始化WASM模块
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    utils::set_panic_hook();
    log("Persona WASM Crypto Module initialized");
}

/// 获取模块版本信息
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 日志输出到浏览器控制台
#[wasm_bindgen]
pub fn log(message: &str) {
    web_sys::console::log_1(&JsValue::from_str(message));
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_version() {
        assert!(!version().is_empty());
    }
}
