//! Web3 Secret Storage v3 导入（scrypt/pbkdf2 KDF 参数、keccak MAC、
//! AES-128-CTR）。密码固定，覆盖的是结构解析与 KDF 参数钳制路径。
//! 入口：`crypto::wallet_import_export::import_from_json`。
#![no_main]

use libfuzzer_sys::fuzz_target;
use persona_core::crypto::wallet_import_export::import_from_json;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    if let Ok(json) = std::str::from_utf8(data) {
        let _ = import_from_json(Uuid::nil(), None, json, "fuzz-password");
    }
});
