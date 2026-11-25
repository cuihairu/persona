//! Web3 Secret Storage v3 import (scrypt/pbkdf2 KDF params, keccak MAC,
//! AES-128-CTR). The password is fixed; this targets structural parsing and
//! KDF parameter clamping paths. Entry point: `crypto::wallet_import_export::import_from_json`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use persona_core::crypto::wallet_import_export::import_from_json;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    if let Ok(json) = std::str::from_utf8(data) {
        let _ = import_from_json(Uuid::nil(), None, json, "fuzz-password");
    }
});
