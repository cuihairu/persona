//! OpenSSH 私钥导入解析（OpenSSH format / PKCS#8 / PKCS#1 / SEC1，含 PBES2）。
//! 入口：`crypto::ssh_import::import_openssh_private_key`。
#![no_main]

use libfuzzer_sys::fuzz_target;
use persona_core::crypto::ssh_import::import_openssh_private_key;

fuzz_target!(|data: &[u8]| {
    if let Ok(pem) = std::str::from_utf8(data) {
        let _ = import_openssh_private_key(pem, None);
        let _ = import_openssh_private_key(pem, Some("fuzz"));
    }
});
