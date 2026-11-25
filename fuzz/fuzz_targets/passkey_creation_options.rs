//! Parses WebAuthn `navigator.credentials.create` creation-options JSON
//! (required rp/user, alg allowlist, options-side validation beyond
//! collectedClientData). Entry point: `crypto::passkey::parse_creation_options`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use persona_core::crypto::passkey::parse_creation_options;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(options) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let _ = parse_creation_options(&options, "https://fuzz.example");
});
