//! Parses the context.toml mapping (the global `~/.persona/context.toml` and
//! the in-repo `.persona/context.toml` share one parser). Regex keys must be
//! single-quoted literal strings; this target hunts for panics or silent
//! misjudgment from syntax variants. Entry point: `context::ContextMapFile::parse`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use persona_core::context::ContextMapFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = ContextMapFile::parse(text);
    }
});
