//! context.toml 映射解析（全局 `~/.persona/context.toml` 与仓库内
//! `.persona/context.toml` 共用同一解析器）。正则键须单引号字面串；这里专找
//! 语法变体导致的 panic 或静默误判。入口：`context::ContextMapFile::parse`。
#![no_main]

use libfuzzer_sys::fuzz_target;
use persona_core::context::ContextMapFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = ContextMapFile::parse(text);
    }
});
