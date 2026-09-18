// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// 薄入口：装配逻辑全在库（src/lib.rs），集成测试经 lib 直驱命令与
// 审批服务端，不必再起真实 GUI 进程。
fn main() {
    persona_desktop::run();
}
