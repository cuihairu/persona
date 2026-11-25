// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Thin entry point: all wiring lives in the library (src/lib.rs); integration
// tests drive commands and the approval server directly through the lib,
// without spawning a real GUI process.
fn main() {
    persona_desktop::run();
}
