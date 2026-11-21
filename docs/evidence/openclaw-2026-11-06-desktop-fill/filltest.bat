@echo off
set RUSTUP_TOOLCHAIN=stable
set CARGO_INCREMENTAL=0
set REPO=C:/Users/Administrator/persona
set RUSTFLAGS=-C link-arg=/MANIFEST:EMBED -C link-arg=/MANIFESTINPUT:%REPO%/desktop/src-tauri/windows/app.manifest -C link-arg=/NODEFAULTLIB:libvcruntimed.lib -C link-arg=/NODEFAULTLIB:vcruntime.lib -C link-arg=/NODEFAULTLIB:libcmtd.lib -C link-arg=/NODEFAULTLIB:msvcrt.lib -C link-arg=/NODEFAULTLIB:msvcrtd.lib -C link-arg=/NODEFAULTLIB:libucrt.lib -C link-arg=/NODEFAULTLIB:libucrtd.lib -C link-arg=/DEFAULTLIB:libcmt.lib -C link-arg=/DEFAULTLIB:libvcruntime.lib -C link-arg=/DEFAULTLIB:ucrt.lib
cd /d %REPO%/desktop/src-tauri
if exist C:\Users\Administrator\filltest.done del C:\Users\Administrator\filltest.done
cargo test --lib desktop_fill > C:\Users\Administrator\filltest-lib.log 2>&1
set LIBEXIT=%errorlevel%
cargo test -p persona-fill-test --lib readback_frame > C:\Users\Administrator\filltest-frame.log 2>&1
set FRAMEEXIT=%errorlevel%
cargo test --features fill-test-host -p persona-fill-test --test desktop_fill_cross_process > C:\Users\Administrator\filltest-xproc.log 2>&1
set XEXIT=%errorlevel%
cargo test --features fill-test-host -p persona-fill-test --test desktop_fill_command_cancel > C:\Users\Administrator\filltest-cmdcancel.log 2>&1
set CMDEXIT=%errorlevel%
echo lib_exit=%LIBEXIT% frame_exit=%FRAMEEXIT% xproc_exit=%XEXIT% cmdcancel_exit=%CMDEXIT% > C:\Users\Administrator\filltest.done
