# Mobile HarmonyOS Bridge Design (P2 design-first)

> [English](MOBILE_HARMONY_BRIDGE.md) | [中文](https://github.com/cuihairu/persona/blob/main/docs/MOBILE_HARMONY_BRIDGE.zh.md)

PERSONA-MOBILE-002 P2: the ArkTS UI skeleton and `PersonaBridge.ets` stub already exist
(`mobile/harmony/`); the napi wrapper layer is the missing piece. This document fixes the
design before any code lands. Status: **design only — no DevEco/OpenHarmony SDK on any
current fleet machine, so implementation waits for that environment.**

## Decision: raw N-API shim over the existing C ABI (not napi-rs)

The three platforms must share one native contract. That contract already exists:
`mobile/rust/src/lib.rs` + `mobile/rust/src/remote.rs` export platform-independent
`extern "C"` functions (lifecycle `PersonaResult` + business `{"ok",...}` JSON envelopes;
Android's JNI layer just forwards them; iOS links the staticlib directly).

| Option | Rust side | New deps | ABI consistency |
| --- | --- | --- | --- |
| **A. napi-rs (ohos backend)** | `#[napi]` re-wrapping of every function | heavy proc-macro chain into `mobile/rust` | second re-wrapping layer drifts from iOS/Android |
| **B. raw N-API C shim (chosen)** | none | DevEco template's default `cpp/` dir only | shim forwards the *same* extern "C" symbols, like jni_android.rs |

Option B keeps `mobile/rust` free of napi dependencies and makes the HarmonyOS layer a
sibling of `jni_android.rs` (thin forwarder, identical envelope semantics). The shim is
mechanical: per function — parse N-API string args, call the C function, wrap the
returned JSON heap string into a `napi_value`, `persona_free_string` it, return.

## Wiring plan

1. **Rust staticlib**: `cargo build -p persona-mobile --release` per OHOS target
   (`aarch64-unknown-linux-ohos` for device, `x86_64-unknown-linux-ohos` for emulator;
   both Tier 2, installable via `rustup target add` on Linux). The OHOS SDK's native
   toolchain (NDK clang wrapper) supplies `CC_aarch64_unknown_linux_ohos` et al.
   Artifacts land in `entry/libs/<abi>/libpersona_mobile.so`.
2. **C shim** (`entry/src/main/cpp/napi_init.cpp` + `CMakeLists.txt`, the DevEco default
   template): declares the C ABI (same signatures as `include/Persona.h`), links the
   prebuilt `.so` via an `IMPORTED` CMake target per ABI, and registers one napi module
   (`persona_mobile`) exporting: `personaInit`, `personaVersion`,
   `personaServiceInit`, `personaServiceUnlock`, `personaServiceLock`,
   `personaServiceIsUnlocked`, `personaShutdown`, `personaCredentialSearch`,
   `personaRemoteRegisterDevice`, `personaRemoteLogin`, `personaRemoteDevices`,
   `personaFreeString`. All JSON-envelope pass-through; no envelope re-parsing in C.
3. **ArkTS**: `PersonaBridge.ets` swaps the `NOT_WIRED` stubs for real calls
   (`import personaNapi from 'libentry.so'`); adds `parseBusiness` (mirror of the
   Kotlin one) and the three remote methods. `types/libentry/index.d.ts` declares the
   module surface. Signatures stay exactly as stubbed today.
4. **Threading**: the C functions block on the native tokio runtime. First pass is
   synchronous napi calls driven from ArkTS `taskpool` (the Android pattern: never the
   UI thread). If latency shows, upgrade to `napi_create_async_work` inside the shim —
   the ArkTS surface does not change.
5. **UI**: `Index.ets` gains the same three screens already shipped on Android
   (init/unlock lifecycle, credential list, login-awareness settings section with
   register/login/refresh-devices). Device name default: `ohos-<deviceName>` with the
   same `[A-Za-z0-9._-]` whitelist, 48 chars.

## DEVALERT linkage

Nothing OHOS-specific: `persona_remote_register_device` / `persona_remote_login` /
`persona_remote_devices` are the same shared-C-ABI functions the Android emulator E2E
validated end-to-end (herald `[warning] New device login: …`). The fingerprint report
is the SRP login itself, on every platform.

## Build & verification chain

- **Can run on current Linux fleet machines**: rust cross-build of
  `libpersona_mobile.so` for both ohos targets + `cargo test -p persona-mobile`
  (host) + shim-free unit tests. CI can adopt this alongside the Android job.
- **Needs DevEco Studio (Windows/macOS only)**: `hvigorw assembleHap`, the emulator,
  `hdc install`, and on-device walkthrough. Same acceptance recipe as the Android P0
  round: init → unlock → lock → re-unlock → credential list → register → SRP login →
  device list, then a second device login to trigger the herald NOTICE.

## Open questions

1. **napi module naming**: `libentry.so` (DevEco template default) vs
   `libpersona_mobile_napi.so` (README's earlier wording). Leaning toward the template
   default to keep the DevEco import path stock; the README wording updates at
   implementation time.
2. **OHOS SDK availability on fleet machines**: none today; the rust cross-build leg
   can start as soon as the SDK native toolchain is provisioned anywhere.
3. **Signature-scoped key store**: OHOS HUKS could later host the master-password
   unlock (like Keychain/Keystore on iOS/Android) — out of scope for the first wired
   build; noted because the desktop biometric trait (`BiometricProvider`) is the same
   seam a `HuksProvider` would plug into.
