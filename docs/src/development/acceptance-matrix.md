# Acceptance Scenarios & Cross-Platform Capability Matrix

> **English** | [中文](/zh/development/acceptance-matrix)

One-line framing: **acceptance is not just "tests are green"**. This list splits acceptance into
four layers (compiles / simulated test / real interaction / long-running), gives the current
inventory, then a capability matrix, per-scenario clauses, and a build backlog.

## The four layers

| Layer            | Definition                                                                                                                | Qualifying evidence                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Compiles         | A runnable artifact is produced on that platform/toolchain                                                                | A passing CI job, or local build logs                   |
| Simulated test   | Automated assertions against controlled stand-ins (in-memory DB, mock IPC, jsdom, temp HOME, real loopback TCP)           | `cargo test` / `nextest` / `jest`                       |
| Real interaction | Round trips against a real external system: real sshd / real GitHub / real browser / real desktop session / real hardware | Manual scripts with actual output, or on-device records |
| Long-running     | Multi-hour durability, crash recovery, background residency, restart recovery                                             | A soak job, or a scheduled long-running job artifact    |

**Status labels** (four from AUDIT-061 in the
[2026-10-18 audit task list](https://github.com/cuihairu/persona/blob/main/docs/review/task-list-2026-10-18.md),
plus two more to describe the mobile side):

- **Implemented & tested**: code exists, automated tests assert its behavior
- **Implemented, not verified on-device**: code exists, correctness was never executed on that
  platform
- **In design**: plan written, code not landed
- **Explicitly unsupported**: deliberately unsupported on this platform (including VM/CI without
  hardware)
- **Skeleton only**: directory and bridge interface exist, but the bridge returns a stub or cannot
  compile
- **Not implemented**: does not exist

## Current inventory (count method at the bottom)

### Test assets

| Surface                                      | Tests                                                                                | CI job                                           | Artifact                                          |
| -------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------ | ------------------------------------------------- |
| `core` (persona-core)                        | 1,198 inline + 7 integration files in `core/tests/`                                  | `rust` / `rust-windows` / `rust-windows-desktop` | lib only                                          |
| `cli` (persona)                              | 521 inline + 19 integration (assert_cmd driven)                                      | same as core                                     | `persona` binary, **no published package**        |
| `agents/ssh-agent`                           | 80 inline + 13 (`e2e_test.rs` 10, `daemon_test.rs` 3)                                | same as core                                     | binary, not published                             |
| `server` (persona-server)                    | 131 inline + 6 (real TCP, two devices)                                               | same as core + `docker.yml`                      | GHCR image                                        |
| `connect-server`                             | 37 inline, **no `tests/` dir**                                                       | `rust`                                           | none (embedded in desktop/CLI)                    |
| `desktop/src-tauri` (**separate workspace**) | 261 inline + 8 integration                                                           | `desktop` / `rust-windows-desktop`               | deb/rpm/AppImage/nsis/dmg                         |
| `desktop/src` frontend                       | 726 `it()`, 56 test files                                                            | `desktop` (`test:ci:coverage`)                   | bundled into desktop packages                     |
| `browser/chromium-extension`                 | 164 `it()`/`test()`                                                                  | `web`                                            | unzipped extension built in CI, **not published** |
| `browser/safari-extension`                   | **0** (no test target in `Package.swift`)                                            | none                                             | none                                              |
| `mobile/rust`                                | 20 (`jni_android.rs` untested)                                                       | `rust` (host) + `android` (aarch64)              | `libpersona_mobile.so`                            |
| `mobile/android`                             | **0** (no test source sets)                                                          | `desktop-build.yml::android`                     | arm64 APK                                         |
| `mobile/ios`                                 | 2 XCTest methods, **never executed**                                                 | none                                             | none                                              |
| `mobile/harmony`                             | **0** (hypium declared, no test dir)                                                 | none                                             | none                                              |
| `website`                                    | **0**                                                                                | `web` (only `run build`)                         | built in CI, not deployed                         |
| fuzz                                         | 4 targets, corpora present locally (2,176 / 857 / 744 / 127 inputs)                  | **not in CI**                                    | none                                              |
| Cross-impl oracle                            | 1 (`scripts/steam_guard_verify.py`, independent implementation pinned by core tests) | `rust`                                           | —                                                 |

### Load-bearing facts (honest boundaries)

1. **`desktop/src-tauri` is a separate cargo workspace**: root-level
   `cargo clippy --workspace --all-features` does not cover it — it needs
   `--manifest-path desktop/src-tauri/Cargo.toml` (same for fmt).
2. **iOS and HarmonyOS have never been compiled anywhere** — not in CI, and there is no evidence of
   local compilation; `rust-toolchain.toml` installs only the `aarch64-linux-android` target.
3. **The Android APK builds but has never been run on a device**; zero test source sets.
4. **Long-running coverage is zero**: the longest job is 120 minutes, nextest hard-kills at 240s,
   and there is no soak job or multi-target `Makefile` long-run.
5. **All real-interaction evidence is outside CI**: `scripts/e2e-ssh-github.sh`,
   `verify-account-redline.sh`, `verify-sync-group-pairing.sh`, and `verify-biometric-linux.md` are
   manual scripts; `Xvfb` and `playwright` have zero hits repo-wide.
6. **The `ci.yml` biometric spike is `continue-on-error` and explicitly marked non-gating** — the
   runner VM has no Secure Enclave / Touch ID / Windows Hello, so the probe's real OSStatus/HRESULT
   output _is_ the deliverable.
7. **Toolchain**: `rust-toolchain.toml` pins `1.97.0`; the `dtolnay/rust-toolchain@stable` in the
   workflows does not take effect (the directory-level override always wins).
8. **The `Makefile` `release-*` targets call a nonexistent `scripts/release.sh`** — dangling targets
   (consistent with the manual-version-number redline; `git tag` contains only `nightly`).
9. `agents/ssh-agent/TESTING.md` says "7 passed; 2 ignored", but `e2e_test.rs` now contains 10
   `#[test]` — the doc is stale.
10. **`docs/src/` previously had no acceptance/gate content at all**, and `.github/ISSUE_TEMPLATE`
    has no acceptance field. This page is net-new.

### Platform capability matrix

| Platform / surface                                   | Compiles                                                                                                | Simulated test                            | Real interaction                                            | Long-running |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------- | ------------ |
| Rust core (core/cli/server/ssh-agent/connect-server) | ✅ ubuntu + windows-gnu/msvc check                                                                      | ✅ 1,930 inline + 65 integration          | ⚠️ manual scripts only                                      | ❌ zero      |
| Desktop (src-tauri, ubuntu)                          | ✅                                                                                                      | ✅ 261 + 8                                | ⚠️ Linux walkthrough pipeline is local-only, not in CI      | ❌           |
| Desktop Windows                                      | ⚠️ **`cargo check` only** (`rust-windows-desktop` comment: runtime behavior still needs a real machine) | ⚠️ only the host-side `cargo test` subset | ❌ named-pipe approval / TPM / NSIS all unverified          | ❌           |
| Desktop macOS                                        | ⚠️ only `desktop-build.yml::build` can build it                                                         | ⚠️ no macOS test job                      | ❌ Secure Enclave / Safari bridge unverified                | ❌           |
| Desktop Linux                                        | ✅                                                                                                      | ✅                                        | ⚠️ manual scripts + local screenshot pipeline (not in CI)   | ❌           |
| Browser extension Chromium                           | ✅ `web` build                                                                                          | ✅ 164 (jsdom)                            | ❌ no real browser↔host round trip                         | ❌           |
| Safari extension                                     | ❌ no build                                                                                             | ❌ 0 tests                                | ❌                                                          | ❌           |
| Android                                              | ✅ arm64 APK (`desktop-build.yml::android`, **conditional on the nightly 48h gate**)                    | ❌ 0 tests                                | ❌ never run on a device                                    | ❌           |
| iOS                                                  | ❌ **never compiled** (`Persona.h` exposes only 10 lifecycle symbols; business FFI not exposed)         | ❌ 2 XCTest never executed                | ❌                                                          | ❌           |
| HarmonyOS                                            | ❌ never compiled (no hvigor wrapper; builds only inside DevEco Studio)                                 | ❌ 0 tests                                | ❌                                                          | ❌           |
| Self-hosted server (GHCR)                            | ✅ docker buildx                                                                                        | ✅ 6 two-device tests                     | ⚠️ `verify-account-redline.sh` boots a real server manually | ❌           |

### Cross-client consistency: the biggest hole

Searching `desktop/src-tauri/src` for lock/identity notification to **other processes**: **zero
hits**. The only cross-process entry is the Unix socket in `passkey_bridge.rs` (approval requests
inbound only). Every client opens the same vault file and holds its own `PersonaService`, with no
shared lock state, no active-identity broadcast, and no permission revocation.

## End-to-end scenario list

Status uses the labels above; the "evidence" column names the existing anchor or the explicit gap.

### Identity switching

| ID  | Scenario                                                                                       | Layer          | Status                  | Acceptance clause                                                                                                                                              | Evidence / gap                                                                                    |
| --- | ---------------------------------------------------------------------------------------------- | -------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| S01 | After a desktop identity switch, CLI / browser extension / mobile see the same active identity | Simulated test | ❌ Not implemented      | Two clients share one vault; after switching to B in desktop, the other side returns B                                                                         | **Missing a two-client-one-vault harness**; `connect-server` does not read active identity at all |
| S02 | When the backend switch fails, the UI keeps the original identity and reports the error        | Simulated test | ✅ Implemented & tested | All three arms (`success:false` / thrown / `silent`) assert the original identity is unchanged, target credentials are not fetched, and no success toast fires | `desktop/src/hooks/usePersonaService.test.tsx` (R-P1)                                             |
| S03 | Identity switching goes through audit and sync capture                                         | Simulated test | 🔶 In design            | A switch produces an audit row and a sync operation                                                                                                            | The current path bypasses the service — see [Session Center](/zh/design/session-center) Phase 1   |
| S04 | Switching while locked is rejected                                                             | Simulated test | ✅ Implemented & tested | Locked state returns `Service is locked`                                                                                                                       | Desktop set/clear handler gate                                                                    |
| S05 | A lock is visible across processes                                                             | Simulated test | ❌ Not implemented      | After desktop locks, the CLI/agent/bridge next request returns `vault_locked`                                                                                  | Session center A2                                                                                 |

### Credential context selection

| ID  | Scenario                                                              | Layer            | Status                             | Acceptance clause                                                              | Evidence / gap                                          |
| --- | --------------------------------------------------------------------- | ---------------- | ---------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------- |
| S06 | Context only suggests, never authorizes                               | Simulated test   | ✅ Implemented, single client only | A context match widens no authorization decision                               | `CONTEXT_AWARE_DESIGN.md` has a staged acceptance table |
| S07 | Context → credential → fill / sign chain is consistent across clients | Real interaction | ❌ Not implemented                 | The same context yields the same credential for desktop fill and agent signing | No cross-client harness exists                          |

### Unified authorization

| ID  | Scenario                                                                         | Layer          | Status                  | Acceptance clause                                                       | Evidence / gap                                              |
| --- | -------------------------------------------------------------------------------- | -------------- | ----------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------- |
| S08 | Principal × action × resource decision matrix                                    | Simulated test | ✅ Implemented & tested | All four decisions covered, including non-interactive folding to denial | `core/src/authz.rs` unit tests                              |
| S09 | Decisions are attributable (audit carries principal and reason)                  | Simulated test | 🔶 In design            | Granted actions carry `principal_kind` / `decision_reason` too          | Today only Connect scope denials are audited (P0)           |
| S10 | A Connect token's overreach is denied immediately and converges immediately      | Simulated test | ✅ Implemented & tested | Per-request table lookup; revocation converges across processes         | `connect_authenticate`; S13 regression                      |
| S11 | A limited agent grant: signing allowed, export and non-bound keys denied         | Simulated test | 🔶 In design            | Overreach in a non-interactive context fails fast rather than hanging   | [Principal & Action design](/zh/design/principal-action) P3 |
| S12 | The write path goes through unified adjudication (after write verbs are decided) | Simulated test | 🔶 In design            | The 32 `ensure_unlocked()` sites converge onto `ensure_authorized`      | Same doc, P1/P2                                             |

### Cross-client consistency

| ID  | Scenario                                                                             | Layer            | Status                  | Acceptance clause                                                                        | Evidence / gap             |
| --- | ------------------------------------------------------------------------------------ | ---------------- | ----------------------- | ---------------------------------------------------------------------------------------- | -------------------------- |
| S13 | Revoking a Connect token takes effect across processes immediately                   | Simulated test   | ✅ Implemented & tested | Keep as a regression item                                                                | `core/src/service.rs:2374` |
| S14 | After desktop unlock, the CLI perceives it immediately                               | Simulated test   | ❌ Not implemented      | Once the version column advances on unlock, the CLI's next request succeeds              | Session center A1          |
| S15 | Whether Connect follows the active identity (needs an explicit decision)             | Simulated test   | ⚠️ Undefined            | Either follow it, or document "does not follow" — silent inconsistency is not acceptable | Session center A3          |
| S16 | A CLI-started SSH agent can surface signing requests to the desktop for confirmation | Real interaction | ❌ Not implemented      | The desktop dialog opens and can be answered Allow/Deny; 120s timeout denies             | Session center A5          |

### Security regression (AUDIT-060 coverage)

| ID  | Scenario                                                                                      | Layer            | Status                                              | Acceptance clause                                                                                | Evidence / gap                                                                  |
| --- | --------------------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| S17 | Auto-lock / re-authentication consistent across three platforms                               | Real interaction | ⚠️ Partial                                          | Linux has a manual script; macOS / Windows have no on-device records                             | `verify-biometric-linux.md`; `BUGS.md` 15/15                                    |
| S18 | SSH agent Windows named-pipe approval + biometrics                                            | Real interaction | 🚫 BLOCKED                                          | Requires a real Windows desktop session                                                          | AUDIT-032 still open; `ci.yml` runs `cargo check` only                          |
| S19 | NSIS installer 7 steps (fresh×2 / upgrade / silent / MSI migration / uninstall×2 / downgrade) | Real interaction | ⚠️ checklist, no automation                         | Each step executed manually with records                                                         | `WINDOWS_INSTALLER.md` §5                                                       |
| S20 | Two-device sync convergence over real TCP + real-conflict dual-version retention              | Simulated test   | ✅ Implemented & tested                             | On equal lamport / different device, the loser is demoted to the conflict area and never dropped | `server/tests/sync_two_device_e2e.rs`; `E2EE_SYNC_DESIGN.md` acceptance anchors |
| S21 | Biometrics (Secure Enclave / Touch ID / TPM)                                                  | Real interaction | 🚫 Explicitly unsupported (CI VMs have no hardware) | Spike probe output is the deliverable; non-gating                                                | `desktop-build.yml::build` biometric spike                                      |
| S22 | Cross-implementation crypto oracle                                                            | Simulated test   | ✅ Implemented & tested                             | Vectors from an independent Python implementation are pinned by core tests                       | `scripts/steam_guard_verify.py`                                                 |

### Long-running and durability

| ID  | Scenario                                                                   | Layer        | Status                        | Acceptance clause                                                               | Evidence / gap                                       |
| --- | -------------------------------------------------------------------------- | ------------ | ----------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------- |
| S23 | Restart recovery: unlock state is not persisted; a lock survives a restart | Long-running | ⚠️ Untested                   | Re-authentication is required after restart                                     | No recovery test                                     |
| S24 | Loss of unflushed batches after a crash                                    | Long-running | ❌ Known limitation, untested | Quantify the loss window, or add a persistent outbox                            | Recorded as a known limitation in `FINAL_SUMMARY.md` |
| S25 | Multi-hour background residency (agent / connect / bridge)                 | Long-running | ❌ Zero coverage              | No leaks, no lock leaks, no handle growth                                       | No soak job; `Makefile::benchmark` has no benches    |
| S26 | Concurrent clients writing the same vault                                  | Long-running | ⚠️ Transaction-level only     | SQLite transaction correctness ≠ session consistency (see Session Center C1/C3) | No concurrency stress test                           |

### Mobile

| ID  | Scenario                                                           | Layer            | Status             | Acceptance clause                                                    | Evidence / gap                                       |
| --- | ------------------------------------------------------------------ | ---------------- | ------------------ | -------------------------------------------------------------------- | ---------------------------------------------------- |
| S27 | The Android arm64 APK runs a complete unlock flow on a real device | Real interaction | ⚠️ Unverified      | Unlock → identity → credential → copy/TOTP                           | The APK builds; never run on a device                |
| S28 | iOS at least compiles                                              | Compiles         | ❌ Not implemented | Add the `aarch64-apple-ios` target and produce a compilable artifact | `Persona.h` exposes only 10 lifecycle symbols        |
| S29 | The HarmonyOS bridge compiles and returns real results             | Compiles         | 🔶 Skeleton only   | `PersonaBridge.ets` stops returning `NOT_WIRED`                      | No napi-rs backend; builds only inside DevEco Studio |

## Build backlog (by priority)

**P1**

1. **Two-client-one-vault harness** (unblocks S01 / S05 / S14 / S16): one vault file plus a desktop
   and CLI command chain, running "switch identity / lock / unlock / revoke" cross-end assertions
   under a `tempfile` or temp HOME. This is the single biggest current gap.
2. **Soak job** (unblocks S23 / S24 / S25 / S26): a separate workflow on `workflow_dispatch` plus a
   daily schedule, not blocking `ci.yml`; the artifact is memory/handle curves plus restart-recovery
   records.

**P2**

3. **Real interaction in CI** (unblocks S17 / S18 / S19): the local desktop screenshot walkthrough
   pipeline (`~/.cache/persona-ui-shots/shoot.mjs`, `__TAURI_INTERNALS__` shim + dual Xvfb
   instances) exists — land the Linux desktop walkthrough first; Windows/macOS need a real machine or
   a cloud desktop runner.
4. **Add the iOS target** (unblocks S28): add `aarch64-apple-ios` to `rust-toolchain.toml` and
   require only that it compiles — turning "never compiled" into "compiled, not verified on-device".
5. **`connect-server` integration tests**: the dev-deps (`tower`, real TCP, real DB) are already
   present; only the `tests/` directory is missing.

**P3**

6. Realign `agents/ssh-agent/TESTING.md` with `e2e_test.rs` (10 tests; the doc still says 7).
7. Add an acceptance field to `.github/ISSUE_TEMPLATE`; use the four layers here as PR-template
   checkbox dimensions.
8. Clean up the dangling `Makefile::release-*` targets (or add a manual-trigger explanation for
   `scripts/release.sh`).

## Count method

- Rust: `grep -rn '#\[test\]\|#\[tokio::test\]'` across `core` / `cli` / `server` /
  `agents/ssh-agent` / `connect-server` / `desktop/src-tauri` / `mobile/rust` gives 2,294 inline;
  73 in the `tests/` directories; **2,367 total**.
- JS: `grep -ro "\bit(\|test("` gives 726 in `desktop/src` and 164 in
  `browser/chromium-extension`; **890 total**.
- Other: 2 XCTest on iOS; 0 on Android / Harmony / website / Safari.
- Counted 2026-10-24.

## Related

- [Cross-Process Session Center](/zh/design/session-center): its A1–A5 align with S05 / S14 / S16
  here
- [Principal & Action Authorization Design](/zh/design/principal-action): source for S08–S12
- [Prototype external review](https://github.com/cuihairu/persona/blob/main/docs/review/2026-10-24-persona-external-architecture-review.md): origin of the four-layer split and the R-P6 tracking item
- [Audit task list](https://github.com/cuihairu/persona/blob/main/docs/review/task-list-2026-10-18.md): original definitions of AUDIT-050 / 051 / 060 / 061
