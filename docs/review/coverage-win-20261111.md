# Windows Coverage Baseline — persona

- **Date:** 2026-11-11
- **Repo:** cuihairu/persona (public, non-fork, `main`)
- **Host:** imac — Windows 11 Pro 10.0.26300, MSVC target (`x86_64-pc-windows-msvc`)
- **Toolchain:** Rust 1.99.1 standalone (scoop `rust`, **no rustup**), cargo-llvm-cov 0.9.1
- **Task:** `C:\tools\imac_persona_cov.md` — establish a Windows coverage baseline, supplement the lowest-coverage modules with behavior tests, compare before/after, and record the honest ceiling.

## 1. Environment notes (Windows-specific, documented not hidden)

| Item | Detail |
|---|---|
| **openssl / vcpkg** | `persona-core`'s dev-dependency enables `openssl` with the `vendored` feature; the vendored build needs `perl` + MSVC `cl` which this box lacks (Git's MinGit has no perl). Routed `openssl-sys` to vcpkg's OpenSSL 3.6.2 instead: `OPENSSL_NO_VENDOR=1`, `OPENSSL_DIR=C:\Users\cui\vcpkg\installed\x64-windows`, plus its `bin` on `PATH` for the DLLs. |
| **llvm-cov toolchain** | No rustup → `llvm-tools-preview` is unavailable. Pointed `LLVM_COV`/`LLVM_PROFDATA` at scoop's LLVM 23.1.5 (`C:\Users\cui\scoop\apps\llvm\current\bin`). |
| **clippy** | `scoop` only shims `rustc`/`cargo`; `cargo-clippy` lives in the toolchain bin dir (`C:\Users\cui\scoop\apps\rust\1.99.1\bin`) and is not on `PATH` by default. Added it to the env wrapper so `cargo clippy` resolves. |
| **shell-hook test (fixed, `ffc71d15`)** | `cli::commands::shell_hook` smoke test passed a Windows `temp_dir()` backslash path as an argv to msys `bash` from a non-msys parent. A standalone Rust probe proved argv `C:\…`/`C:/…`/`/c/…` all fail (exit 127 "No such file or directory"; backslashes eaten as escapes) — the only portable feed is **stdin**. Rewrote the bash check to `bash -n` / `bash -s` over stdin, preset `PS1='$ '` so the interactive gate passes non-interactively, and chained with `&&` so a missing function fails. The original smoke also passed vacuously (the trailing `test -z` status wins). This is the only production-file change in the whole task (test-module only); plus a whitespace-only rustfmt join in the same test module so `cargo fmt --all -- --check` stays clean (CI gates on it). |
| **CI ignore regex** | `ci.yml`'s `--ignore-filename-regex` uses forward slashes which do not match Windows backslash paths. Used a separator-agnostic regex (`[\\/]`) so the same 6 entry-point files are excluded on both platforms — this keeps the Windows number comparable to the CI/project baseline (97.20%). |
| **cargo-llvm-cov quirk** | If a test binary exits with a failure, its `.profraw` is dropped and the **whole crate shows 0%** coverage. Hence `--ignore-run-fail`; and the shell-hook fix above was a precondition for the `cli` crate's coverage to be measurable at all. |
| **unix-gated tests** | `#[cfg(unix)]` tests (SSH unix sockets, `/proc/<pid>/cmdline`, `stop_agent_pid` unix branch) do not run on Windows, so those branches are structurally uncovered here; they are covered on the Linux CI. Recorded, not padded. |

## 2. Test results (`cargo test --workspace --no-fail-fast`)

| Run | Passed | Failed | Ignored |
|---|---|---|---|
| Baseline | 2111 | 0 | 2 |
| After (10 tests added) | **2121** | 0 | 2 |

## 3. Coverage baseline (before)

Command (identical before/after, matches CI's exclusion intent with a Windows-compatible regex):

```
cargo llvm-cov --workspace --all-features --summary-only --ignore-run-fail \
  --ignore-filename-regex '(cli[\\/]src[\\/]main\.rs|cli[\\/]src[\\/]commands[\\/]tui_runtime\.rs|cli[\\/]src[\\/]utils[\\/]terminal_ui\.rs|server[\\/]src[\\/]main\.rs|agents[\\/]ssh-agent[\\/]src[\\/]daemon\.rs|agents[\\/]ssh-agent[\\/]src[\\/]main\.rs)'
```

| Metric | Before | After | Δ |
|---|---|---|---|
| **Lines** | 96.63% (2829 / 83883 missed) | **96.65%** (2807 missed) | +0.02 pp, −22 lines |
| **Regions** | 95.30% (6388 / 135843 missed) | **95.32%** (6355 missed) | +0.02 pp, −33 regions |
| **Functions** | 89.05% (925 / 8445 missed) | **89.09%** (921 missed) | +0.04 pp, −4 functions |

### Lowest 5 modules (baseline, by line %)

| Module | Lines before | Lines after | Regions before | Function before |
|---|---|---|---|---|
| `cli/src/commands/bridge/sync.rs` | **22.47%** (69/89) | **25.84%** (66/89) | 14.93% | 36.84% |
| `cli/src/commands/ssh/agent.rs` | **44.05%** (174/311) | **50.16%** (155/311) | 39.48% | 63.33% |
| `cli/src/commands/bridge/sync_connect.rs` | **47.73%** (46/88) | **48.86%** (45/88) | 38.06% | 36.84% |
| `cli/src/commands/bridge/account.rs` | **58.76%** (40/97) | — (untouched) | 54.01% | 50.00% |
| `cli/src/commands/bridge/paths.rs` | **69.03%** (35/113) | — (untouched) | 60.98% | 70.83% |

## 4. Tests added (Step 4) — 10 behavior tests, 3 lowest modules, no production-code changes

The lowest-3 modules were supplemented with behavior tests that anchor their coverable surface (wire serde, fail-closed parsing, pure formatting, and read-only state-file branches). The positive paths of these modules require a real OS keyring, a live sync server, and a live agent daemon — external I/O that unit tests cannot drive (see §6).

### `cli/src/commands/bridge/tests/sync.rs` (+4)

- `sync_push_now_request_defaults_gesture_to_false` — `user_gesture` serde default (absent → false; explicit true).
- `sync_resolve_conflict_request_parses_ids_and_defaults_gesture` — both UUIDs + gesture default.
- `sync_push_now_payload_serializes_all_report_fields` — all 6 report counters serialize under snake_case keys.
- `sync_resolve_conflict_rejects_malformed_adopt_op_id` (`#[tokio::test]`) — non-UUID `adopt_op_id` → `invalid_payload` before session assembly.

### `cli/src/commands/bridge/tests/sync_connect.rs` (+3)

- `sync_connect_rejects_envelope_sealed_for_other_device` — envelope present for our `device_id` but sealed to another device's key → `sync_group_key_failed` (distinct from `sync_not_authorized`, fail-closed, no silent fallback).
- `sync_connect_request_requires_explicit_gesture` — `user_gesture` is a required bool (absent → deserialization error).
- `sync_connect_payload_round_trips_snake_case` — `server_url`/`token`/`device_id`/`device_name`/`group_key_hex` round-trip.

### `cli/src/commands/ssh/tests/lifecycle.rs` (+3)

- `format_sock_export_lines_matches_platform_contract` — Linux emits one `export` line; Windows emits the PowerShell + cmd.exe pair (each with a comment header).
- `agent_status_reports_not_running_when_state_dir_empty` — empty state dir + no `SSH_AUTH_SOCK` → "not running", no error (query skipped on empty target).
- `agent_status_reads_state_files_when_present` — `ssh-agent.sock` + `ssh-agent.pid` read; a missing agent's query fails silently (covered by `if let Ok`), not an error.

All 10 pass in isolation; workspace total is 2121 passed / 0 failed / 2 ignored.

## 5. Gate results (Step 5)

- **`cargo clippy --workspace --all-targets -- -D warnings` → 0 errors** (exit 0). This required adding the toolchain bin dir to `PATH` so `cargo-clippy` resolves (see §1).
- **`cargo fmt --all -- --check` → clean** (CI gates on it).
- **Coverage re-run** (identical command) → Lines **96.65%**, Regions **95.32%**, Functions **89.09%**; every targeted module improved: `bridge/sync.rs` 22.47%→25.84%, `ssh/agent.rs` 44.05%→50.16%, `bridge/sync_connect.rs` 47.73%→48.86%.

## 6. Honest ceiling — 98% is not reachable under the task's constraints

**Recorded per the task boundary, not padded.** The 98% line target is above the repo's demonstrated best coverage and cannot be reached from unit tests under the stated budget.

- The repo's **own CI project baseline is 97.20%** (Linux CI, `codecov.yml` project target, same 6-file exclusion). 98% exceeds the best coverage this repo has ever measured.
- Reaching 98% on this run would require covering **~1,130 more lines** (from 2,807 missed down to ≤1,677 missed). The task budget is 2–3 modules × 3–8 behavior tests with **no production-code changes** and **no padding**; the 10 tests supplied covered 22 lines. Even with a much larger test budget, the remaining uncovered lines are concentrated in code that **unit tests structurally cannot execute**:
  - **`bridge/sync.rs` / `bridge/sync_connect.rs`** — the positive paths of `run_sync_push_now` / `run_sync_connect` need a real OS keyring (Windows Credential Manager) and a live sync server (HTTP + E2EE round-trip). Only the serde/parse fail-closed branches (now anchored) are coverable without that infrastructure.
  - **`ssh/agent.rs`** — the live-agent positive path needs a real agent process (named pipe on Windows, unix socket on unix) and a responding daemon; `query_agent_identities` success is IPC to an external process. The coverable surface (export-line formatting, status file-reading/not-running) is now anchored.
  - **`bridge/account.rs` / `bridge/paths.rs`** — keyring/account-sync paths and OS-user/`PathBuf` resolution, the same external-I/O dominance.
  - **Event loops / entry points** — the 6 files CI excludes (`main.rs`, `tui_runtime`, `terminal_ui`, server `main`, agent `daemon`/`main`) are terminal/TTY/daemon entry points that are not unit-testable and are excluded by the repo's own CI baseline.
- The **realistic Windows ceiling** is therefore ~96.7% line coverage — the remaining 3.3% is external I/O, event-loop/daemon entry points, defensive branches that would require fault injection (i.e. production changes), and unix-only branches gated behind `#[cfg(unix)]` tests that do not run on this host.

## 7. Artifacts

- Report: this file.
- Env wrapper (not committed; local to this box): `C:\tools\persona-env.sh` (openssl/vcpkg + LLVM + clippy PATH).
- Baseline/after coverage logs: `C:\tools\persona-cov-baseline2.log`, `C:\tools\persona-cov-after.log`.
