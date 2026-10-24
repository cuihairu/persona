# Cross-Process Session & Authorization Center

> **English** | [中文](/zh/design/session-center)

One-line framing: Persona's **unlock state, active identity, permission revocation, and user
confirmations** currently have no cross-process coordination at all — every process holds its own
`PersonaService` and relies on the same SQLite file to "happen to agree". This document starts with
current-state research, then gives a phased plan.

**Out of scope (explicitly not done):** no new network listening surface; no change to SQLite
transaction or concurrency semantics; no C/S re-architecture. The existing embedded Connect listener
on `127.0.0.1` stays as it is.

## Current-state research

### 1. Unlock state: per-process memory fields, no shared home

The truth about "unlocked" is three in-memory fields on `PersonaService`, judged by a pure
in-memory predicate (`core/src/service.rs:187`):

```rust
pub fn is_unlocked(&self) -> bool {
    if let (Some(_), Some(last)) = (&self.master_encryption, *self.last_activity.lock().unwrap()) {
        return last.elapsed() < self.auto_lock_timeout;
    }
    false
}
```

Note that this doubles as the auto-lock check — after `auto_lock_timeout` idle (default 300s,
`core/src/service.rs:138`) it returns `false`.

- **No persisted unlock marker**: there is no "unlocked" row, settings key, or file anywhere; the
  `user_auth` table holds only password hashes, salt, and failure counters.
- **No watcher**: `core/src/storage/database.rs` sets no `busy_timeout` / `WAL` / any PRAGMA, and
  neither `core/` nor `cli/` has `notify` / `inotify` / file watching (the only `Notify` is
  `tokio::sync::Notify` inside the audit emitter).
- **Each process unlocks independently**: desktop (`AppState.service` slot), CLI
  (`PERSONA_MASTER_PASSWORD`), bridge NMH (`cli/src/commands/bridge.rs` models it explicitly as
  "locked unless the environment variable was injected"), the embedded SSH agent (`agents/ssh-agent`
  news its own `PersonaService` and authenticates itself), and a standalone `persona connect serve`
  — five entry points, five independent unlock states, mutually invisible.

### 2. Auto-lock runs twice, and the two are unaware of each other

| Mechanism                              | Location                           | Defaults                                                        |
| -------------------------------------- | ---------------------------------- | --------------------------------------------------------------- |
| `is_unlocked()` in-memory short window | `core/src/service.rs:138,187`      | 300s idle                                                       |
| `AutoLockManager`                      | `core/src/auth/session.rs:186-196` | 900s inactivity / 3600s absolute cap / 300s sensitive operation |

`PersonaService::new` constructs the manager unconditionally with `AutoLockConfig::default()`
(`core/src/service.rs:119`), while `WorkspaceSettings.session_timeout_seconds`
(`core/src/models/workspace.rs:106`, default 3600) is stored but never fed in. The two timers each
observe only the user/session set inside their own process — one process auto-locking does not lock
another.

`lock()` is also incomplete (`core/src/service.rs:176-184`): it clears `master_encryption`,
`last_activity`, and `current_user`, but the `current_session_id` clear is commented out (the
comment says "this requires async"), and it does not stop auto-lock monitoring. The desktop wrapper
compensates by detaching the sync capture itself.

### 3. Active identity: the one persisted layer, zero broadcast

Persistence exists in exactly one place: `workspaces.active_identity_id`
(`core/src/models/workspace.rs:18`; read/written through the `workspaces` table SQL in
`core/src/storage/repository.rs`). It is **per-workspace** (keyed by vault file path) — there is no
global active identity.

- **Only desktop writes it**: `set_active_identity` / `clear_active_identity`
  (`desktop/src-tauri/src/commands.rs`) check `service.is_unlocked()`, then **bypass
  `PersonaService` entirely** — opening the DB themselves, constructing a `WorkspaceRepository`, and
  calling `repo.update()`. Audit, sync capture (`attach_sync_capture`), and the sensitive-operation
  gate are all skipped.
- **Nothing is broadcast**: `emit_all` has zero hits repo-wide, all Tauri events are window-scoped,
  and no unlock / lock / identity switch / settings change event is ever emitted.
- **The Connect data plane never reads the active identity**: `active_identity` has zero hits in
  `connect-server/src/lib.rs`; the identity list is filtered by token scope, not by active identity.
  So a desktop identity switch has no effect on automation consumers at all.
- The CLI never sets the active identity; it only clears it defensively on identity deletion.

### 4. Existing cross-process channels

| Channel                             | Direction                                      | Content                                                                    | Note                                                             |
| ----------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Tauri events ×5                     | desktop process → frontend window              | `persona://auto-lock`, `ssh-approval`, `passkey-approval`, quick-access ×2 | Window-scoped, no `emit_all`                                     |
| Unix socket `ssh-agent.sock`        | OpenSSH → agent                                | OpenSSH agent protocol                                                     | Existing                                                         |
| Unix socket `passkey-approval.sock` | bridge CLI → desktop                           | One JSON line request / one reply, `0o600`                                 | **The only real cross-process request-reply channel**            |
| Connect HTTP `127.0.0.1`            | browser/automation → embedded desktop listener | 5 REST routes                                                              | No SSE / no WebSocket / no push                                  |
| Native Messaging (stdin/stdout)     | browser extension → local CLI                  | Chrome 4-byte length prefix + UTF-8 JSON                                   | Pairing sessions persisted in `~/.persona/bridge`                |
| `POST /api/v1/events`               | client → remote server                         | Audit batches, **one-way**                                                 | No return channel at all; zero WebSocket in `server/` or `core/` |
| SQLite file                         | all processes                                  | Transaction-level consistency                                              | **The de facto only cross-process bus — and nobody watches it**  |

The load-bearing property: the only thing that converges across processes through SQLite is Connect
token authentication, because `connect_authenticate` looks up the table per request with no cache
window, so a revocation takes effect for every process immediately. Unlock state and active identity
are **per-process memory caches** — stale until re-read.

### 5. Revocation: covers exactly one credential class

`revoke_connect_token` (`core/src/service.rs:2374`) is the only revocation API: gated by the lock
and `connect_gate`, i.e. **it requires the local process to be unlocked** to revoke. It re-reads the
table per request, so it converges across processes immediately.

Everything else has neither revocation nor renewal (there is no `renew` API anywhere; the only
`renew` hits are dictionary words in the passphrase wordlist): bridge pairing sessions, NMH session
ids, account bearer tokens, sync device identities, SSH key policies, passkeys.

### 6. User confirmation: two duplicated oneshot registries

`state.ssh_approvals` and `state.passkey_approvals` (`desktop/src-tauri/src/types.rs`) are two
identically-shaped `Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>`, each replicating the same
pattern:

1. Mint a `request_id` (`ssh-{n}` / `passkey-{n}`) and insert it into the map;
2. Emit to the frontend (on emit failure, remove the entry and deny — never silently allow);
3. Await the receiver under a 120s timeout (`APPROVAL_TIMEOUT` in `desktop/src-tauri/src/approval.rs`);
4. Timeout / dropped responder / unknown id all deny; `resolve_from_map` removes before sending,
   guaranteeing exactly-once.

**The key limitation**: answers can only come from the desktop webview (the two Tauri commands
`ssh_approval_respond` / `passkey_approval_respond`). There is no socket, no HTTP route, no
file-based answer path. And the SSH agent's `ApprovalHandler` has only three implementations —
desktop GUI, `TtyApprovalHandler`, `DenyAllApprovalHandler` — so an agent started by the CLI gets a
terminal prompt or a denial on a signing request and **never reaches the desktop GUI** (passkeys reach
the desktop only because they happen to use a socket the desktop owns).

## Core problems

15 details converge to 5:

| #   | Problem                                    | Consequence                                                                                                                                             |
| --- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1  | No shared home for unlock state            | Two hosts can independently unlock the same vault, unaware of each other; the CLI's "injected env var unlocks it" is architecture-by-configuration      |
| C2  | Incomplete lock + two auto-lock timers     | `lock()` misses the session id and monitoring; the same behavior has different timeouts per process                                                     |
| C3  | Zero broadcast of changes                  | Active identity and lock state are invisible to other processes; the Connect data plane does not even read active identity                              |
| C4  | Write path bypasses the service layer      | Identity switching skips audit, sync capture, and the sensitive-operation gate — which is exactly part of identity-context trustworthiness              |
| C5  | Narrow confirmation and revocation surface | Confirmations only return to the desktop webview; revocation covers one credential class and requires a local unlock (so it cannot happen while locked) |

## Plan orientation: no daemon first

`docs/LOCAL_SERVICE.md` records the historical decision: no local daemon, the CLI links the core
library directly, and the bridge integrates in-process. This plan keeps that orientation — **no new
process** — and externalizes state into the existing SQLite, reusing the proven "re-read per
request" pattern (Connect tokens already show it works). Only if Phase 1 proves insufficient does
Phase 2 discuss a hub model.

## Phase 1: no new process, state externalized

1. **Session table + version column.** Add a `sessions` table (`session_id`, `host`,
   `identity_id`, `unlock_epoch`, `updated_at`). Unlock / lock / identity switch each write a row
   and advance `unlock_epoch`; every read path that needs cross-process consistency **re-reads the
   version each time** without caching. This reuses Connect's "no cache window" pattern and is the
   lowest-risk step.
2. **Complete `lock()`**. Move the `current_session_id` clear, stopping auto-lock monitoring, and
   detaching the sync capture into `PersonaService::lock()`, instead of relying on the desktop
   wrapper to compensate.
3. **Unify auto-lock**. Have `PersonaService::new` build `AutoLockConfig` from
   `WorkspaceSettings.session_timeout_seconds`, and state the division explicitly: the
   `is_unlocked()` in-memory short window does fast per-process checks, while `AutoLockManager`'s
   absolute cap governs cross-process session validity. This is the same item as P0 step 2 in
   [Principal & Action Authorization Design](./principal-action.md).
4. **Move active identity back into the service layer.** Provide `switch_identity` /
   `clear_active_identity` from `PersonaService` (through audit + sync capture + sensitive gate);
   desktop handlers call the service instead of opening the DB themselves. Also decide whether the
   Connect data plane should follow the active identity — it currently does not, and if that stays
   it should be a documented design decision rather than "forgot to read it".
5. **Merge the confirmation primitive.** Collapse the two maps into one `ApprovalRegistry` plus a
   request-type enum, preserving the existing exactly-once and fail-closed semantics; and extend the
   passkey socket pattern to the SSH agent — a new socket handler lets a non-desktop-started agent
   surface signing requests to the desktop instead of only a TTY prompt or a denial.

**Acceptance**: see A1–A5 below.

## Phase 2 (optional): the desktop as a hub for limited RPC

If Phase 1 runs stably and a real need emerges for "multiple clients needing key material
simultaneously", evaluate: the desktop process holds the keys, and the CLI / bridge request
**limited actions** (read / use / sign with a grant) from the desktop over the existing Unix socket
pattern, so key material is never copied into a second unlock state. This path merges with P3
(agent delegation) in [Principal & Action Authorization Design](./principal-action.md): the socket
request carries a grant, adjudicated by `authz::authorize`.

**Preconditions**: Phase 1's version re-reading is proven stable, and "multiple clients needing key
material at once" is confirmed to be a real requirement rather than a hypothetical one.

## Explicitly not done

- No new daemon process (Phase 2 still reuses the desktop process plus the existing socket pattern —
  not a new process).
- No new network listening surface (other than the existing Connect `127.0.0.1`).
- No change to SQLite concurrency semantics, no C/S architecture.
- No second copy of key material in the CLI / bridge — that would mean a second unlock state.
- No SQLite file watching as a substitute for re-reading: file watchers are unreliable (missed
  notifications, inconsistent cross-filesystem behavior), and per-request re-reading is cheap
  enough.

## Acceptance scenarios

| #   | Scenario                                                           | Layer            | Today       | Acceptance clause                                                                                                                                                |
| --- | ------------------------------------------------------------------ | ---------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1  | After desktop unlock, the CLI immediately sees unlocked            | Simulated test   | Unreachable | Once desktop unlock advances `unlock_epoch`, the CLI's next request succeeds without re-entering the master password                                             |
| A2  | After desktop lock, the CLI / agent / bridge next request fails    | Simulated test   | Unreachable | After lock, all non-desktop processes return `vault_locked`; the embedded Connect listener keeps returning 503 (already true)                                    |
| A3  | After desktop identity switch, Connect behavior is explicit        | Simulated test   | Undefined   | Either return the new active identity, or document "Connect does not follow the active identity" — silent inconsistency is not acceptable                        |
| A4  | Revoking a Connect token takes effect across processes immediately | Simulated test   | **Covered** | Keep as a regression item; make "cannot revoke while locked" explicit or fix it                                                                                  |
| A5  | A CLI-started SSH agent can reach the desktop for confirmation     | Real interaction | Unreachable | Agent started via `persona ssh agent`, desktop unlocked, a signing request opens the desktop approval dialog and can be answered Allow/Deny; 120s timeout denies |

These scenarios are numbered to align with
[Acceptance Scenarios & Cross-Platform Capability Matrix](/development/acceptance-matrix).

## Related

- [Principal & Action Authorization Design](./principal-action.md): verb vocabulary, decision
  observability, agent delegation; this file is its fulfillment infrastructure.
- [Security Design](./security.md)
- [Prototype external review and verification record](https://github.com/cuihairu/persona/blob/main/docs/review/2026-10-24-persona-external-architecture-review.md): origin and verification log for R-P4.
