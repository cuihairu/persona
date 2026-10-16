# Connect Local Automation Endpoint — Design Draft (Stage 0)

> [English](CONNECT_AUTOMATION_DESIGN.md) | [中文](CONNECT_AUTOMATION_DESIGN.zh.md)

> Status: **Design draft; stages 1–4 are all landed (2026-09)**. This is the kickoff document for the TODO item
> "Connect-like local-first secrets automation endpoint" (ROADMAP Milestone 6), modeling the shape of
> 1Password Secrets Automation / Connect server under Persona's local-first architecture: lock down the design
> decisions that must be settled first, and lay out the implementation stage mapping plus a threat-model
> registration skeleton. Where the implementation lands: the standalone `connect-server/` crate (host-embedded
> axum listener, shared by desktop and CLI), the desktop `connect_server_start/stop/status` commands, and the CLI
> `persona connect token create/list/revoke` + `serve`; per-stage status markers are in §8.
>
> Related docs: [`ROADMAP.md`](./ROADMAP.md) Milestone 6, [`E2EE_SYNC_DESIGN.md`](./E2EE_SYNC_DESIGN.md)
> (its sister draft on the same track — this endpoint does **not** depend on the sync track and can land on its own),
> [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`BOUNDARY.md`](../BOUNDARY.md)
> (automation-friendly access is inside the boundary). **Guide for external projects:
> [`EXTERNAL_INTEGRATION.md`](./EXTERNAL_INTEGRATION.md)** (three-step onboarding,
> measured response samples, token expiry/revocation semantics, permission boundaries, error code table; added 2026-10-12).

## 1. Goals and non-goals

**Goals**

1. Let local scripts/CI/SDKs read credentials and TOTP within their granted scope
   **without ever touching the master password** — an automation consumer gets a token, not an unlock passphrase.
2. Zero exposure by default: if the feature is not enabled, **no port is listened on at all** (not a 403 — no bind).
3. Reuse existing assets: the `PersonaService` unlocked state, the audit log, the settings persistence pattern,
   the server-side axum layering precedent, and the passkey desktop approval local IPC precedent.
4. Grants are fine-grained, revocable, and auditable — the blast radius of a leaked token is fenced by scope.

**Non-goals (explicitly out of scope for the first stage)**

- **Write paths**: automation does not modify the vault (no create/update/delete). 1P Connect is likewise
  read-first; the audit attribution, conflict surface, and mistake radius of automation writing to the vault are separate topics (§9).
- **passkey / wallet / SSH key private-key surface**: scope excludes sensitive types by default; passkey
  attestation flows through the desktop approval chain, not the token endpoint.
- **Remote/LAN shape**: only 127.0.0.1 is served. A containerized standalone Connect server and remote automation
  routed through Persona Server (1P's deployment shape) are not done — to be reassessed once the E2EE sync track
  is stable.
- **Search/rich queries**: at the start, only deterministic retrieval (by id / exact title match +
  identity/type filters); no full-text search surface.

## 2. Trust model

- **Trust root = master-password unlocked state + connect token**. The endpoint returns data only when the vault is unlocked;
  the token decides "which types under which identity may be seen". Missing either one means refuse.
- **Consumer positioning = a local, semi-trusted process**. There is no stranger on 127.0.0.1, but there are malicious pages
  rendered by the browser (§5 three defenses) and processes belonging to other local users (token required + OS-level
  boundary; no extra claim of multi-user isolation — consistent with the THREAT_MODEL's existing stance).
- **Endpoint visible surface**: plaintext fields of items inside the token's granted scope (that is exactly the point of the feature) + minimal
  metadata. Items outside the scope **do not exist** to the consumer (404 and 403 are not distinguished, to avoid
  probing). The health endpoint is zero-information (no unlock state, no vault-existence signal).

## 3. Decision record

### DR-1 Deployment shape: listener embedded in the host process (rejected: standalone resident process / container)

The HTTP service is embedded in the **already-unlocked host process**; core ships a framework-agnostic service layer that both hosts reuse:

- **A1 Desktop embedded (first)**: start an axum listener inside desktop's tokio runtime.
  No new process boundary for the keys; desktop exiting = automation stops naturally (honest semantics: automation follows
  the unlock session).
- **A2 CLI `persona connect serve` (later)**: for headless servers/CI long sessions,
  the same core service layer + the same token store (inside the workspace database), foreground process + Ctrl-C
  to quit, no daemonization (systemd user units are configured by the user, with an example in the docs).
- **Rejected standalone process/container**: 1P Connect's container shape serves "server-hosted, multi-consumer
  remote access" — the opposite of the local-first boundary; a standalone local resident process would instead introduce cross-process
  key transfer (violating the single boundary of "the unlocked state lives inside the host process") plus a second lifecycle manager.
- **Dependencies**: axum 0.8 (same version as server/connect-server, an existing workspace precedent;
  desktop's separate workspace has 0.7 — each location's version is decided by its own lockfile) +
  the existing tokio. The bind address is hardcoded to `127.0.0.1`,
  the port defaults to `0` (OS-assigned) plus an explicit config option; **any non-loopback configuration is rejected**
  (fail-closed: if one is set, startup fails with an error — no silent fallback).

### DR-2 Authentication and authorization: scoped tokens (shown once, hash-only storage, three-dimensional scope)

- **Token shape**: `pconn_` prefix + 32 random bytes (base64url). Shown in plaintext exactly once
  at creation (desktop settings-page copy button / CLI stdout); storage keeps only the SHA-256 hash +
  the first 8 bytes as a fingerprint (for listing identification and revocation, never the token body).
- **Three scope dimensions**:
  - `identities`: the list of allowed identity UUIDs (empty = all — an explicit choice, and the UI needs
    a second-confirmation phrase: "this token can read every identity");
  - `item_types`: the allowed credential types (`ConnectItemType` has 10 variants in the actual enum:
    `password`/`totp`/`note`/`api_key`/`bank_card`/`server_config`/
    `certificate`/`game_account`/`identity`/`software_license`;
    custom/ssh/wallet are never grantable and are not in the legal enum);
  - `verbs`: `read` (the only legal value at the start; future write paths add enum values).
- **Storage**: a new table `connect_tokens` inside the workspace database (id, hash, fingerprint,
  scope JSON, created_at, last_used_at, revoked_at, label). Traveling with the database =
  backups cover it and machine migrations carry it, consistent with "the database is the first source of truth"; **not part of the sync track**
  (v1 does not sync; if synced in the future, tokens must still be per-device local assets — registered
  as an open-question input for the sync design).
- **Verification**: SHA-256, then constant-time comparison; every request bumps `last_used_at` (batch writes are throttled). Revocation takes effect immediately (decided by a table lookup, no caching window — v1 has no token cache;
  revisit if performance proves insufficient).
- **1P alignment**: 1P Connect tokens grant per vault, verify server-side, and are revocable —
  Persona uses "identity" instead of "vault" as the grant granularity, matching the IdentitySwitcher's
  product semantics.

### DR-3 Endpoint surface: minimal read-only + TOTP resolve

`/api/v1/connect/*`, all of which require `Authorization: Bearer pconn_…` (except health):

| Endpoint                       | Method | Semantics                                                                                              |
| -------------------------- | ---- | ------------------------------------------------------------------------------------------------- |
| `/connect/health`          | GET  | `{ "service": "persona-connect", "version": … }`, zero vault info, no auth                                |
| `/connect/identities`      | GET  | identity list within scope (id + name)                                                                     |
| `/connect/items`           | GET  | item metadata within scope (id, title, type, urls, updated_at); `?identity=`/`?type=`/`?title=` exact filters |
| `/connect/items/{id}`      | GET  | one item, all fields (decrypted JSON; 404 if outside scope)                                                       |
| `/connect/items/{id}/totp` | POST | current TOTP code + remaining seconds (reuses the CLI/desktop TOTP parsing path)                                        |

- **Response envelope**: follows the server convention `{"ok":true,"data":…}` / `{"ok":false,
"error":{…}}`; error codes align with the desktop `ApiResponse`, so consumers learn one error-handling shape.
- **Rate limit**: 120 requests per token per minute (in-memory counter, 429 when exceeded) — guards against an out-of-control
  polling loop dragging down the host; the cap is hardcoded, not configurable (a bigger config surface means a bigger misuse surface).
- **Audit**: every authentication success/failure enters the audit log (token fingerprint, endpoint; the source
  PID is omitted when it cannot be obtained — an honest registration: there is no reliable caller identity on 127.0.0.1).

### DR-4 Local exposure hardening: off by default + three defenses against browser-side attacks

The real threat to a local HTTP endpoint is not "a remote attacker" — it is a **malicious page in the browser**
(DNS rebinding, CSRF-style fetch, intranet probing). None of the three defenses may be skipped:

1. **Host header allowlist**: accept only `127.0.0.1:{port}` / `localhost:{port}`
   (a rebinding attack whose `evil.com`→`127.0.0.1` resolution carries a malicious Origin/Host;
   a Host mismatch is rejected outright with 421).
2. **CORS fully off**: return no `Access-Control-Allow-*` headers at all; a request with an `Origin` header
   gets 403 (a local API has no legitimate cross-origin browser consumer). Preflight requests are always rejected.
3. **Token required**: no anonymous surface (except health, and health is zero-information).

In addition:

- **Off by default**: not enabled in settings = no listener is created. The toggle wording follows the THREAT_MODEL
  style and states plainly: "once enabled, local processes can read credentials within a token's grant".
- **Lock gate**: vault not unlocked (including after auto-lock/manual lock/travel enter) = 503 on all data
  endpoints + `error: "vault_locked"`; it recovers the moment the vault is unlocked. A valid token against a locked vault does **not** consume
  429 quota (a locked-screen automation retry storm cannot brick a token).
- **Response headers**: `Cache-Control: no-store` (TOTP codes and plaintext fields never enter any
  intermediate cache), `Content-Type` strictly `application/json`.

### DR-5 Token management surface: desktop settings page first, CLI in the same batch

- Desktop: a new Automation section in settings (token list: label/fingerprint/scope/last_used/
  revoke; creation dialog: scope selection + one-time plaintext display + a "cannot be viewed again once closed"
  warning). Create/revoke go through the reauth gate (same semantics as sensitive settings).
- CLI: `persona connect token create/list/revoke` + `persona connect serve`
  (stage A2). Non-interactive CI mode follows the `--passphrase-env` convention.
- No "edit scope" — changing a grant = create a new token and revoke the old one (a clean audit trail, and it avoids
  "a token's permissions quietly growing").

## 4. Data flow (unlock state checked once, token verified per request)

```
Script/SDK ──Bearer pconn_…──> 127.0.0.1:port (axum, inside the host process)
    │ 1. Host/Origin/rate-limit checks (DR-4)
    │ 2. token hash comparison + scope parsing (DR-2, database lookup)
    │ 3. Lock gate: PersonaService not unlocked → 503 (DR-4)
    │ 4. Scope filter: identity ∈ scope ∧ type ∈ scope (DR-2)
    └ 5. PersonaService read/decrypt → JSON (no-store)
             audit: token fingerprint + endpoint + result
```

Plaintext fields exist only in host-process memory and the response body; the security of the consumer side (script environment variables, CI logs) is the **consumer's responsibility** — the docs warn plainly "the response contains plaintext, do not write it to logs".

## 5. Boundaries against existing systems

| Existing asset                        | Relationship                                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `PersonaService` unlocked state         | the only data surface; the endpoint keeps no cache of its own (the DR-3 rate-limit counter excepted — not data)                                                                        |
| desktop settings/feature flags      | toggles persist in the same pattern; the automation switch is the Nth feature flag plus the token table                                                                 |
| passkey desktop approval (Unix socket) | precedent reference (local IPC + GUI approval); connect does not reuse the socket (HTTP serves consumers in any language), and the approval chain is **not** wired to the token endpoint                       |
| audit log                       | new `AuditAction::ConnectTokenCreated/Revoked/Used` (names finalized at implementation); Used is throttled to prevent log spam (e.g. one aggregate entry per token per minute)                   |
| backup chain                          | the `connect_tokens` table travels with VACUUM INTO snapshots (scope/hash is database data); restoring a backup = the token set returns to the backup's point in time, and plaintext tokens were never in any backup to begin with |
| server / sync track               | no coupling; connect is a pure local surface. The server's Bearer/SRP system is not reused (different trust domains: remote device vs local consumer)                                  |
| Travel Mode                     | while travel is active the endpoint is naturally 503 through the lock gate; token requests whose scope includes a travel-excluded identity return 404 (item does not exist), without exposing travel state                |

## 6. Threat-model registration skeleton (fleshed out in THREAT_MODEL.md at implementation time)

- **Trust root and visible surface**: §2.
- **Not claimed**: protection against a malicious local process (a token is equally visible in its environment variables/arguments — the same boundary as 1P CLI); protection against a compromised host process (automation neither widens nor narrows that boundary);
  multi-user OS isolation.
- **Malicious pages**: the DR-4 three defenses + the known residual surface (if a token is placed in storage reachable by a browser extension, the defenses are void — the docs forbid that usage).
- **Blast radius of a leaked token**: a read-only surface fenced by scope + revocation + audit visibility;
  no write paths = no tampering radius.
- **DoS**: the 429 limit protects the host; the listener's port footprint is minimal (a single loopback port).

## 7. Test points (acceptance pre-registration)

- fail-closed assertions: no port listening under the default config; a non-loopback bind configuration fails to start.
- Three defenses: rejection paths for malicious Host / Origin present / no token / wrong token / out-of-scope;
  items outside scope return 404 and 403 in identical shape.
- Lock semantics: locked → 503, recovery on unlock, no quota consumption while locked.
- Token lifecycle: one-time display at creation, hash-only storage assertion (no plaintext in the database), immediate revocation,
  last_used updates.
- TOTP endpoint consistency with the CLI/desktop parsing path.
- 429 rate-limit boundaries; health zero-information assertion.

## 8. Implementation stage mapping

| Stage     | Scope                                                                                            | Acceptance essentials                                        | Threat-model registration                                                                                                      |
| --------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| 0 (this doc) | Design draft                                                                                     | Decisions settled + user confirmation                        | Skeleton (§6)                                                                                                                  |
| 1         | core `connect` service layer: token table migration + management API + scope filtering + lock-gate orchestration (framework-agnostic, purely functional) | core tests: token lifecycle / scope filtering / 404 same shape | **Landed 2026-09**: `core/src/connect/` (token table + scope filtering + lock orchestration)                                    |
| 2         | desktop embedded axum (DR-1 A1) + three defenses + rate limit + settings-page token management UI | DR-4 full rejection-path tests; `cargo test -p persona-desktop` + jest | **Landed 2026-09**: `desktop/src-tauri` embedded listener (`connect_server_start/stop/status`) + `ConnectAutomationSection` settings page |
| 3         | CLI `persona connect token …` + `serve` (DR-1 A2)                                                | CLI integration tests (ScriptedUi seam); cross-host shared token store interoperability | **Landed 2026-09**: `cli/src/commands/connect.rs` (token create/list/revoke + serve)                                           |
| 4         | Docs wrap-up: STORAGE_AND_SYNC gains an automation section + README quick start (curl examples)  | Docs consistent with the implementation                       | **Landed 2026-09-22** (TODO stage 4 docs wrap-up)                                                                               |

Size estimate: on the order of 3–4 sessions; stages 1–2 are the main surface.

## 9. Open questions

1. **Write path** (create/update via token): 1P leaves writes to the SDK+CLI;
   does Persona take the same road (tokens read-only, writes via the interactive CLI)
   or open up a write scope? Settle it once real automation demand appears.
2. **SDK shape**: shell functions (`persona connect env` injecting env vars) vs
   an official SDK package; leaning toward the former (zero dependencies, consistent
   with the CI env pattern).
3. **desktop lifecycle details**: while the screen is locked, does the listener stay
   up (fast recovery) or shut down (minimal exposure surface)? This draft designs for
   "stay up + 503"; the implementation stage may overturn that with a real
   power-draw / security assessment.
4. **Token table and the sync track**: if E2EE sync lands in the future, are tokens
   included in sync (leaning no — per-device local assets)? Registered as new input
   for E2EE_SYNC_DESIGN §11.
5. **Indirect authorization UI**: after a token is created, should "the first use
   requires one desktop popup confirmation" be enforced (1P has no such step;
   Persona's GUI-approval precedent supports doing it) — it closes the window in which
   a freshly created token could be stolen, at the cost of adding a manual step to the
   first automation onboarding.
