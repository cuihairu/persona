# Principal & Action Authorization Design

> **English** | [中文](/zh/design/principal-action)

One-line framing: **a principal is "who is initiating an action", an action is "what it wants to do
to a resource"**, and every sensitive entry point is decided at the single adjudication point
`authorize()` in `core/src/authz.rs`. This document designs only the **completion**: the verb
vocabulary, principal binding, decision observability, and agent delegation.

**Out of scope (explicitly not done):** no reworking of identity CRUD. `PersonaService`'s
identity/credential create, read, delete, and switch surface (the data plane in the middle of
`core/src/service.rs`) stays as it is. This document adds no identity model, migrates no identity
storage, and changes no credential encryption or unlock flow.

## What already exists

### 1. The unified adjudication point `core/src/authz.rs`

| Vocabulary | Type             | Values                                                                                                                                                                                               |
| ---------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Action     | `AuthzAction`    | `Read` metadata/data · `Use` in-vault use (decrypt-display, sign assertion) · `Export` the secret itself leaving the vault boundary · `Sign` signing outward with a key                              |
| Principal  | `AuthzPrincipal` | `LocalSession` authenticated local session · `ConnectToken { scope }` browser automation token · `AgentKey { credential_id, identity_id }` signing key held by the SSH agent                         |
| Resource   | `AuthzResource`  | `Vault` vault-wide · `Identity { id }` the identity itself · `Credential { identity_id, credential_type }` a credential under an identity · `SshKey { credential_id }` signing key held by the agent |
| Context    | `AuthzContext`   | `origin` ∈ `local` / `connect` / `ssh-agent`, `interactive: bool`                                                                                                                                    |
| Decision   | `AuthzDecision`  | `Allowed` · `InteractionRequired { reason }` allowed but the caller must fulfill · `Denied { reason }`                                                                                               |

Decision semantics (`core/src/authz.rs:143`):

- **Interaction folds fail-closed**: with `interactive == false`, any `InteractionRequired` becomes a
  denial — no "waiting on a confirmation that never comes".
- **Layers stay separated**: this module answers only "can this principal do this action on this
  resource". Session lock, auto-lock, and sensitive re-authentication stay in
  `ensure_sensitive_operation_allowed` (`core/src/service.rs:432`); token revocation and
  per-request table lookup stay in the service layer; host rules, rate limits, and confirm counts
  stay in the agent's `PolicyEnforcer` (`agents/ssh-agent/src/policy.rs:142`).
- **Verb folding**: `read`/`use` may be granted to Connect tokens; `export`/`sign` are not Connect
  verbs and are always denied for tokens (deliberate isolation, not an oversight); an agent key can
  only sign its own key; a local session's export always requires explicit confirmation.

### 2. The four call sites already converged onto `authorize()`

| Call site                                      | Principal                | Context   | Purpose                                       |
| ---------------------------------------------- | ------------------------ | --------- | --------------------------------------------- |
| `core/src/service.rs:449` `ensure_authorized`  | `LocalSession`           | `LOCAL`   | Unified gate for the local-session data plane |
| `core/src/service.rs:2463` `token_allows_read` | `ConnectToken { scope }` | `CONNECT` | Resource filtering for Connect endpoints      |
| `cli/src/commands/export.rs:80` / `:106`       | `LocalSession`           | `LOCAL`   | Export / sensitive-operation confirmation     |
| `agents/ssh-agent/src/lib.rs:291`              | `AgentKey { .. }`        | `AGENT`   | Signing authorization                         |

### 3. What remains deliberately outside adjudication

- `CachedAutoLockManager` in `core/src/auth/auto_lock_cached.rs` supports `AutoLockPolicy`
  (`with_policy_repository`), and the policy table exists
  (`core/src/storage/auto_lock_policy_repository.rs`) — but `PersonaService` does not use it.
- `SignatureDecision` in `agents/ssh-agent/src/policy.rs:570` bridges back to `AuthzDecision` via
  `to_authz` (`:588`), so the agent's TOML policy and the unified vocabulary already have a
  translation layer between them.

## Gaps

| #   | Gap                                                                                                                                                                                                                                                                    | Evidence                                                     |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| G1  | **Write verbs undecided.** `AuthzAction` has only read/use/export/sign; no create/update/delete. The module comment states "the write path is undecided", and management operations still use the sensitive gate rather than data-plane verbs                          | `core/src/authz.rs` module comment; `service.rs:459` comment |
| G2  | **`ConnectTokenRow.principal` is an opaque string that `authorize` never consumes.** The column is written at table creation (`connect_repository.rs:28,50,62,127`), holding literals like `"browser-extension"` / `"cockpit"`; adjudication reads only `scope`        | Migrations 015/019                                           |
| G3  | **32 `ensure_unlocked()` call sites verify only the unlock and express no resource or action.** They prove "the key is in memory" but never enter unified adjudication and leave no decision record                                                                    | `grep ensure_unlocked()` count                               |
| G4  | **Decisions do not feed the audit log.** `AuditAction` has 34 variants with no mapping to `AuthzAction`'s 4 verbs; besides the Connect scope-denial audit (`service.rs:2476` `audit_scope_denied`), granted decisions leave zero records                               | —                                                            |
| G5  | **`ensure_authorized` hardcodes `LocalSession` + `LOCAL`.** Principal and context are parameter slots with a single current value; the three principal paths each write their own entry point                                                                          | `service.rs:449`                                             |
| G6  | **Resource coverage is incomplete.** `AuthzResource` has no Attachment / Backup / Workspace / ConnectToken / Sync                                                                                                                                                      | `core/src/authz.rs:75`                                       |
| G7  | **`AutoLockPolicy` table exists but the manager is unwired.** `PersonaService::new` hardcodes `AutoLockConfig::default()` (900s/3600s); `WorkspaceSettings.session_timeout_seconds` is stored but never read                                                           | `core/src/service.rs:124-126`                                |
| G8  | **Dead code**: `core/src/auth/permissions.rs` (179 lines) is only `pub use`-re-exported in `auth/mod.rs`, with no caller anywhere in the repo                                                                                                                          | —                                                            |
| G9  | **Terminology collision**: the vault's `Identity` is a **credential grouping** (a resource), not an authorization subject. Documentation and code both call it identity/principal, making "switching a grouping" easy to misread as "switching an authorizing subject" | —                                                            |

## Design principles

1. **Single adjudication point, layered mechanisms**: policy decisions only in `authorize()`;
   stateful gates (lock, re-auth) and conditional policies (host rules, rate limits) stay in their
   own mechanism layers. Do not push them into the pure function.
2. **Explainable**: every decision must answer "which principal, on which resource, doing which
   action, and why", and must be able to land in the audit log.
3. **Fail-closed**: a non-interactive context never accepts "waiting on a confirmation"; any
   abnormal path folds to denial rather than allow.
4. **Principal is a first-class citizen**: AI agents do not receive full credentials, only limited
   actions. Authorization decisions must be distinguishable by subject.
5. **Vocabulary before mechanisms**: complete the verb and resource vocabulary first, then converge
   the call sites. Do not model paths that do not exist.

## Phased plan

### P0 — cleanup (no behavior change)

1. Delete `core/src/auth/permissions.rs` and its re-export in `auth/mod.rs` — no caller anywhere.
2. Wire `AutoLockPolicy` into `PersonaService`: at `new`, build `AutoLockConfig` from the workspace
   setting `session_timeout_seconds` instead of a hardcoded default; and decide how the
   `is_unlocked()` in-memory short window and the `AutoLockManager` absolute cap divide labor (see
   [Cross-Process Session & Authorization Center](./session-center.md)).
3. Add `principal_kind` + `decision_reason` audit columns and have `ensure_authorized` record the
   decision — so granted actions carry adjudication context, not just scope denials.
4. Fix the stale doc: `docs/src/concepts/principal.md` still claims "the code contains no
   principals table and no authorization rules that differentiate by principal", which contradicts
   `core/src/authz.rs`.

**Acceptance**: `cargo clippy --workspace --all-targets --all-features -- -D warnings` and the full
`cargo test` pass; a new regression test asserts that a management action carries a
`principal_kind` audit record.

### P1 — verb and resource completion (deciding the write path)

1. Add `Create` / `Update` / `Delete` to `AuthzAction` (one-to-one with CRUD; no vague single
   `Write`).
2. **Connect tokens still grant only read/use**: write verbs are always denied for tokens, reusing
   the existing `connect_verb() -> None` pattern. Management verbs are granted only to
   `LocalSession`.
3. Extend `AuthzResource` for Attachment / Backup / Workspace / ConnectToken / Sync as needed —
   **only objects that already have a gate point**, avoiding modeling nonexistent paths.
4. Complete `authorize_local` with write verbs: a local session may create/update/delete, with the
   stateful gate still in `ensure_sensitive_operation_allowed`; management operations keep the
   current behavior.

**Acceptance**: new decision unit tests covering the `AuthzAction × AuthzPrincipal × AuthzResource`
matrix (including token-denies-write, agent-denies-non-bound-key, and non-interactive export folding
to denial); the four existing call sites behave unchanged.

### P2 — local-session convergence + activating principal binding

1. **Migrate the 32 `ensure_unlocked()` sites in batches to `ensure_authorized(resource, action)`**:
   read paths → write paths → management. A local session keeps full rights, behavior unchanged, but
   now enters unified adjudication and audit.
2. **Activate `ConnectTokenRow.principal`**: the minimal step is to surface the field in audit
   records and the Connect API (who is using this token), then decide whether to promote it to an
   adjudication input. Prefer machine-readable labels over free text.
3. **Generalize the `ensure_authorized` signature** to take `(principal, ctx)` rather than a
   hardcoded `LocalSession`, so token and agent paths share one entry point.

**Acceptance**: the audit table can answer "which token/agent key triggered a given signature, and
what was the decision reason"; no bare `ensure_unlocked()` call remains in the data plane.

### P3 — agent delegation (AI gets no full key)

1. `AgentKey` already carries `credential_id` + `identity_id` binding; extend it into an `AgentGrant`
   with a **per-action allowlist**, reusing the TOML shape of `agents/ssh-agent/src/policy.rs` (no
   policy DSL).
2. Unify the `InteractionRequired` fulfillment interface (see the confirmation-primitive merge in
   [Cross-Process Session & Authorization Center](./session-center.md)).
3. **Acceptance scenario**: an AI agent with a limited grant can complete `git fetch` / `git commit`
   / `git push` (signing allowed), and is denied reading credentials of another identity, exporting
   any secret, and signing a non-bound key; in a non-interactive context an overreach fails fast
   rather than hanging.

## Non-goals

- No reworking of identity CRUD, no new identity model, no identity storage migration.
- No policy DSL / CEL; TOML is enough.
- No change to SQLite transaction or concurrency semantics.
- No write capability for Connect tokens in P1.
- No "policy covers every object" — only paths with a real gate point.

## Terminology

- **principal (authorization subject)** ≠ **Identity (credential grouping)**. The latter is a vault
  resource — the object being authorized over; the former is the subject initiating the action.
  Switching identity switches the resource, not the subject.
- **Verbs**: `read` / `use` / `export` / `sign` (current) + `create` / `update` / `delete` (P1).
- **`InteractionRequired`**: policy allows but the call edge must fulfill (confirmation dialog,
  biometrics); treated as unauthorized until fulfilled, and folded to denial in a non-interactive
  context.

## Related

- [Cross-Process Session & Authorization Center](./session-center.md): shared unlock state, active-
  identity broadcast, confirmation-primitive merge, and limited agent RPC — the fulfillment
  infrastructure for P2/P3.
- [Security Design](./security.md): layered boundaries and sensitive-operation constraints.
- [Prototype external review and verification record](https://github.com/cuihairu/persona/blob/main/docs/review/2026-10-24-persona-external-architecture-review.md): origin and verification log for R-P3.
