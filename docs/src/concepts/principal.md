# Principal — a reserved direction

**In one sentence**: a principal is the abstraction of whoever initiates an action — a
human, an AI agent, or a device is just one kind of subject. This is a **reserved
direction**: Persona's model refuses to hard-code the world as "human ↔ credentials"
and instead models "principal → identity → material → action", so Agents and CI can
enter the model naturally.

```text
Principal
 ├── Human    (cuihairu)
 ├── Agent    (codex / claude / CI runner — reserved)
 └── Device   (desktop / laptop / server / phone — reserved)
```

## Why it is worth reserving

The AI coding tools in daily use today (Claude Code, Codex, CI, multi-agent setups,
multiple machines) all consume materials such as SSH keys, API keys, and npm tokens.
What they actually need is not "to obtain credentials" but "to obtain controlled
actions that have passed policy checks" — for example:

```text
Agent: codex
Context: github.com/cuihairu/persona
Allowed:  git fetch / git commit / git push (controlled signing)
Denied:   AWS production, personal GitHub, wallet signing
```

Once "who is requesting" is modeled explicitly — in the data model and in audits — the
above stops being a script that needs human supervision and becomes a **policy rule**.
Many of Persona's mechanisms are already paving the way: pairing + session bound to
the extension instance, audits recording the request's origin, explicit env-var
switches for non-interactive mode, per-action gates. The only missing piece is making
the "initiator" a first-class citizen of the model.

## Current state (honest boundaries)

- **Partially implemented, not yet a standalone model**: `core/src/authz.rs` is now the single
  adjudication point with three principal kinds — `LocalSession`,
  `ConnectToken { scope }`, and `AgentKey { credential_id, identity_id }` — and adjudication
  already differs by principal. There is still no `principals` table, and the
  `connect_tokens.principal` column exists only as an opaque label that `authorize()` never reads.
- The gap list and phasing live in
  [Principal & Action Authorization Design](/design/principal-action.md): write verbs are still
  undecided, decisions do not feed the audit log, and agent delegation is not there yet.
- Precursors that are why this direction was reserved in the first place: non-interactive CLI
  mode (CI scenarios), bridge pairing/session authentication, the request-origin field in audits,
  and the SSH Agent's key/host policy dimensions;
- The API semantics still do not hard-code "user" as the only subject — service and commands are
  centered on identity + action and never depend on "which account owns the vault."
- Terminology: the vault `Identity` is a **credential grouping** (a resource), not a principal.
  Switching identity switches the resource, not the authorizing subject.

## Planned direction (no timeline promised)

The sequence is worked out in the design doc:

1. The audit trail gains the principal dimension first — `principal_kind` + `decision_reason`,
   so granted actions are attributable, not just scope denials (P0 in the design doc);
2. The bridge protocol / CLI gains an optional `principal_id` field (backwards-compatible);
3. Per-principal trimming of the [Action](./action) allowlist — an Agent can only ever obtain
   whitelisted actions, never the materials themselves (P3 in the design doc).

Until (1), (2), and (3) land, everything above is a **direction**, not a feature commitment.
