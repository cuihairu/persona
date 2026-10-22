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

- **Not implemented** as a standalone principal model: as of 2026-10 the code contains
  no `principals` table and no authorization rules that differentiate by principal;
- Existing precursors: non-interactive CLI mode (CI scenarios), bridge pairing/session
  authentication, the request-origin field in audits, and the SSH Agent's key/host
  policy dimensions;
- The API semantics do not hard-code "user" as the only subject — `cmds`/service are
  both centered on identity + action and never depend on "which account owns the
  vault."

## Planned direction (no timeline promised)

1. Add a topic to actions in the audit trail first (human/agent/device + process
   identifier);
2. Add an optional `principal_id` field to the bridge protocol/CLI (required becomes
   optional, backwards-compatibly);
3. At the rule layer, allow trimming the [Action](./action) allowlist per principal —
   an Agent can only ever obtain whitelisted actions, never the materials themselves.

Until (1), (2), and (3) land, everything above is a **direction**, not a feature
commitment.
