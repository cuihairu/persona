# Context

**In one sentence**: context is the set of environmental facts the client **can
observe**, used to answer "where am I and what am I doing right now," so it can suggest
identities and feed policy decisions.

The key constraint: **context is observed fact, not user declaration**. There is no
"manually switch my web identity" action — a URL is a URL, and a local directory is a
directory. So the ceiling of what context can do is **suggestions** and **default
choices**, never forging an identity.

## Context dimensions that have landed

| Dimension          | Source of fact                                   | Consumers                                                                                        |
| ------------------ | ------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Page origin        | browser extension's page origin                  | suggestion queries, **origin binding** (TLD+1 domain binding; no match, no fill/save)            |
| Site preferences   | per-site autofill defaults                       | password/TOTP default entries, `savePromptDisabled`                                              |
| Current identity   | `workspaces.active_identity_id` (global pointer) | suggestion filtering in every entry point, ownership of new credentials                          |
| SSH session        | SSH Agent's key + host                           | per-key/per-host policy, known_hosts, confirmation gates                                         |
| Trust/threat state | domain policy table                              | aggressive autofill only on trusted domains; blocked/suspicious domains refuse all fill and save |

Note that the "current identity" itself also participates in context: the flip side of
context-independent behavior is that identity is the **explicit** component and context
the **implicit** one, and the two combine into the final suggestion. The browser
extension's `suggesting_for` is exactly that combination of origin + current identity.

## Planned direction

> **Phases 1–4 are implemented** (2026-10-12 ~ 2026-10-14): `persona suggest
[--json|--short]`, `persona context map/get/unmap/status`, `persona shell-hook`,
> history learning (migration 020, off by default), host-dimension suggestions in
> `persona ssh run --host`, and suggestion ranking in the bridge and browser extension.

```text
Context:
    repository = github.com/cuihairu/persona
    directory  = ~/workspace/persona
    host       = dev-pc
    terminal   = zsh
    user       = cuihairu

        ↓ (suggestion)

Identity: OpenSource
```

- Terminal/CLI scenarios (phases 1+2): the repository containing the cwd and the
  hostname → `persona suggest` proposes identities likely to apply, `persona context
map/unmap` manages static mappings, `persona shell-hook` puts candidates into your
  prompt, and `persona use` confirms in one step;
- SSH scenarios (phase 3): `persona ssh run --host <host>` prints one line of
  host-scoped identity suggestions to stderr before connecting (suggestion only, never
  authorization; disable with `PERSONA_NO_CONTEXT=1`); `persona ssh add-to-agent
--identity <name>` makes the agent load only that identity's SSH keys (filtered
  fail-closed by `PERSONA_AGENT_IDENTITY`);
- Browser scenarios (phase 4): the bridge protocol's `get_suggestions` accepts
  optional `host`/`cwd` signals, responses carry a `context` hint and per-entry
  `identity` labels, and the suggested identity's credentials join the results ranked
  first; the extension popup consumes the same signals (the same core `suggest()`,
  silently degrading to plain suggestions when a mapping is broken).

For the full design see
[CONTEXT_AWARE_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/CONTEXT_AWARE_DESIGN.md)
(phases 1–4 implemented).
Across all of it, the mechanism obeys one hard rule: **context only ever influences
suggestions and defaults — it never bypasses policy to allow an action.**
