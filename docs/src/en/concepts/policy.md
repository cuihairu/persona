# Policy

**In one sentence**: policy decides whether "who, in which [context](./context),
performing which [action](./action) on which [material](./material)" is allowed,
requires confirmation, or is denied.

**Policy is not an implementation detail of security — it is a first-class model on
par with Identity/Material.** Every sensitive path in Persona answers to the same
adjudication semantic:

```text
Action (requested action)
   │
   ▼
Policy Engine (inside core)
   │
 ├─ allow        → execute and audit
 ├─ confirm      → execute after desktop/CLI confirmation
 └─ deny         → deny and audit
```

## Policies that have landed (hard gates + configurable)

| Domain      | Rule                                                                                                        | How to configure                                                                 |
| ----------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Browser     | fill/copy/TOTP require user gesture                                                                         | Auto-fill switch (per-site default)                                              |
| Browser     | TLD+1 **origin binding** (`validate_origin_binding`, match ≥ 60)                                            | Cannot be turned off — hard gate                                                 |
| Browser     | blocked/suspicious domains refuse fill and save (phishing protection)                                       | Maintained through the domain policy table                                       |
| Write path  | `save_credential` requires user gesture + desktop approval gate (auto/require/off) + origin binding + audit | Approval mode in desktop settings                                                |
| SSH Agent   | known_hosts, deny-all, rate limits, per-key/per-host rules, confirmation/biometric precedence               | Configurable via `~/.persona/agent-policy.toml` (or `PERSONA_AGENT_POLICY_FILE`) |
| Lock layer  | auto-lock, re-authentication for sensitive operations                                                       | Client-configurable                                                              |
| Automation  | non-interactive mode requires explicit env vars to enable (CI scenarios)                                    | `PERSONA_NON_INTERACTIVE` etc.                                                   |
| All domains | every sensitive action goes to the (redacted) audit log                                                     | Cannot be turned off                                                             |

Three principles:

1. **Policy lives in core, not in client UI** — CLI, desktop, extension, and Agent
   alike cannot bypass core to read or write sensitive plaintext directly (the
   top-level constraint of [Security Design](/en/design/security));
2. **Hard gates cannot be configured away** — security invariants like origin binding,
   user gesture, and auditing have no switches;
3. **What is configurable is only the experience** — what runs automatically, what
   needs confirmation, and what is remembered per site.

## Vision: the rule layer (planned, not implemented)

In the future, user-configurable rules will be provided (the following is a YAML
vision example, not current reality):

```yaml
identity: work
rules:
  aws:
    access_key:
      allow: false # the work identity's AWS key is forbidden from browser use
  ssh:
    hosts: ["*.company.com"]
    require_confirmation: true
  browser:
    domains: [github.com, company.com]
```

Once the rule layer lands, the configurable items in the "landed" table above become
the rule engine's **built-in default set**, and the rule engine itself stays inside
core, on the side that cannot bypass hard gates.
For the implementation cadence, see the
[roadmap](https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md).
