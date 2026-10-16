# Context-Aware Identity Suggestion — Design

> [English](CONTEXT_AWARE_DESIGN.md) | [中文](CONTEXT_AWARE_DESIGN.zh.md)

Status: **Stages 1+2 implemented** (2026-10-12: core `ContextService` + `context.toml`
parsing + `persona suggest [--json]` + `persona context map/get/unmap/status`;
2026-10-13, stage 2: `persona shell-hook` (bash/zsh snippet, PS1 prefix ⛵ candidate) +
`persona use` (= an alias for switch; the audit entry carries the reason when the top suggestion is confirmed) + history learning
(migration 020 `context_learn`/`context_settings`, off by default,
`persona context learn on|off|status|clear`, suggestion weight 0.7, 30-day window);
2026-10-13, stage 3: `persona ssh run --host` prints a suggestion line using the target host as its only signal
(stderr; it suggests without authorizing), and `--identity` moves from reserved to an agent key filter
(the CLI first verifies the name exists, and the agent loads only
that identity's keys under `PERSONA_AGENT_IDENTITY`, failing closed);
2026-10-14, stage 4 bridge half: the bridge protocol's `get_suggestions` accepts optional `host`/`cwd` signals,
the response gains a `context` field and items gain an `identity` annotation, and the suggested identity's credentials merge into the candidate list ranked first
(shared with `persona suggest` through core `suggest()`; `PERSONA_NO_CONTEXT` switches the whole layer off;
corrupt mappings degrade silently); same day, browser half: the popup consumes `context`/`identity` — ordering
follows the bridge-side order (the suggested identity is already ranked first), each entry is labeled with its identity name, and one line at the top reads "Context suggests X"
(`autofillUx.ts` pure-function test, 5 cases). Remaining: the desktop tray candidate.
Related: [Core concept: context](src/concepts/context.md),
[ROADMAP M7](ROADMAP.md#milestone-7-identity-runtime-positioning-concepts-feature-track-follows).

## 1. Goals and positioning

The next step after autofill is **identity suggestion**: when the user enters a directory, opens a repository, or connects to a
host, Persona should know "which identity is most likely now" and rank it first — rather than leaving the
user to pick by hand among six identities.

Iron rule (consistent with `concepts/context.md`):

> **Context suggests; it never authorizes.** A suggestion never bypasses policy to allow an action; an unconfirmed
> suggestion does not change `active_identity_id` — it only changes the "default/first candidate".

## 2. Where the concepts land

```
Signal collection (facts observable by the client)
      │
      ▼
core: ContextService (pure function, unit-testable)
      │  Input: Context { cwd, host, remote, origin, ... } + mapping table
      │  Output: candidate identity list (identity, score, reason) — ranking, threshold, fallback
      ▼
Consumers (CLI prompt / bridge suggestions / desktop UI)
      │
      ▼
User confirms → persona switch (the only identity-change path, audited)
```

- Decisions must live in **core** (ContextService); all clients share one scoring implementation;
- Clients only **collect signals** (cwd, host, origin); they carry no reasoning of their own;
- Identity changes still go through `persona switch` and the `active_identity_id` pointer — a suggestion only
  replaces the "which one is the default" decision.

## 3. Context signal inventory

| Dimension | Signal                                                                    | Source                                               | Reliability                                                               | In v1?        |
| --------- | ------------------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------- | ------------- |
| Terminal  | `cwd`                                                                     | `std::env::current_dir`                              | Scripts can forge it, but suggestions do not authorize, so it is harmless | ✅            |
| Git       | Walk up from `cwd` to `.git`, read `remote origin` → forge and owner/repo | Shell call into git, or `git2`                       | High                                                                      | ✅            |
| Terminal  | `hostname`                                                                | `gethostname` / `PERSONA_HOST` override              | High (can be changed via env var; see below)                              | ✅            |
| Terminal  | Parent process chain (is the shell interactive)                           | `/proc/<ppid>/comm` heuristic                        | Medium; only prompt on an interactive TTY, leave scripts alone            | ⚠️ Stage 2    |
| SSH       | Host / key requested by the agent                                         | Existing agent policy input                          | High                                                                      | ✅ (stage 3)  |
| Browser   | page origin / per-site default                                            | Existing autofillDefaults                            | High                                                                      | ⚠️ Stage 4    |
| Desktop   | Current window/project                                                    | Tauri side                                           | Medium                                                                    | ⚠️ Stage 4    |
| Device    | Machine role (dev-pc / laptop / server)                                   | Hostname convention, or `~/.persona/machine-profile` | User self-declared                                                        | ✅ (optional) |

Privacy boundary: all signals are computed locally and never leave the machine; suggestion history never enters sync and never enters the server;
the audit log records only "which suggestion the user confirmed" (reusing the existing switch audit), never the signal itself.

## 4. Suggestion algorithm v1 (deterministic scoring)

Pure function `score(ctx) -> Vec<(identity, score, reason)>`; no randomness or ML allowed:

```
score = Σ (signal_match × signal_weight)
Threshold: only entries with score ≥ MIN_SUGGEST (e.g. 0.6) qualify as candidates; take the first
Tie: most recently used active entry wins (SQLite records the identity + ts of every switch)
No candidate: fallback = current active identity (behavior identical to today)
```

Example (static mapping table):

```toml
# ~/.persona/context.toml (user-maintained; v1 also supports the persona context map subcommand)
# Valid TOML syntax is dot-separated quoted keys (the whitespace form in the first design draft was git-config style and is invalid)
[project."github.com/cuihairu/persona"]
identity = "OpenSource"

[host.".*-server$"]
identity = "Ops"
```

- `cwd=~/workspace/persona` → remote `github.com/cuihairu/persona` →
  hits `[project ...]` → OpenSource (score 1.0, reason="repository github.com/cuihairu/persona");
- `cwd=~/workspace/client-a` → no project mapping, host=`dev-pc` matches no `-server` pattern,
  but `persona switch` was run 41 times in this directory within the last 30 days, to "Client-A" →
  learned candidate "Client-A" (score 0.7, reason="used in this directory recently");
- Nothing hits → active identity, behavior unchanged.

### 4.1 History learning (optional, off by default)

Off by default; once `persona context learn on` is set, every `persona switch` writes
`(identity, cwd_hash, host, ts)` into a new SQLite table (local, never synced).
When suggesting, one learned candidate is produced from "how recently the same signal group was used". Rationale:
learning builds on behavior the user already has, and the result only affects the default, so the risk is low; but keeping it off by default
preserves the "no surprises" principle.

## 5. User model and data

- Mapping table: `~/.persona/context.toml` (global) + optional `$repo/.persona/context.toml`
  (inside the repository; ignored by `.gitignore` by default — sharing identity preferences across a repository is a team decision,
  so nothing is auto-shared; an in-repo **plaintext** mapping may only reference identity names and never touches key material);
- Override chain (highest precedence first): environment variable `PERSONA_CONTEXT_OVERRIDE=<identity>` >
  in-repo mapping > global mapping > history learning > active identity;
- Identity name references share their source with `persona switch` (if the name check fails, skip that candidate and warn).

## 6. Integration points

- **CLI (v1 core)**: `persona suggest` (human-readable) and `persona suggest --json`
  (script-friendly); `persona context map/get/unmap/learn on|off/status`;
- **Interactive prompt (v1)**: `persona shell-hook` generates a zsh/bash snippet; on an interactive TTY only,
  and only when `PERSONA_NO_CONTEXT` is unset, it shows an "⛵ OpenSource" candidate in PS1,
  and offers `persona use` for one-keystroke confirmation (= an alias for `persona switch`, audited)
  — note that `persona switch` semantics are unchanged; a suggestion is never executed automatically;
- **Bridge protocol (stage 4, implemented 2026-10-14)**: a `get_suggestions` request may carry
  optional `host`/`cwd` fields; the serving side (the bridge, not the server) scores with the **same** core
  `suggest()`: the response gains `context` (identity/score/reason), items gain an
  `identity` annotation, and the suggested identity's credentials merge into the candidates ranked first (cards merge the same way) —
  backward compatible: with fields omitted / no mappings, behavior matches today (no `context` in the response,
  legacy extension shape unchanged); the extension side (`popup.ts`) consumes the same response: ordering follows the bridge-side order,
  each entry is labeled with its identity name, and one context hint line sits at the top (`autofillUx.ts` pure function;
  `nativeBridge.ts` types gain the optional `identity`/`context` fields);
- **SSH (stage 3)**: the host dimension already present in agent policy feeds into ContextService —
  when touching `*.company.com`, suggest the Work identity; `--identity` moves from reserved to a filter.

### 6.1 Why not debut in the bridge protocol

The browser extension is the highest-frequency entry point today, but it already has a baseline suggestion from "per-site default + active identity";
cwd/host signals are worth the most in terminal scenarios. v1 locks onto the CLI, gets ContextService
proven in core, and only then rolls out horizontally to the browser and desktop.

## 7. Compatibility and security

- With no mappings configured and learning off, `suggest` results ≡ today's behavior (active identity);
- A suggestion **never** triggers `switch` on its own and never changes any policy evaluation (origin binding,
  user gesture, and the approval gate all stay untouched);
- The environment variable override is a "suggestion-layer" override and expands no authorization (consistent with the existing `PERSONA_*` precedent);
- An in-repo mapping only references identity names in plaintext and writes no material or keys; it never enters sync (that table is not in the database).

## 8. Stage plan

| Stage | Delivery                                                                                            | Acceptance                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | core `ContextService` + `context.toml` parsing + `persona suggest [--json]` + `context` subcommands | Unit tests: mapping hit/miss, override chain, tie-break, forged signals; with no mappings the output = active **— implemented 2026-10-12 (`core/src/context.rs` 30 cases + CLI 8 cases; suggest/context are exempt from the workspace requirement and can run from any project directory; a corrupt mapping file is handled as "ignore that layer and warn")**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 2     | shell-hook, interactive TTY prompt, `persona use`, history learning table (off by default)          | Both shells smoke-tested; the learning switch defaults off; the audit entry includes the reason **— implemented 2026-10-13 (`persona shell-hook [bash\|zsh]` generates a snippet that passes `bash -n`/`zsh -n` syntax smoke plus a source-and-call degradation smoke; `persona suggest --short` feeds PS1; `persona use` = a switch alias, and when the top suggestion is confirmed the audit details record "confirmed context suggestion: {reason}"; the learning table is migration 020, the switch defaults off, `persona context learn on/off/status/clear`, records store only the cwd SHA-256 + identity name and never enter sync; the learned candidate weight is 0.7 with a 30-day window, and any mapping hit outranks it)**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 3     | SSH host dimension wired in, `--identity` takes effect                                              | `ssh -T git@github.com` scenario suggests correctly; host policy interplay unchanged **— implemented 2026-10-13 (`persona ssh run --host` runs the target host as its only signal through ContextService: on a hit it prints one suggestion line to stderr (without touching the agent's target host file or policy evaluation), a non-empty `PERSONA_NO_CONTEXT` switches the whole layer off, and any load failure degrades silently to no suggestion; the agent policy chain is untouched. `ssh add-to-agent --identity <name>` verifies the name exists before spawning; the agent loads only that identity's SSH keys under `PERSONA_AGENT_IDENTITY` and loads no keys for an unknown name (fail-closed). 7 suggest host cases + 2 agent filter cases + 2 CLI argument/early-failure cases all green; live walkthrough: in a scratch workspace, `--host git.company.com` prints the suggestion line, an unknown host is silent, opt-out is silent, a fake agent receives the filter env, and `--identity Ghost` fails first without spawning)**                                                                                                                                                                                                                  |
| 4     | bridge protocol fields, desktop tray candidate, browser suggestion ordering                         | Consistent candidates across all entry points; legacy extensions (unknown fields) do not regress **— bridge half implemented 2026-10-14 (bridge protocol optional `host`/`cwd` fields + `context` response + items `identity` annotation + the suggested identity merged and ranked first; 8 seam-level tests (host mapping hit and cross-identity merge, no mapping, corrupt mapping degradation, env override beating mapping, explicit host field beating origin, cwd repository discovery + in-repo mapping beating global, `PERSONA_NO_CONTEXT`, card form merge) + end-to-end compatibility tests (signals accepted, `context` absent when there is no mapping, items carry identity); identity enumeration/parsing goes through the existing `Repository` trait (consistent with the whole-repo convention, no duplicate inherent methods added). The browser half shipped the same day: the popup consumes `context`/`identity` (ordering follows the bridge-side order, the suggested identity already ranked first; each entry labeled with its identity name; a top "Context suggests X (score N.NN)" hint; `autofillUx.ts` gains 5 pure-function test cases; the extension's 164 cases + tsc + build all green). Remaining: the desktop tray candidate)** |

## 9. Open questions

1. Opt-in auto-switch: allow a direct switch when there is a single high-confidence candidate? (Leaning: revisit in v2;
   v1 only prompts) — the review's "one-click switch" vision is landed here as "suggestion + one-click confirm";
2. Should the history learning table reuse the sync channel for cross-device consistency? (Leaning: tombstone semantics
   are too heavy; v1 can stay local, and cross-device can be assessed later as "per-device learning + a synced global mapping table");
3. Should suggestion results feed the desktop "recently used" ordering? (Does not affect this design; pure UI layer).

## 10. Failure modes and fallback

- Corrupt mapping table → ignore that layer and warn (no crash);
- git fails to read the remote (offline / corrupt repository) → degrade to no Git signal, other signals proceed as usual;
- All scores 0 → fall back to active, behavior unchanged — so the worst case for this feature is
  "exactly like today", which is why it is safe in the CLI default path.
