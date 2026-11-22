# persona-relay

Persona's relay node: a thin binary over `persona-server` that serves ONLY the
E2EE sync + pairing mailbox surfaces — a dumb encrypted courier for code-paired
(zero-account) cross-device sync.

The events/backups/auth/accounts surfaces that a full `persona-server` exposes
are absent by construction: the router mounts `/api/v1/sync/*` and
`/api/v1/pairing/*` only, and the migrations create only the sync/pairing
tables (no audit/backup/account schema).

## Usage

```bash
PERSONA_SERVER_TOKENS="relay:your-token" \
PERSONA_SERVER_DB=./persona-relay.db \
PERSONA_SERVER_HOST=0.0.0.0 \
PERSONA_SERVER_PORT=3000 \
  persona-relay
```

`PERSONA_SERVER_TOKENS` (or the legacy single-device `PERSONA_SERVER_TOKEN`)
is fail-closed: unset disables `/api/v1` entirely. Environment variables
reuse the `PERSONA_SERVER_*` namespace of `persona-server` — see
`docs/SELF_HOST_SERVER.md` for the full reference.
