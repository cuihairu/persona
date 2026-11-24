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

## Run with Docker

`persona-relay` ships its own image, separate from `persona-server` and tagged
independently: `ghcr.io/<owner>/persona-relay`, multi-arch
(`linux/amd64` + `linux/arm64`). Tag policy: a `v*` release publishes the
semver tags (`1.2.3`, `1.2`); pushes to `main` and `workflow_dispatch` publish
the rolling `nightly`.

```bash
docker pull ghcr.io/cuihairu/persona-relay:nightly
```

Minimal run — SQLite on a named volume so the sync/pairing state survives
restarts, token injected from the environment:

```bash
docker run -d --name persona-relay \
  -p 3000:3000 \
  -e PERSONA_SERVER_TOKENS="relay:your-token" \
  -e PERSONA_SERVER_DB=/data/persona-relay.db \
  -v persona-relay-data:/data \
  ghcr.io/cuihairu/persona-relay:nightly
```

Configuration surface (everything is read by `relay/src/main.rs`):

| Variable | Default | Purpose (source) |
|---|---|---|
| `PERSONA_SERVER_TOKENS` | — (fail-closed) | Bearer tokens for the `/api/v1/sync` surface, `name:token,name:token` (`relay/src/main.rs:45-49`) |
| `PERSONA_SERVER_TOKEN` | — (legacy) | single-device token; prefer the plural form above (`relay/src/main.rs:50-56`) |
| `PERSONA_SERVER_DB` | `./persona-relay.db` | SQLite path; point it at a mounted volume to persist (`relay/src/main.rs:33-34`) |
| `PERSONA_SERVER_HOST` | `0.0.0.0` | bind address (`relay/src/main.rs:75`) |
| `PERSONA_SERVER_PORT` | `3000` | listen port; the image `EXPOSE`s 3000 (`relay/src/main.rs:76-79`) |

Two semantics worth stating: with neither token variable set, `/api/v1` is
disabled entirely (fail-closed, `relay/src/main.rs:57-63`) while the pairing
mailbox stays reachable — pairing exchanges carry no shared credential by
design. The image also carries a container `HEALTHCHECK` against the
unauthenticated `/health` endpoint, which the relay router keeps
(`server/src/lib.rs:238-243`, mounted by `build_relay_router`
`server/src/lib.rs:38-43`); the healthcheck follows
`PERSONA_SERVER_PORT` at container start, so an overriden port still probes the
right place.
