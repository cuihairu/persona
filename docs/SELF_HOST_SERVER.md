# Self-hosting persona-server (one-command startup)

> [English](SELF_HOST_SERVER.md) | [中文](SELF_HOST_SERVER.zh.md)

`persona-server` is an optional sync/backup relay. It is off by default: the
desktop app and CLI are fully functional locally without configuring a server
(the privacy red line: accounts/sync default to off and are enabled explicitly).

Positioning: **pure relay + ciphertext custody**. The server only ever sees
ciphertext and minimal metadata (backups are whole-database PERSENC1 ciphertext,
sync oplog is ciphertext payload + item UUID/kind/lamport/timestamp/device public
key/envelope — for the full visible-surface list see `E2EE_SYNC_DESIGN.md` §10).
The master password never leaves the device.

## Three deployment forms (S3)

A single `persona-server` binary is the entire server-side implementation of the
sync relay, and the three deployment forms map to the S3 model: ① official
hosting = persona officially runs the same image; ② self-hosted relay = the
compose/cargo path on this page; ③ LAN self-hosted relay = the same binary bound to the
on-site device's LAN address (`PERSONA_SERVER_HOST=192.168.x.x` or the default
`0.0.0.0`). Clients only change `base_url`; the protocol is byte-for-byte
identical — consistency across the three forms comes from "one router, one test
suite", with no need for three implementations; the only differences are
deployment and transport error shapes.

## Prerequisites

- Docker (compose v2) or local cargo (inside the workspace, `cargo run -p persona-server`).
- One strong random token (for multiple devices, splitting per device is recommended).

## One-command startup (compose, recommended)

```bash
export PERSONA_SERVER_TOKEN="replace-with-a-strong-random-string"   # single device; for multiple devices see below
# export PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"  # multi-device tokens (optional, additive)
docker compose -f docker/docker-compose.deploy.yml up -d
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/health  # 200
```

Notes:

- When `PERSONA_SERVER_TOKEN` is unset, compose refuses to start (`:?` fail-closed: the server never comes up quietly with the API disabled).
- Multi-device tokens `PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"`: device names are derived from the tokens and cannot be self-reported by clients; backup versions are attributed per device; the legacy single token is compatible as a `default` device.
- Data lands in the named volume `persona-server-data` (`/data/persona-server.db` + `/data/backups`), preserved across container restarts.
- Health checks: `GET /health` (unauthenticated); `/metrics` is unauthenticated (Prometheus text).

## Building the image locally

compose pulls `ghcr.io/<owner>/persona-server:<tag>` by default. To build your
own image:

```bash
docker build -f docker/Dockerfile.server -t persona-server:local .
# point compose's image at persona-server:local, then up -d as before
```

## Environment variable reference

| Variable                                      | Default               | Description                                                                                                                                                             |
| --------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PERSONA_SERVER_TOKEN`                        | — (one required)      | Legacy single token; if neither it nor TOKENS is configured → all of `/api/v1` returns 503 (fail-closed), `/health` still 200                                           |
| `PERSONA_SERVER_TOKENS`                       | —                     | Multi-device `name:token,…`; an invalid format fails at startup                                                                                                         |
| `PERSONA_SERVER_HOST` / `PERSONA_SERVER_PORT` | `0.0.0.0` / `3000`    | Listen surface; change HOST as needed when exposing only to the LAN/127.0.0.1                                                                                           |
| `PERSONA_SERVER_DB`                           | `./persona-server.db` | Event database (WAL, separate from the core identity store)                                                                                                             |
| `PERSONA_SERVER_BACKUP_DIR`                   | `./backups`           | Directory for encrypted backups on disk (`{uuid}.persenc`)                                                                                                              |
| `PERSONA_SERVER_BACKUP_MAX_VERSIONS`          | `0` (unlimited)       | Deletes the oldest once exceeded (global, across devices)                                                                                                               |
| `PERSONA_SERVER_OPS_RETENTION_DAYS`           | `0` (no cleanup)      | Sync oplog window: opening one means giving up replaying history to devices that were offline past the window; the window must be ≥ the slowest device's offline period |
| `PERSONA_SERVER_EVENTS_RETENTION_DAYS`        | `0` (no cleanup)      | Retention for the audit event copy, sized to your SIEM ingestion cadence                                                                                                |

## Client wiring

Backup chain (CLI): enabled only when both `PERSONA_SERVER_URL` and
`PERSONA_SERVER_TOKEN` are non-empty (fail-closed);
`persona backup push/list/pull/restore/delete`. push does not require unlocking;
restore confirms first, then takes the passphrase, swaps the database only after
the staged re-verification succeeds, and keeps the old database as `.bak`.

Sync (desktop): fill in URL + token on the Settings page's sync pane (the real
token goes into the OS keyring, only a placeholder is kept in the database) →
join/authorize/revoke in the device management area → `sync_now` push/pull. When
the first device joins, an empty group is created automatically
(`bootstrap_group_if_empty`); a revoked device's short-lived token becomes
invalid immediately (beyond waiting out the TTL), and forward secrecy for
historical ciphertext relies on manually "rotating the group key".

Device authentication (SRP, DR-2): `POST /api/v1/auth/register` requires an
existing Bearer as the bootstrap chain (the client generates salt/verifier
locally and uploads them; the password never leaves the machine) → `challenge` →
`verify` exchanges it for a 15-minute short-lived token; five consecutive failures
lock for 15 minutes. The static-token path is kept coexisting (the backup chain
and event reporting are not interrupted).

## Endpoint quick reference (auth = Bearer, static or SRP short-lived)

- `/api/v1/events` (POST/GET): audit event batches ≤500/body ≤1MiB, partially deduplicated by `client_event_id`, cursor pagination.
- `/api/v1/backups` (POST/GET/DELETE): streaming to disk with a 256 MiB cap, dedup by sha256 of the newest version from the same device, download ETag=sha256.
- `/api/v1/sync/devices` (POST/GET/DELETE): device registration (public key + device name)/list/revoke; `/api/v1/sync/devices/remark` (PUT): device remarks visible to each other within the group (S4).
- `/api/v1/sync/snapshot` (PUT/GET): group snapshot watermark anchor.
- `/api/v1/sync/status` (GET): sync status.
- `/api/v1/sync/group-keys` (GET/PUT): device envelope fetch/store; `/api/v1/sync/group-key/rotate-begin` grabs the envelope write window with an epoch optimistic lock (409 = the latecomer re-reads and retries).
- `/api/v1/sync/oplog` (POST/GET): push ≤500 entries/batch idempotent (`op_id`), pull cursor-based incremental. The server neither sorts nor merges (DR-4; adjudication happens client-side with LWW + conflicting dual versions).
- `/api/v1/accounts/*`: account system (M2). `register`, `{id}/srp/register|challenge|verify` (SRP password authentication, the second account domain beyond DR-2 above), `{id}/passkeys/create-options|register|login-options` (WebAuthn ceremonies), `{id}/recovery-codes` (generate/verify one-time recovery codes), `{id}/devices` (POST/GET/DELETE device authorization and revocation), `{id}/sessions` (POST to create/DELETE to revoke account sessions). Write paths behind a Bearer gate: srp/register, recovery-codes generation, devices, sessions.
- `/api/v1/pairing/*`: accountless mailbox for sync-group dynamic password pairing (S1, `docs/sync-group-mode.md`; **Bearer not required**). `POST sessions` (create a session, TTL 600s), `GET|DELETE sessions/{id}` (read back salt/queue watermark/delete a session), `POST|GET messages/to-host`, `POST|GET messages/to-guest` (GET consumes; per-direction queue ≤4, payload ≤4KiB, 404 merges existence). The relay does not interpret payloads.

## Operational notes

- Backup dedup is ciphertext-level sha256: PERSENC1's random salt+nonce makes each fresh push produce different ciphertext, so dedup only prevents retrying identical ciphertext; the version count is capped by `BACKUP_MAX_VERSIONS`.
- Once an oplog/event retention window is opened, devices that were offline past the window are filled in from their local source of truth plus idempotent re-push (backfilled verbatim with INSERT OR IGNORE), and views still converge.
- The server does not guard against tampering/rollback/withholding (the same boundary as backup custody, registered in THREAT_MODEL); the blast radius of a compromised device = all sync data visible to that device (equivalent to the local machine being compromised).
