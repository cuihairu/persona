# Sync API

Persona Server's end-to-end-encrypted sync track: the server **relays
ciphertext only** — the ciphertext operation log (oplog), device envelopes,
and group-key envelopes — and never holds any ability to decrypt. For the full
protocol, see
[E2EE_SYNC_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/E2EE_SYNC_DESIGN.md).

Every endpoint requires a Bearer token (obtained via the
Authentication API).

## Endpoints

| Method | Path                                  | Purpose                                                                                    |
| ------ | ------------------------------------- | ------------------------------------------------------------------------------------------ |
| POST   | `/api/v1/sync/devices`                | Register this device (device envelope upload)                                              |
| GET    | `/api/v1/sync/devices`                | List the devices in the sync group                                                         |
| DELETE | `/api/v1/sync/devices/:id`            | Revoke a device (cascade-deletes envelopes and the same-name SRP registration; idempotent) |
| GET    | `/api/v1/sync/group-keys`             | Fetch the group-key envelope family (delivered with the epoch baseline)                    |
| PUT    | `/api/v1/sync/group-keys`             | Write group-key envelopes (rotation reseals for every device)                              |
| POST   | `/api/v1/sync/group-key/rotate-begin` | Rotation mutual exclusion: epoch CAS, the late arrival gets 409                            |
| PUT    | `/api/v1/sync/devices/remark`         | Device self-remark (only a device can edit its own remark)                                 |
| POST   | `/api/v1/sync/oplog`                  | Push ciphertext oplog entries (idempotent; replays don't bloat the log)                    |
| GET    | `/api/v1/sync/oplog`                  | Pull oplog entries (cursor pagination; every non-empty page returns a cursor)              |
| PUT    | `/api/v1/sync/snapshot`               | Upload a snapshot (overwrite semantics with monotonically narrowing watermarks)            |
| GET    | `/api/v1/sync/snapshot`               | Fetch the latest snapshot (the bootstrap starter pack; 404 when none)                      |
| GET    | `/api/v1/sync/status`                 | Group instruction stream watermark (the group's latest version number)                     |

## Key Semantics

- **Conflict resolution lives on the client**: the server does not interpret
  oplog contents; when concurrent edits hit the same credential, clients
  settle the winner with Lamport-clock LWW, and the loser is kept as an
  unresolved duplicate (for manual resolution in the UI).
- **Concurrent rotation is mutually exclusive**: `rotate-begin` performs an
  epoch CAS inside a transaction (the epoch is incremented and committed only
  if `epoch ==` the `if_epoch` carried by the request), and the later arrival
  gets a 409 — that prevents two devices rotating at the same time from
  producing a split envelope family. It guards against accidental concurrency
  by honest clients, not against malicious bypass.
- **Crash resume**: a mixed envelope state left behind by a crash mid-rotation
  needs no manual repair — retrying the rotation re-runs under the new epoch
  and overwrites the leftovers with fresh envelopes.
- **Server-visible surface**: ciphertext, device IDs/names, operation counts,
  and timestamps — never plaintext, URLs, usernames, or other credential
  content.

## Boundaries

- Request bodies are capped at 1 MiB (credential ciphertext is kilobyte-sized,
  so a 500-item batch fits comfortably); there is no decompression layer
  (ciphertext does not compress, which also closes off the decompression-bomb
  surface).
- Attachments do not participate in sync (stored locally; routing them through
  the backup channel is a v2 topic).
- Retention policy: oplog/events are pruned on a rolling window set via env
  (no pruning by default), and the window must be ≥ the offline period of the
  slowest device — see the deployment section of
  [STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md).

## Operations Surface

Unauthenticated endpoints: `GET /` (service info), `GET /health`, and
`GET /metrics` (Prometheus: sync/event/cleanup counters). Audit-event intake
and queries (`/api/v1/events`) and encrypted-backup custody
(`/api/v1/backups`) run on separate Bearer token tracks — see the endpoint
table in
[STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md).
