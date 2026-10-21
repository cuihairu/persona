# Authentication API

Persona Server's device authentication track: device login based on SRP
(Secure Remote Password), trading the proof for a short-lived Bearer token.
For the protocol design, see
[E2EE_SYNC_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/E2EE_SYNC_DESIGN.md).

## Authentication Model

- **The device is the identity**: each device registers an SRP salt and
  verifier on the server under its device name; the same name counts as the
  same device (a reinstall simply re-registers over the old entry).
- **Tokens**: a successful `/auth/verify` issues a short-lived token (about a
  15-minute TTL), carried on subsequent `/api/v1/*` requests as
  `Authorization: Bearer <token>`.
- **Fail-closed**: when the token track is not configured on the server,
  protected endpoints return 503 across the board — there is no degraded,
  open-access fallback.
- **Revocation is immediate**: deleting a device instantly revokes its
  in-memory short-lived tokens and pending handshakes, without waiting out
  the TTL.

## Endpoints

| Method | Path                     | Auth            | Purpose                                                                  |
| ------ | ------------------------ | --------------- | ------------------------------------------------------------------------ |
| POST   | `/api/v1/auth/register`  | existing Bearer | Register/overwrite this device's SRP salt and verifier (bootstrap chain) |
| POST   | `/api/v1/auth/challenge` | none            | Start an SRP challenge                                                   |
| POST   | `/api/v1/auth/verify`    | none            | Submit SRP proof, receive a short-lived Bearer token                     |

`challenge` / `verify` require no authentication — they are themselves the
login steps that obtain the token; `register` sits behind Bearer protection
(a new device is bootstrapped in by an already authenticated session).

## Boundaries

- Request bodies are capped at 64 KiB (the salt / verifier / SRP public values
  are all far smaller than that; the cap guards against anomalous payloads).
- The server stores only the verifier and never touches the master password or
  the vault keys.
- A successful authentication only proves "this device has registered" — it
  does not mean membership in a sync group; for sync-group authorization see
  the Sync API.

## How It Hooks Into the Clients

The desktop app completes this handshake under "Settings → Sync Devices"; the
CLI is configured through environment variables (see the client configuration
section of
[STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md)).
