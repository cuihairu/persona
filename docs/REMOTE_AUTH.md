# Remote Authentication (SRP-like Abstraction)

Persona prepares for a future client-server sync model by exposing a protocol-agnostic abstraction that mirrors the Secure Remote Password (SRP) workflow. The goal is to avoid sending master passwords to the server while still deriving a mutually authenticated session key.

## Components

- `SrpParameters`: server-provided modulus/generator/salt tuple (hex encoded for easier transport).
- `SrpHandshake`: client and server public values (`A`/`B` in SRP terminology).
- `SrpProof`: message authentication (`M1`/`M2`).
- `RemoteAuthProvider`: trait that begins/finalizes the handshake.
- `MockRemoteAuthProvider`: default in-memory placeholder so CLIs can run offline.

## Flow

1. Client calls `begin_remote_auth(username)` which returns:
   - Random `user_id` (UUID placeholder until real server IDs exist).
   - `SrpParameters` (currently mocked with small values).
   - `SrpHandshake` containing the server public value and a placeholder client public.
2. Client derives its proof locally and calls `finalize_remote_auth(challenge, client_proof)`.
3. Provider verifies the client proof and returns `RemoteAuthResult` (server proof + session key fingerprint).
4. Higher layers can now bind this fingerprint to the unlock key/sessions.

The mock provider serves tests/UI wiring only; server implementations will supply real SRP math and persist salts/verifiers.

## Real implementation (2026-09, E2EE sync track phase 1)

Server-side SRP is live:

- `core/src/auth/srp.rs` — production SRP-6a math (RFC 5054 4096-bit group, SHA-256, Argon2id pre-hash), shared by client and server; correctness locked by the RFC 5054 Appendix B interop vectors.
- `server/src/api/auth.rs` — `POST /api/v1/auth/register` (requires an existing bearer token), `/challenge`, `/verify` (issues a 15-minute bearer token; lockout after 5 failures). The static `PERSONA_SERVER_TOKENS` bearer path stays in place alongside it.
- Threat-model registration: `docs/THREAT_MODEL.md`, section "SRP 设备认证端点"; design decisions in `docs/E2EE_SYNC_DESIGN.md` (DR-2).

Client-side HTTP wiring is live too (2026-09-22):

- `core/src/auth/remote_http.rs` (feature `remote-auth`) — `HttpRemoteAuthProvider` (`register_device` / `begin_login` / `PendingRemoteLogin::finish`) drives the real three-endpoint flow and verifies the server proof `M2` before handing out the token. The mock trait above stays as the UI seam: its two-step shape cannot carry a real SRP session (`a_priv` must live with one owner from `A` to `M2` verification), so the real client is a standalone type and future OPAQUE work replaces this file only.
- Cross-end integration test: `server/src/api/auth.rs::tests::http_provider_full_round_trip_over_real_tcp` runs the full register → challenge → verify flow over real TCP against the server router and asserts the issued SRP token passes `require_bearer` alongside static tokens.

## Account-domain SRP (2026-10, M2) and pairing relay (S1)

The same SRP math backs two more remote-auth surfaces:

- **Account domain** — `POST /api/v1/accounts/{id}/srp/register|challenge|verify` (server: `server/src/api/accounts.rs`): password auth for the persona-account track, with passkey (WebAuthn) ceremonies, one-time recovery codes, and account-scoped device/session management alongside it. Bearer-gated write paths: srp/register, recovery-code generation, devices, sessions. Red-line verification script: `scripts/verify-account-redline.sh` (10 live assertions: public register, fail-closed 401s, one-time recovery codes, session-evidence 422, device/session family 401).
- **Sync-group pairing relay client** — `core/src/sync/pairing.rs::relay` (same `remote-auth` feature): `PairingRelayClient` drives the zero-account pairing mailbox (`/api/v1/pairing/*`, no bearer) for the dynamic-password PAKE handshake; see `docs/sync-group-mode.md` §四 for status. Verification script: `scripts/verify-sync-group-pairing.sh`.
