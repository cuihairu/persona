# Persona Threat Model and Periodic Security Review

> [English](THREAT_MODEL.md) | [中文](THREAT_MODEL.zh.md)

This document defines the security boundary, principal threats, landed controls, and review mechanism for Persona's current mainline product. Scope follows the root `BOUNDARY.md`: Persona is a local-first, zero-knowledge identity-material manager, primarily protecting passwords, API keys, TOTP, SSH keys, browser fill data, and related metadata for the same user across different identity contexts.

## Goals and Non-Goals

Goals:

- Protect identity material in the local workspace from unauthorized read, fill, export, and signing.
- Constrain sensitive material such as credentials, SSH keys, and TOTP to use within explicit identity contexts and origin contexts.
- Maintain consistent encryption, audit, and policy boundaries across CLI, desktop, browser extension, and SSH Agent.
- Leave sufficient local audit evidence when misuse, anomalous fill, anomalous signing, or configuration changes occur.

Non-goals:

- Does not defend against malicious kernels, debuggers, or system-level malware that has fully taken control of the current user session.
- Does not promise plaintext recovery when the master password is lost and the vault cannot be unlocked.
- Does not treat Server/Sync as a hard dependency; the optional server must not touch plaintext identity material (except for encrypted backup restore points — see "Backup Custody Endpoint"; the server holds ciphertext but not keys).
- Does not treat wallet capabilities as part of the current security mainline; wallet-related capabilities remain in experimental scope.

## Assets

| Asset                                  | Example                                                       | Primary risk                                                                                                                                             |
| -------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Master password and derived master key | `PERSONA_MASTER_PASSWORD`, in-memory unlock key               | Once compromised, decrypts the local workspace                                                                                                           |
| Per-item credential key                | item key after unwrapping `wrapped_item_key`                  | Single-item plaintext disclosure or lateral expansion                                                                                                    |
| Credential plaintext                   | password, API key, TOTP secret, SSH private key seed          | Data exfiltration, unauthorized fill, unauthorized signing                                                                                               |
| Workspace database                     | SQLite, migrations, user auth records, metadata               | Offline brute force, tampering, rollback                                                                                                                 |
| Browser bridge session                 | pairing key, short-term session, Native Messaging messages    | Malicious extension requests fill or copy                                                                                                                |
| SSH Agent socket/pipe                  | `SSH_AUTH_SOCK`, Windows Named Pipe                           | Unauthorized signing, agent-forwarding abuse                                                                                                             |
| Audit log                              | login, unlock, credential decryption, SSH signature digests   | Tampering, deletion, sensitive fields written by mistake                                                                                                 |
| Backup/import-export files             | JSON/YAML/CSV, encrypted backups                              | Backup disclosure, format injection, weak passphrase                                                                                                     |
| Wallet keys (experimental track)       | BIP39 mnemonic, xprv/derived private key, keystore/WIF export | Irreversible loss, poisoned address, forged signature — highest-tier asset; the experimental declaration is in the "Wallet (Experimental Track)" section |
| OS keyring escrow entry                | master password in keyring (for biometric unlock)             | Read by a same-user malicious process, stale entries                                                                                                     |

## Trust Boundaries

1. **Local user boundary**: the current OS user account is the primary security boundary. Persona must not write plaintext to world-readable paths, nor rely on the cloud for secrecy.
2. **In-process unlock boundary**: the unlocked master key and partial plaintext must exist only on short-lived in-memory paths; on lock, service state must be cleared.
3. **Workspace boundary**: SQLite, attachments, and configuration files belong to the same local workspace; migrations must stay backward-compatible and least-privilege.
4. **Browser bridge boundary**: the browser extension invokes `persona bridge` over Native Messaging; sensitive operations must pass pairing, HMAC, short-term session, origin binding, and user gesture.
5. **SSH Agent boundary**: OpenSSH clients request signatures over a socket/pipe; the agent exposes only public-key listing and signing capability, never exports private keys.
6. **Optional server boundary**: server/sync may handle only event digests, ciphertext, or sync metadata; it must never become the plaintext decryption party. The landed events API receives only audit event digests (action, resource type, optional ID, timestamp, success flag, and bounded metadata), authenticated by Bearer token (multi-device tokens or the legacy single token), and is fully disabled when no token is configured (fail-closed). The backup custody endpoint (2026-09) stores only client-encrypted PERSENC1 ciphertext and metadata; restore requires two factors — the backup passphrase + the master password. See the "Backup Custody Endpoint" section.
7. **Automation boundary**: non-interactive mode allows injecting the master password via environment variable, which suits CI, but the caller is responsible for isolating and clearing that environment variable.

## Principal Threats and Controls

| STRIDE                 | Threat                                                                        | Existing controls                                                                                                                                                                               | Still needs attention                                                                         |
| ---------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Spoofing               | A malicious browser extension impersonates a paired client                    | Pairing code, `client_instance_id`, short-term session, HMAC-SHA256 request authentication                                                                                                      | Pairing state file permissions and revocation UX need ongoing review                          |
| Spoofing               | SSH connection target host impersonated                                       | known_hosts forced mode, unknown-host confirmation, per-host policy                                                                                                                             | known_hosts parsing needs retesting as OpenSSH formats evolve                                 |
| Tampering              | Local SQLite or configuration tampered offline                                | AES-GCM authenticated encryption protects credential ciphertext; migration tests cover schema                                                                                                   | Plaintext metadata and audit logs can still be modified by a local attacker                   |
| Tampering              | Import files or Native Messaging messages crafted as malicious input          | JSON parsing, length-prefixed protocol, format-parser tests and fuzz paths                                                                                                                      | New parsers must be added to the fuzz list                                                    |
| Repudiation            | User denies a sensitive operation                                             | Audit records identity CRUD, credential decryption, export, SSH signature digests                                                                                                               | The audit log is not currently a tamper-evident ledger                                        |
| Spoofing (wallet)      | Address poisoning: history lures copying a forged address                     | Desktop confirmation-panel heuristic alerts + mandatory backend check at signing entry points (CLI/desktop; an unconfirmed hit refuses to sign — see the "Wallet (Experimental Track)" section) | Heuristic false positives/negatives need real-world samples; no hardware wallet               |
| Repudiation            | Client forges/replays audit events reported to the server                     | The server explicitly claims no non-repudiation; the events API is aggregation-only observability (single Bearer token gate, `client_event_id` idempotent dedup)                                | Per-client device identity and non-repudiation (SRP/event signing) deferred to the sync track |
| Information Disclosure | Workspace files copied and attacked offline                                   | Argon2id/PBKDF2 derivation, AES-256-GCM, per-item key wrapping                                                                                                                                  | Master password strength remains the core risk; KDF parameters need periodic review           |
| Information Disclosure | Browser background page quietly reads passwords/TOTP                          | user gesture, origin binding, active-identity filtering, return only matching credentials                                                                                                       | Credentials without a URL cannot be origin-bound; the UI/CLI should surface this risk         |
| Information Disclosure | Logs leak secrets, tokens, verification codes                                 | Log redaction policy and unit tests cover common secret/key/value shapes                                                                                                                        | New log fields must first be confirmed plaintext-free                                         |
| Denial of Service      | Agent flooded with signature requests or resource exhaustion                  | Global minimum interval, per-hour/per-day limits, per-key/per-host policy                                                                                                                       | Long-running agents need real-machine stress tests                                            |
| Elevation of Privilege | A low-trust automation script borrows the unlocked state to run sensitive ops | Auto-lock, sensitive-operation re-authentication, explicit env switch for non-interactive mode                                                                                                  | The unlocked state is a high-risk window; desktop wiring must avoid implicit authorization    |

## Landed Security Controls

- **Local encryption**: credential plaintext is encrypted with AES-256-GCM; newly written credentials use a random item key wrapped by the master key. Attachments reuse the owning credential's item key for sealing — master-password rotation only rewraps the wrapped key, the item key is unchanged, so attachments remain decryptable across rotation without rewriting; legacy credentials (without a wrapped key) are upgraded in place to item-key wrapping the first time an encrypted attachment is attached, and credential deletion cascade-cleans attachment blobs (an orphaned blob's item key is already unrecoverable).
- **Key derivation**: password export and some data encryption use Argon2id; the core master-key service still contains a PBKDF2 path today — track its parameters and migration strategy in security review.
- **Session and locking**: the service layer supports auto-lock, sensitive-operation re-authentication, a biometric provider abstraction, and a remote-authentication abstraction.
- **Browser bridge**: the Native Messaging protocol includes pairing, HMAC request authentication, short-term session, replay window, origin binding, and user gesture requirements.
- **SSH Agent policy**: supports deny-all, rate limiting, known_hosts, per-key/per-host allow/deny, confirmation, and biometric priority.
- **Audit**: sensitive events such as identity, credential, unlock, export, and SSH signing are written to the local audit log; SSH signing records only the digest of the data to be signed.
- **Supply-chain checks**: `deny.toml`, cargo-deny, cargo-audit, npm audit/pnpm audit, and license policy have documented processes.
- **Parser tests**: TOTP, wallet import/export, SSH protocol encoding, and the browser bridge protocol have unit/integration test paths; some parsers are already listed as fuzz targets.

## Currently Accepted Limitations

- Local administrators, kernel-level malware, debuggers, and memory dumps can still attack unlocked plaintext.
- The current audit log emphasizes traceability; it provides no cryptographic signature chain or remote non-repudiation.
- `PERSONA_MASTER_PASSWORD` suits automation, but is exposed to processes/logs in the same execution environment; CI must use a secret store and disable command echo.
- Browser credentials without a URL cannot do strict origin binding; high-value credentials must be bound to a URL.
- The optional Server/Sync is still not a trust root: encrypted backups let the server act as a restore point for ciphertext snapshots, but restore capability presupposes locally holding the backup passphrase and the master password; server unavailability must not make data unrecoverable (the local vault is the first source of truth).
- persona-server's events API is a token-gated observability surface: it accepts self-reported client event digests (`client_timestamp` is untrusted, ordering uses only the server's `received_at`), retention is off by default (the event store grows unboundedly; setting `PERSONA_SERVER_EVENTS_RETENTION_DAYS` prunes by day), and it is not a tamper-evident audit ledger.
- Wallet capabilities remain experimental; the current mainline security commitments do not cover production-grade fund safety.

## Security Review Cadence

Every release must complete:

- Run `cargo test --workspace`, plus the corresponding frontend/extension tests.
- Run `cargo deny check` and the JS dependency audit.
- Check new logs, error messages, and audit metadata for plaintext secrets.
- Check whether new CLI/bridge/agent parameters bypass user gesture, origin binding, confirmation, or auto-lock.
- Check whether new migrations protect historical ciphertext and `wrapped_item_key`.

Every month must complete:

- Review RustSec, npm/pnpm audit, and outdated dependencies.
- Spot-check `PERSONA_*` environment-variable documentation for new high-risk defaults.
- Spot-check browser bridge pairing state, session expiry, and nonce/HMAC logic.
- Spot-check SSH Agent policy defaults to confirm signing permissions are not widened by default.

Every quarter must complete:

- Re-evaluate KDF parameters, master-key migration, and backup encryption parameters.
- Re-review this threat model and `BOUNDARY.md` to confirm new features stay within the product boundary.
- Run one manual security drill covering browser fill, SSH signing, import/export, and backup restore.
- Clean up or explain `deny.toml`, audit exemptions, and unfixed security TODOs.

## Change Thresholds

The following changes must explicitly update this threat model in the PR, or state why an update is not needed:

- New plaintext secret types, export formats, sync paths, or long-running background processes.
- Changes to the master key, item key, KDF, nonce, backup encryption, or signing algorithms.
- Changes to authentication/authorization rules of the browser bridge, Native Messaging, SSH Agent, or automation environment variables.
- Changes to audit log structure, redaction policy, sensitive metadata, or log retention policy.
- Introducing new production network APIs, production telemetry, or cloud storage paths.

## Optional Sync Server (persona-server)

The Events API (`POST/GET /api/v1/events`) and `/metrics` are persona-server's first production network endpoints, registered here per "Change Thresholds":

- **Data scope**: receives and stores only audit event digests and metadata — action, resource_type, optional user/identity/credential/session ID, timestamp, success flag, bounded metadata (≤32 entries, bounded key/value lengths). The protocol carries no plaintext secrets or key material; the request body is length-limited on two layers — `Content-Length` pre-check of on-the-wire bytes ≤1 MiB (including gzip-compressed transfer) and post-decompression plaintext ≤10 MiB (defuses decompression bombs and backstops chunked requests without Content-Length); ≤500 entries per batch.
- **Authentication**: shared Bearer token (legacy single token `PERSONA_SERVER_TOKEN` or multi-device tokens `PERSONA_SERVER_TOKENS`), constant-time comparison against all entries; unconfigured means 503 full disable (fail-closed). `/`, `/health`, and `/metrics` are unauthenticated.
- **Explicitly not claimed**: this store is not a tamper-evident ledger and provides no non-repudiation — a token-holding client can report arbitrary content, and `client_timestamp` is untrusted; audit semantics defer to each endpoint's local audit log, with the server side as aggregation-only observability.
- **Metrics surface**: `/metrics` exposes request counters (method + route template + status code) and event-ingress counters, with bounded label cardinality and no user data or path parameters.
- **Known limitations**: the retention window is off by default (the event store grows unboundedly; a positive integer for `PERSONA_SERVER_EVENTS_RETENTION_DAYS` prunes by day, default 0 = no cleanup, see `server/src/main.rs`); no rate limiting or quota; `ip_address`/`user_agent` are client self-reported fields; permissive CORS (current clients are not browsers); a single token carries no per-client identity.

Client reporter (`core::events::Emitter` + `ServerEventSink`, best-effort replication of local audit events to the Events API above):

- **Data scope**: identical to the server's storage scope — local audit digests and bounded metadata, carrying no plaintext secrets or key material; the wire layer pre-validates each entry byte-wise against the server's limits, and poison-pill events are dropped client-side (the server validates all-or-nothing, so a single entry never drags down the whole batch).
- **Token**: the Bearer token is host-injected (`ServerEventSink::new(base_url, token)`); core reads no environment variables and persists nothing to disk; reports go only to the explicitly configured base_url.
- **Non-persistent**: an in-memory queue replicates best-effort — a process crash loses unflushed batches, with no persistent outbox and no backfill; the local sqlite audit store remains the only evidentiary source (continuing the "no tamper-evidence / non-repudiation claim").
- **Backpressure**: reporting never blocks audit writes — a full queue drops the oldest and counts it; on send failure the whole batch requeues in original order with 1s→5min exponential backoff; the final flush in `stop()` is best-effort, so the abort loss window is capped at one batch_size.
- **Transport compression** (gap closed): batches with plaintext body >1 KiB are gzip-compressed (flate2 default level) and sent with `Content-Encoding: gzip`; the server side decompresses via `RequestDecompressionLayer` (tower-http 0.6); smaller batches are sent as plaintext. Purely transport-layer compression — protocol shape, authentication, and audit-evidence semantics are unchanged; compression is encapsulated inside `ServerEventSink` with zero host changes. The decompression surface is already length-limited (1 MiB on the wire / 10 MiB plaintext); corrupted gzip streams return 4xx.
- **AutoLock events** (gap closed): `PersonaService::set_event_emitter` propagates synchronously to `AutoLockManager`, whose SessionLocked/Unlocked audits go through the same reporting chain after being written to the store; audit rows for background-monitor timeout locks get session_id/user_id/details backfilled in the same batch. `LockPending`/`Activity` are UI events, not audit actions — neither written to the audit log nor reported (status quo maintained).

Host wiring (the endpoints where desktop / CLI / mobile construct the Emitter and inject it into `PersonaService`):

- **desktop (Tauri)**: the `settings.sync` section lives in the vault's `workspaces.settings` JSON column, but `server_token` is **always written as an empty-string placeholder** — the real token value lives in the OS keyring (keyring 4: Linux secret-service / macOS Keychain / Windows Credential Manager; service `"persona-sync"`, key = vault db_path; the field-level encryption gap is closed). Legacy plaintext from before the keyring batch is migrated into the keyring once at runtime and the DB is cleared; if the keyring is unavailable before migration, **the plaintext is kept rather than destroying data** (reporting disabled, retried at the next attach). `get_workspace_settings`, which is unlock-free (needed by the unlock-screen trimmed UI), therefore returns a sync section without the token — IPC exposes no token while locked; a new unlock-free boolean query `sync_token_present` (leaking only the single "ever configured" bit of metadata) drives the frontend placeholder, with no token backfill. Fail-closed semantics: submitting a non-empty token whose keyring write fails refuses the save; attaching the reporter requires all three of enabled + non-empty url + keyring token present; disabling clears the keyring (failure only warns — a leftover token stays within the same OS user's trust domain); copying the vault file to another machine → no matching keyring entry → reporting stays off and requires re-entry. Saving the config re-attaches the reporter (stop old, start new); process exit does a best-effort final flush via `RunEvent::Exit`.
- **CLI**: env-only (`PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` must both be non-empty to enable; whitespace counts as unset), **never persisted to disk** — the config-file channel is deliberately not provided; `stop()` at the end of `main` flushes best-effort, and the release `panic = "abort"` crash path skips the flush (loss window identical to the in-memory queue limit above).
- **mobile (persona-mobile, three-platform native hosts + Rust FFI bridge)**: the Flutter shell was removed entirely on 2026-10-02; there are now three native hosts (iOS Swift / Android Kotlin / HarmonyOS ArkTS) sharing one Rust bridge (`mobile/rust`, hand-written extern "C") through each platform's standard native binding (C ABI staticlib / JNI cdylib / NAPI). Bridge functions: `persona_service_init` (account-creation/auth sequence aligned with desktop), `persona_service_unlock/lock/is_unlocked`, `persona_configure_sync` (enables only when url+token are both non-empty after trim, detached if either is blank — fail-closed aligned with CLI; the URL gets no format pre-validation, consistent with desktop attach, so format errors surface at send time with backoff), `persona_shutdown` (lock and clear keys + best-effort final flush + clear the slot). **The Rust side never persists to disk or reads environment variables**: url/token are injected by the host (Swift/Kotlin/ArkTS layer) via FFI parameters; service state stays in a Rust-side global slot, and key material never crosses the FFI boundary. Unfinished surfaces, stated honestly: iOS/Android hosts have wired the init/unlock/lock/is_unlocked/shutdown sequence; HarmonyOS `PersonaBridge.ets` is a same-signature stub (napi wrapper layer pending; real-machine acceptance needs a device/emulator); `persona_configure_sync` is not yet exposed to the host side (neither the iOS C header `Persona.h` nor the JNI layer exports it) — reporting configuration is not yet wired on any of the three hosts, so the current security conclusions cover the Rust FFI bridge layer and the already-wired sequences; losing unflushed batches on process kill is a known limitation (same as CLI/desktop). Android cdylib cross-compilation is in CI (`desktop-build.yml`: cargo-ndk aarch64 → `libpersona_mobile.so` + arm64 APK artifact); acceptance against a real server awaits a device environment.
- **Reporting surface unchanged**: all three hosts use the same `ServerEventSink` (Bearer + POST /api/v1/events) and send only to the user-configured base_url; on desktop, the new egress surface is exactly the server that configuration points to.

## Backup Custody Endpoint (`/api/v1/backups`, 2026-09)

Sync phase one: custody of whole-database encrypted backups. The client gzips a VACUUM INTO physical snapshot and encrypts it with PERSENC1 (Argon2id + AES-256-GCM, the same format as the CLI `--encrypt` export) before uploading; the server only ever sees ciphertext.

- **Data scope**: stores only the ciphertext file (`{backup_dir}/{uuid}.persenc`) and metadata (device name, byte count, sha256, timestamp). The server has neither the backup passphrase nor the master password, so the ciphertext is undecryptable; the device name is derived from the matched device token and cannot be self-reported by the client.
- **Authentication**: the same Bearer gate as events — multi-device tokens `PERSONA_SERVER_TOKENS` (`"laptop:tok1,phone:tok2"`, constant-time comparison against all entries with no early exit) or a legacy single token (the "default" device); an invalid format is a startup error (fail-closed). Upload limit 256 MiB (Content-Length pre-check plus streaming counter as a double guard; over-limit uploads delete the partial file); the sub-route has no decompression layer (ciphertext is incompressible, removing one decompression-bomb surface).
- **Explicitly not claimed**: does not protect against a server operator **withholding, deleting, or rolling back** backups — there is no hash chain, no signatures, no non-repudiable version proof, so a party holding the token or host control can roll the database back to an older version (client restore performs no freshness check). Phase 2 could add a hash chain/signatures; this risk is accepted today and hedged by treating the local vault as the first source of truth.
- **Two-factor restore**: restore = download ciphertext + decrypt with the backup passphrase + unlock the vault with the master password. Losing the backup passphrase = the backup is unrecoverable (no escrow, no reset); the same holds for the master password.
- **Retention and dedup**: a re-upload with the same sha256 as the latest version from the same device is deduplicated (idempotent re-upload); `PERSONA_SERVER_BACKUP_MAX_VERSIONS` (default 0 = unlimited) deletes the oldest globally (file and row deleted together).
- **Known limitations**: attachment blobs are not in v1 backups (after restore, attachment metadata is present but the file bodies are missing, stated explicitly by the client UI/CLI); a backup contains the complete snapshot as of creation time, with no subsequent increments.

## SRP Device Authentication Endpoint (`/api/v1/auth/*`, 2026-09, E2EE sync track phase 1)

SRP-6a (RFC 5054 4096-bit group + SHA-256) device login: the client pre-hashes the master password locally with Argon2id
to derive the SRP private key, and the server stores only the verifier (`auth_devices` table: device name, salt,
verifier — the password and the Argon2-derived value never leave the device). Design in
`docs/E2EE_SYNC_DESIGN.md` DR-2.

- **Data scope**: persisted data is only device name + salt + verifier (uploaded at registration via the existing Bearer — the bootstrap chain); pending handshakes (session_id, server ephemeral private key, client public value, TTL 120s), issued short-term tokens (TTL 15 minutes), and failure counts are **all in-memory and deliberately not persisted** — a server restart invalidates all of them (fail-closed, re-login required).
- **Authentication**: `/register` requires an existing Bearer (a static token or an already-logged-in SRP token); `/challenge` and `/verify` are Bearer-free (they are the login steps that exchange for a token) and pass on the SRP proof alone; issued tokens are random ≥256-bit base64url, and `require_bearer` prefers the static token, falling back to the SRP token table on a miss — **the TOKENS Bearer path is preserved in coexistence so the backup chain is not interrupted**. With the auth system unconfigured (no TOKENS), all three endpoints return 503 (same fail-closed as events/backups).
- **Brute-force and abuse mitigation**: Argon2id pre-hash (v19, m=19 MiB, t=2, p=1 — the argon2 crate defaults, same family as the local password-verification hash; the local vault unlock is a separate PBKDF2-600k path (`core/src/crypto/keys.rs`, iteration count persisted per vault in `user_auth.kdf_iterations`), a different algorithm and parameters — see `KEY_HIERARCHY.md`; domain-separated salt `persona-srp-v1`) makes the offline guessing cost after verifier exposure ≈ Argon2 cost; five consecutive verification failures lock for 15 minutes (aligned with local user_auth semantics, returning 423); a challenge is single-use (verify takes it from the cache) + 120s TTL; a nonexistent device name and any handshake failure return an identical 401 (does not expose registration state); M1/M2 bidirectional proof verification (the client verifies M2 against malicious-server/MITM downgrade). The `/auth` sub-route has an overall 64 KiB body limit, and base64 fields have per-field byte decode limits.
- **Explicitly not claimed**: does not protect against a server operator **offline brute-forcing the verifier in the `auth_devices` table** (the verifier is in the server's hands; cost = Argon2 + master password strength — same class as the local vault being dragged off, and master password strength remains the core risk); does not protect against **unauthenticated challenge flooding** (the in-memory session cache has no rate limit — a known DoS surface, mitigated by a deployment-side reverse proxy); does not protect against the server **refusing service / deleting registration records** (a device has no second copy; simply re-register, but this is an availability loss); the SRP math is implemented inline in `core/src/auth/srp.rs` (the RustCrypto `srp` crate was not adopted due to digest-ecosystem drift and is no longer a dependency) — the implementation is pinned by RFC 5054 official test vectors, with a seam isolated so it can be swapped.
- **Known limitations**: device revocation/removal has landed (2026-09 revocation closed loop): revoking a synced device (`DELETE /sync/devices/:id`) cascade-deletes the same-named `auth_devices` row (SRP registration is keyed by device name) and immediately revokes its in-memory short-term token and pending handshake (`SrpAuthState::revoke_device` — a revoked device's existing credentials no longer work, pinned by real TCP tests); but the revocation granularity is the **device** — there is no independent "revoke the token only, not the device" operation, and a token leaving the device still expires naturally by TTL (15 minutes); no audit beyond the change threshold — registration/login appear only in server logs (`tracing`), not in the event store.

## E2EE Sync Relay (`/api/v1/sync/*`, 2026-09, E2EE sync track phase 2)

Ciphertext relay for end-to-end encrypted sync between devices: the oplog (per-entry `SyncOp`: item UUID, kind,
`(lamport, device_id)` ordering key, ciphertext payload) is appended in arrival order and forwarded by cursor;
the group key is kept in "device envelope" form (sealed with an X25519 static public key + AES-256-GCM,
`persona-dev-env-1`). The server is a **pure relay**: blind store, append, forward — it makes no
win/lose decisions and performs no merging. Design in `docs/E2EE_SYNC_DESIGN.md` (DR-1/3/4); the server-side
visibility inventory is in its §9.

- **Trust root**: the master password (local only, never transmitted) + per-device X25519 private key (DR-1; persistence is the host's responsibility — OS keyring / 0600 file, core has no keyring dependency). The server has no decryption path: it never sees the group key plaintext or any per-item key, only ciphertext and metadata (pinned by the integration test `server_stores_only_ciphertext`).
- **Data scope**: oplog rows (op_id/item_id/kind/op/lamport/device_id/timestamp + two ciphertext columns; ≤500 entries per batch, payload ≤512 KiB, body ≤1 MiB), device registration (device name + 32-byte X25519 public key; a duplicate name returns 409 — a public key cannot be silently replaced), and envelopes (80 bytes, **attachable only to a registered device** — an envelope cannot attach to a phantom device, half of the server-side fail-closed guarantee). **Metadata side channel from honest registration**: the server can observe entry counts, sizes, arrival times, and device topology — not mitigated (by design; ciphertext length is unavoidable).
- **Conflicts are adjudicated by clients** (DR-4): win/lose is computed independently by each client as a total order over `(lamport, device_id)` (same item, same lamport, different device = a real conflict, and both versions are kept pending user adjudication); the server stores and forwards in arrival order, and the semantics are pinned by `server_does_not_arbitrate_conflicts` and the two-device convergence test `two_devices_converge_over_real_tcp_conflict_keeps_both_versions` (real TCP; both ends edit offline into a real conflict → both converge on the same primary position with both ciphertext versions present).
- **Authentication and authorization**: the whole sub-route is gated by `require_bearer` (static tokens and SRP short-term tokens coexist, as with events/backups). The authorization semantic is **"having an envelope = being authorized", borne by cryptography rather than a server ACL**: an unauthorized device can GET someone else's envelope, but without the matching private key the GCM tag verification always fails — it cannot obtain the group key and cannot open any entry (`group_key_envelope_round_trip_and_fail_closed` pins this).
- **Explicitly not claimed**: does not protect against the server tampering with / rolling back / selectively withholding the oplog ("device-private-key-signed oplog" is design doc §11 open question 6, long-term); does not protect against a malicious server/client flooding the oplog indefinitely (per-batch limits only mitigate the magnitude, not eliminate it); **this phase does not verify that op.device_id corresponds to the authenticated identity** (static and SRP tokens are mixed, with no unified mapping) — a malicious client can write arbitrary ciphertext garbage to the oplog or forge a higher-lamport fake version, but it cannot open any entry and cannot delete other devices' local vaults (local-first: the server is never the source of truth; a forged version enters LWW on a normal device just like any other and does not overwrite its local plaintext vault). The blast radius of a compromised device = that device's private key → group key → all synced data, the same class as "this machine compromised = this vault lost", and does not enlarge the asset exposure through sync.
- **Known limitations**: attachments do not go through the oplog (512 KiB payload limit; a v2 topic); during an active travel the push/pull double-stop is a **client engine gate** (`SyncEngine` constructor injection, invisible to the server) — a gate failure would break travel semantics through sync, a walkthrough item for the phase-3 wiring; group key rotation is implemented (2026-09 phase 3d, desktop "Rotate Group Key") but **revocation ≠ rotation**: revoking without rotating still lets ciphertext from before the removal be opened by the removed device's old key (**no forward secrecy**, the DR-3 honest boundary; after rotation new ciphertext is unreadable to that device, except for old ciphertext pushed within the window — the user docs and confirmation dialog both state this accurately). **Concurrent rotation is mutually excluded by an epoch optimistic lock** (2026-09-24, `rotate-begin` CAS): it prevents only honest clients from accidentally racing — the later arrival gets 409 and aborts without writing an envelope or rewrapping; it **does not prevent a malicious client** from bypassing begin and writing envelopes/rewrap ops directly (write authenticity is the long-term boundary of "device-private-key-signed oplog", same family as this phase's registered "does not verify op.device_id against the authenticated identity"). Oplog unbounded growth is mitigated by a retention policy (2026-09-24: client GC + `PERSONA_SERVER_OPS_RETENTION_DAYS`, closing design §11 open question 3 on both ends; default 0 = no cleanup, and opening the window means giving up responsibility for backfilling history to devices offline beyond the window).

## Travel Mode (travel.persenc sidecar, 2026-09)

Per-identity "remove from this device": enter packs all data of the marked identities (including attachment ciphertext
file bytes), gzips it, and encrypts it as `<db dir>/travel.persenc` with PERSENC1 (an independent travel passphrase,
Argon2id 64 MiB default parameters), then deletes it from the main vault in a single transaction — leaving zero trace in
the main vault, **and the master password cannot open the sidecar (by design, not a defect)**; exit enters the travel passphrase to restore as-is.
This design introduces a new single-point asset and a new loss surface:

- **Passphrase strength is self-borne**: the sidecar has only one passphrase protecting it, and its strength rests entirely on the user; losing the passphrase
  = the removed identities are permanently unrecoverable (no escrow, no reset, no master-password fallback). The UI/CLI states "no master-password fallback"
  explicitly at enter time.
- **Deleting the sidecar = data loss**: while travel is active (`travel_mode=true`), manually deleting the sidecar or losing it through media damage means permanent data loss.
  The status command and the desktop settings page present this honestly with an `inconsistent` red warning (without pretending it is recoverable),
  and perform no automatic cleanup.
- **A local attacker can delete the sidecar (denial of service, accepted)**: a process of the same OS user can destroy the only copy of a removed identity by
  writing the sidecar file. We do not claim to protect against a local attacker destroying data (the same trust boundary as
  "a malicious process can read the keyring"); a malicious process could equally delete the main vault, so travel mode adds no new boundary —
  it only concentrates the loss surface onto one file.
- **Encryption surface**: the sidecar ciphertext leaks no plaintext to the device holder, a cloud sync folder, or a USB copy
  (the same PERSENC1 format as the whole-database backup); crash-window semantics — the main vault is only touched after the sidecar is written successfully,
  a crash between 4→5 = the sidecar exists but the flag is false (enter refuses, suggesting exit or deleting the leftover),
  a crash between 5→6 = exit self-heals by overwriting.
- **Password-change exclusion**: changing the master password is refused while travel is active (the sidecar has no master-password binding, and a password change
  would not itself break the sidecar, but to avoid proving every combination of "key material semantics drifting while active",
  the request is refused outright and returns `TRAVEL_MODE_ACTIVE`; the change is allowed after exit).
- **Running-state cleanup**: a successful desktop enter stops the SSH agent (the agent memory may hold keys of the removed
  identities); audit_logs keep only id references (plaintext metadata moves into the sidecar along with change_history,
  leaving no readable residue in the main vault).

## Biometric Unlock (desktop fingerprint/biometric unlock)

The desktop app escrows the master password in the OS keyring and exchanges it for unlock-without-typing via a system authentication prompt (Linux polkit `auth_self` /
macOS LocalAuthentication `DeviceOwnerAuthentication` / Windows Hello) —
**this design downgrades "knowing the master password" to "passing OS user authentication"** —
the new assets and threat surface are recorded here in black and white:

- **Asset**: the master password plaintext stored in the keyring (Linux secret-service `persona-biometric` service /
- **Asset**: the master password plaintext, stored in the keyring —
  Linux secret-service `persona-biometric` service / macOS Keychain /
  Windows Credential Manager — keyed by vault db_path.
- **Inherent exposure (accepted)**: **any process of the same OS user can read the OS keyring** —
  Linux secret-service offers essentially no defense against same-session processes; **Windows Credential
  Manager has no per-entry ACL, so any same-user user-mode process can read it directly**. This is the inherent
  cost of the same direct-storage design 1Password uses: once the local user boundary is breached (malware
  running as the current user), the escrowed master password is exposed. The only mitigation is a "user-level front-line defense"
  (OS user authentication, app-provenance control); countering this scenario needs dedicated hardware (TPM/SEP
  binding + AT-CK-class process isolation), beyond this design's scope.
- **Biometric-path brute force**: biometric_unlock fetches the password and then goes through the real `authenticate_user`,
  **consuming the failure counter shared with the password path** (5 failures locks the account). Controls: a missing entry returns a clean error
  without prompting; InvalidCredentials deletes the entry on the spot and returns
  `BIOMETRIC_RESET` (preventing repeated fingerprint taps from locking the account).
- **Stale entries**: a password change outside the desktop (CLI) cannot reach the keyring linkage — the InvalidCredentials
  self-deletion (above) is the backstop; a successful in-desktop password change updates the entry synchronously, and a write failure deletes it
  (fail-closed: rather have the user retype the password than leave an old password that cannot open the vault).
- **System-prompt impersonation**: any process can request the OS authentication prompt, and the user cannot tell from the
  prompt itself who initiated it. Mitigations: the action id/message are fixed to Persona-exclusive
  (`com.persona.desktop.biometric-unlock`); the polkit subject uses
  system-bus-name (the bus daemon resolves the peer's credentials, immune to PID-reuse-class defects,
  avoiding the zbus_polkit <5.1.0 CVE-2026-78422).
- **Availability fail-closed**: no fprintd/polkit agent, no secret service,
  rpm/AppImage/dev builds without the action file installed → an availability probe failure degrades to
  unavailable as a whole (the button is not rendered), never a half-open/half-closed state.
- **Timeout**: the ceremony runs on a dedicated thread with a 120s timeout + a macOS inner reply wait of 110s,
  so a hung prompt does not drag down the UI thread.
- **enable gate**: the master password is verified before the OS authentication prompt — an unverified password is
  never written to the keyring; enable goes through the unlock gate (like set_locale), while disable idempotently deletes without a gate
  (tightening operations are kept permissive).
- **SSH agent linkage**: the agent's require_biometric policy denies by default + explicit OS provider injection
  (removing the silent-passthrough surface of a built-in Mock).
- **Hardware-bound wrapping layer (2026-09-26, `docs/biometric-unlock-design.md`)**:
  an upgrade tier above the gate layer — the keyring gains a `persona-biometric-wrap` service
  storing a **ciphertext blob** wrapped by platform hardware keys (a BIOWRAP1 envelope), mutually exclusive with
  the gate-layer password entry. Under this tier T1 (a same-user malicious process reading the keyring) can only obtain
  ciphertext it cannot open: decryption must pass hardware authentication (SE/TPM/Keystore) and the private key is never exported.
  Residual threat surface: enrollment drift (a changed fingerprint) → an unwrap failure automatically deletes the blob and falls back to the master password
  (a second comparison of the core envelope fingerprint as defense in depth); after a password change the old blob wraps a stale key,
  and the desktop password-change linkage deletes it on the spot; `BIOMETRIC_CANCELLED` does not delete the blob (cancel ≠ failure).
  Linux is pinned to the gate tier (no hardware wrapping); the macOS/Windows hardware tiers stay disabled by default until a real-device spike
  verifies them — an unverified path does not sit on the production unlock chain. CI-side measurement
  (2026-09-26, desktop-build macos runner): the VM has no Secure Enclave and
  spike probe 1 fails immediately (`os_status=-25293` `errSecAuthFailed`, no signing
  entitlement) — confirming "runner output is not evidence of SE behavior"; a real-device spike
  remains separately outstanding.
- **Windows enrollment-set drift has no platform semantic (2026-09-26, accepted)**: macOS
  `biometryCurrentSet` makes old SE keys permanently invalid after a fingerprint change; **Windows has
  no equivalent mechanism** — `NCRYPT_UI_PROTECT_KEY_FLAG` only enforces "every private-key use requires
  user verification", so verifying with a newly enrolled fingerprint still unwraps the old blob. Therefore
  `enrollment_fingerprint()` can only return a placeholder on Windows, and core's second
  comparison is empty as well. Residual risk: once the local login state is compromised, an attacker who
  completes **one** Windows Hello verification (having enrolled any fingerprint or PIN at some point)
  can unwrap the old blob — the "change the fingerprint to invalidate" anti-duress property does not hold on Windows.
  Mitigations: the master password as backstop + only unopenable ciphertext in the keyring. The full register is in
  the design doc `docs/biometric-unlock-design.md` §6.2.

## Quick Access (OS-level global hotkey + search floating window, 2026-09, benchmark #22)

Registers a global hotkey at the process level, summoning a borderless always-on-top floating window from any app for
cross-identity search and retrieval (copy primary secret / username / TOTP, or send the entry back to the main window
to open). In **exposure terms it is equivalent to "moving already-unlocked search and copy capability to a place that
does not require clicking the Persona icon first"**, adding a threat surface:

- **Larger visibility surface (inherent, accepted)**: the hotkey summon no longer requires focusing the Persona window,
- **Larger visibility surface (inherent, accepted)**: the hotkey summon no longer requires focusing the Persona window,
  and entry-name/username search results appear directly in the floating window for any bystander (shoulder-surfing surface).
  Mitigation: the floating window self-dismisses on focus loss (does not linger), Esc dismisses, it hides immediately on account lock,
  and in the locked state it does not search at all. Same boundary as 1Password Quick Access.
- **Unlocked-state gates unchanged**: all search/copy in the floating window goes through the unlocked `PersonaService`,
  with the same gate set as the main window at the command layer (`SERVICE_LOCKED` refuses outright, sensitive fields go
  through the `reveal_credential_secret` reauth gate + audit). **Nothing is copied in the locked state** — the floating window only
  prompts to unlock in the main window (deliberately not replicating the unlock flow in the 620×460 small window;
  rationale in the `quick_access.rs` module comment).
- **Clipboard**: reuses the existing `copyWithAutoClear` (30s auto-clear), the same path as the credential list /
  generator, adding no clipboard exposure duration.
- **Hotkey grab is not a privilege-escalation surface**: the binding string lives in workspace settings (plaintext, no key),
  so a grab failure / being occupied affects only availability. The settings page displays "configured" and "actually in effect" separately,
  and **failures are not silent** (including the backend's verbatim reason).
- **Plugin load fail-open degrades to "unavailable" rather than crashing**: the global-shortcut plugin is
  loaded at runtime inside `setup` (not on the `Builder::plugin` chain) — its setup fails on
  headless Linux / Wayland without XWayland, and running it on the Builder chain would fail the whole
  app build. The absence of an optional enhancement must never prevent a password manager from starting; the failure reason
  is recorded in running state and shown on the settings page.
- **Not claimed**: the hotkey cannot distinguish "the user pressed it" from "a same-user malicious process simulating an input event",
  the same boundary as OS shortcuts; the floating window does no browser autofill (fill belongs to the browser extension),
  so it introduces no "press-to-deliver credentials to an arbitrary page" path.

## Connect Local Automation Endpoint (`127.0.0.1` HTTP, 2026-09, secrets automation)

The desktop host embeds an in-process axum listener (DR-1) so local scripts/tools can pull credentials read-only
within a token scope. **The switch is off by default**: no listener created means no port surface; when enabled the bind is
hardcoded to loopback and the port is OS-assigned (no configuration surface, cannot be coaxed into listening on 0.0.0.0). New threat surface:

- **Trust root and visibility**: an unlocked-state + token two-way gate (either missing refuses). The token decides
- **Trust root and visibility**: an unlocked-state + token two-way gate (either missing refuses). The token decides
  "which types under which identity"; entries outside the scope return 404 identically to 403 (they do not exist to the consumer,
  preventing probing). health is unauthenticated but zero-information (does not report unlock state, does not report vault existence).
- **Not claimed**: defense against a local malicious process — at the moment the token lands in its hands (environment variable /
  argument / config file) it is visible to it, the same boundary as 1Password CLI; defense against the host process being
  compromised — automation neither widens nor narrows that boundary; multi-user OS isolation (same existing posture).
- **Three defenses against malicious web pages** (DR-4): the browser is the only "foreign caller" on 127.0.0.1, and
  the three independent defenses each fail-closed — ① Host header allowlist (only
  `127.0.0.1`/`localhost`/`[::1]`); after DNS rebinding the Host is the attacker domain, and 421 refuses;
  ② a request carrying an `Origin` header (the marker of a browser fetch) gets 403, with CORS
  fully off (no `Access-Control-Allow-*` returned, preflight fails outright); ③ a Bearer
  token is required, and missing/unknown/revoked all return an identical 401. A malicious page must bypass all three
  simultaneously to reach data, and the token itself is not reachable from a page.
- **Known residual (this usage is prohibited in the docs)**: if a user puts a plaintext token into **browser
  extension-reachable storage** (localStorage, extension settings), the three defenses above are meaningless to a page holding that
  token — the defenses target "pages without a token". The warning at the plaintext display spot on the settings page is one-shot only
  and does not change this boundary.
- **Token-leak blast radius**: a **read-only** surface bounded by the three-dimensional scope (verbs always read,
  no write path = no tampering radius) + immediate revocation (no cache, the next request gets 401) + audit
  visibility (Used goes through per-token per-minute throttled aggregation). Tokens are stored only as SHA-256 hashes,
  so a vault/backup leak does not equal a token leak; plaintext `pconn_` prefix + 32B random, not offline brute-forceable.
  The passkey/wallet/ssh/custom types are never authorizable (they do not exist at the vocabulary level).
- **Management surface**: create/revoke go through the reauth gate (core `ensure_sensitive_operation_allowed`
  is authoritative); plaintext appears only once, in the create response; management actions in the locked state are first refused by the sensitive gate.
- **DoS / resource surface**: a hardcoded 120-requests-per-minute 429 limit per token, protecting the host
  from being dragged down by an automation consumer; during lock 503 `vault_locked` is returned and **the quota is not decremented**;
  health does not consume quota. The listener footprint is minimal (a single loopback port), returning
  data only in the unlocked state, and 503 while locked.
- **Revocation and audit**: revocation is immediate and idempotent; the three
  audit actions `ConnectTokenCreated/Revoked/Used` enter the audit log; create/revoke records carry resource_id, with no token plaintext at rest.

## Wallet (Experimental Track) (M5, 2026-10-13, wallet graduation)

BTC (BIP-143 P2WPKH) / ETH (EIP-155/1559) / Solana derivation and signing have landed (official
vectors regressed), and the CLI and desktop wallet flows are usable. But wallet keys (the BIP39 mnemonic and the
private keys/xprv derived from it) are the **highest-tier asset**: loss is irreversible (no private key = permanently lost funds), with no dispute/rollback
mechanism. **Experimental-track declaration: this section carries none of the mainline security commitments and must not be used for production-grade fund safety** —
the same posture as "Non-Goals" item 4 and the final item of "Currently Accepted Limitations"; graduation (graduation criteria and
open questions such as hardware wallets) is in [WALLET_DESIGN.md](WALLET_DESIGN.md).

**Key hierarchy and passphrase isolation** (see WALLET_DESIGN.md §2/§3): the mnemonic and xprv are **doubly
wrapped** (Argon2id + AES-256-GCM, the same wallet passphrase, each with independent salt/nonce, both independently
unlockable), so either surviving copy recovers all addresses. The wallet passphrase is **independent of the master
password**, and a master-password rotation **does not touch** `crypto_wallets` — a master-password leak is not a
fund-material leak (blast-radius isolation). Existing exposure before `persona wallet passwd`: `change_wallet_password`
exists but has no production caller; the docs have settled on adding the command and an `EncryptedMnemonic` rewrap path.

| Threat surface                               | Threat                             | Landed controls                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Still needs attention                                                                                                                                       |
| -------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Export surface (keystore/WIF/plaintext JSON) | Export file copied/exfiltrated     | Export requires the wallet passphrase; keystore v3 = geth standard (scrypt/pbkdf2 + AES-128-CTR + keccak MAC, a 256MiB import memory limit + constant-time MAC comparison, pinned to spec vectors); CLI and desktop import/export both support keystore (2026-10-13); exports are audited                                                                                                                                                                                                                                                       | Mnemonic export is the strongest surface; the audit records the action only, not the content                                                                |
| Storage surface                              | Wallet ciphertext cracked offline  | Same parameters as credentials (Argon2id defaults not persisted; version=1, a parameter upgrade goes via version=2 + lazy rewrap, no in-place default change)                                                                                                                                                                                                                                                                                                                                                                                   | The parameter review cadence matches the mainline; the rewrap migration is not yet in code                                                                  |
| Signing surface                              | Forged/poisoned transaction signed | Verify before persist (ETH/Solana verify locally; a failure does not land in the store; BTC assembly failure degrades to audit only and never produces a broadcastable illusion); mandatory backend anti-poisoning (2026-10-13): the core heuristic (first 6 + last 6 characters) is enforced at the CLI and desktop signing entry points, an unconfirmed hit refuses to sign (CLI `--confirm-poisoning-check` / desktop second-confirmation ack); the passphrase is never logged; the confirmation panel must list from/to/amount/fee/chain id | The known-address set is currently = all wallet addresses; " + user-marked" is open; no hardware wallet, and the signing passphrase = the wallet passphrase |

**Signing-confirmation UX invariants** (backend-enforced, the UI is only a presentation layer; WALLET_DESIGN.md §5):
verify before persist, mandatory confirmation-panel fields (missing fields block submission), the passphrase is typed inside the panel and
never logged, and the audit records a digest-level summary. The Context suggestion track does **not apply to the wallet** —
a suggest candidate is an avatar, not a wallet, and wallet selection is always explicit.

**Change threshold**: any change to wallet key types, export formats, signing algorithms, or confirmation fields
must explicitly update this section and WALLET_DESIGN.md per "Change Thresholds" items 1/2/5, and state in the PR
the impact on the blast radius and the recovery path.
