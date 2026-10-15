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

| Asset                        | Example                                                        | Primary risk                                                                              |
| --------------------- | ---------------------------------------------- | -------------------------------------------------------------------------------- |
| Master password and derived master key | `PERSONA_MASTER_PASSWORD`, in-memory unlock key | Once compromised, decrypts the local workspace                                                  |
| Per-item credential key            | item key after unwrapping `wrapped_item_key`          | Single-item plaintext disclosure or lateral expansion                                        |
| Credential plaintext               | password, API key, TOTP secret, SSH private key seed   | Data exfiltration, unauthorized fill, unauthorized signing                                    |
| Workspace database                 | SQLite, migrations, user auth records, metadata          | Offline brute force, tampering, rollback                                                     |
| Browser bridge session             | pairing key, short-term session, Native Messaging messages | Malicious extension requests fill or copy                                            |
| SSH Agent socket/pipe              | `SSH_AUTH_SOCK`, Windows Named Pipe                     | Unauthorized signing, agent-forwarding abuse                                               |
| Audit log                          | login, unlock, credential decryption, SSH signature digests | Tampering, deletion, sensitive fields written by mistake                              |
| Backup/import-export files         | JSON/YAML/CSV, encrypted backups                         | Backup disclosure, format injection, weak passphrase                                      |
| Wallet keys (experimental track)   | BIP39 mnemonic, xprv/derived private key, keystore/WIF export | Irreversible loss, poisoned address, forged signature — highest-tier asset; the experimental declaration is in the "Wallet (Experimental Track)" section |
| OS keyring escrow entry            | master password in keyring (for biometric unlock)        | Read by a same-user malicious process, stale entries                                      |

## Trust Boundaries

1. **Local user boundary**: the current OS user account is the primary security boundary. Persona must not write plaintext to world-readable paths, nor rely on the cloud for secrecy.
2. **In-process unlock boundary**: the unlocked master key and partial plaintext must exist only on short-lived in-memory paths; on lock, service state must be cleared.
3. **Workspace boundary**: SQLite, attachments, and configuration files belong to the same local workspace; migrations must stay backward-compatible and least-privilege.
4. **Browser bridge boundary**: the browser extension invokes `persona bridge` over Native Messaging; sensitive operations must pass pairing, HMAC, short-term session, origin binding, and user gesture.
5. **SSH Agent boundary**: OpenSSH clients request signatures over a socket/pipe; the agent exposes only public-key listing and signing capability, never exports private keys.
6. **Optional server boundary**: server/sync may handle only event digests, ciphertext, or sync metadata; it must never become the plaintext decryption party. The landed events API receives only audit event digests (action, resource type, optional ID, timestamp, success flag, and bounded metadata), authenticated by Bearer token (multi-device tokens or the legacy single token), and is fully disabled when no token is configured (fail-closed). The backup custody endpoint (2026-09) stores only client-encrypted PERSENC1 ciphertext and metadata; restore requires two factors — the backup passphrase + the master password. See the "Backup Custody Endpoint" section.
7. **Automation boundary**: non-interactive mode allows injecting the master password via environment variable, which suits CI, but the caller is responsible for isolating and clearing that environment variable.

## Principal Threats and Controls

| STRIDE               | Threat                                                | Existing controls                                                                                              | Still needs attention                                                |
| ---------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Spoofing            | A malicious browser extension impersonates a paired client | Pairing code, `client_instance_id`, short-term session, HMAC-SHA256 request authentication                    | Pairing state file permissions and revocation UX need ongoing review  |
| Spoofing            | SSH connection target host impersonated                    | known_hosts forced mode, unknown-host confirmation, per-host policy                                          | known_hosts parsing needs retesting as OpenSSH formats evolve       |
| Tampering           | Local SQLite or configuration tampered offline             | AES-GCM authenticated encryption protects credential ciphertext; migration tests cover schema                | Plaintext metadata and audit logs can still be modified by a local attacker |
| Tampering           | Import files or Native Messaging messages crafted as malicious input | JSON parsing, length-prefixed protocol, format-parser tests and fuzz paths                          | New parsers must be added to the fuzz list                         |
| Repudiation         | User denies a sensitive operation                          | Audit records identity CRUD, credential decryption, export, SSH signature digests                        | The audit log is not currently a tamper-evident ledger                |
| Spoofing (wallet)   | Address poisoning: history lures copying a forged address  | Desktop confirmation-panel heuristic alerts + mandatory backend check at signing entry points (CLI/desktop; an unconfirmed hit refuses to sign — see the "Wallet (Experimental Track)" section) | Heuristic false positives/negatives need real-world samples; no hardware wallet |
| Repudiation         | Client forges/replays audit events reported to the server  | The server explicitly claims no non-repudiation; the events API is aggregation-only observability (single Bearer token gate, `client_event_id` idempotent dedup) | Per-client device identity and non-repudiation (SRP/event signing) deferred to the sync track |
| Information Disclosure | Workspace files copied and attacked offline            | Argon2id/PBKDF2 derivation, AES-256-GCM, per-item key wrapping                                             | Master password strength remains the core risk; KDF parameters need periodic review |
| Information Disclosure | Browser background page quietly reads passwords/TOTP   | user gesture, origin binding, active-identity filtering, return only matching credentials                    | Credentials without a URL cannot be origin-bound; the UI/CLI should surface this risk |
| Information Disclosure | Logs leak secrets, tokens, verification codes         | Log redaction policy and unit tests cover common secret/key/value shapes                                   | New log fields must first be confirmed plaintext-free             |
| Denial of Service   | Agent flooded with signature requests or resource exhaustion | Global minimum interval, per-hour/per-day limits, per-key/per-host policy                                   | Long-running agents need real-machine stress tests                 |
| Elevation of Privilege | A low-trust automation script borrows the unlocked state to run sensitive ops | Auto-lock, sensitive-operation re-authentication, explicit env switch for non-interactive mode           | The unlocked state is a high-risk window; desktop wiring must avoid implicit authorization |

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

SRP-6a (RFC 5054 4096-bit group + SHA-256) device login: the client pre-hashes the master password locally with Argon2id to derive the SRP private key, and the server stores only the verifier (`auth_devices` table: device name, salt, verifier — the password and the Argon2-derived value never leave the device). Design in
预 hash 主密码派生 SRP 私钥，服务器只存 verifier（`auth_devices` 表：设备名、
`docs/E2EE_SYNC_DESIGN.md` DR-2.
`docs/E2EE_SYNC_DESIGN.md` DR-2。

- **Data scope**: persisted data is only device name + salt + verifier (uploaded at registration via the existing Bearer — the bootstrap chain); pending handshakes (session_id, server ephemeral private key, client public value, TTL 120s), issued short-term tokens (TTL 15 minutes), and failure counts are **all in-memory and deliberately not persisted** — a server restart invalidates all of them (fail-closed, re-login required).
- **Authentication**: `/register` requires an existing Bearer (a static token or an already-logged-in SRP token); `/challenge` and `/verify` are Bearer-free (they are the login steps that exchange for a token) and pass on the SRP proof alone; issued tokens are random ≥256-bit base64url, and `require_bearer` prefers the static token, falling back to the SRP token table on a miss — **the TOKENS Bearer path is preserved in coexistence so the backup chain is not interrupted**. With the auth system unconfigured (no TOKENS), all three endpoints return 503 (same fail-closed as events/backups).
- **Brute-force and abuse mitigation**: Argon2id pre-hash (v19, m=19 MiB, t=2, p=1 — the argon2 crate defaults, same family as the local password-verification hash; the local vault unlock is a separate PBKDF2-600k path (`core/src/crypto/keys.rs`, iteration count persisted per vault in `user_auth.kdf_iterations`), a different algorithm and parameters — see `KEY_HIERARCHY.md`; domain-separated salt `persona-srp-v1`) makes the offline guessing cost after verifier exposure ≈ Argon2 cost; five consecutive verification failures lock for 15 minutes (aligned with local user_auth semantics, returning 423); a challenge is single-use (verify takes it from the cache) + 120s TTL; a nonexistent device name and any handshake failure return an identical 401 (does not expose registration state); M1/M2 bidirectional proof verification (the client verifies M2 against malicious-server/MITM downgrade). The `/auth` sub-route has an overall 64 KiB body limit, and base64 fields have per-field byte decode limits.
- **Explicitly not claimed**: does not protect against a server operator **offline brute-forcing the verifier in the `auth_devices` table** (the verifier is in the server's hands; cost = Argon2 + master password strength — same class as the local vault being dragged off, and master password strength remains the core risk); does not protect against **unauthenticated challenge flooding** (the in-memory session cache has no rate limit — a known DoS surface, mitigated by a deployment-side reverse proxy); does not protect against the server **refusing service / deleting registration records** (a device has no second copy; simply re-register, but this is an availability loss); the SRP math is implemented inline in `core/src/auth/srp.rs` (the RustCrypto `srp` crate was not adopted due to digest-ecosystem drift and is no longer a dependency) — the implementation is pinned by RFC 5054 official test vectors, with a seam isolated so it can be swapped.
- **Known limitations**: device revocation/removal has landed (2026-09 revocation closed loop): revoking a synced device (`DELETE /sync/devices/:id`) cascade-deletes the same-named `auth_devices` row (SRP registration is keyed by device name) and immediately revokes its in-memory short-term token and pending handshake (`SrpAuthState::revoke_device` — a revoked device's existing credentials no longer work, pinned by real TCP tests); but the revocation granularity is the **device** — there is no independent "revoke the token only, not the device" operation, and a token leaving the device still expires naturally by TTL (15 minutes); no audit beyond the change threshold — registration/login appear only in server logs (`tracing`), not in the event store.

## E2EE 同步中继（`/api/v1/sync/*`，2026-09，E2EE 同步轨道阶段 2）

设备间端到端加密同步的密文中继：oplog（逐条 `SyncOp`：item UUID、kind、
`(lamport, device_id)` 排序键、密文载荷）按到达顺序追加、按游标转发；
group key 以「设备信封」形态保管（X25519 静态公钥密封 + AES-256-GCM，
`persona-dev-env-1`）。服务器是**纯中继**：盲存、追加、转发，不做任何
胜负判定或合并。设计见 `docs/E2EE_SYNC_DESIGN.md`（DR-1/3/4），服务端
可见面清单见其 §9。

- **信任根**：主密码（仅本地，从不外发）+ 每设备 X25519 私钥（DR-1，持久化由宿主负责——OS keyring / 0600 文件，core 不依赖 keyring）。服务器没有任何解密路径：不见 group key 明文、不见 per-item key，只有密文与元数据（集成测试 `server_stores_only_ciphertext` 锁定）。
- **数据处理范围**：oplog 行（op_id/item_id/kind/op/lamport/device_id/timestamp + 密文两列，单批 ≤500 条、载荷 ≤512 KiB、body ≤1 MiB）、设备登记（设备名 + 32 字节 X25519 公钥，重名 409——公钥不可被静默替换）、信封（80 字节，**只能挂已登记设备**——信封不能挂幽灵设备，服务器侧 fail-closed 的一半）。**诚实登记的元数据侧信道**：服务器可观察条目数量、尺寸、到达时间与设备拓扑——不缓解（by design，密文长度不可避免）。
- **冲突由客户端裁决**（DR-4）：胜负以 `(lamport, device_id)` 全序由各客户端独立计算（同 item 同 lamport 异 device = 真冲突，保双版本等用户裁决）；服务器按到达顺序存储转发，`server_does_not_arbitrate_conflicts` 与双端收敛测试 `two_devices_converge_over_real_tcp_conflict_keeps_both_versions`（真 TCP，双端离线编辑真冲突 → 两端收敛同一主位 + 双版本密文都在）锁定该语义。
- **认证与授权**：整个子路由挂 `require_bearer`（静态令牌与 SRP 短期令牌共存，同 events/backups）。授权语义 = **「有信封 = 已授权」，由密码学而非服务器 ACL 承担**：未授权设备 GET 拿得到别人的信封，但无对应私钥则 GCM tag 校验必失败——拿不到 group key 也解不开任何条目（`group_key_envelope_round_trip_and_fail_closed` 锁定）。
- **明确不宣称**：不防服务器篡改/回滚/选择性扣留 oplog（「设备私钥签名 oplog」是设计稿 §11 开放问题 6，远期）；不防恶意服务器/客户端无限灌 oplog（批内上限只缓解量级，不根除）；**本阶段不校验 op.device_id 与认证身份的对应**（静态 token 与 SRP token 混用，无统一映射）——恶意客户端可向 oplog 写任意密文垃圾或伪造更高 lamport 的假版本，但解不开任何条目，也删不掉其他设备的本地库（本地优先：服务器永远不是事实源，伪造版本在正常设备上同样进 LWW、不覆盖其本地明文库）。设备被攻破的爆炸半径 = 该设备私钥 → group key → 全部同步数据，与「本机被攻破 = 本库全失」同级，不因同步而放大额外资产。
- **已知限制**：附件不经 oplog（512 KiB 载荷上限；v2 议题）；travel 激活期间 push/pull 双停是**客户端引擎闸**（`SyncEngine` 构造注入，服务器无感知）——闸失效的后果是 travel 语义被同步破坏，属阶段 3 接线时的走查项；group key 轮换已实现（2026-09 阶段 3d，桌面「轮换组密钥」）但**吊销 ≠ 轮换**：只吊销不轮换时历史密文仍可被被移除设备移除前的密钥解开（**无前向安全**，DR-3 诚实边界；轮换后新密文对该设备不可读，窗口内未推送的旧密文除外——用户文档与确认弹窗均如实提示）。**并发轮换以 epoch 乐观锁互斥**（2026-09-24，`rotate-begin` CAS）：只防诚实客户端的意外并发——后到者 409 中止、未写信封未重包；**不防恶意客户端**绕过 begin 直接写信封/重包 op（写入真实性属「设备私钥签名 oplog」远期边界，本阶段登记的「不校验 op.device_id 与认证身份」同族）。oplog 无限增长已由保留策略缓解（2026-09-24：客户端 GC + `PERSONA_SERVER_OPS_RETENTION_DAYS`，§11 开放问题 3 两端收口；默认 0 = 不清理，开窗即放弃向离线超窗设备补发历史的责任）。

## Travel Mode（travel.persenc sidecar，2026-09）

按 identity 粒度的"从本设备移除"：enter 把被标记身份的全部数据（含附件密文
文件字节）打包 gzip 后按 PERSENC1（独立 travel 口令，Argon2id 64 MiB 默认
参数）加密为 `<db dir>/travel.persenc`，再在单事务内从主库删除——主库零痕迹，
**主密码打不开 sidecar（by design，非缺陷）**；exit 输 travel 口令原样恢复。
该设计引入新的单点资产与新的丢失面：

- **口令强度自担**：sidecar 只有一个口令保护，强度完全由用户承担；口令丢失
  = 被移除身份永久不可恢复（无托管、无重置、无主密码回退）。UI/CLI 在
  enter 时明示"no master-password fallback"。
- **sidecar 删除 = 数据丢失**：travel 激活期间（`travel_mode=true`）手删或
  介质损坏丢失 sidecar 即数据永久丢失。status 命令与桌面设置页以
  `inconsistent` 红色警告诚实呈现（不假装可恢复），不做任何自动清理。
- **本机攻击者可删 sidecar（拒绝服务，接受）**：同 OS 用户进程对
  sidecar 文件有写权限即可销毁被移除身份的唯一副本。不宣称防本机攻击者
  破坏数据（与"恶意进程可读 keyring"同一信任边界）；恶意进程同样可删主库，
  travel mode 未新增该边界，只是把丢失面集中到一个文件。
- **加密面**：sidecar 密文对持有设备者、云同步目录、USB 拷贝均不泄露明文
  （与整库备份同一 PERSENC1 格式）；崩溃窗口语义——sidecar 写成功后才动库，
  4→5 之间崩 = sidecar 在但旗标 false（enter 拒绝，提示 exit 或删残留），
  5→6 之间崩 = exit 自愈覆写。
- **改密互斥**：travel 激活期间拒绝改主密码（sidecar 无主密码绑定，改密
  本身不破坏 sidecar，但为避免"激活期间密钥材料语义漂移"的全部组合证明，
  直接拒绝并返回 `TRAVEL_MODE_ACTIVE`，exit 后可改）。
- **运行态清理**：desktop enter 成功后停 SSH agent（agent 内存可能持有被
  移除身份的密钥）；audit_logs 只保留 id 引用（明文元数据随 change_history
  一并搬入 sidecar，主库不留可读残留）。

## Biometric Unlock（桌面指纹/生物识别解锁）

桌面端把主密码托管进 OS 钥匙串，用系统认证框（Linux polkit `auth_self` /
macOS LocalAuthentication `DeviceOwnerAuthentication` / Windows Hello）换取
免输主密码解锁。**该设计把"知道主密码"降级为"能通过 OS 用户认证"**，
新增资产与威胁面在此白纸黑字：

- **资产**：keyring（Linux secret-service `persona-biometric` service /
  macOS Keychain / Windows Credential Manager）中按 vault db_path 为键存的
  主密码明文。
- **固有暴露（接受）**：**同 OS 用户的任意进程可读 OS 钥匙串**——
  Linux secret-service 对同会话进程基本不设防；**Windows Credential
  Manager 无 per-entry ACL，同用户任意用户态进程可直接读取**。这是
  1Password 同款直存设计的固有代价：本机用户边界一旦被攻破（恶意软件
  以当前用户运行），托管的主密码即泄露。缓解只有"用户级前置防线"
  （OS 用户认证、应用来源管控）；对抗该场景需要专用硬件（TPM/SEP
  绑定 + ATTCK 级进程隔离），超出本设计范围。
- **生物路径爆破**：biometric_unlock 取回密码后走 `authenticate_user`
  本尊，**吃与密码路径共享的失败计数**（5 次锁户）。控制：条目不存在
  时干净报错不弹框；InvalidCredentials 当场自删条目并返回
  `BIOMETRIC_RESET`（防反复点指纹把账户锁死）。
- **陈旧条目**：桌面外改密（CLI）覆盖不到 keyring 联动——InvalidCredentials
  自删（上一条）即兜底；桌面内改密成功则同步更新条目，写失败即删
  （fail-closed：宁可让用户重输密码，不留打不开库的旧密码）。
- **系统弹窗仿冒**：任何进程都能请求 OS 认证框，用户无法从框本身分辨
  是谁发起。缓解：action id/message 固定为 Persona 专属
  （`com.persona.desktop.biometric-unlock`）；polkit subject 用
  system-bus-name（bus daemon 解析对端凭据，免疫 PID 复用类缺陷，
  规避 zbus_polkit <5.1.0 的 CVE-2026-78422）。
- **可用性 fail-closed**：无 fprintd/polkit agent、无 secret service、
  rpm/AppImage/dev 构建未装 action 文件 → availability 探测失败即整体
  降级为不可用（按钮不渲染），不做半开半关。
- **超时**：ceremony 专用线程 120s 超时 + macOS 内层 reply 等待 110s，
  弹框卡死不拖死 UI 线程。
- **enable 门禁**：先验主密码后弹 OS 认证框——绝不把未验证的密码写进
  keyring；enable 走解锁门禁（同 set_locale），disable 幂等删且不设门禁
  （收紧操作从宽）。
- **SSH agent 联动**：agent 的 require_biometric 策略默认拒绝 + 显式注入
  OS provider（消除内置 Mock 静默放行面）。
- **硬件绑定包裹层（2026-09-26，`docs/biometric-unlock-design.md`）**：
  门禁层之上的升级档——keyring 新增 `persona-biometric-wrap` service，
  存的是被平台硬件密钥包裹的**密文 blob**（BIOWRAP1 信封），与门禁层
  密码条目互斥。T1（同用户恶意进程读 keyring）在此档下只能拿到打不开
  的密文：解密必须过硬件认证（SE/TPM/Keystore），私钥永不导出。
  剩余威胁面：enrollment 漂移（换指纹）→ 解包失败即自动删 blob 回主密码
  （core 信封指纹二次比对纵深防御）；改密后旧 blob 包的是 stale key，
  桌面改密联动当场删除；`BIOMETRIC_CANCELLED` 不删 blob（取消≠失败）。
  Linux 定格门禁档（无硬件封装），macOS/Windows 硬件档待真机 spike 验证前
  默认不启用——未验证的路径不在生产 unlock 链上。CI 侧实测
  （2026-09-26，desktop-build macos runner）：VM 无 Secure Enclave，
  spike 探针 1 即失败（`os_status=-25293` `errSecAuthFailed`，无签名
  entitlement）——坐实「runner 输出不构成 SE 行为证据」，真机 spike
  仍另行待办。
- **Windows 注册集漂移无平台语义（2026-09-26，接受）**：macOS 的
  `biometryCurrentSet` 会在换指纹后让旧 SE 密钥永久失效；**Windows 没有
  对应机制**——`NCRYPT_UI_PROTECT_KEY_FLAG` 只强制"每次私钥使用都要用户
  验证"，换一枚已注册的新指纹验证，旧包裹照样解开。因此
  `enrollment_fingerprint()` 在 Windows 只能返回占位值，core 的第二道
  比对也是空的。残余风险：本机登录态被攻破后，攻击者若能完成**一次**
  Windows Hello 验证（已注册过任一指纹或 PIN）即可解开旧包裹——
  "换指纹即失效"的反胁迫性质在 Windows 上不成立。缓解：主密码兜底 +
  keyring 里只有打不开的密文。设计稿 `docs/biometric-unlock-design.md`
  §6.2 有完整登记。

## Quick Access（OS 级全局热键 + 检索浮窗，2026-09，对标 #22）

进程级抢注一个全局热键，任意应用中唤出无边框置顶浮窗做跨身份检索与
取件（复制主密文 / 用户名 / TOTP，或把条目送回主窗口打开）。它在
**暴露面上等价于「把已解锁的检索与复制能力搬到一个不用先点 Persona 图标
的位置」**，新增威胁面：

- **可见面扩大（固有，接受）**：热键唤起不再需要先聚焦 Persona 窗口，
  条目名/用户名的检索结果会在浮窗里直接呈现给任何旁观者（肩窥面）。
  缓解：浮窗失焦即自收尾（不驻留）、Esc 即收、锁户时立刻隐藏、锁定态
  根本不检索。与 1Password Quick Access 同边界。
- **解锁态门禁不变**：浮窗的检索/复制全部经已解锁的 `PersonaService`，
  命令层与主窗口同一套门禁（`SERVICE_LOCKED` 直接拒、敏感字段走
  `reveal_credential_secret` 的 reauth 门禁 + 审计）。**锁定态不复制任何
  东西**——浮窗只提示去主窗口解锁（刻意不在 620×460 的小窗里复刻解锁
  流，理由见 `quick_access.rs` 模块注释）。
- **剪贴板**：复用既有 `copyWithAutoClear`（30s 自动清空），与凭据列表/
  生成器同一条路径，不新增剪贴板暴露时长。
- **热键抢注不是提权面**：绑定串存在 workspace settings（明文，无密钥），
  抢注失败/被占用只影响可用性。设置页把「配置」与「实际生效」分开显示，
  **失败不静默**（含后端原文原因）。
- **插件装载 fail-open 到「不可用」而非崩溃**：global-shortcut 插件在
  `setup` 里运行时装载（不进 `Builder::plugin` 链）——它的 setup 在
  headless Linux / 无 XWayland 的 Wayland 上会失败，走 Builder 链会让整个
  app 构建失败。一个可选增强项的缺失绝不能让密码管理器起不来；失败原因
  记入运行态并在设置页显示。
- **不宣称**：热键无法区分「用户按的」与「同用户恶意进程模拟的输入事件」，
  这与 OS 快捷键同边界；浮窗不做浏览器自动填充（填充归浏览器扩展），
  故不引入「按键即向任意页面交付凭据」的路径。

## Connect 本机自动化端点（`127.0.0.1` HTTP，2026-09，secrets automation）

桌面宿主进程内嵌 axum listener（DR-1），让本机脚本/工具按 token 范围只读
拉取凭据。**开关默认关闭**：不创建 listener 即无端口面；启用时 bind 硬编码
loopback、端口由 OS 分配（无配置面，不可被诱导监听 0.0.0.0）。新增威胁面：

- **信任根与可见面**：解锁态 + token 二元门禁（缺一即拒）。token 决定
  「哪个身份下的哪些类型」；scope 外条目 404 与 403 同形（对消费者不存在，
  防探测）。health 免认证但零信息（不报解锁态、不报库存在性）。
- **不宣称**：防本机恶意进程——token 交到它手里的那一刻（环境变量/参数/
  配置文件）就对它可见，与 1Password CLI 同边界；防宿主进程被攻破——
  automation 不扩大也不缩小该边界；多用户 OS 隔离（同既有口径）。
- **恶意网页三防线**（DR-4）：浏览器是 127.0.0.1 上唯一"陌生调用方"，
  三道独立防线各自 fail-closed——① Host 头白名单（仅
  `127.0.0.1`/`localhost`/`[::1]`），DNS rebinding 后 Host 是攻击域，
  421 拒绝；② 请求带 `Origin` 头（浏览器 fetch 的标记）即 403，CORS
  全关（不回 `Access-Control-Allow-*`，preflight 直接失败）；③ Bearer
  token 必需，缺失/未知/已吊销同形 401。恶意网页同时需要绕过全部三道
  才能触达数据，而 token 本身不在网页可及处。
- **已知残面（文档禁止此用法）**：若用户把明文 token 配置进**浏览器
  扩展可及的存储**（localStorage、扩展 settings），上述三防线对持有该
  token 的网页形同虚设——防线防的是"无 token 的网页"。设置页明文展示
  处的警示只说明一次性，不改变此边界。
- **token 泄露爆炸半径**：三维 scope 圈定的**只读**面（verbs 恒 read，
  无写路径 = 无篡改半径）+ 即时吊销（无缓存，下一请求即 401）+ audit
  可见（Used 走每 token 每分钟节流聚合）。token 只存 SHA-256 哈希，
  库/备份泄露不等于 token 泄露；明文 `pconn_` 前缀 + 32B 随机，离线
  不可爆破。passkey/wallet/ssh/custom 类型恒不可授权（词汇表层面不存在）。
- **管理面**：创建/吊销走 reauth 门禁（core `ensure_sensitive_operation_allowed`
  权威）；明文只在创建响应出现一次；锁定态管理动作先被敏感门禁拒绝。
- **DoS / 资源面**：每 token 每分钟 120 请求 429 上限（写死），保护宿主
  不被自动化消费者拖垮；锁定期间 503 `vault_locked` 且**不扣限额**；
  health 不占限额。listener 占用面极小（loopback 单口），仅解锁态返回
  数据，锁定 503。
- **吊销与审计**：吊销即时幂等；`ConnectTokenCreated/Revoked/Used` 三
  audit 动作入审计日志；创建/吊销记录 resource_id，不落 token 明文。

## 钱包（实验轨道）（M5，2026-10-13，wallet graduation）

BTC（BIP-143 P2WPKH）/ ETH（EIP-155/1559）/ Solana 派生与签名已落地（官方
向量回归），CLI 与桌面端钱包流程可用。但钱包密钥（BIP39 助记词与由其派生的
私钥/xprv）是**最高级资产**：丢失不可逆（无私钥即永久失款）、无争议/回滚
机制。**实验轨道声明：本节不享受主线安全承诺，不能用于生产级资金安全**——
与「非目标」第 4 条、「当前接受的限制」最后一条同口径；毕业（毕业条件与
硬件钱包等开放问题）见 [WALLET_DESIGN.md](WALLET_DESIGN.md)。

**密钥层级与口令隔离**（详见 WALLET_DESIGN.md §2/§3）：助记词与 xprv **双
包装**（Argon2id + AES-256-GCM，同一钱包口令、各自独立 salt/nonce，都能独
立解锁），任一损坏另一份可恢复全部地址。钱包口令**独立于主密码**，主密码
轮换**不动** `crypto_wallets`——主密码泄露不等于资金材料泄露（爆炸半径隔
离）。现有 `persona wallet passwd` 前的暴露面：`change_wallet_password` 已
存在但无生产调用方，文档已定案补命令与 `EncryptedMnemonic` 重包路径。

| 威胁面                           | 威胁                | 已落地控制                                                                                                                                                                                                                                                                                                               | 仍需关注                                                                           |
| -------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| 导出面（keystore/WIF/明文 JSON） | 导出文件被复制/外泄 | 导出需钱包口令；keystore v3 = geth 标准（scrypt/pbkdf2 + AES-128-CTR + keccak MAC，导入 256MiB 内存上限 + 常数时间 MAC 比较，规范向量钉版）；CLI 与桌面端 import/export 均支持 keystore（2026-10-13）；导出经审计                                                                                                        | 助记词/mnemonic 导出是最强面，审计只记动作不记内容                                 |
| 存储面                           | 钱包密文离线破解    | 与凭据同参数（Argon2id 默认参数不落盘；version=1，参数升级走 version=2 + 惰性重包，禁止原地改默认）                                                                                                                                                                                                                      | 参数复审节奏同主线；重包迁移未落代码                                               |
| 签名面                           | 伪造/投毒交易被签   | 签名先验证后持久化（ETH/Solana 本地验签，失败不落库；BTC 组装失败降级仅审计，绝不产出可广播假象）；后端防投毒强制（2026-10-13）：core 启发式（首 6 + 末 6 字符）在 CLI 与桌面签名入口强制，命中未确认即拒签（CLI `--confirm-poisoning-check` / 桌面二次确认 ack）；口令不落日志；确认面板必列 from/to/金额/费用/chain id | 已知地址集合目前 = 钱包全部地址，「+ 用户标记」开放；无硬件钱包，签名口令=钱包口令 |

**签名确认 UX 不变量**（后端强制、UI 只是展示层；WALLET_DESIGN.md §5）：
先验证后持久化、确认面板必列字段（缺项不允许提交）、口令在面板内输入且
不落日志、审计记 digest 级摘要。Context 建议轨道**不作用于钱包**——
suggest 候选是分身不是钱包，钱包选择永远显式。

**变更门槛**：钱包密钥类型、导出格式、签名算法、确认字段的任何变更，都
按「变更门槛」第 1/2/5 条显式更新本节与 WALLET_DESIGN.md，并在 PR 中说
明对爆炸半径与恢复路径的影响。
