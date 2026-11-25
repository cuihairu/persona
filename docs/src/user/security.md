# Security Design

**In one sentence**: persona is a local-first, zero-knowledge identity
manager — credential plaintext exists only on your device (AES-256-GCM
encrypted), the optional server may touch ciphertext or digests only and
never decrypts; the current **OS user account is the primary local
boundary**, and risks outside that boundary are stated plainly rather than
promised away.

This page is the **user-level integration guide**: what is protected, where
the boundaries sit, how threats are controlled, and what protections wrap a
credential from storage to use. The full threat model and engineering detail
live in the "Deep dives" links at the end.

## What is protected (assets)

| Asset                        | Risk                                                                             |
| ---------------------------- | -------------------------------------------------------------------------------- |
| Master password & master key | Leakage decrypts the whole local workspace                                       |
| Per-item key (item key)      | Single-item plaintext leak or lateral expansion                                  |
| Credential plaintext         | Password / API key / TOTP / SSH key exfiltration or misuse                       |
| Workspace database           | Offline brute force, tampering, rollback                                         |
| Browser bridge sessions      | Malicious extensions requesting fill or copy                                     |
| SSH Agent socket/pipe        | Unauthorized signing, agent-forwarding abuse                                     |
| Audit logs                   | Tampering, deletion, sensitive fields leaking in                                 |
| Backup / export files        | Backup leakage, weak passphrases                                                 |
| Wallet keys (experimental)   | Irreversible loss, address poisoning — not covered by mainline security promises |

## Trust boundaries

1. **Local user boundary**: the current OS user account is the primary
   boundary; persona does not defend against malware, kernels, or debuggers
   that already fully control that account.
2. **Unlock boundary**: unlocked master keys live only in short-lived memory
   and are cleared on lock.
3. **Browser bridge boundary**: extensions call in over Native Messaging;
   sensitive operations must pass pairing, HMAC, short-lived sessions,
   origin binding, and a user gesture.
4. **SSH Agent boundary**: only public-key listing and signing are exposed;
   private keys cannot be exported.
5. **Optional server boundary**: server/sync handles ciphertext, event
   digests, or sync metadata only — it must **never become a plaintext
   decryptor**; with no tokens configured it is disabled entirely
   (fail-closed).
6. **Automation boundary**: non-interactive mode allows injecting the master
   password via environment variables (for CI); callers own isolation and
   cleanup.

## Main threats and controls (STRIDE summary)

| Category               | Representative threat                            | Existing controls                                                                                |
| ---------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Spoofing               | Malicious extension poses as a paired client     | Pairing code + short-lived session + HMAC-SHA256 request auth                                    |
| Spoofing               | SSH target host impersonation                    | known_hosts enforced mode, unknown-host confirmation, per-host policy                            |
| Tampering              | Local vault or config tampered offline           | AES-GCM authenticated encryption; parsers for imports and the bridge have test and fuzz coverage |
| Repudiation            | Denying sensitive operations                     | Audit records identity CRUD, decryption, exports, SSH signature digests                          |
| Information disclosure | Vault file stolen and attacked offline           | Argon2id/PBKDF2 derivation, per-item key wrapping                                                |
| Information disclosure | Browser background page silently reads passwords | User gesture, origin binding, active-identity filtering                                          |
| Information disclosure | Logs leaking secrets / tokens                    | Log redaction policy with unit tests over common secret shapes                                   |
| Denial of service      | Agent flooded with signing requests              | Global minimum interval, hourly / daily limits, per-key / per-host policy                        |
| Elevation of privilege | Low-trust scripts riding an unlocked session     | Auto-lock, re-authentication for sensitive ops, explicit non-interactive env switch              |

## Layered protections

| Layer               | Responsibility                                                         | Key controls                                                                                 |
| ------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Client entry points | CLI / desktop / extension / SSH Agent do interaction and routing only  | No reading or writing sensitive plaintext around core                                        |
| Core services       | The single entry for identities, credentials, unlocking, audit, policy | Auto-lock, re-authentication for sensitive operations, local audit log                       |
| Crypto layer        | Master key derivation, item key wrapping, encrypt / decrypt            | An independent item key per credential; AES-256-GCM authenticated encryption                 |
| Storage layer       | SQLite, attachments, migrations, configuration                         | Backward-compatible migrations, `wrapped_item_key` compatibility, minimal plaintext metadata |
| External interfaces | Native Messaging, SSH Agent, optional server                           | Pairing / HMAC, origin binding, known_hosts, ciphertext or digests only                      |
| Supply chain        | Dependencies, licenses, build artifacts                                | cargo-deny / cargo-audit / pnpm audit in CI; lockfiles committed                             |

## Credential lifecycle

**Storage**: a newly written credential is encrypted with a random item key,
and the item key is wrapped by the master key derived from the master
password (`wrapped_item_key`) — one leaked item key does not spread
sideways. Attachments reuse their credential's item key, so master-password
rotation re-wraps keys only and never rewrites attachment files.

**Unlocking and sessions**: the master password unlocks the vault (PBKDF2
path, iteration count persisted per vault); auto-lock, re-authentication for
sensitive operations (reveal / copy / fill / TOTP), and biometric unlock are
supported. Biometrics downgrade "knows the master password" to "can pass OS
user authentication": the password is custodied in the OS keychain (Linux
secret-service / macOS Keychain / Windows Credential Manager), with an
optional hardware-wrapped tier (BIOWRAP1 — the keychain holds only ciphertext
wrapped by platform hardware keys, unreadable even to same-user malware).
**Honest registration**: in principle any process of the same OS user can
read the OS keychain (Windows has no per-entry ACL) — the inherent cost of
the same direct-custody design 1Password uses; countering it needs dedicated
hardware boundaries.

**Browser fill**: the extension must pair with the host over Native
Messaging first; requests carry HMAC-SHA256 authentication, short-lived
sessions, and replay windows; credentials with a URL get **origin binding**
(mismatched pages get nothing); sensitive operations require a user gesture —
background pages cannot silently read passwords. **Credentials without a URL
cannot be strictly origin-bound** — always set a URL for high-value items.

**SSH Agent**: offers public-key listing and signing only; private keys are
not exportable by default. Policies cover deny-all, known_hosts checks, rate
limits, per-key / per-host allow/deny, signing confirmation, and biometric
precedence.

**Auditing and redaction**: identity operations, credential decryption,
exports, and SSH signatures land in the local audit log; signatures record
digests only; the redaction policy covers common secret / token /
verification-code shapes with tests locking it in. The audit log emphasizes
traceability and is not currently a tamper-proof ledger.

**Backups**: full-vault exports are PERSENC1-encrypted files (Argon2id +
AES-256-GCM); server-side backup custody likewise stores ciphertext only,
and restore needs **both the backup passphrase and the master password** —
losing either loses the backup (no custody, no reset).

## Supply chain security

persona continuously checks its own dependency chain — tools and runbooks in
the [Supply Chain Security Guide](../reference/SUPPLY_CHAIN_SECURITY):

- **CI gates**: `cargo deny check` (RustSec advisories + license allowlist +
  banned dependencies + source checks) and `cargo audit` run on every push /
  PR; the JS/TS side runs pnpm audit reporting moderate-and-above findings.
- **Licenses**: the deny.toml allowlist (MIT / Apache-2.0 / BSD / ISC and
  other permissive licenses); anything unlisted is rejected.
- **Lockfiles**: Cargo.lock and pnpm-lock.yaml are committed (the docs
  sub-site installs standalone with npm); builds are reproducible, and image
  base layers are digest-pinned
  ([Reproducible Builds](../reference/REPRODUCIBLE_BUILDS)).
- **Review cadence**: RustSec and npm audit re-checked monthly; KDF
  parameters, backup encryption, and the threat model re-reviewed quarterly;
  every deny.toml exemption must state its reason in the PR.

## What persona does not do (non-goals)

- No defense against malicious kernels, debuggers, or system-level malware
  that already fully control the current OS session.
- No promise of recovering plaintext when the vault is locked and the master
  password is lost.
- The optional server/sync is not a trust root; the local vault is the first
  source of truth.
- Wallet capabilities are an experimental track without mainline security
  promises — not for production-grade funds.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues.**
The formal SECURITY.md and security contact mailbox are pending (placeholder:
chuihairu@gmail.com; this section will be updated once the mailto channel
exists).

## Deep dives

- [Threat Model and Periodic Security Reviews](../reference/THREAT_MODEL)
  — assets, boundaries, the full STRIDE table, per-endpoint threat
  registrations
- [Supply Chain Security Guide](../reference/SUPPLY_CHAIN_SECURITY)
  — toolchain, license policy, vulnerability handling process
- [Key Hierarchy](../reference/KEY_HIERARCHY)
  — key derivation and wrapping layers
- [E2EE Sync Design](../reference/E2EE_SYNC_DESIGN)
  — keys and threat registrations on the sync path

## Related pages

- [How Sync Works](./sync) — how end-to-end encrypted sync works
- [Security Requirements](../analysis/security-requirements) — the requirements-side constraints
- [Security (Overview)](../overview/security) / [Security Design (System Design)](../design/security)
