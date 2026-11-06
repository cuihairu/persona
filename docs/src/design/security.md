# Security Design

This page describes the security design constraints that Persona's current
implementation is expected to follow. For the fuller treatment of assets, trust
boundaries, and the STRIDE analysis, see the
[threat model and periodic security review](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md).

## Layered Security Boundaries

| Layer               | Responsibility                                                                                 | Key controls                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Client entry points | CLI, desktop app, browser extension, and SSH Agent handle only interaction and request routing | No reading or writing sensitive plaintext around core                           |
| Core services       | The single entry point for identities, credentials, unlocking, audit, and policy               | Auto-lock, re-authentication for sensitive operations, audit log                |
| Crypto layer        | Master key derivation, item key wrapping, AES-GCM encryption/decryption                        | An independent key per credential; authenticated encryption prevents tampering  |
| Storage layer       | SQLite, attachments, migrations, and configuration                                             | Schema migrations, `wrapped_item_key` compatibility, minimal plaintext metadata |
| External interfaces | Native Messaging, SSH Agent socket/pipe, optional server                                       | Pairing/HMAC, origin binding, known_hosts, ciphertext or digests only           |

## Authorizing Sensitive Operations

Sensitive operations must pass through the explicit authorization path — never
rely only on the caller's UI:

- Credential reveal, copy, fill, and TOTP retrieval must verify the unlocked
  state and bind to the active identity wherever possible.
- Browser fill/copy/TOTP must require a user gesture; credentials that carry a
  URL must get origin binding.
- SSH signatures must pass the agent policy check; private keys must not be
  exported by default.
- Exports containing sensitive content must confirm the unlocked state and the
  target encryption policy.
- Non-interactive mode must be enabled explicitly via `PERSONA_NON_INTERACTIVE`
  and the related environment variables.

## Key and Data Handling

- Newly written credentials encrypt their plaintext with a random item key, and
  the item key is then wrapped with the master key.
- The unlocked master key service lives in memory only; its state is cleared on
  lock.
- Backup, import/export, and attachment encryption must use a random
  salt/nonce, and the decryption-failure path must be verified.
- Audit logs may record resource IDs, actions, timestamps, and digests; they
  must never record plaintext passwords, TOTP secrets, SSH private keys, or
  complete to-be-signed payloads.

## Design Constraints

- No new direct storage access paths that bypass the core service layer.
- Never treat the cloud, the server, or the browser extension as a plaintext
  trust root.
- No broad-permission interfaces reserved for future features; any new
  capability must first define its assets, authorization conditions, and audit
  events.
- No real secrets in logs, error messages, test snapshots, or CI output.
