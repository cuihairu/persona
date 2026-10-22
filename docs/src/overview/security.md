# Security

Persona's security model centers on local-first operation and end-to-end encryption (the
server sees only ciphertext and metadata and cannot decrypt credentials): sensitive identity
material is stored encrypted locally, and the CLI, desktop app, browser extension, and SSH
Agent all perform unlocking, auditing, and policy checks through the same core service. For
the full threat model, see
[Threat Model and Periodic Security Reviews](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md).

## Core Protections

- **Local encryption**: credential plaintext is encrypted with AES-256-GCM; new credentials
  get an independent item key wrapped by the master key, limiting the blast radius if a
  single item key leaks.
- **Identity-context isolation**: identity material such as credentials, TOTP, and SSH keys
  is bound to a specific identity; browser suggestions and autofill are filtered by the
  active identity by default.
- **Unlocking and auto-lock**: the core service supports master-password unlock, auto-lock,
  re-authentication for sensitive actions, and a biometric provider abstraction.
- **Browser bridge protection**: the Native Messaging protocol requires pairing,
  short-lived sessions, HMAC request authentication, origin binding, and user gesture, so
  background pages cannot silently read credentials.
- **SSH Agent policies**: the Agent supports known_hosts, deny-all, rate limiting,
  per-key/per-host policies, confirmation prompts, and biometric precedence.
- **Auditing and redaction**: identity operations, credential decryption, exports, and SSH
  signatures are written to a local audit log; redaction tests cover common secrets, tokens,
  and verification-code patterns.

## Default Security Boundaries

- The current OS user account is the primary local boundary; Persona does not defend
  against malware that has already fully compromised that account or the kernel.
- The optional Server/Sync may only handle ciphertext, event digests, or sync metadata; it
  must never become a plaintext decryptor.
- Non-interactive mode allows injecting the master password via environment variables,
  which suits CI, but callers must use a secret store and keep it out of log output.
- Browser credentials without a URL cannot be strictly origin-bound; always set a URL for
  high-value credentials.

## Review Requirements

Before every release, the Rust/frontend tests and supply-chain audits must run, and new
logging, audit metadata, browser bridge changes, and SSH Agent policies must be checked for
expanded authorization of sensitive actions. KDF parameters, master-key migration, backup
encryption, and the threat model are reviewed at least quarterly.
