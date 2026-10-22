# Core Features

Persona's feature surface revolves around one principle: **sensitive data is decrypted only
on your devices**. Below is the list of currently implemented capabilities — we make no
claims about unimplemented features; planned work lives in the
[roadmap](https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md).

## Credentials and Identity Vaults

- **Vaults isolated per identity**: passwords, TOTP, API keys, SSH keys, tags, and security
  metadata, with an independent view per identity.
- **Item history** (1Password-style): every create/modify/delete is timestamped and
  traceable.
- **Dual-version conflict retention**: concurrent offline edits to the same credential from
  multiple devices are never overwritten or lost; you pick which version to keep in the
  resolution UI.
- **Import/export**: JSON / YAML / CSV with optional gzip compression and passphrase
  encryption (Argon2id + AES-GCM).

## Developer Tools

- **Built-in SSH Agent**: SSH keys are hosted and signed by Persona, and signing events go
  into the audit log.
- **CLI**: scriptable credential CRUD, import/export, and workspace management (see
  Get Started).
- **Connect automation API**: a local HTTP service that lets scripts and tools read
  credentials, with passphrase protection and one-time plaintext display.

## Browser Extension

- Autofill and suggestions: form detection and per-site identity defaults.
- Phishing protection and domain policies: fill is refused when the site domain does not
  match.

## Security Foundation

- **Local encrypted storage (zero-knowledge storage semantics)**: a key derived from the
  master password (Argon2id) encrypts the whole SQLite database; a lost master password
  cannot be recovered by any means.
- **Auto-lock and re-authentication for sensitive actions**: locking drops the keys;
  actions like revealing stored credentials or changing the master password require
  re-authentication.
- **Travel mode**: proactively strips local key material for extended offline periods.
- **Audit log**: critical operations and signing events (with digests) are recorded
  locally.
- **Reproducible builds**: deb artifacts are byte-for-byte reproducible on the same
  machine, with the build container pinned (see
  [REPRODUCIBLE_BUILDS.md](https://github.com/cuihairu/persona/blob/main/docs/REPRODUCIBLE_BUILDS.md)).

## Sync and Backup (All Optional)

- **Fully local by default, zero network** — with no server configured, nothing phones
  home.
- **Sync group pairing** (the default sync path): dynamic passwords + PAKE pairing into a
  group, with zero accounts and zero registration; both ends verify a 6-digit numeric
  fingerprint to prevent man-in-the-middle attacks; the group key never leaves the device.
  Implemented at the protocol level (show-code/enter-code pairing can be started from the
  desktop settings page).
- **End-to-end encrypted sync** (account-based, explicitly enabled): a self-hosted Persona
  Server relays an encrypted operation log, so the server sees only ciphertext and
  metadata; group keys are rotatable (concurrent rotations are mutually excluded with an
  optimistic lock).
- **Backup**: encrypted export files (with a passphrase independent of the master
  password); self-hosted users can keep full-vault snapshots off-site.

For boundaries and the threat model, see
[THREAT_MODEL.md](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md).
