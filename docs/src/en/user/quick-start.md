# Quick Start

Persona is a local-first identity material manager: your vault is **an encrypted
SQLite file on your device**, and every networked capability (sync, audit
copies) is an optional add-on. This page gets you from zero to running.

## Two Ways to Use It

| Path                          | Best for                                                              | How to start                               |
| ----------------------------- | --------------------------------------------------------------------- | ------------------------------------------ |
| **Desktop app** (recommended) | Day-to-day credential management, GUI + browser extension + SSH Agent | Build the deb from source, or run dev mode |
| **CLI**                       | Scripting, servers, terminal people                                   | `cargo build --workspace`                  |

Both share the same local vault format and encryption stack, and you can mix
them freely.

## Desktop App

### Build and Install

```bash
git clone git@github.com:cuihairu/persona.git
cd persona
pnpm install

# Reproducible deb build (about 15-25 minutes, artifact lands in the repo root)
scripts/build-repro.sh
sudo dpkg -i Persona_0.1.0_amd64.deb
```

For development and debugging, just run dev mode:

```bash
pnpm --filter persona-desktop run dev
```

> For build details and the byte-for-byte reproducibility contract, see
> [REPRODUCIBLE_BUILDS.md](https://github.com/cuihairu/persona/blob/main/docs/REPRODUCIBLE_BUILDS.md).

### First Run

1. Launch Persona, **create a vault** and set a master password — the master
   password derives the encryption key, and the vault file is encrypted on disk
   at all times. **A lost master password cannot be recovered** (there is no
   back door), so commit it to memory.
2. Add credentials in the main window (passwords, API keys, TOTP, etc.);
   sensitive fields are masked by default.
3. Locking drops the key: after lockout the master key does not stay in memory,
   and unlocking requires re-entering the master password.

## CLI

```bash
# Build the CLI and SSH agent
cargo build --workspace

# Initialize an encrypted workspace
persona init --path ~/Persona --yes --encrypted --master-password "your-master-password"

# Identities and credentials
persona add                      # add an identity
persona list                     # list identities
persona switch <name>            # switch the active identity
persona credential add --identity alice --name "GitHub" \
  --credential-type password --prompt-secret
persona credential list --identity alice --format table
persona credential show --id <UUID> --reveal
```

Every entry keeps history (1Password-style): each create, update, and delete is
recorded with a timestamp and can be traced back.

::: tip What an identity actually is
An "identity" is a **grouping unit** for credentials — not an account, and not
an encryption boundary. Switching identities does not change the master
password, does not re-lock the vault, and does not alter the encryption
hierarchy. It is also the smallest unit a travel-mode bundle packs (the whole
set travels together), and the carrier for the "current identity" pointer
shared across devices. For the full semantics, see
[Identity](./identity).
:::

## Backups (do this right now)

Outside the primary vault, the **encrypted export file** is the only recovery
path — a lost master password or a corrupted vault file has no other way back.
The backup passphrase is independent of the master password:

```bash
persona export --encrypt --out vault-backup.persenc   # encrypted export
persona import vault-backup.persenc --decrypt --mode merge --backup   # restore
```

Self-hosted server users can additionally run `persona backup push` to keep an
off-site snapshot of the whole vault. For the full walkthrough (including the
cloud-drive cold-storage warning and restore semantics), see
[the backup section of STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md).

## Optional: Multi-Device End-to-End Encrypted Sync

By default Persona is **purely local, zero network**. To sync credentials
across devices:

1. Self-host a Persona Server (Docker image; the server only ever sees
   ciphertext);
2. On the desktop, go to "Settings → Sync Devices", join, and authorize each
   device one by one.

Concurrent offline edits to the same credential never lose data (both versions
are kept and you decide). For deployment steps, honest boundaries, and conflict
adjudication, see
[STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md).

## Next Steps

- [Project introduction](/en/overview/introduction) — problem boundaries and design philosophy
- [Security features](/en/overview/security) — key hierarchy and encryption stack
- [Engineering docs](https://github.com/cuihairu/persona/tree/main/docs) — threat model, E2EE sync design, and other deep-dive material
