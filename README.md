# Persona - Local-First Identity Material Manager

[![CI](https://img.shields.io/github/actions/workflow/status/cuihairu/persona/ci.yml?branch=main&label=CI)](https://github.com/cuihairu/persona/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cuihairu/persona/branch/main/graph/badge.svg)](https://codecov.io/gh/cuihairu/persona)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Manage your digital selves. Switch identity material with confidence.

## 🎯 Project Overview

Persona is a local-first, zero-knowledge manager for one person operating multiple digital selves. Each identity is a distinct key-and-credential context used in a different environment, such as work, personal browsing, infrastructure access, or automation.

The product focuses on identity-scoped credentials and developer workflows: passwords, API keys, TOTP, SSH keys, browser autofill, and active identity switching. Wallet material fits the same conceptual model, but is currently a deferred priority rather than part of the main product track.

### Key Features
- 🔐 Identity-scoped vault: passwords, TOTP secrets, API keys, SSH keys, tags, and secure metadata
- 🔑 Developer tooling: built-in SSH agent, CLI workflows, and automation-friendly credential access
- 🌐 Browser assistance: autofill, suggestion, phishing resistance, and per-site identity defaults
- 🗄️ Import/export: JSON/YAML/CSV with optional gzip compression and passphrase encryption (Argon2id + AES-GCM)
- 🧾 Audit log: critical operations and signing events (with digest)
- 🛡️ Local-first security: zero-knowledge storage, auto-lock, confirmation, and supply chain checks

## 🏗️ Architecture

### Monorepo Layout
```
persona/
├── core/               # Rust core library: models, crypto, storage, service layer
├── cli/                # Persona CLI: init/add/list/show/switch/export/import/ssh/...
├── agents/ssh-agent/   # Built-in SSH agent (UNIX socket, ed25519)
├── desktop/            # Tauri + React desktop client (prototype)
├── browser/            # Browser clients (Chromium extension, etc.)
│   └── chromium-extension/ # Chrome/Edge extension (Native Messaging bridge)
├── mobile/             # Mobile placeholder
├── server/             # Optional sync/automation service (prototype)
├── website/            # Marketing site (UmiJS)
└── docs/               # Documentation and roadmap
```

### Tech Stack
- Core library: Rust with sqlx + SQLite
- Cryptography: Argon2id key derivation and AES-256-GCM symmetric encryption
- Desktop: Tauri + React + TypeScript (prototype)
- Server: Rust + Axum (optional)

## 🔒 Security Highlights

- **Zero-knowledge architecture** – servers never see plaintext user data
- **End-to-end encryption** – AES-256-GCM plus Argon2id-based key derivation
- **Local-first** – all sensitive data is encrypted/decrypted on the local device
- **Signed audit trail** – SSH signatures are logged with sha256 digest and context metadata
- **Policy controls** – the SSH agent can enforce rate limits, interactive confirmations, and optional `known_hosts` validation

## 🚀 Getting Started

### Requirements
- Rust 1.75+
- Node.js 18+

### Build and Install (CLI + Agent)
```bash
# Clone the repository
git clone git@github.com:cuihairu/persona.git
cd persona

# Build CLI and SSH agent
cargo build --workspace

# Optional: run local CI checks
make ci
```

### JS/Desktop Dependencies (pnpm)
```bash
# Install workspace dependencies (desktop + browser extension + website)
pnpm install

# Run the desktop client in dev mode
pnpm --filter desktop run dev

# Build the browser extension bundle
pnpm --filter persona-chromium-extension run build

# Run the website in dev mode
pnpm --filter persona-website run dev
```

### Initialize a Workspace and Perform Basic Actions
```bash
# Initialize an unencrypted workspace
persona init --path ~/PersonaDemo --yes

# Initialize an encrypted workspace with a master password
persona init --path ~/PersonaSecure --yes --encrypted --master-password "your_password"

# Add / show / list identities
persona add
persona show <name>
persona list

# Switch the active identity (Workspace v2 persists the state)
persona switch <name>

# Run migrations to keep the schema up to date
persona migrate

# Credential management (passwords, API keys, etc.)
persona credential add --identity alice --name "GitHub" --credential-type password --prompt-secret
persona credential list --identity alice --format table
persona credential show --id <UUID> --reveal
persona credential remove --id <UUID>

# Item history (1Password-style): every create/update/delete is recorded with
# field-level diffs; encrypted payloads only ever show as "<encrypted>"
persona credential history --id <UUID>

# Attachments (1Password-style): files are encrypted with the owning item's
# key and stay decryptable across master-password rotation
persona credential attach --id <UUID> --file ~/Documents/recovery-codes.txt
persona credential attachments --id <UUID>
persona credential save-attachment --attachment-id <UUID> --output ~/Downloads/recovery-codes.txt
persona credential remove-attachment --attachment-id <UUID>

# Secure Note (1Password-style): the body is stored fully encrypted under the
# per-item key — unlike the plain notes column on other item types
persona credential add --identity alice --name "Recovery codes" --credential-type note --note "1111-2222
3333-4444"

# Identity / Software License (1Password standard categories): document numbers
# and license keys are sealed under the item's key; unspecified fields stay empty
persona credential add --identity alice --name "Passport (main)" --credential-type identity \
  --first-name Alice --last-name Zhang --id-number 110101199001310011 --passport-number E12345678
persona credential add --identity alice --name "JetBrains All Products" --credential-type software-license \
  --license-key AAAA-BBBB-CCCC-DDDD --version 2024.2 --seats 3 --valid-until 2027-05-01

# TOTP (two-factor authentication) workflows
persona totp setup --identity alice --qr ~/Downloads/github.png
persona totp code --id <UUID>
persona totp code --id <UUID> --watch

# Steam Guard (game token; shared_secret is the base64 from the Steam authenticator export)
persona totp setup-steam --identity alice --account alice_steam --secret <base64-shared-secret>
persona totp code --id <UUID>   # game token credentials share the same code command

# Battle.net authenticator: export via a community tool (serial + restore code ->
# standard TOTP secret), then import like any TOTP with 8 digits
persona totp setup --identity alice --secret <base32-secret> --issuer Battle.net --digits 8

# Vendor-bound game tokens (Tencent Game Security Center, NetEase Da Shen,
# miHoYo security token, ...): recorded as vault entries only — their seeds live
# inside the vendor's app, so codes must be generated there
persona totp setup-game-token --identity alice --provider tencent_security --account qq_123456 --url https://gamesafe.qq.com

# Password generator with custom sets
persona password generate --length 32 --set lowercase --set uppercase --set digits --set symbols
persona password generate --pronounceable --length 18 --set lowercase --set uppercase

# TUI dashboard (ratatui + crossterm)
persona tui --identity alice   # optional: preselect identity
q to quit, r to reload, ↑/↓ or j/k to navigate
```

### Export / Import (Compression + Encryption)
```bash
# Export to JSON with sensitive content (requires unlock)
persona export --include-sensitive --output backup.json

# Enable gzip compression and passphrase-based encryption
persona export --format yaml --compression 9 --encrypt --output backup.yaml

# Import (.json/.yaml/.csv); --decrypt prompts for the passphrase
persona import backup.enc --decrypt --mode merge --backup
```

### Migrating from 1Password
Export an unencrypted `.1pux` file from 1Password (Settings → Export),
then preview and import it:
```bash
persona import-1pux export.1pux --dry-run   # show the plan, touch nothing
persona import-1pux export.1pux             # confirm, then import
```
Each 1Password vault becomes one identity (same-name identities are reused);
Login items map to password credentials with TOTP secrets split into their own
credentials, and API Credential / SSH Key items map to their persona
equivalents. Unsupported categories, archived items, and attachments are
reported and skipped — nothing is silently dropped or forced into a lossy
shape.

### SSH Agent (Developer Enhancements)
```bash
# Generate an SSH key (ed25519) and store it in the vault
persona ssh generate --identity <name> --name "GitHub Key"

# Start the built-in agent and print the export command
persona ssh start-agent --print-export
export SSH_AUTH_SOCK=...   # Copy to the current shell

# Provide the destination host and run a command
persona ssh run --host github.com -- ssh -T git@github.com

# Optional agent policies
export PERSONA_AGENT_REQUIRE_CONFIRM=1          # Prompt before every signature
export PERSONA_AGENT_MIN_INTERVAL_MS=1000       # Rate limit in milliseconds
export PERSONA_AGENT_ENFORCE_KNOWN_HOSTS=1      # Enforce known_hosts checks
export PERSONA_AGENT_CONFIRM_ON_UNKNOWN=1       # Ask before unknown hosts

# Status and shutdown
persona ssh agent-status
persona ssh stop-agent
```

## 📖 Documentation

- [ONEPASSWORD_FEATURES](./docs/ONEPASSWORD_FEATURES.md) – reference checklist for 1Password parity
- [FEATURE_GAP_ANALYSIS](./docs/FEATURE_GAP_ANALYSIS.md) – Persona vs. 1Password comparison
- [PASSKEYS_DESIGN](./docs/PASSKEYS_DESIGN.md) – passkeys (WebAuthn) design draft
- [MONOREPO](./docs/MONOREPO.md) – monorepo rationale and tooling
- [ROADMAP](./docs/ROADMAP.md) – roadmap and detailed TODO items
- [TODO](./TODO.md) – daily-maintained task list
- [BRIDGE_PROTOCOL](./docs/BRIDGE_PROTOCOL.md) – browser extension native messaging protocol
- [Brand assets](./docs/branding/README.md) – logos, wordmarks, colors, and guidelines

### Architecture & Design

- [Client Communication Architecture](./docs/CLIENT_COMMUNICATION_ARCHITECTURE.md) – unified IPC architecture
- [Non-Interactive Mode Guide](./docs/NON_INTERACTIVE_MODE.md) – CI/CD integration guide

### Security Documentation

- [SSH Agent Features](./docs/SSH_AGENT_FEATURES.md) – complete SSH agent documentation
- [SSH Agent README](./agents/ssh-agent/README.md) – SSH agent quick start
- [SSH Agent Testing](./agents/ssh-agent/TESTING.md) – comprehensive testing guide
- [Threat Model](./docs/THREAT_MODEL.md) – security boundary and periodic review checklist
- [Supply Chain Security](./docs/SUPPLY_CHAIN_SECURITY.md) – dependency security checks

## 🛣️ Roadmap

Priority policy: the password-manager track targets 1Password parity first; wallet work stays experimental and deferred until that foundation is proven (wallet security requirements are higher and get a dedicated design pass).

- [x] Monorepo, core library, workspace v2, audit logging, export/import (gzip + encryption)
- [x] SSH agent with a full policy engine (known_hosts, rate limits, per-host/key rules, biometric gating)
- [x] Browser extension + native messaging bridge (autofill MVP, domain policies, phishing resistance)
- [x] CLI parity: CRUD, TOTP, password generator, TUI, non-interactive CI mode
- [x] Wallet material (experimental): BTC/ETH/Solana derivation + signing on audited crates (rust-bitcoin/alloy)
- [x] Passkeys (WebAuthn) storage + autofill
- [x] Watchtower-class health checks (weak/reused/expired, breach checks)
- [x] Desktop app data wiring and polished UI
- [ ] Optional sync/automation service with a local-first design
- [ ] Wallet graduation: design doc, signing confirmations, PSBT, keystore JSON (after parity)

## 🤝 Contributing

- Read [`docs/CONTRIBUTING.md`](./docs/CONTRIBUTING.md) for Conventional Commits and PR expectations.
- Fork the repo and create a feature branch (for example, `git checkout -b feat/cli-edit`).
- Follow [Conventional Commits](https://www.conventionalcommits.org) when writing PR/commit titles, e.g. `feat(cli): add credential filters`.
- Push your branch and open a Pull Request. Make sure `make lint-all` and `make test-all` both pass.

## 📄 License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.

## 🔗 Links

- [Issue tracker](https://github.com/cuihairu/persona/issues)

---

Security note: Persona is evolving quickly, and APIs/storage formats may change. Avoid using it with production secrets until the interfaces stabilize.

Manage your digital selves. Switch identity material with confidence.
