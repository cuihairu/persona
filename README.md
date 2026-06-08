# Persona - Local-First Identity Material Manager

[![CI](https://img.shields.io/github/actions/workflow/status/cuihairu/persona/ci.yml?branch=main&label=CI)](https://github.com/cuihairu/persona/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cuihairu/persona/branch/main/graph/badge.svg)](https://codecov.io/gh/cuihairu/persona)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Chinese brand name: "Shuyao" (数钥, pronounced "shu yao"). It captures the idea of "digital keys" in a short, memorable word. We generally refer to the product as "Persona (数钥)" or "Shuyao Persona" in brand materials.

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

# TOTP (two-factor authentication) workflows
persona totp setup --identity alice --qr ~/Downloads/github.png
persona totp code --id <UUID>
persona totp code --id <UUID> --watch

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
- [Supply Chain Security](./docs/SUPPLY_CHAIN_SECURITY.md) – dependency security checks

## 🛣️ Roadmap

- [x] Monorepo and core library scaffold, end-to-end CLI + database wiring
- [x] Workspace v2 (path/active_identity/settings) with migration command
- [x] Export/import (gzip + encryption) and expanded audit logging
- [x] SSH agent MVP (UNIX socket / ed25519) with CLI management commands
- [ ] SSH agent policy hardening (full known_hosts parser, allow/deny lists, Windows support)
- [ ] Desktop app data wiring and polished UI
- [ ] Optional sync/automation service with a local-first design
- [ ] Wallet support as a deferred, identity-material extension

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
