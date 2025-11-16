# Persona Roadmap & TODO (Detailed)

This plan focuses on parity with 1Password for general users and enhanced developer-centric features like SSH Agent and digital wallet support. Tasks are grouped by track and milestone with concrete deliverables.

Milestone 0 – Repo Hygiene (1–2 days)
- Monorepo
  - [x] Ensure Cargo workspace across crates
  - [x] Add JS workspace for desktop (root `package.json`)
  - [x] Add `agents/ssh-agent` crate skeleton
  - [ ] Add CI (GitHub Actions): Rust fmt/clippy/test, Desktop lint/test
  - [ ] Add CODEOWNERS; PR templates; Conventional Commits
- Docs
  - [x] 1Password feature inventory
  - [x] Monorepo guide
  - [x] Roadmap
  - [ ] Architecture diagram (core/service/storage/agents)

Milestone 1 – Core Security & Storage (1–2 weeks)
- Crypto & Auth
  - [ ] Replace simple unlock with SRP-like remote auth abstraction (prep for server)
  - [ ] Key hierarchy: per-item keys wrapped by user master key
  - [ ] Biometric unlock hook (macOS Touch ID; Windows Hello; Linux Secret Service)
  - [ ] Auto-lock timers; “require re-auth for sensitive ops”
- Storage
  - [ ] Workspace schema v2: persist `path`, `active_identity_id`, `settings` in DB
  - [ ] Migrations for workspace v1→v2; CLI to migrate existing workspaces
  - [ ] Item history/versioning (identity/credential changes)
  - [ ] Attachments blob store (file chunks + refs)
- Audit & Events
  - [x] Audit repo queries
  - [ ] Emit audit events from CLI/service operations
  - [ ] Export events to server (optional)

Milestone 2 – CLI Parity (1–2 weeks)
- Identity lifecycle
  - [x] add/list/show wired to DB with unlock flow
  - [ ] edit/remove wired to DB
  - [ ] switch: persist `active_identity_id` and last N history
  - [ ] export/import: implement compression + encryption; integrity checks
- Credentials
  - [ ] CRUD for credentials; filters (type/tags/active/favorite)
  - [ ] TOTP: generate/setup via QR; time skew handling
  - [ ] Password generator (policy controls: length, symbols, pronounceable)
- Dev usability
  - [ ] TUI mode (crossterm/ratatui) for quick flows
  - [ ] Non-interactive CI mode with env var injection

Milestone 3 – SSH Agent (2–3 weeks)
- Agent Core
  - [ ] UNIX socket server implementing SSH agent protocol (add/list/remove/sign)
  - [ ] Windows named pipe support
  - [ ] Key management: create/import keys; store in core with metadata
  - [ ] Per-host/per-command policies; confirmation prompts
  - [ ] Touch ID/biometric gating for signing; rate limiting; logging
  - [ ] Known_hosts policy check; refusal on mismatch
- CLI Integration
  - [ ] persona ssh import <key> / generate
  - [ ] persona ssh add-to-agent / list / rm
  - [ ] Agent status; test harness against `ssh -T git@github.com`

Milestone 4 – Digital Wallet (3–5 weeks incremental)
- Data Model
  - [x] Credential type placeholders (CryptoWallet)
  - [ ] Wallet models: seed phrase/mnemonic, HD paths, chain meta, watch-only
  - [ ] Per-chain derivation: BTC (BIP32/44), ETH (SLIP-44), Solana (ed25519)
  - [ ] Key import (mnemonic/private key/keystore JSON), export w/ confirmations
- Crypto Ops
  - [ ] Derive addresses; checksum validation; QR display
  - [ ] Sign primitives: BTC (PSBT), ETH (EIP-1559), Solana (ed25519)
  - [ ] Testnets; multiple networks per wallet
- UI/CLI
  - [ ] CLI: wallet create/import/derive/list/sign/verify
  - [ ] Desktop: wallet overview; address lists; copy/share with warnings
  - [ ] Security prompts before revealing secrets; 2-person approval (optional)

Milestone 5 – Desktop App (2–4 weeks)
- Foundation
  - [ ] Wire to core via FFI/tauri command; unlock flow
  - [ ] Vault/identity/credential views; search; filters
  - [ ] TOTP display; password reveal flow; copy-once
  - [ ] Keyboard-friendly UX; theming; accessibility basics
- Advanced
  - [ ] SSH agent controls; signing prompts as desktop notifications
  - [ ] Wallet UI (addresses, QR, signing confirmations)
  - [ ] Import/export; Watchtower-like panels (weak/reused/2FA)

Milestone 6 – Server & Sync (optional, 3–6 weeks)
- Server
  - [ ] Events API; audit ingestion; metrics
  - [ ] “Connect-like” secrets automation endpoint (local-first, optional)
  - [ ] End-to-end encrypted sync (key envelopes, conflict resolution)
  - [ ] SCIM/SSO bridging (future)

Milestone 7 – Browser & Autofill (future)
- [ ] WebExtension skeleton (autofill; domain rules)
- [ ] Passkeys (WebAuthn) – store and autofill platform credentials
- [ ] Phishing protections; identity-based context switching

Quality & Compliance (ongoing)
- [ ] Threat model & security review
- [ ] Fuzzing paths for parsers (mnemonic, keystore)
- [ ] Secrets redaction policy in logs; zero sensitive data in telemetry
- [ ] Reproducible builds; supply chain checks (cargo-deny, npm audit)

Open Questions
- Recovery model for master password (none by default; consider Shamir/guardians)
- Cross-device sync key exchange without server (QR pair? local LAN?)
- Wallet hardware integration (Ledger/Trezor) roadmap

