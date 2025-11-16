# Persona Monorepo TODO

This is the master checklist to reach “1Password-like” parity while adding developer‑first features (SSH Agent, Digital Wallet). Keep this file up to date as work progresses.

Now (current sprint)
- [x] CI: GitHub Actions (Rust fmt/clippy/test; Desktop lint/test)
- [ ] Architecture diagram in docs (core/service/storage/agents/desktop/server)
- [x] CLI: identity edit/remove wired to DB
- [x] CLI: switch active identity (persist `active_identity_id`, maintain history)
- [x] Core: workspace schema v2 (persist `path`, `active_identity_id`, `settings`) + migration
- [x] Audit: emit logs from service/CLI for identity CRUD and switch
- [x] CLI: migrate command to apply DB migrations and ensure workspace row

Monorepo & Tooling
- [x] Rust workspace crates (core, cli, server, mobile/rust)
- [x] JS workspace for desktop (root `package.json`)
- [x] Add SSH Agent crate skeleton (`agents/ssh-agent`)
- [ ] CODEOWNERS + PR template + Conventional Commits
- [ ] Makefile targets for build/test/lint across all packages

Security & Auth
- [ ] Key hierarchy: per-item keys wrapped by master key
- [ ] SRP-like remote auth abstraction (prep for server)
- [ ] Biometric unlock hooks (Touch ID/Face ID/Windows Hello)
- [ ] Auto-lock timers and “re-authenticate for sensitive ops”
- [ ] Secrets redaction policy for logs

Storage & Data
- [ ] Workspace v2 schema + migrations and CLI migration command
- [ ] Item versioning (identity/credential change history)
- [ ] Attachments blob store (file chunks + refs)
- [ ] Export/Import with compression + encryption + integrity checks

CLI
- [x] add/list/show wired to DB with unlock flow and fallback when no user
- [ ] edit/remove identity
- [ ] switch (activate/deactivate, history, config persistence)
- [ ] credential CRUD (filters: type/tag/active/favorite)
- [ ] TOTP: setup via QR + code generation
- [ ] password generator options (length, symbol sets, pronounceable)
- [ ] TUI mode (ratatui/crossterm)
- [ ] Non-interactive CI mode with environment variable injection

SSH Agent (developer focus)
- [ ] UNIX socket server implementing SSH agent protocol (list/add/remove/sign)
- [x] UNIX socket server MVP: request_identities/sign_request (ed25519), loads keys from vault
- [ ] Windows named pipe support
- [x] Key management (create/list/remove), store in core with metadata
- [ ] Per-host/per-command policies; confirmation prompts
- [x] Basic confirmation prompt gating via env `PERSONA_AGENT_REQUIRE_CONFIRM`
- [x] Rate limiting via env `PERSONA_AGENT_MIN_INTERVAL_MS`
 - [x] CLI control: start/stop/status, query agent identities
 - [x] Known hosts policy (optional): env `PERSONA_AGENT_ENFORCE_KNOWN_HOSTS`, wrapper `persona ssh run --host <h> -- <cmd>` to pass host, confirm-on-unknown via env `PERSONA_AGENT_CONFIRM_ON_UNKNOWN`
- [ ] Biometric gating for signing + rate limiting + detailed audit
- [ ] known_hosts policy check; refusal on mismatch
- [ ] CLI commands: `persona ssh import|generate|list|add-to-agent|rm|status`
- [x] CLI commands (partial): `generate|list|rm|status|add-to-agent (placeholder)`
- [ ] E2E test: `ssh -T git@github.com` path using agent

Digital Wallet (Persona enhancement)
- [ ] Wallet models: mnemonic/seed, HD paths, chain metadata, watch-only
- [ ] Derivations: BTC (BIP32/44), ETH (SLIP‑44), Solana (ed25519)
- [ ] Import (mnemonic/private key/keystore JSON) & export with confirmations
- [ ] Sign: BTC (PSBT), ETH (EIP‑1559), Solana; testnets/multiple networks
- [ ] CLI: wallet create/import/derive/list/sign/verify
- [ ] Desktop: wallet overview, address lists, QR, signing confirmations

Desktop (Tauri + React)
- [ ] Wire Tauri commands to core (unlock, lists, CRUD)
- [ ] Vault/identity/credential views; search; filters
- [ ] TOTP display; password reveal flow; copy-once clipboard
- [ ] SSH Agent control & signing approvals via notifications
- [ ] Wallet UI (addresses, QR, signing confirmations)

Server & Sync (optional)
- [ ] Events API, audit ingestion, metrics
- [ ] Connect-like local-first secrets automation endpoint
- [ ] End-to-end encrypted sync (key envelopes, conflict resolution)
- [ ] SCIM/SSO bridging (future)

Browser & Autofill (future)
- [ ] Browser extension skeleton (autofill; domain rules)
- [ ] Passkeys (WebAuthn) storage + autofill
- [ ] Phishing protections; identity-based context switching

Quality & Security
- [ ] Threat model & periodic security review
- [ ] Fuzz tests for parsers (mnemonic/keystore/QR)
- [ ] Supply chain checks (cargo-deny, npm audit)
- [ ] Reproducible builds

References
- docs/ONEPASSWORD_FEATURES.md
- docs/FEATURE_GAP_ANALYSIS.md
- docs/ROADMAP.md
- docs/MONOREPO.md
