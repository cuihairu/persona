# Persona Monorepo TODO

This is the master checklist to reach “1Password-like” parity while adding developer‑first features (SSH Agent, Digital Wallet). Keep this file up to date as work progresses.

Now (current sprint)
- [x] CI: GitHub Actions (Rust fmt/clippy/test; Desktop lint/test)
- [x] Architecture diagram in docs (core/service/storage/agents/desktop/server)
- [x] CLI: identity edit/remove wired to DB
- [x] CLI: switch active identity (persist `active_identity_id`, maintain history)
- [x] Core: workspace schema v2 (persist `path`, `active_identity_id`, `settings`) + migration
- [x] Audit: emit logs from service/CLI for identity CRUD and switch
- [x] CLI: migrate command to apply DB migrations and ensure workspace row

Monorepo & Tooling
- [x] Rust workspace crates (core, cli, server, mobile/rust)
- [x] JS workspace for desktop (root `package.json`)
- [x] Add SSH Agent crate skeleton (`agents/ssh-agent`)
- [x] CODEOWNERS + PR template + Conventional Commits
- [x] Makefile targets for build/test/lint across all packages
- [x] 文档：整理统一客户端通信架构（CLI/桌面/浏览器/Agent 依赖同一个本地服务/IPC 协议）
- [x] 文档：说明本地服务 IPC 优先使用 Unix Socket（含 Windows 支持，必要时回退 Named Pipe）

Security & Auth
- [x] Key hierarchy: per-item keys wrapped by master key
- [x] SRP-like remote auth abstraction (prep for server)
- [x] Biometric unlock hooks (Touch ID/Face ID/Windows Hello)
- [x] Auto-lock timers and “re-authenticate for sensitive ops”
- [x] Secrets redaction policy for logs

Storage & Data
- [x] Workspace v2 schema + migrations and CLI migration command
- [x] Item versioning (identity/credential change history)
- [x] Attachments blob store (file chunks + refs)
- [x] Export/Import with compression + encryption + integrity checks

CLI
- [x] add/list/show wired to DB with unlock flow and fallback when no user
- [x] edit/remove identity (完整实现:交互式编辑、字段验证、备份、审计日志)
- [x] switch (activate/deactivate, history, config persistence)
- [x] credential CRUD (filters: type/tag/active/favorite)
- [x] TOTP: setup via QR + code generation
- [x] password generator options (length, symbol sets, pronounceable)
- [x] TUI mode (ratatui/crossterm)
- [x] Non-interactive CI mode with environment variable injection

SSH Agent (developer focus)
- [x] UNIX socket server implementing SSH agent protocol (list/add/remove/sign)
- [x] UNIX socket server MVP: request_identities/sign_request (ed25519), loads keys from vault
- [x] Windows named pipe support (cross-platform transport abstraction)
- [x] Key management (create/list/remove), store in core with metadata
- [x] Per-host/per-command policies; confirmation prompts
- [x] Basic confirmation prompt gating via env `PERSONA_AGENT_REQUIRE_CONFIRM`
- [x] Rate limiting via env `PERSONA_AGENT_MIN_INTERVAL_MS`
- [x] CLI control: start/stop/status, query agent identities
- [x] Known hosts policy (optional): env `PERSONA_AGENT_ENFORCE_KNOWN_HOSTS`, wrapper `persona ssh run --host <h> -- <cmd>` to pass host, confirm-on-unknown via env `PERSONA_AGENT_CONFIRM_ON_UNKNOWN`
- [x] Biometric gating for signing (with fallback to confirmation)
- [x] Comprehensive policy system (TOML-based configuration)
  - [x] Global policies (deny_all, rate limits, known_hosts enforcement)
  - [x] Per-key policies (allowed/denied hosts, time ranges, daily limits, biometric requirements)
  - [x] Per-host policies (allowed keys, confirmation requirements, hourly limits)
  - [x] Glob pattern matching for hostname restrictions
- [x] E2E tests for SSH protocol encoding/decoding
- [x] E2E tests for agent request_identities and GitHub connection
- [x] CLI commands: `persona ssh import|generate|list|list-all|export-pub|add-to-agent|start-agent|stop-agent|agent-status|run|remove`
- [x] Complete README documentation with usage examples
- [ ] Full E2E test: manual testing with real `ssh -T git@github.com` (requires user setup)
- [ ] Windows-specific testing and optimization

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
- [ ] 文档：用户可选的存储/同步模式（纯本地、自托管云/自有 iCloud、Persona Server 辅助）

Browser & Autofill (future)
- [x] Browser extension skeleton (autofill; domain rules)
  - [x] Wire popup UI to Persona desktop/CLI bridge
  - [x] Form detection + autofill heuristics (passwords, TOTP, address)
  - [x] Domain policies + phishing protections
- [x] Safari WebExtension host shell (Swift bridge + manifest sync)
- [ ] Passkeys (WebAuthn) storage + autofill
- [ ] Phishing protections; identity-based context switching

Quality & Security
- [ ] Threat model & periodic security review
- [x] Fuzz tests for parsers (mnemonic/keystore/QR)
- [x] Supply chain checks (cargo-deny, npm audit)
- [ ] Reproducible builds

References
- docs/ONEPASSWORD_FEATURES.md
- docs/FEATURE_GAP_ANALYSIS.md
- docs/ROADMAP.md
- docs/MONOREPO.md
