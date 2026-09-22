# Persona Roadmap & TODO (Detailed)

Priority policy (2026-09): the password-manager track targets 1Password parity first. The wallet track stays experimental and deferred until that foundation is proven — wallet security requirements (irreversible outcomes, signing confirmations, a transaction-level threat model) deserve a dedicated design pass of their own. Daily task tracking lives in the root [TODO](../TODO.md); this file is the milestone view.

Milestones 0–3 – Foundation (done)

- [x] Monorepo + CI + Conventional Commits + supply-chain checks (cargo-deny, npm/pnpm audit)
- [x] Workspace v2 schema + migrations; audit logging from service/CLI
- [x] Per-item key hierarchy (wrapped item keys); SRP-like remote-auth abstraction; biometric hooks; auto-lock + re-auth for sensitive ops
- [x] CLI parity: identity/credential CRUD, TOTP (QR setup + watch), password generator, TUI, export/import (gzip + encryption), non-interactive CI mode
- [x] SSH agent: policy engine (per-key/per-host rules, rate limits, known_hosts, glob allow/deny, biometric gating), full CLI control, E2E protocol tests
- [x] Browser: Chromium extension + Native Messaging bridge (pairing, HMAC request auth, origin binding, user gesture, autofill MVP, phishing resistance); Safari host shell

Milestone 4 – 1Password Parity (current focus)

- [ ] Passkeys (WebAuthn): storage model + autofill — design at `PASSKEYS_DESIGN.md` (review stage; P1 core/CLI done, P2 browser interception done, P3 desktop done — confirmation gate via tray app + passkey management page with list/detail/delete/self-test/export)
- [x] 1Password migration: 1PUX import — parser + pure import planner in core (`import_1pux`), `persona import-1pux --dry-run` plan preview (per-vault identities, Login/API Credential/SSH Key mapping, TOTP split into dedicated credentials, skip reporting for unmapped categories/archived items/attachments)
- [x] Watchtower-class health checks: rules engine (weak/reused/expired/stale; core + CLI + desktop command layer, metadata-only reports)
- [x] Watchtower: desktop UI panel (scan with optional HIBP breach check; severity-grouped metadata-only report)
- [x] Watchtower: breach checks via HIBP k-anonymity (offline BreachChecker seam; `persona watchtower --check-breaches` + desktop `health_scan` flag; only a 5-char hash prefix leaves the machine, network failure degrades to offline rules)
- [x] Desktop app: wired to core on Tauri v2 (unlock, lists, CRUD; vault/identity/credential views; search + type/tag/favorite filters)
- [x] Desktop: TOTP display (shared core path, RFC 6238 vectors); password reveal flow (re-auth gate + 30s auto-hide + copy-once clipboard); SshKey/ApiKey/BankCard rendering
- [x] Desktop: SSH agent controls; signature approvals via in-app modal + system notification (agent stays UI-free behind an ApprovalHandler seam; CLI keeps TTY prompts unchanged)
- [x] Desktop: auto-lock end-to-end (backend event → countdown banner → enforced lock clears in-memory master key even if the frontend is gone)
- [x] Browser: polished TOTP autofill UX (chained fill after login, stale-code refetch, remaining-seconds notices, multi-candidate picker — 2026-09)
- [ ] SSH agent: real-host E2E test (`ssh -T git@github.com`); Windows-specific testing and optimization
- [ ] Reproducible builds

Milestone 5 – Wallet Graduation (deferred until Milestone 4; experimental today)
Existing experimental base: BTC (BIP-143 P2WPKH) / ETH (EIP-155/1559) / Solana derivation and signing on audited crates (rust-bitcoin, alloy, bech32), CLI wallet flows, official test vectors as regression harness.

- [ ] `docs/WALLET_DESIGN.md`: wallet key hierarchy (seed ↔ master key wrapping, re-wrap on password change), identity-binding model, signing-confirmation UX, wallet threat-model extension
- [ ] keystore JSON import/export (replace the simplified keystore path with standard scrypt/pbkdf2)
- [ ] PSBT workflow
- [ ] Signing confirmations verifying recipient address, amount, fees and chain id (anti address-poisoning)
  - [x] Desktop confirmation modal exists: from/to/amount/fee display, address-poisoning heuristic warning, password stays in the modal, signature verified before persisting; backend signing UX policy (threat model) still pending
- [x] Desktop wallet UI (addresses, QR, confirmations)
- [ ] Open question: hardware wallets (Ledger/Trezor) in-scope here or a separate later track

Milestone 6 – Server & Sync (optional)

- [x] Events API, audit ingestion, metrics
- [x] Device tokens + encrypted vault-backup custody (`/api/v1/backups`: multi-device bearer tokens, streaming upload with sha256 dedup, versioned list/download/delete, retention policy; server holds PERSENC1 ciphertext only — sync phase 1, 2026-09)
- [x] Client-side backup chain (core `backup` feature: VACUUM INTO snapshot → gzip → PERSENC1, byte-compatible with `--encrypt` exports; `BackupClient` for the custody endpoints; CLI `persona backup push/list/pull/restore/delete` — push needs no master-password unlock, restore stages via a verified temp file and keeps a `.bak`; attachments are not in v1 backups, 2026-09)
- [ ] Connect-like local-first secrets automation endpoint (design doc `CONNECT_AUTOMATION_DESIGN.md` stage 0, 2026-09-22; implementation stages 1–4 pending)
- [ ] End-to-end encrypted sync (key envelopes, conflict resolution; per-item incremental sync is sync phase 2 — backup custody leaves room for it without implementing it)
- [x] Documented storage/sync options: pure local, self-hosted cloud, Persona-server-assisted (`STORAGE_AND_SYNC.md`, 2026-09)

Ongoing quality

- [x] Threat model + periodic review process (`THREAT_MODEL.md`)
- [x] Fuzz tests for parsers (mnemonic/keystore/QR); secrets redaction policy for logs
- [ ] KDF parameter review: both paths documented (`KEY_HIERARCHY.md`); PBKDF2 iteration count and Argon2 parameters revisited quarterly, changes applied via re-wrap/re-encrypt migrations
