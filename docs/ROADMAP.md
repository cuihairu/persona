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
- [ ] Passkeys (WebAuthn): storage model + autofill — design at `PASSKEYS_DESIGN.md` (review stage; P1 core/CLI done, P2 browser interception done; P3 desktop GUI approval surface pending)
- [x] Watchtower-class health checks: rules engine (weak/reused/expired/stale; core + CLI + desktop command layer, metadata-only reports)
- [ ] Watchtower: desktop UI panels
- [x] Watchtower: breach checks via HIBP k-anonymity (offline BreachChecker seam; `persona watchtower --check-breaches` + desktop `health_scan` flag; only a 5-char hash prefix leaves the machine, network failure degrades to offline rules)
- [x] Desktop app: wired to core on Tauri v2 (unlock, lists, CRUD; vault/identity/credential views; search + type/tag/favorite filters)
- [x] Desktop: TOTP display (shared core path, RFC 6238 vectors); password reveal flow (re-auth gate + 30s auto-hide + copy-once clipboard); SshKey/ApiKey/BankCard rendering
- [x] Desktop: SSH agent controls; signature approvals via in-app modal + system notification (agent stays UI-free behind an ApprovalHandler seam; CLI keeps TTY prompts unchanged)
- [x] Desktop: auto-lock end-to-end (backend event → countdown banner → enforced lock clears in-memory master key even if the frontend is gone)
- [ ] Browser: polished TOTP autofill UX
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
- [ ] Events API, audit ingestion, metrics
- [ ] Connect-like local-first secrets automation endpoint
- [ ] End-to-end encrypted sync (key envelopes, conflict resolution)
- [ ] Documented storage/sync options: pure local, self-hosted cloud, Persona-server-assisted

Ongoing quality
- [x] Threat model + periodic review process (`THREAT_MODEL.md`)
- [x] Fuzz tests for parsers (mnemonic/keystore/QR); secrets redaction policy for logs
- [ ] KDF parameter review: both paths documented (`KEY_HIERARCHY.md`); PBKDF2 iteration count and Argon2 parameters revisited quarterly, changes applied via re-wrap/re-encrypt migrations
