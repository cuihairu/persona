# Feature Gap Analysis (Persona vs 1Password)

Status as of 2026-09. Legend: [=] parity or similar, [≈] partial, [+] Persona advantage, [−] missing/incomplete

- Security
  - E2E encryption, zero-knowledge: [=] per-item keys wrapped by the master key (AES-256-GCM); Argon2id for export/backup encryption; legacy direct-encryption rows still readable
  - SRP auth model: [≈] SRP-like remote-auth abstraction landed (PBKDF2-HMAC-SHA256, 100k iterations); full server-side flow waits for the sync track
  - Biometric unlock: [≈] provider abstraction + hooks landed; native Touch ID/Windows Hello wiring lands with the desktop app
  - Auto-lock policies: [=] auto-lock timers + re-authentication for sensitive ops
- Vaults/Items
  - Multiple vaults/collections: [−] single workspace by design (identity-scoped); multi-user vault features intentionally out of scope (see `BOUNDARY.md`)
  - Item types: [≈] password, API key, TOTP, SSH key, bank card, server config, digital certificate, game account, crypto-wallet placeholder; secure notes via metadata
  - Passkeys (FIDO): [−] not started — the next major parity gap
  - Attachments/versioning: [=] blob store + item change history
- Autofill & Browser
  - Browser extension: [≈] Chromium extension + Native Messaging bridge MVP (username/password fill, TOTP verb, pairing + HMAC + origin binding + user gesture, domain policies, phishing resistance); Safari host shell present
  - TOTP autofill: [≈] bridge protocol supports it; polished in-page UX pending
- Watchtower
  - Breach/weak/reused/expired detection: [x] rules engine + HIBP breach check done (core + `persona watchtower --check-breaches` CLI + desktop `health_scan` flag; k-anonymity: only a 5-char hash prefix is sent, network failure degrades to offline rules; metadata-only reports, zxcvbn strength/reuse/expiry/staleness); desktop `Watchtower` panel done (scan + optional HIBP breach check, severity-grouped report)
- Sharing/Admin
  - Multi-user vaults, RBAC, SCIM/SSO, account recovery: [−] out of scope for a single-principal product (`BOUNDARY.md`)
- Apps & Interfaces
  - Desktop app: [≈] full command wiring on Tauri v2 (50+ commands: vault/credential CRUD, TOTP, auto-lock with backend-enforced lock, audit query, passkey seams, reveal + re-auth gating, wallet create/sign confirmations with address-poisoning heuristics, SSH signature approvals via in-app modal + system notification, passkey approval gate for browser bridge requests via Unix socket + approval modal + system tray with close-to-tray, passkey management page: cross-identity list/detail/delete/self-test/private-key export); remaining: biometric unlock, attachments UI, change-history UI, packaged-build acceptance
  - Mobile: [−] placeholder
  - CLI: [=] full CRUD, TOTP (QR setup + watch), password generator, TUI, export/import (gzip + encryption), 1Password migration (`import-1pux`: per-vault identities, Login/API Credential/SSH Key mapping, TOTP split-out, skip reporting), non-interactive CI mode, migrations
- Developer
  - SSH Agent: [+] first-class: policy engine (per-key/per-host rules, rate limits, known_hosts, glob allow/deny, biometric gating), E2E tests — exceeds 1Password's agent controls
  - Secrets automation: [−] planned (server optional)
  - SDKs & CI plugins: [≈] env-var non-interactive mode covers CI basics
- Digital Wallet
  - Wallet item type, derivation, signing: [+] experimental advantage: BTC (BIP-143 P2WPKH), ETH (EIP-155/1559), Solana derivation + signing on audited crates (rust-bitcoin/alloy/bech32); deferred until password parity per the priority policy — keystore JSON, PSBT, signing-confirmation UX and a wallet threat model all pending
