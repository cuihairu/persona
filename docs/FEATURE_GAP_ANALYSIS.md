# Feature Gap Analysis (Persona vs 1Password)

Status as of 2026-09. Legend: [=] parity or similar, [≈] partial, [+] Persona advantage, [−] missing/incomplete

- Security
  - E2E encryption, zero-knowledge: [=] per-item keys wrapped by the master key (AES-256-GCM); Argon2id for export/backup encryption; legacy direct-encryption rows still readable
  - SRP auth model: [≈] SRP-like remote-auth abstraction landed (PBKDF2-HMAC-SHA256, 100k iterations); full server-side flow waits for the sync track
  - Biometric unlock: [=] native wiring landed on all three desktop platforms (Linux polkit `auth_self` / macOS LocalAuthentication / Windows Hello; master password escrowed in the OS keyring, InvalidCredentials self-purges the entry, fail-closed when the OS provider is unavailable — 2026-09)
  - Auto-lock policies: [=] auto-lock timers + re-authentication for sensitive ops
- Vaults/Items
  - Multiple vaults/collections: [−] single workspace by design (identity-scoped); multi-user vault features intentionally out of scope (see `BOUNDARY.md`)
  - Item types: [≈] password, API key, TOTP, SSH key, bank card, server config, digital certificate, game account, crypto-wallet placeholder; secure notes as a first-class encrypted item type (`CredentialData::SecureNote`, body under the per-item key — 2026-09); Identity + Software License categories (document numbers / license keys under the per-item key, 2026-09)
  - Passkeys (FIDO): [=] software authenticator in core/CLI (ES256, per-item-key-wrapped storage), browser-bridge interception with approval gating (protocol v2), desktop management page + Unix-socket approval server; cross-device sync waits for the phase-2 E2EE sync track; OS platform authenticators (macOS/Windows) still pending
  - Attachments/versioning: [=] attachments fully landed (files sealed under the owning item's per-item key, survive master-password rotation, cascade-deleted with the item; desktop pane with native file dialogs + `persona credential attach/attachments/save-attachment/remove-attachment` CLI, 2026-09); item change history recorded on every create/update/delete with metadata-only field diffs and surfaced in desktop detail pane + `persona credential history` (2026-09); restore-to-version landed for metadata (core `restore_credential_version`, `persona credential restore --id --version`, desktop history-timeline Restore button — 2026-09-22); secret-field versioning stays out: history snapshots never contain ciphertext (password/key rollback would need snapshot storage + a ciphertext-replay risk pass)
- Autofill & Browser
  - Browser extension: [≈] Chromium extension + Native Messaging bridge MVP (username/password fill, TOTP verb, pairing + HMAC + origin binding + user gesture, domain policies, phishing resistance); Safari host shell present
  - TOTP autofill: [x] bridge protocol + polished in-page UX (2026-09-22): focus auto-fill, 6-cell digit-group fill, chained fill after login fill (`autoFillTotpAfterLogin` setting), stale-code window (≤3s) waits out the period and refetches once, fill/copy notices carry remaining seconds, multi-candidate auto-fill opens an inline picker instead of failing silently (per-origin default memory unchanged); follow-ups: Shadow-DOM isolation for injected widgets, inline code-display widget (deliberately omitted — page scripts can read content-script DOM)
- Watchtower
  - Breach/weak/reused/expired detection: [x] rules engine + HIBP breach check done (core + `persona watchtower --check-breaches` CLI + desktop `health_scan` flag; k-anonymity: only a 5-char hash prefix is sent, network failure degrades to offline rules; metadata-only reports, zxcvbn strength/reuse/expiry/staleness); desktop `Watchtower` panel done (scan + optional HIBP breach check, severity-grouped report)
  - Domain breach alerts / dark web monitoring / Sherlock-style OSINT identifier queries: [−] deferred past 1Password parity (2026-09-22) — sending usernames/emails/phones to third parties conflicts with the "no standing egress" privacy line and cross-site username enumeration collides with `BOUNDARY.md`'s "social identity aggregation" exclusion; hosting the probes on persona-server later does not change that verdict this round. Revisit only after Milestone 4 parity is complete (see `TODO.md` deferred entry).
- Sharing/Admin
  - Multi-user vaults, RBAC, SCIM/SSO, account recovery: [−] out of scope for a single-principal product (`BOUNDARY.md`)
- Apps & Interfaces
  - Desktop app: [≈] full command wiring on Tauri v2 (50+ commands: vault/credential CRUD, TOTP, auto-lock with backend-enforced lock, audit query, passkey seams, reveal + re-auth gating, wallet create/sign confirmations with address-poisoning heuristics, SSH signature approvals via in-app modal + system notification, passkey approval gate for browser bridge requests via Unix socket + approval modal + system tray with close-to-tray, passkey management page: cross-identity list/detail/delete/self-test/private-key export, biometric unlock on all three platforms (OS keyring escrow + system auth prompt), secure-note item type + item-history timeline + attachments (native file dialogs) in the detail pane); remaining: packaged-build acceptance
  - Mobile: [−] placeholder (deferred this parity round — desktop + CLI + browser first, alongside the wallet deferral)
  - CLI: [=] full CRUD, TOTP (QR setup + watch), password generator, TUI, export/import (gzip + encryption), 1Password migration (`import-1pux`: per-vault identities, Login/API Credential/SSH Key mapping, TOTP split-out, skip reporting), non-interactive CI mode, migrations
- Developer
  - SSH Agent: [+] first-class: policy engine (per-key/per-host rules, rate limits, known_hosts, glob allow/deny, biometric gating), E2E tests — exceeds 1Password's agent controls
  - Secrets automation: [−] planned (server optional)
  - SDKs & CI plugins: [≈] env-var non-interactive mode covers CI basics
- Digital Wallet
  - Wallet item type, derivation, signing: [+] experimental advantage: BTC (BIP-143 P2WPKH), ETH (EIP-155/1559), Solana derivation + signing on audited crates (rust-bitcoin/alloy/bech32); deferred until password parity per the priority policy — keystore JSON, PSBT, signing-confirmation UX and a wallet threat model all pending
