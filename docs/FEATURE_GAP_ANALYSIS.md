# Feature Gap Analysis (Persona vs 1Password)

Legend: [=] parity or similar, [+] Persona advantage, [−] missing/incomplete

- Security
  - E2E encryption, zero-knowledge: [=] design parity target; implementation WIP
  - SRP auth model: [−] not implemented
  - Biometric unlock: [−] planned hooks
  - Auto-lock policies: [−] pending
- Vaults/Items
  - Multiple vaults/collections: [−] single workspace MVP
  - Item types (login/note/card/bank): [−] partial; identity/credential present
  - Passkeys (FIDO): [−] future
  - Attachments/versioning: [−] planned
- Autofill & Browser
  - Browser extension: [−] future
  - TOTP autofill: [−] future (CLI/desktop display only first)
- Watchtower
  - Breach/weak/reused: [−] rules engine to implement
- Sharing/Admin
  - Multi-user vaults & RBAC: [−] future
  - SCIM/SSO/Recovery: [−] future
- Apps & Interfaces
  - Desktop app: [≈] skeleton present (Tauri), needs data wiring
  - Mobile: [−] placeholder
  - CLI: [=] MVP; needs full CRUD and export/import
- Developer
  - SSH Agent: [+] first-class priority (crate skeleton added)
  - Secrets automation: [−] planned (server optional)
  - SDKs & CI plugins: [−] planned
- Digital Wallet
  - Wallet item type, derivation, signing: [+] Persona advantage (planned)

