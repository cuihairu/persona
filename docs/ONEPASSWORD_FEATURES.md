# 1Password Feature Inventory (Reference)

This list captures the major features of 1Password grouped by domain, to guide Persona's roadmap and parity/gap analysis.

- Security Model
  - End‑to‑end encryption keyed by user secrets (Secret Key + Master Password)
  - Zero‑knowledge architecture; SRP-based remote authentication
  - Client-side crypto; per-item keys; item sharing with re-encryption
  - Biometric unlock (Touch ID/Face ID/Windows Hello); Auto-lock; Travel Mode
- Vaults, Items, Organization
  - Multiple vaults; vault collections; per-vault permissions
  - Item types: Login, Password, Identity, Secure Note, Credit Card, Bank Account, API Credential, SSH Key, Software License, Passkey (FIDO)
  - Item metadata: tags, custom fields, attachments, item history/versioning
  - Item sharing: direct member/group access; time-limited links; permissions
- Autofill & Browser
  - Browser extension (autofill logins, passkeys, TOTP)
  - Phishing protections; domain matching rules; private mode support
- Passwords & Passkeys
  - Password generator (rules, entropy meter)
  - Passkeys (WebAuthn) storage and autofill
  - TOTP generator; 2FA setup QR scanning; OTP autofill
- Watchtower & Health
  - Breach monitoring; reused/weak passwords; expiring items; 2FA available
  - Domain breach alerts; dark web monitoring (business plans)
- Sharing, Admin & Recovery
  - Families/Teams/Business accounts; group-based RBAC
  - Admin console, policies (password policy, 2FA policy, device approvals)
  - Account recovery flows; emergency access
  - SCIM provisioning; SSO integrations (Okta/Azure AD/Google)
- Apps & Interfaces
  - Native apps: macOS/Windows/Linux/iOS/Android; Web app
  - CLI: item CRUD, connect to secrets automation; SSH agent integration
  - Events API, audit logs; reports
- Developer & Automation
  - 1Password CLI (op); Connect server (secrets automation)
  - SSH Agent: sign with keys stored in 1Password
  - Shell Plugins for auto-injecting secrets to tools
  - Kubernetes/CI integrations; SDKs; Terraform provider
- Extras
  - Masked emails (Fastmail integration)
  - Travel Mode (remove vaults from devices)
  - Local item history; attachments; file secure storage

Notes
- 1Password does not act as a crypto wallet, but can store seed phrases/private keys as secrets. Persona will extend here with first-class wallet support (BIP32/44/SLIP10 derivations, signing).

