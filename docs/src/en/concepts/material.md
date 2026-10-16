# Identity Material

**In one sentence**: identity material is the protected **data asset** held under an
identity — passwords, SSH keys, API keys, TOTP, wallets, and passkeys are all
materials. "Material" unifies their storage, encryption, audit, and authorization
semantics: one material can be acted on by many [actions](./action), but the material
itself carries no permission.

## Current state: what counts as material

In the core data model, materials live in three tables (all owned by an identity via
`identity_id`):

| Storage table    | Materials                                                                                                                                                                  |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `credentials`    | `CredentialType`: Password, TwoFactor(TOTP), ApiKey, SshKey, CryptoWallet, BankCard, GameAccount, ServerConfig, Certificate, SecureNote, SoftwareLicense, Identity, Custom |
| `crypto_wallets` | Crypto wallets (BTC/ETH/Solana; BIP-143 / EIP-155 / EIP-1559 derivation and signing)                                                                                       |
| `passkeys`       | WebAuthn passkeys (RP binding, attestation retained)                                                                                                                       |

Security properties (see [Security Design](/en/design/security) and
[Key Hierarchy](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.md)):

- Every credential is encrypted with its **own item key** (AES-GCM), and the master
  key only wraps item keys — a single-item leak does not affect other materials;
- URL, username, and similar fields are **display/binding fields**: browser fill/save
  binds by TLD+1 domain; sensitive content (passwords, TOTP secrets, private keys)
  exists only in transient decrypted memory;
- Audit logs record only resource IDs, actions, and digests — never material content.

## How material relates to identity

A material **belongs to exactly one identity**, but an identity can own any number of
materials; multiple materials for the same entity (GitHub password / GitHub SSH key /
GitHub API key) are independent entries, each rotated, audited, and authorized on its
own.

## Material ≠ action

Material is just data. "Reveal it," "fill with it," "have the SSH Agent sign with it"
are actions ([Action](./action)) — only actions trigger policy checks and audits. Two
direct consequences of this separation:

- The browser extension **does not own the password** — it only requests actions such
  as `request_fill` / `save_credential`, adjudicated by the local core;
- SSH private keys are **never exported** — external programs request the signature
  result, not the key itself (private-key export is forbidden by default; see
  [SSH Agent Features](https://github.com/cuihairu/persona/blob/main/docs/SSH_AGENT_FEATURES.md)).

## Plans

- **Configurable policy** for materials (which actions require confirmation or are
  forbidden) → the rule layer of [Policy](./policy);
- For the parts of material-level sharing and group keys (sync groups) that have
  already landed, see the E2EE sync design.
