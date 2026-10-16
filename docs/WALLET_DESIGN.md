# Wallet Key Hierarchy & Signing — Design

> [English](WALLET_DESIGN.md) | [中文](WALLET_DESIGN.zh.md)

Status: **current-state inventory + decisions** (2026-10-13, M5 wallet graduation
track). This doc answers four things: the key hierarchy (seed ↔ master key
wrapping), re-wrap semantics on passphrase change, the persona-to-wallet binding
model, and the signing-confirmation UX plus backend policy; the threat-model
extension is in [the THREAT_MODEL.md "Wallet (experimental track)" section](THREAT_MODEL.md).
Related: [ROADMAP M5](ROADMAP.md#milestone-5--wallet-graduation-deferred-until-milestone-4-experimental-today),
[KEY_HIERARCHY.md](KEY_HIERARCHY.md) (the identity-vault hierarchy — the wallet is the
documented sixth, independent KDF path within it).

**The line between this doc and the code**: §1/§2 are a current-state inventory
(already implemented in the vault); §2.1/§3/§4/§5 are **decisions** — of those, §3's
`persona wallet passwd` and the `EncryptedMnemonic` re-wrap **have landed (2026-10-13)**,
as have §5's item 3 (backend address-poisoning enforcement) and the desktop keystore
arm (2026-10-13); §2.1's version=2 lazy re-wrap migration is still to do. "Decision"
does not mean "implemented" — read according to the markers in this section.

## 1. Current-Code Map (inventory, 2026-10-13)

| Layer                | Location                                                                                                   | Key points                                                                                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BIP39 mnemonic       | `core/src/crypto/wallet_crypto.rs` `SecureMnemonic` (bip39 3.0)                                            | 12–24 words, `to_seed(passphrase)` = BIP39 64-byte seed                                                                                                             |
| secp256k1 master key | `MasterKey` (bip32 0.6 `XPrv`)                                                                             | `from_seed` → `derive_path` → `to_xpub`; **serialization is the base58 xprv/xpub string**                                                                           |
| Solana master key    | `Ed25519Key` (SLIP-0010 ed25519, homegrown, hardened derivation only)                                      | HMAC-SHA512 chain; persisted as `(secret, chain_code)` 64 bytes; zeroized on drop                                                                                   |
| Single-key wrap      | `EncryptedWalletKey {version:1, encrypted_data, salt, nonce}`                                              | Argon2id (argon2 crate defaults m≈19MiB/t=2/p=1, parameters not persisted) + AES-256-GCM (`crypto/encryption.rs`)                                                   |
| Mnemonic wrap        | `EncryptedMnemonic {version:1, encrypted_phrase, salt, nonce}`                                             | Same as above                                                                                                                                                       |
| keystore v3          | `crypto/wallet_encryption.rs`                                                                              | scrypt(n=2^18,r=8,p=1)/pbkdf2 + AES-128-CTR + keccak MAC; 256MiB import memory cap, constant-time MAC comparison; locked to geth spec vectors                       |
| Derivation path      | `recommended_derivation_path` (BTC `m/44'/0'/{a}'/0`, ETH `m/44'/60'/{a}'/0`, Solana `m/44'/501'/{a}'/0'`) | BIP-84/86 is currently only the `BipVersion` type and path builder (test vectors covered), **not in the default flow**; BTC address generation is P2WPKH only today |
| Signing              | `crypto/transaction_signing.rs`                                                                            | ETH EIP-155/1559 (alloy), BTC BIP-143 P2WPKH (rust-bitcoin), Solana ed25519 (the caller supplies the serialized message)                                            |
| PSBT                 | `crypto/transaction_psbt.rs`                                                                               | BIP-174 single-sig P2WPKH export/sign/finalize (finalize homegrown); CLI `wallet export-psbt/sign-psbt/finalize-psbt`                                               |

## 2. Key Hierarchy (decision)

```
BIP39 mnemonic ──(BIP39 seed, optional passphrase)──▶ 64-byte seed
      │                                                 │
      │ wrap: EncryptedMnemonic                         │ wrap: EncryptedWalletKey
      │ (Argon2id + AES-256-GCM, wallet password)       │ (same; an HD wallet holds the xprv string)
      ▼                                                 ▼
  recovery / migration surface                MasterKey (bip32 XPrv)
                                                   │ derive_path
                                                   ▼
                                        DerivedKey → address / signing key
```

- **seed ↔ master key is derivation, not wrapping**: the master key is derived from
  the seed (BIP32); what the storage plane wraps is the "xprv serialized string"
  (HD) or the "single key" (single); the mnemonic is wrapped separately for
  recovery/export. Both wraps use the same wallet passphrase and the same
  Argon2id+AES-256-GCM pipeline (independent fresh salt/nonce each).
- **Rationale**: the mnemonic is not treated as the single source of truth and
  re-derived on every signature (the unlock cost), and the xprv is not treated as
  the single source of truth (losing the mnemonic would make recovery impossible) —
  both are stored, both can be unlocked and used independently, and if either is
  damaged the other can still recover all addresses.
- **keystore v3 is an interop exit/entry, not a storage format**: on export the
  decrypted private key is wrapped one further level with scrypt/pbkdf2 (the geth
  ecosystem standard); on import, once the private key is decrypted it immediately
  goes through `import_from_private_key`'s storage wrapping. The two KDF sets have
  different semantics (ecosystem interop vs local storage) and are deliberately
  not unified.

### 2.1 Evolution constraints on stored parameters

`EncryptedWalletKey.version = 1`, with KDF parameters taking the crate defaults
and not persisted — a parameter upgrade (e.g. aligning with the OWASP Argon2
recommended values) must: add `version = 2` + persist the parameters + lazy
re-wrap (on reading v1, decrypt with the old parameters and re-wrap/write back with
the new ones), isomorphic to KEY_HIERARCHY.md's re-wrap migration rule. Changing
the default parameters in place is forbidden (it would leave old data undecryptable).

## 3. Password Change and Re-wrap (decision)

Current state (2026-10-13 inventory):

- `change_wallet_password(encrypted_key, old, new)` exists (decrypt with the old one →
  re-wrap with a new salt/nonce); the symmetric `change_mnemonic_password` was added
  (2026-10-13), with the two wired together by the CLI `persona wallet passwd` as
  their production caller.
- Master-password rotation `change_master_password → rewrap_all_item_keys` only covers
  credentials/passkeys item keys; the wrapped material in the `crypto_wallets` table is
  **deliberately left alone**: the wallet password is a second factor independent of
  the master password, so a master password leak should not directly equal a leak of
  fund material (blast-radius isolation, consistent with 1Password's independent
  wallet-password semantics). This is a design decision, not a gap.

Decisions:

1. **The wallet password stays independent of the master password** (entered at
   signing/export; verified by a trial decrypt in `validate_wallet_password`).
2. **New `persona wallet passwd` command** (**implemented 2026-10-13**): in a single
   operation, re-wrap both `encrypted_private_key` and `encrypted_mnemonic` — reusing
   `change_wallet_password` and adding a symmetric `change_mnemonic_password` for
   `EncryptedMnemonic` (both with fresh salt/nonce). Write-back order: first decrypt
   with the old password and re-wrap both materials (any step failing aborts with the
   original row untouched — no half-write), and only on success does `repo.update` write
   back. The old password comes from the same source as signing (prompt interactively,
   `PERSONA_WALLET_PASSWORD` non-interactively); the new password is interactive-only
   (same rule as `persona passwd`: no environment-variable override, so a stale
   environment variable cannot silently rotate the password), comes with a
   confirmation prompt, and must differ from the old password and be ≥8 characters;
   watch-only wallets are refused (nothing to re-wrap).
3. **Not rotated with the master password**: `change_master_password` continuing to
   leave `crypto_wallets` untouched still holds; this is stated in the docs here and
   in the THREAT_MODEL wallet section at the same time.

## 4. Persona Binding Model (decision)

- `CryptoWallet.identity_id` is a foreign key to an `identities` row: a wallet
  belongs to a persona, not to a workspace; listing wallets filters by persona,
  and `watch_only` wallets fall under this same model (no
  `encrypted_private_key`, xpub only).
- **Activation semantics unchanged**: `persona switch` only moves the persona
  pointer; it does not unlock a wallet and does not change wallet visibility;
  signing always requires the wallet password (or the desktop item-password
  second factor `wallet_set_item_password`).
- **The Context suggestion track does not apply to wallets** (v1): the candidates
  offered by suggest are personas, not wallets; wallet selection is always an
  explicit action (`--wallet` / desktop dropdown).
- A single persona can hold multiple wallets across multiple chains; deleting a
  persona cascades to its wallet rows (the current `wallet_repository` semantics
  are preserved).

## 5. Signing-Confirmation UX and Backend Policy (decision)

Invariants (enforced by the backend; the UI is only a presentation layer):

1. **Verify before persist**: ETH/Solana signatures are verified locally after
   signing (`verify_ethereum_transaction` / `verify_solana_transaction`, including a
   recover-to-address comparison); on failure nothing is ever persisted; a BTC
   assembly failure degrades to an audit record only (`audit:<sha256>`) and never
   produces a broadcastable artifact.
2. **Mandatory fields on the confirmation panel**: from (the full signing address),
   to (full address + EIP-55 checksum), amount + precision, fees (gas × price or fee
   rate), chain id (EVM), network. Missing any one of them does not allow a signature
   to be submitted.
3. **Address-poisoning heuristics moved to the backend** (**implemented 2026-10-13**):
   core `crypto/address_poisoning.rs`'s `detect_address_poisoning` (first 6 + last 6
   characters identical, middle different, case-insensitive, never panics on
   character-wise slicing) + `enforce_poisoning_check` (a hit without confirmation
   refuses to sign) is enforced at the backend signing entry points: the CLI
   `create-transaction --sign` check runs before the password prompt, and a hit
   requires an explicit `--confirm-poisoning-check`; the desktop
   `wallet_sign_transaction` is enforced the same way — only after the warning dialog
   is shown and the user confirms a second time does the request carry the
   `confirm_poisoning_check` ack (serde default false; an old frontend missing the
   field is treated as unconfirmed and refused). The known-address set = all wallet
   addresses (this implementation's standard); "+ user flagging" remains open.
4. **The password never leaves the panel**: the desktop password is entered inside
   the modal and cleared in `finally`; the CLI uses the standard password prompt;
   neither is written to logs (the redaction policy has tests).
5. **Audit**: each signature records a digest-level summary (to/amount/fee/chain id
   hash), at the same granularity as SSH signing.

The CLI and the desktop share the `signing_key_for_address → sign_transaction → verify →
persist` chain; the only policy difference is the form of confirmation (desktop modal
vs CLI prompt), while the verification and audit invariants are identical on both ends.

## 6. Threat-Model Extension

See the [THREAT_MODEL.md](THREAT_MODEL.md) "Wallet (experimental track)" section:
wallet keys are classified as the top-tier asset, the export surface
(keystore/WIF/plaintext JSON) has its own boundaries, plus the experimental
declaration and the upgrade path. §2.1/§3 of this doc cross-reference that section.

## 7. Open Questions (need a call, not in this round)

- **Hardware wallets** (Ledger/Trezor): the `WalletType::Hardware` type is reserved;
  whether it enters the mainline awaits the user's call (ROADMAP M5 open question).
- **PSBT workflow**: **the single-sig slice has landed (2026-10-13)** —
  `export-psbt` / `sign-psbt` / `finalize-psbt` (BIP-174, single-sig P2WPKH, core
  `crypto/transaction_psbt.rs`; finalize is homegrown because rust-bitcoin has no
  finalizer; byte-level equality between the direct-sign and PSBT paths is locked by
  a regression anchor). Still open: multi-party `Psbt::combine` co-signing and the
  desktop UI arm.
- **Desktop keystore arm**: ~~`import_wallet_from_request`/`export_wallet_from_request`
  had no keystore branch~~ **completed (2026-10-13)**: desktop `wallet import/export`
  both support `keystore` (export with geth defaults; import decrypts the private key
  then goes through the storage wrapping), with the WalletPanel form and the format
  dropdown kept in sync.
- BIP-84/86 address formats into the default flow (P2WPKH only today).

## 8. Test Inventory (regression anchors)

- geth keystore spec vectors (the official scrypt n=2^18/r=1/p=8 test vector, with a
  triple assertion on ciphertext / MAC / address) + OpenSSL cross-language KDF
  pinning (one each for scrypt/pbkdf2).
- EIP-155 signing spec vectors, BIP-143 P2WPKH byte-by-byte vectors, SLIP-0010
  ed25519 official vectors, BIP-84/86 path-builder vectors (builder layer).
- Password change: `test_password_change` (old ciphertext invalid, new ciphertext
  usable, ciphertexts independent); `mnemonic_password_change_rewraps_with_fresh_salt`
  (symmetric semantics + fresh salt/nonce + wrong old password refused); CLI
  `persona wallet passwd` integration, 4 cases (after both blobs rotate, the new
  password decrypts / the old password fails and salt/nonce have changed; wrong old
  password errors with the original row untouched; watch_only refused;
  same-password / weak-password refused).
- PSBT: `psbt_roundtrip_matches_direct_signing` (direct sign vs export→sign→finalize
  byte-level equality, the RFC-6979 determinism anchor); export determinism /
  deserializability / field completeness + txid invariant; signed per-input
  partial_sigs shape + idempotent re-sign; foreign-key refusal (sign); unsigned /
  foreign-key signature sets refused (finalize); magic check + inputs metadata
  contract reuse; CLI integration, 3 cases (roundtrip wiring, poison-check /
  network gate, watch-only · foreign key · bad base64 refused).
- Tampering paths: keystore ciphertext tampering refused by the MAC, oversized
  scrypt work factor refused, unsupported KDF/cipher/prf refused.
- Address poisoning: 7 core heuristics cases (hit / same-address exemption /
  partial match refused / base58 conservative / case-insensitive / non-ASCII no panic
  / confirmation passes) + CLI integration (unconfirmed refused, passes after
  confirmation) + desktop command layer (missing ack refuses and does not persist,
  ack present signs and persists normally)
  - modal jest (clean address ack=false, spoofed address ack=true).
