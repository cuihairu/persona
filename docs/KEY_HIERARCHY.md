# Key Hierarchy

Persona encrypts each stored item with its own random key and wraps that item key with the master key derived from the user's password. This minimizes blast radius: a compromised item key cannot decrypt any other secret.

## Flow

1. Derive the **master key** from the master password + per-user salt via PBKDF2 (100k iterations).
2. When creating a secret, generate a fresh 32-byte **item key**.
3. Encrypt the payload with AES-256-GCM using the item key.
4. Wrap the item key by encrypting it with AES-256-GCM under the master key.
5. Persist both `ciphertext` and `wrapped_item_key` to storage.
6. On read, unwrap the item key with the master key, then decrypt the payload.

## KDF paths in the codebase

Persona currently has five distinct password-based KDF paths. They serve different purposes and must not be conflated:

| Path                                          | Algorithm           | Parameters                                                                                      | Used by                                                                                                                                                            |
| --------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Master key derivation (local vault unlock)    | PBKDF2-HMAC-SHA256  | 100,000 iterations                                                                              | `core/src/auth/authentication.rs` (`MasterKeyService::derive_master_key`; wraps item keys). Local only — remote auth is the SRP/Argon2id row below, not PBKDF2       |
| Export/backup encryption (PERSENC1)           | Argon2id            | m=64 MiB / t=3 / p=1 (custom `KdfParams::default`)                                              | `core/src/backup/file_crypto.rs` (CLI `--encrypt` export, encrypted vault backup, travel sidecar — all share the PERSENC1 format)                                   |
| Password hash verification                    | Argon2 (PHC string) | crate defaults                                                                                  | `core/src/crypto/hashing.rs`                                                                                                                                       |
| SRP login pre-hash (remote device auth)       | Argon2id            | crate defaults (m≈19 MiB / t=2 / p=1); domain-separated salt `persona-srp-v1` ‖ server-issued salt | `core/src/auth/srp.rs` (`derive_srp_secret` — derives the bytes fed into the SRP-6a protocol as the "password")                                                     |
| Sync-group pairing short-code KDF             | Argon2id            | crate defaults; domain-separated salt `persona-pairing-v1` ‖ pairing salt                        | `core/src/sync/pairing.rs` (`derive_pairing_secret` — short pairing code → SRP "password" role)                                                                    |

Note: `core/src/crypto/encryption.rs` (Argon2 `Argon2::default()`, i.e. m≈19 MiB / t=2 / p=1) is **not** the export/backup path — it now serves only the wallet keystore (`wallet_encryption.rs`). Do not confuse it with the PERSENC1 KDF above.

The PBKDF2 iteration count and the Argon2 parameters must be re-reviewed quarterly (see `THREAT_MODEL.md`). When raising parameters, apply the change with a re-wrap/re-encrypt migration rather than in place, so existing rows stay readable and legacy rows get upgraded on next write.

## Legacy compatibility

Older rows that lack `wrapped_item_key` are treated as legacy and will be decrypted directly with the master key. New writes always use per-item keys.
