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

Persona currently has three distinct password-based KDF paths. They serve different purposes and must not be conflated:

| Path | Algorithm | Parameters | Used by |
| --- | --- | --- | --- |
| Master key / auth derivation | PBKDF2-HMAC-SHA256 | 100,000 iterations | `core/src/auth/authentication.rs` (item-key wrapping, remote-auth abstraction) |
| Export/backup encryption | Argon2id | crate defaults | `core/src/crypto/encryption.rs` |
| Password hash verification | Argon2 (PHC string) | crate defaults | `core/src/crypto/hashing.rs` |

The PBKDF2 iteration count and the Argon2 parameters must be re-reviewed quarterly (see `THREAT_MODEL.md`). When raising parameters, apply the change with a re-wrap/re-encrypt migration rather than in place, so existing rows stay readable and legacy rows get upgraded on next write.

## Legacy compatibility

Older rows that lack `wrapped_item_key` are treated as legacy and will be decrypted directly with the master key. New writes always use per-item keys.
