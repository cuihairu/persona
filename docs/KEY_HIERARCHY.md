# Key Hierarchy

Persona encrypts each stored item with its own random key and wraps that item key with the master key derived from the user's password. This minimizes blast radius: a compromised item key cannot decrypt any other secret.

## Flow

1. Derive the **master key** from the master password + per-user salt via PBKDF2 (100k iterations).
2. When creating a secret, generate a fresh 32-byte **item key**.
3. Encrypt the payload with AES-256-GCM using the item key.
4. Wrap the item key by encrypting it with AES-256-GCM under the master key.
5. Persist both `ciphertext` and `wrapped_item_key` to storage.
6. On read, unwrap the item key with the master key, then decrypt the payload.

## Legacy compatibility

Older rows that lack `wrapped_item_key` are treated as legacy and will be decrypted directly with the master key. New writes always use per-item keys.
