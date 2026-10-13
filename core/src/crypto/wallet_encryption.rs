// Wallet-specific encryption for private keys and mnemonics

use crate::crypto::encryption::{decrypt_data, encrypt_data};
use crate::crypto::wallet_crypto::MasterKey;
use crate::{PersonaError, PersonaResult};
use aes::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encrypted wallet key data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWalletKey {
    /// Encryption metadata
    pub version: u32,
    /// Encrypted private key bytes
    pub encrypted_data: Vec<u8>,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
}

/// Encrypted mnemonic data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMnemonic {
    /// Encryption version
    pub version: u32,
    /// Encrypted mnemonic phrase
    pub encrypted_phrase: Vec<u8>,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
}

/// Wallet key material (in-memory only, never persisted)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WalletKeyMaterial {
    /// Raw private key bytes (32 bytes for secp256k1/ed25519)
    pub private_key: Vec<u8>,
    /// Optional mnemonic phrase
    pub mnemonic: Option<String>,
    /// Derivation path if HD wallet
    pub derivation_path: Option<String>,
}

impl WalletKeyMaterial {
    /// Create from private key bytes
    pub fn from_private_key(private_key: Vec<u8>) -> Self {
        Self {
            private_key,
            mnemonic: None,
            derivation_path: None,
        }
    }

    /// Create from mnemonic
    pub fn from_mnemonic(mnemonic: String, derivation_path: Option<String>) -> Self {
        Self {
            private_key: Vec::new(),
            mnemonic: Some(mnemonic),
            derivation_path,
        }
    }

    /// Check if this contains a mnemonic
    pub fn has_mnemonic(&self) -> bool {
        self.mnemonic.is_some()
    }
}

/// Encrypt private key with user password
pub fn encrypt_private_key(
    private_key: &[u8],
    password: &str,
) -> PersonaResult<EncryptedWalletKey> {
    let encrypted_data = encrypt_data(private_key, password.as_bytes()).map_err(|e| {
        PersonaError::CryptographicError(format!("Failed to encrypt private key: {}", e))
    })?;

    Ok(EncryptedWalletKey {
        version: 1,
        encrypted_data: encrypted_data.ciphertext,
        salt: encrypted_data.salt,
        nonce: encrypted_data.nonce,
    })
}

/// Decrypt private key with user password
pub fn decrypt_private_key(
    encrypted_key: &EncryptedWalletKey,
    password: &str,
) -> PersonaResult<Vec<u8>> {
    if encrypted_key.version != 1 {
        return Err(PersonaError::CryptographicError(format!(
            "Unsupported encryption version: {}",
            encrypted_key.version
        )));
    }

    let decrypted = decrypt_data(
        &encrypted_key.encrypted_data,
        password.as_bytes(),
        &encrypted_key.salt,
        &encrypted_key.nonce,
    )
    .map_err(|e| {
        PersonaError::CryptographicError(format!("Failed to decrypt private key: {}", e))
    })?;

    Ok(decrypted)
}

/// Encrypt mnemonic phrase with user password
pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> PersonaResult<EncryptedMnemonic> {
    let encrypted_data = encrypt_data(mnemonic.as_bytes(), password.as_bytes()).map_err(|e| {
        PersonaError::CryptographicError(format!("Failed to encrypt mnemonic: {}", e))
    })?;

    Ok(EncryptedMnemonic {
        version: 1,
        encrypted_phrase: encrypted_data.ciphertext,
        salt: encrypted_data.salt,
        nonce: encrypted_data.nonce,
    })
}

/// Decrypt mnemonic phrase with user password
pub fn decrypt_mnemonic(
    encrypted_mnemonic: &EncryptedMnemonic,
    password: &str,
) -> PersonaResult<String> {
    if encrypted_mnemonic.version != 1 {
        return Err(PersonaError::CryptographicError(format!(
            "Unsupported encryption version: {}",
            encrypted_mnemonic.version
        )));
    }

    let decrypted = decrypt_data(
        &encrypted_mnemonic.encrypted_phrase,
        password.as_bytes(),
        &encrypted_mnemonic.salt,
        &encrypted_mnemonic.nonce,
    )
    .map_err(|e| PersonaError::CryptographicError(format!("Failed to decrypt mnemonic: {}", e)))?;

    String::from_utf8(decrypted)
        .map_err(|e| PersonaError::CryptographicError(format!("Invalid UTF-8 in mnemonic: {}", e)))
}

/// Encrypt master key for storage
pub fn encrypt_master_key(
    master_key: &MasterKey,
    password: &str,
) -> PersonaResult<EncryptedWalletKey> {
    let key_bytes = master_key.to_bytes();
    encrypt_private_key(&key_bytes, password)
}

/// Decrypt and restore master key
pub fn decrypt_master_key(
    encrypted_key: &EncryptedWalletKey,
    password: &str,
) -> PersonaResult<MasterKey> {
    let key_bytes = decrypt_private_key(encrypted_key, password)?;

    MasterKey::from_bytes(&key_bytes)
}

/// Validate wallet password by attempting decryption
pub fn validate_wallet_password(encrypted_key: &EncryptedWalletKey, password: &str) -> bool {
    decrypt_private_key(encrypted_key, password).is_ok()
}

/// Change wallet password (re-encrypt with new password)
pub fn change_wallet_password(
    encrypted_key: &EncryptedWalletKey,
    old_password: &str,
    new_password: &str,
) -> PersonaResult<EncryptedWalletKey> {
    // Decrypt with old password
    let private_key = decrypt_private_key(encrypted_key, old_password)?;

    // Re-encrypt with new password
    let new_encrypted = encrypt_private_key(&private_key, new_password)?;

    Ok(new_encrypted)
}

/// Change the mnemonic wrapping password (re-encrypt with a fresh salt/nonce).
///
/// Symmetric counterpart of [`change_wallet_password`]; the CLI
/// `wallet passwd` flow re-wraps both blobs in one shot so a wallet is
/// never left with mismatched passwords (WALLET_DESIGN.md §3).
pub fn change_mnemonic_password(
    encrypted_mnemonic: &EncryptedMnemonic,
    old_password: &str,
    new_password: &str,
) -> PersonaResult<EncryptedMnemonic> {
    let phrase = decrypt_mnemonic(encrypted_mnemonic, old_password)?;
    encrypt_mnemonic(&phrase, new_password)
}

/// Keystore format (Web3 Secret Storage v3, the geth/MyCrypto interchange JSON)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeystoreV3 {
    pub version: u32,
    pub id: String,
    pub address: Option<String>,
    pub crypto: KeystoreCrypto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeystoreCrypto {
    pub cipher: String,
    pub ciphertext: String,
    pub cipherparams: CipherParams,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipherParams {
    pub iv: String,
}

/// KDF parameters. The standard names two shapes: scrypt
/// (`{dklen, n, r, p, salt}`) and pbkdf2 (`{dklen, c, prf, salt}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum KdfParams {
    Scrypt {
        dklen: u32,
        n: u32,
        r: u32,
        p: u32,
        salt: String,
    },
    Pbkdf2 {
        dklen: u32,
        c: u32,
        prf: String,
        salt: String,
    },
}

/// scrypt work factors used when exporting. `log_n` encodes n = 2^log_n.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptExportParams {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

/// Geth's standard export work factors (n = 2^18, r = 8, p = 1, ~0.5s native).
pub const SCRYPT_EXPORT_DEFAULT: ScryptExportParams = ScryptExportParams {
    log_n: 18,
    r: 8,
    p: 1,
};

/// Upper bound on scrypt memory (128 * r * n bytes) we are willing to spend
/// while importing an untrusted keystore. Equals geth's default (r=8, n=2^18),
/// so standard exports still import; hostile files asking for more are
/// rejected before any work is done.
const SCRYPT_IMPORT_MAX_MEM: u64 = 256 * 1024 * 1024;

/// Upper bound on the derived-key length accepted from an untrusted keystore.
/// Web3 v3 files use 32; anything above 128 is nonsense, and an unchecked
/// u32 dklen would allocate up to 4 GiB before any check runs.
const KEYSTORE_DKLEN_MAX: u32 = 128;

/// Upper bound on pbkdf2 iteration count accepted from an untrusted keystore.
/// c is a free-form u32; without a cap a hostile file can pin the import for
/// hours. 1,000,000 is ~8x geth's default (262,144) and ~2s of SHA-256 work.
const PBKDF2_IMPORT_MAX_ITERATIONS: u32 = 1_000_000;

fn hex_decode_field(field: &str, name: &str) -> PersonaResult<Vec<u8>> {
    hex::decode(field)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid hex in keystore {name}: {e}")))
}

/// Derive the keystore encryption key (per Web3 Secret Storage v3).
fn derive_keystore_key(crypto: &KeystoreCrypto, password: &str) -> PersonaResult<Vec<u8>> {
    let password_bytes = password.as_bytes();
    let mut dk = match (crypto.kdf.as_str(), &crypto.kdfparams) {
        (
            "scrypt",
            KdfParams::Scrypt {
                dklen,
                n,
                r,
                p,
                salt,
            },
        ) => {
            let salt = hex_decode_field(salt, "kdfparams.salt")?;
            if *r == 0 || *p == 0 || n == &0 {
                return Err(PersonaError::InvalidInput(
                    "Invalid scrypt params: zero work factor".to_string(),
                ));
            }
            let mem = 128u64 * u64::from(*r) * u64::from(*n);
            if mem > SCRYPT_IMPORT_MAX_MEM {
                return Err(PersonaError::InvalidInput(format!(
                    "scrypt work factor too high ({} bytes > {} cap)",
                    mem, SCRYPT_IMPORT_MAX_MEM
                )));
            }
            if *dklen > KEYSTORE_DKLEN_MAX {
                return Err(PersonaError::InvalidInput(format!(
                    "keystore dklen too high ({} > {} cap)",
                    dklen, KEYSTORE_DKLEN_MAX
                )));
            }
            let log_n = u8::try_from(31 - n.leading_zeros())
                .map_err(|_| PersonaError::InvalidInput("scrypt n out of range".to_string()))?;
            if 1u32 << log_n != *n {
                return Err(PersonaError::InvalidInput(
                    "Invalid scrypt params: n must be a power of two".to_string(),
                ));
            }
            let dklen_us = usize::try_from(*dklen).map_err(|_| {
                PersonaError::InvalidInput("keystore dklen out of range".to_string())
            })?;
            let params = scrypt::Params::new(log_n, *r, *p)
                .map_err(|e| PersonaError::InvalidInput(format!("Invalid scrypt params: {e}")))?;
            let mut out = vec![0u8; dklen_us];
            scrypt::scrypt(password_bytes, &salt, &params, &mut out)
                .map_err(|e| PersonaError::CryptographicError(format!("scrypt failed: {e}")))?;
            out
        }
        (
            "pbkdf2",
            KdfParams::Pbkdf2 {
                dklen,
                c,
                prf,
                salt,
            },
        ) => {
            if prf != "hmac-sha256" {
                return Err(PersonaError::InvalidInput(format!(
                    "Unsupported pbkdf2 prf: {prf}"
                )));
            }
            if *c > PBKDF2_IMPORT_MAX_ITERATIONS {
                return Err(PersonaError::InvalidInput(format!(
                    "pbkdf2 work factor too high ({} > {} cap)",
                    c, PBKDF2_IMPORT_MAX_ITERATIONS
                )));
            }
            if *dklen > KEYSTORE_DKLEN_MAX {
                return Err(PersonaError::InvalidInput(format!(
                    "keystore dklen too high ({} > {} cap)",
                    dklen, KEYSTORE_DKLEN_MAX
                )));
            }
            let salt = hex_decode_field(salt, "kdfparams.salt")?;
            let dklen_us = usize::try_from(*dklen).map_err(|_| {
                PersonaError::InvalidInput("keystore dklen out of range".to_string())
            })?;
            let mut out = vec![0u8; dklen_us];
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password_bytes, &salt, *c, &mut out);
            out
        }
        (kdf, _) => {
            return Err(PersonaError::InvalidInput(format!(
                "Unsupported keystore kdf: {kdf}"
            )))
        }
    };
    if dk.len() < 32 {
        dk.zeroize();
        return Err(PersonaError::InvalidInput(
            "keystore dklen must be at least 32".to_string(),
        ));
    }
    Ok(dk)
}

/// Import a private key from Web3 Secret Storage v3 keystore JSON
/// (scrypt or pbkdf2-hmac-sha256 KDF, AES-128-CTR, keccak-256 MAC).
pub fn import_from_keystore(keystore_json: &str, password: &str) -> PersonaResult<Vec<u8>> {
    let keystore: KeystoreV3 = serde_json::from_str(keystore_json)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid keystore format: {}", e)))?;

    if keystore.version != 3 {
        return Err(PersonaError::InvalidInput(format!(
            "Unsupported keystore version: {}",
            keystore.version
        )));
    }
    if keystore.crypto.cipher != "aes-128-ctr" {
        return Err(PersonaError::InvalidInput(format!(
            "Unsupported keystore cipher: {}",
            keystore.crypto.cipher
        )));
    }

    let ciphertext = hex_decode_field(&keystore.crypto.ciphertext, "ciphertext")?;
    let iv = hex_decode_field(&keystore.crypto.cipherparams.iv, "cipherparams.iv")?;
    if iv.len() != 16 {
        return Err(PersonaError::InvalidInput(format!(
            "Invalid keystore iv length: {} (want 16)",
            iv.len()
        )));
    }
    let mac = hex_decode_field(&keystore.crypto.mac, "mac")?;

    let mut dk = derive_keystore_key(&keystore.crypto, password)?;

    // MAC covers dk[16..32] ‖ ciphertext — verify before touching AES.
    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(&dk[16..32]);
    mac_input.extend_from_slice(&ciphertext);
    let expected = sha3::Keccak256::digest(&mac_input);
    let mac_ok: bool = subtle::ConstantTimeEq::ct_eq(&mac[..], &expected[..]).into();
    if !mac_ok {
        dk.zeroize();
        return Err(PersonaError::CryptographicError(
            "Keystore MAC mismatch: wrong password or corrupted keystore".to_string(),
        ));
    }

    let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&dk[..16], &iv)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid keystore key/iv: {e}")))?;
    let mut plaintext = ciphertext.clone();
    cipher.apply_keystream(&mut plaintext);
    dk.zeroize();
    Ok(plaintext)
}

/// Export a private key to Web3 Secret Storage v3 keystore JSON with geth's
/// standard scrypt work factors (n = 2^18, r = 8, p = 1).
pub fn export_to_keystore(
    private_key: &[u8],
    password: &str,
    address: Option<String>,
) -> PersonaResult<String> {
    export_to_keystore_with_params(private_key, password, address, SCRYPT_EXPORT_DEFAULT)
}

/// Export with explicit scrypt work factors (tests and tooling use small
/// factors to stay fast; real exports should use [`SCRYPT_EXPORT_DEFAULT`]).
pub fn export_to_keystore_with_params(
    private_key: &[u8],
    password: &str,
    address: Option<String>,
    params: ScryptExportParams,
) -> PersonaResult<String> {
    if params.r == 0 || params.p == 0 {
        return Err(PersonaError::InvalidInput(
            "Invalid scrypt params: zero work factor".to_string(),
        ));
    }
    if params.log_n > 23 {
        return Err(PersonaError::InvalidInput(
            "Invalid scrypt params: log_n above 23".to_string(),
        ));
    }
    let mem = 128u64 * u64::from(params.r) * (1u64 << params.log_n);
    if mem > SCRYPT_IMPORT_MAX_MEM {
        return Err(PersonaError::InvalidInput(format!(
            "scrypt work factor too high ({} bytes > {} cap)",
            mem, SCRYPT_IMPORT_MAX_MEM
        )));
    }

    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("failed to generate random salt");
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("failed to generate random iv");

    let scrypt_params = scrypt::Params::new(params.log_n, params.r, params.p)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid scrypt params: {e}")))?;
    let mut dk = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), &salt, &scrypt_params, &mut dk)
        .map_err(|e| PersonaError::CryptographicError(format!("scrypt failed: {e}")))?;

    let mut ciphertext = private_key.to_vec();
    ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&dk[..16], &iv)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid key/iv: {e}")))?
        .apply_keystream(&mut ciphertext);

    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(&dk[16..32]);
    mac_input.extend_from_slice(&ciphertext);
    let mac = sha3::Keccak256::digest(&mac_input);
    dk.zeroize();

    let keystore = KeystoreV3 {
        version: 3,
        id: uuid::Uuid::new_v4().to_string(),
        address,
        crypto: KeystoreCrypto {
            cipher: "aes-128-ctr".to_string(),
            ciphertext: hex::encode(&ciphertext),
            cipherparams: CipherParams {
                iv: hex::encode(iv),
            },
            kdf: "scrypt".to_string(),
            kdfparams: KdfParams::Scrypt {
                dklen: 32,
                n: 1u32 << params.log_n,
                r: params.r,
                p: params.p,
                salt: hex::encode(salt),
            },
            mac: hex::encode(mac),
        },
    };
    ciphertext.zeroize();
    serde_json::to_string_pretty(&keystore)
        .map_err(|e| PersonaError::CryptographicError(format!("Failed to serialize keystore: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wallet_crypto::{MnemonicWordCount, SecureMnemonic};
    use proptest::{collection, prelude::*};
    use std::ops::RangeInclusive;
    use uuid::Uuid;

    #[test]
    fn test_private_key_encryption() {
        let private_key = vec![0x42; 32];
        let password = "test_password_123";

        let encrypted = encrypt_private_key(&private_key, password).unwrap();
        assert!(!encrypted.encrypted_data.is_empty());

        let decrypted = decrypt_private_key(&encrypted, password).unwrap();
        assert_eq!(decrypted, private_key);
    }

    #[test]
    fn test_mnemonic_encryption() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "secure_password";

        let encrypted = encrypt_mnemonic(mnemonic, password).unwrap();
        let decrypted = decrypt_mnemonic(&encrypted, password).unwrap();

        assert_eq!(decrypted, mnemonic);
    }

    #[test]
    fn test_password_validation() {
        let private_key = vec![0x99; 32];
        let password = "correct_password";

        let encrypted = encrypt_private_key(&private_key, password).unwrap();

        assert!(validate_wallet_password(&encrypted, password));
        assert!(!validate_wallet_password(&encrypted, "wrong_password"));
    }

    #[test]
    fn test_password_change() {
        let private_key = vec![0xAB; 32];
        let old_password = "old_pass";
        let new_password = "new_pass";

        let encrypted = encrypt_private_key(&private_key, old_password).unwrap();
        let re_encrypted = change_wallet_password(&encrypted, old_password, new_password).unwrap();

        // Old password should not work
        assert!(!validate_wallet_password(&re_encrypted, old_password));

        // New password should work
        assert!(validate_wallet_password(&re_encrypted, new_password));

        // Data should be intact
        let decrypted = decrypt_private_key(&re_encrypted, new_password).unwrap();
        assert_eq!(decrypted, private_key);
    }

    #[test]
    fn mnemonic_password_change_rewraps_with_fresh_salt() {
        let phrase = "test wave barrel tea";

        let encrypted = encrypt_mnemonic(phrase, "old_pass").unwrap();
        let re_encrypted = change_mnemonic_password(&encrypted, "old_pass", "new_pass").unwrap();

        // Old password no longer decrypts; new one restores the phrase.
        assert!(decrypt_mnemonic(&re_encrypted, "old_pass").is_err());
        assert_eq!(decrypt_mnemonic(&re_encrypted, "new_pass").unwrap(), phrase);

        // Fresh salt/nonce: the ciphertext is not byte-identical to the old one.
        assert_ne!(re_encrypted.salt, encrypted.salt);
        assert_ne!(re_encrypted.nonce, encrypted.nonce);

        // Wrong old password is rejected without producing a new blob.
        assert!(change_mnemonic_password(&encrypted, "wrong", "new_pass").is_err());
    }

    #[test]
    fn test_master_key_encryption() {
        let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
        let master_key = MasterKey::from_mnemonic(&mnemonic, "").unwrap();
        let password = "master_password";

        let encrypted = encrypt_master_key(&master_key, password).unwrap();
        let decrypted = decrypt_master_key(&encrypted, password).unwrap();

        // Verify keys match by comparing xpub
        assert_eq!(master_key.to_xpub(), decrypted.to_xpub());
    }

    fn hex_string(range: RangeInclusive<usize>) -> impl Strategy<Value = String> {
        collection::vec(any::<u8>(), range).prop_map(hex::encode)
    }

    fn keystore_strategy() -> impl Strategy<Value = KeystoreV3> {
        (
            proptest::option::of(hex_string(20..=40)),
            hex_string(32..=64),
            hex_string(16..=32),
            hex_string(32..=64),
            hex_string(32..=64),
            hex_string(8..=32),
        )
            .prop_map(
                |(address, ciphertext, iv, mac, salt, _id_fragment)| KeystoreV3 {
                    version: 3,
                    id: Uuid::new_v4().to_string(),
                    address,
                    crypto: KeystoreCrypto {
                        cipher: "aes-128-ctr".to_string(),
                        ciphertext,
                        cipherparams: CipherParams { iv },
                        kdf: "scrypt".to_string(),
                        kdfparams: KdfParams::Scrypt {
                            dklen: 32,
                            n: 16384,
                            p: 1,
                            r: 8,
                            salt,
                        },
                        mac,
                    },
                },
            )
    }

    proptest! {
        #[test]
        fn keystore_json_roundtrip(keystore in keystore_strategy()) {
            let json = serde_json::to_string(&keystore).unwrap();
            let parsed: KeystoreV3 = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, keystore);
        }
    }

    #[test]
    fn wallet_key_material_constructors() {
        let from_key = WalletKeyMaterial::from_private_key(vec![1u8; 32]);
        assert!(!from_key.has_mnemonic());
        assert_eq!(from_key.private_key, vec![1u8; 32]);
        assert!(from_key.derivation_path.is_none());

        let from_mnemonic = WalletKeyMaterial::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            Some("m/44'/60'/0'/0/0".to_string()),
        );
        assert!(from_mnemonic.has_mnemonic());
        assert!(from_mnemonic.private_key.is_empty());
        assert_eq!(
            from_mnemonic.derivation_path.as_deref(),
            Some("m/44'/60'/0'/0/0")
        );
    }

    #[test]
    fn decrypt_private_key_rejects_unknown_version() {
        let encrypted = encrypt_private_key(&[7u8; 32], "pw").unwrap();
        let mut future = encrypted.clone();
        future.version = 2;
        let err = decrypt_private_key(&future, "pw").expect_err("unknown version must be rejected");
        assert!(err
            .to_string()
            .contains("Unsupported encryption version: 2"));
    }

    #[test]
    fn decrypt_mnemonic_rejects_unknown_version() {
        let encrypted = encrypt_mnemonic("test phrase", "pw").unwrap();
        let mut future = encrypted.clone();
        future.version = 99;
        let err = decrypt_mnemonic(&future, "pw").expect_err("unknown version must be rejected");
        assert!(err
            .to_string()
            .contains("Unsupported encryption version: 99"));
    }

    #[test]
    fn decrypt_mnemonic_rejects_non_utf8_payload() {
        let password = "pw";
        // Hand-build an EncryptedMnemonic whose plaintext is not valid UTF-8.
        let encrypted = encrypt_data(&[0xFF, 0xFE, 0xC0], password.as_bytes()).unwrap();
        let forged = EncryptedMnemonic {
            version: 1,
            encrypted_phrase: encrypted.ciphertext,
            salt: encrypted.salt,
            nonce: encrypted.nonce,
        };
        let err =
            decrypt_mnemonic(&forged, password).expect_err("non-UTF-8 mnemonic must be rejected");
        assert!(err.to_string().contains("Invalid UTF-8"));
    }

    #[test]
    fn decrypt_private_key_rejects_wrong_password() {
        let encrypted = encrypt_private_key(&[3u8; 32], "correct").unwrap();
        let err = decrypt_private_key(&encrypted, "wrong").expect_err("wrong password must fail");
        assert!(err.to_string().contains("Failed to decrypt private key"));
    }

    #[test]
    fn decrypt_mnemonic_rejects_wrong_password() {
        let encrypted = encrypt_mnemonic("phrase", "correct").unwrap();
        let err = decrypt_mnemonic(&encrypted, "wrong").expect_err("wrong password must fail");
        assert!(err.to_string().contains("Failed to decrypt mnemonic"));
    }

    #[test]
    fn mnemonic_encryption_roundtrip_with_special_chars() {
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        // Non-ASCII exercises the UTF-8 path end to end.
        let unicode_phrase = "成功 ハэлло wörld";
        let password = "pw-😀";
        for phrase in [phrase, unicode_phrase] {
            let encrypted = encrypt_mnemonic(phrase, password).unwrap();
            assert_eq!(encrypted.version, 1);
            assert_eq!(decrypt_mnemonic(&encrypted, password).unwrap(), phrase);
        }
    }

    #[test]
    fn import_from_keystore_rejects_malformed_json() {
        let err = import_from_keystore("not json at all", "pw")
            .expect_err("malformed keystore JSON must be rejected");
        assert!(err.to_string().contains("Invalid keystore format"));
    }

    #[test]
    fn import_from_keystore_rejects_wrong_version() {
        let keystore = KeystoreV3 {
            version: 1,
            id: Uuid::new_v4().to_string(),
            address: None,
            crypto: KeystoreCrypto {
                cipher: "aes-128-ctr".to_string(),
                ciphertext: "aa".to_string(),
                cipherparams: CipherParams {
                    iv: "bb".to_string(),
                },
                kdf: "scrypt".to_string(),
                kdfparams: KdfParams::Scrypt {
                    dklen: 32,
                    n: 16384,
                    p: 1,
                    r: 8,
                    salt: "cc".to_string(),
                },
                mac: "dd".to_string(),
            },
        };
        let json = serde_json::to_string(&keystore).unwrap();
        let err = import_from_keystore(&json, "pw").expect_err("non-v3 keystore must be rejected");
        assert!(err.to_string().contains("Unsupported keystore version: 1"));
    }

    /// The canonical scrypt vector from go-ethereum's own testdata
    /// (`accounts/keystore/testdata/v3_test_vector.json`, the
    /// "wikipage_test_vector_scrypt" entry). Conformance is self-contained:
    /// a wrong MAC formula fails the MAC check; wrong AES/CTR composition
    /// yields a key whose address cannot match the spec's published address.
    #[test]
    fn import_from_keystore_spec_vector() {
        let keystore_json = r#"{
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
                "kdf": "scrypt",
                "kdfparams": {"dklen": 32, "n": 262144, "r": 1, "p": 8, "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},
                "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
            },
            "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version": 3
        }"#;
        let secret = import_from_keystore(keystore_json, "testpassword")
            .expect("canonical spec vector must decrypt");
        assert_eq!(
            hex::encode(&secret),
            "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
        );

        // secp256k1 address of the recovered key must equal the spec's
        // published address: keccak256(pubkey_xy)[12..].
        let signing_key = k256::ecdsa::SigningKey::from_slice(&secret)
            .expect("recovered key is a valid secp256k1 key");
        let uncompressed = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let hash = sha3::Keccak256::digest(&uncompressed[1..]);
        let address = hex::encode(&hash[12..]);
        assert_eq!(address, "008aeeda4d805471df9b2a5b0f38a0c3bcba786b");

        // Wrong password must fail at the MAC, not produce garbage.
        let err = import_from_keystore(keystore_json, "wrongpassword")
            .expect_err("wrong password must not decrypt");
        assert!(err.to_string().contains("MAC mismatch"));
    }

    /// scrypt KDF layer cross-checked against OpenSSL (python hashlib.scrypt):
    /// password "test", salt aa×16, n=16 r=1 p=1 dklen=32.
    #[test]
    fn keystore_scrypt_derivation_matches_openssl() {
        let crypto = KeystoreCrypto {
            cipher: "aes-128-ctr".to_string(),
            ciphertext: "00".to_string(),
            cipherparams: CipherParams {
                iv: "00".repeat(16),
            },
            kdf: "scrypt".to_string(),
            kdfparams: KdfParams::Scrypt {
                dklen: 32,
                n: 16,
                r: 1,
                p: 1,
                salt: "aa".repeat(16),
            },
            mac: "00".to_string(),
        };
        let dk = derive_keystore_key(&crypto, "test").unwrap();
        assert_eq!(
            hex::encode(dk),
            "977a0f4a5c2267090ead966af8edd176a319dec3607cfcbb0b2436687408ffea"
        );
    }

    /// pbkdf2 KDF layer cross-checked against OpenSSL (python
    /// hashlib.pbkdf2_hmac): password "test", salt bb×8, c=1000, sha256.
    #[test]
    fn keystore_pbkdf2_derivation_matches_openssl() {
        let crypto = KeystoreCrypto {
            cipher: "aes-128-ctr".to_string(),
            ciphertext: "00".to_string(),
            cipherparams: CipherParams {
                iv: "00".repeat(16),
            },
            kdf: "pbkdf2".to_string(),
            kdfparams: KdfParams::Pbkdf2 {
                dklen: 32,
                c: 1000,
                prf: "hmac-sha256".to_string(),
                salt: "bb".repeat(8),
            },
            mac: "00".to_string(),
        };
        let dk = derive_keystore_key(&crypto, "test").unwrap();
        assert_eq!(
            hex::encode(dk),
            "78862acd1a1b83cc9120c3214f52ae2e04c19918ebd6f6019231ac41189efb35"
        );
    }

    /// Build a full pbkdf2 keystore JSON for roundtrip tests (the KDF layer
    /// itself is pinned to OpenSSL above; this exercises the MAC + AES
    /// composition through the same public surface as a real file).
    fn build_pbkdf2_keystore_json(secret: &[u8], password: &str, c: u32) -> String {
        use sha3::Digest;
        let salt = [0x42u8; 16];
        let iv = [0x43u8; 16];
        let mut dk = vec![0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, c, &mut dk);
        let mut ciphertext = secret.to_vec();
        ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&dk[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
        mac_input.extend_from_slice(&dk[16..32]);
        mac_input.extend_from_slice(&ciphertext);
        let mac = sha3::Keccak256::digest(&mac_input);
        serde_json::json!({
            "version": 3,
            "id": Uuid::new_v4(),
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": hex::encode(&ciphertext),
                "cipherparams": {"iv": hex::encode(iv)},
                "kdf": "pbkdf2",
                "kdfparams": {
                    "dklen": 32, "c": c, "prf": "hmac-sha256", "salt": hex::encode(salt)
                },
                "mac": hex::encode(mac)
            }
        })
        .to_string()
    }

    #[test]
    fn pbkdf2_keystore_roundtrip() {
        let secret = [0x5Au8; 32];
        let json = build_pbkdf2_keystore_json(&secret, "roundtrip-pass", 1000);
        let recovered = import_from_keystore(&json, "roundtrip-pass").unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn keystore_scrypt_export_roundtrip() {
        let secret = [0xC0u8; 32];
        let json = export_to_keystore_with_params(
            &secret,
            "export-pass",
            Some("008aeeda4d805471d9ce51f053c6c1265d6a6ad9".to_string()),
            ScryptExportParams {
                log_n: 4,
                r: 1,
                p: 1,
            },
        )
        .unwrap();
        let parsed: KeystoreV3 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 3);
        assert_eq!(
            parsed.address.as_deref(),
            Some("008aeeda4d805471d9ce51f053c6c1265d6a6ad9")
        );
        let recovered = import_from_keystore(&json, "export-pass").unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn keystore_tampered_ciphertext_fails_mac() {
        let secret = [0x11u8; 32];
        let json = build_pbkdf2_keystore_json(&secret, "mac-pass", 1000);
        let mut keystore: KeystoreV3 = serde_json::from_str(&json).unwrap();
        // Flip one bit of the ciphertext.
        let mut ct = hex::decode(&keystore.crypto.ciphertext).unwrap();
        ct[0] ^= 0x01;
        keystore.crypto.ciphertext = hex::encode(ct);
        let err = import_from_keystore(&serde_json::to_string(&keystore).unwrap(), "mac-pass")
            .expect_err("tampered ciphertext must fail the MAC");
        assert!(err.to_string().contains("MAC mismatch"));
    }

    #[test]
    fn keystore_rejects_unsupported_kdf_cipher_and_prf() {
        let secret = [0x22u8; 32];
        let json = build_pbkdf2_keystore_json(&secret, "fmt-pass", 100);
        let bad_kdf = json.replace("\"pbkdf2\"", "\"bcrypt\"");
        let err = import_from_keystore(&bad_kdf, "fmt-pass")
            .expect_err("unsupported kdf must be rejected");
        assert!(err.to_string().contains("Unsupported keystore kdf"));

        let bad_cipher = json.replace("aes-128-ctr", "aes-256-cbc");
        let err = import_from_keystore(&bad_cipher, "fmt-pass")
            .expect_err("unsupported cipher must be rejected");
        assert!(err.to_string().contains("Unsupported keystore cipher"));

        let bad_prf = json.replace("hmac-sha256", "hmac-sha512");
        let err = import_from_keystore(&bad_prf, "fmt-pass")
            .expect_err("unsupported prf must be rejected");
        assert!(err.to_string().contains("Unsupported pbkdf2 prf"));
    }

    #[test]
    fn keystore_rejects_oversized_scrypt_work_factor() {
        let crypto = KeystoreCrypto {
            cipher: "aes-128-ctr".to_string(),
            ciphertext: "00".to_string(),
            cipherparams: CipherParams {
                iv: "00".repeat(16),
            },
            kdf: "scrypt".to_string(),
            // 128 * r * n = 128 * 8 * 2^24 = 4 GiB > 256 MiB cap.
            kdfparams: KdfParams::Scrypt {
                dklen: 32,
                n: 16_777_216,
                r: 8,
                p: 1,
                salt: "aa".repeat(16),
            },
            mac: "00".to_string(),
        };
        let keystore = KeystoreV3 {
            version: 3,
            id: Uuid::new_v4().to_string(),
            address: None,
            crypto,
        };
        let json = serde_json::to_string(&keystore).unwrap();
        let err = import_from_keystore(&json, "pw")
            .expect_err("oversized scrypt must be rejected before any work");
        assert!(err.to_string().contains("work factor too high"));
    }

    /// pbkdf2 迭代数无上界 = 恶意 keystore 可让导入挂死（c 是 u32，
    /// 40 亿次 HMAC 在真机上要跑数小时）。必须在派生前拒绝。
    #[test]
    fn keystore_rejects_oversized_pbkdf2_iterations() {
        let json = build_pbkdf2_keystore_json(&[0x33u8; 32], "pw", 100)
            .replace("\"c\":100", "\"c\":4000000000");
        let err = import_from_keystore(&json, "pw")
            .expect_err("oversized pbkdf2 iteration count must be rejected before any work");
        assert!(
            err.to_string().contains("work factor too high"),
            "unexpected error: {err}"
        );
    }

    /// dklen 无上界 = 恶意 keystore 可凭一个 u32 让派生输出缓冲直接分配
    /// 4 GiB（u32::MAX），内存 DoS。scrypt 与 pbkdf2 两条 KDF 臂都要拦。
    #[test]
    fn keystore_rejects_oversized_dklen_before_allocating() {
        let base = build_pbkdf2_keystore_json(&[0x44u8; 32], "pw", 100);
        let json = base.replace("\"dklen\":32", "\"dklen\":4000000000");
        let err = import_from_keystore(&json, "pw")
            .expect_err("oversized pbkdf2 dklen must be rejected before allocating");
        assert!(err.to_string().contains("dklen"), "unexpected error: {err}");

        let crypto = KeystoreCrypto {
            cipher: "aes-128-ctr".to_string(),
            ciphertext: "00".to_string(),
            cipherparams: CipherParams {
                iv: "00".repeat(16),
            },
            kdf: "scrypt".to_string(),
            kdfparams: KdfParams::Scrypt {
                dklen: 4_000_000_000,
                n: 1024,
                r: 8,
                p: 1,
                salt: "aa".repeat(16),
            },
            mac: "00".to_string(),
        };
        let keystore = KeystoreV3 {
            version: 3,
            id: Uuid::new_v4().to_string(),
            address: None,
            crypto,
        };
        let json = serde_json::to_string(&keystore).unwrap();
        let err = import_from_keystore(&json, "pw")
            .expect_err("oversized scrypt dklen must be rejected before allocating");
        assert!(err.to_string().contains("dklen"), "unexpected error: {err}");
    }

    /// 确定性变异 harness：以合法小工作因子 keystore 为基线，做字节翻转、
    /// 截断与字段级篡改，断言解析器是全函数——任何变异要么 Ok 要么 Err，
    /// 绝不 panic。补上 ROADMAP 登记的 keystore 变异 harness 缺口。
    #[test]
    fn keystore_mutation_harness_is_total() {
        let base = build_pbkdf2_keystore_json(&[0x55u8; 32], "harness-pass", 100);
        // 基线本身必须可解，否则 harness 锚点失效。
        assert!(import_from_keystore(&base, "harness-pass").is_ok());

        let mut cases: Vec<(String, String)> = Vec::new();
        let bytes = base.as_bytes();
        // 字节翻转：全串按步长取样，每个位置打三种替换值。
        for pos in (0..bytes.len()).step_by(7) {
            for val in [0x00u8, 0xFF, 0x22] {
                let mut mutated = base.clone().into_bytes();
                mutated[pos] = val;
                cases.push((
                    format!("flip@{pos}=0x{val:02X}"),
                    String::from_utf8_lossy(&mutated).into_owned(),
                ));
            }
        }
        // 截断：从空串到接近全长的锚点长度。
        for len in [0usize, 1, 2, 5, 10, 50, 100, base.len() / 2, base.len() - 1] {
            cases.push((
                format!("truncate@{len}"),
                base[..len.min(base.len())].to_string(),
            ));
        }
        // 字段级篡改：类型混淆、未知算法、越界参数、坏 hex。
        for (label, mutation) in [
            (
                "version-string",
                base.replace("\"version\":3", "\"version\":\"3\""),
            ),
            (
                "version-zero",
                base.replace("\"version\":3", "\"version\":0"),
            ),
            ("cipher-unknown", base.replace("aes-128-ctr", "aes-256-gcm")),
            ("kdf-unknown", base.replace("\"pbkdf2\"", "\"argon2id\"")),
            ("prf-unknown", base.replace("hmac-sha256", "hmac-sha1")),
            ("c-negative", base.replace("\"c\":100", "\"c\":-1")),
            ("c-huge", base.replace("\"c\":100", "\"c\":4000000000")),
            (
                "dklen-huge",
                base.replace("\"dklen\":32", "\"dklen\":4000000000"),
            ),
            ("dklen-zero", base.replace("\"dklen\":32", "\"dklen\":0")),
            (
                "iv-short",
                base.replace("43434343434343434343434343434343", "4343"),
            ),
            (
                "iv-odd-hex",
                base.replace(
                    "43434343434343434343434343434343",
                    "4343434343434343434343434343434g",
                ),
            ),
            ("mac-empty", {
                // 用 serde 改 mac 更稳：直接定位 `"mac":"..."` 值段。
                let mut keystore: serde_json::Value = serde_json::from_str(&base).unwrap();
                keystore["crypto"]["mac"] = serde_json::json!("");
                keystore.to_string()
            }),
            ("salt-nonhex", {
                let mut keystore: serde_json::Value = serde_json::from_str(&base).unwrap();
                keystore["crypto"]["kdfparams"]["salt"] = serde_json::json!("zz-not-hex");
                keystore.to_string()
            }),
            ("ciphertext-array", {
                let mut keystore: serde_json::Value = serde_json::from_str(&base).unwrap();
                keystore["crypto"]["ciphertext"] = serde_json::json!([1, 2, 3]);
                keystore.to_string()
            }),
        ] {
            cases.push((label.to_string(), mutation));
        }

        for (label, mutated) in cases {
            let result =
                std::panic::catch_unwind(|| import_from_keystore(&mutated, "harness-pass"));
            match result {
                Ok(Ok(_)) | Ok(Err(_)) => {} // 全函数：两种返回都合法
                Err(_) => panic!("keystore mutation harness panicked on case: {label}"),
            }
        }
    }

    #[test]
    fn master_key_encryption_rejects_wrong_password() {
        let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
        let master_key = MasterKey::from_mnemonic(&mnemonic, "").unwrap();
        let encrypted = encrypt_master_key(&master_key, "right").unwrap();
        assert!(decrypt_master_key(&encrypted, "wrong").is_err());
        assert!(decrypt_master_key(&encrypted, "right").is_ok());
    }
}
