// Wallet-specific encryption for private keys and mnemonics

use crate::crypto::encryption::{decrypt_data, encrypt_data};
use crate::crypto::wallet_crypto::MasterKey;
use crate::{PersonaError, PersonaResult};
use serde::{Deserialize, Serialize};
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
    let encrypted_data = encrypt_data(private_key, password.as_bytes())
        .map_err(|e| PersonaError::Cryptography(format!("Failed to encrypt private key: {}", e)))?;

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
        return Err(PersonaError::Cryptography(format!(
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
    .map_err(|e| PersonaError::Cryptography(format!("Failed to decrypt private key: {}", e)))?;

    Ok(decrypted)
}

/// Encrypt mnemonic phrase with user password
pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> PersonaResult<EncryptedMnemonic> {
    let encrypted_data = encrypt_data(mnemonic.as_bytes(), password.as_bytes())
        .map_err(|e| PersonaError::Cryptography(format!("Failed to encrypt mnemonic: {}", e)))?;

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
        return Err(PersonaError::Cryptography(format!(
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
    .map_err(|e| PersonaError::Cryptography(format!("Failed to decrypt mnemonic: {}", e)))?;

    String::from_utf8(decrypted)
        .map_err(|e| PersonaError::Cryptography(format!("Invalid UTF-8 in mnemonic: {}", e)))
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

/// Keystore format (Ethereum-compatible JSON keystore)
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

/// Import from Ethereum keystore JSON
pub fn import_from_keystore(keystore_json: &str, _password: &str) -> PersonaResult<Vec<u8>> {
    let keystore: KeystoreV3 = serde_json::from_str(keystore_json)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid keystore format: {}", e)))?;

    if keystore.version != 3 {
        return Err(PersonaError::InvalidInput(format!(
            "Unsupported keystore version: {}",
            keystore.version
        )));
    }

    // Simplified keystore decryption (production should use proper scrypt/pbkdf2)
    // This is a placeholder for the full implementation
    Err(PersonaError::Cryptography(
        "Keystore import not yet fully implemented".to_string(),
    ))
}

/// Export to Ethereum-compatible keystore JSON
pub fn export_to_keystore(
    _private_key: &[u8],
    _password: &str,
    _address: Option<String>,
) -> PersonaResult<String> {
    // Simplified keystore export (production should use proper scrypt)
    // This is a placeholder for the full implementation
    Err(PersonaError::Cryptography(
        "Keystore export not yet fully implemented".to_string(),
    ))
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
                        kdfparams: KdfParams {
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
                kdfparams: KdfParams {
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

    #[test]
    fn import_from_keystore_v3_reports_unimplemented() {
        let keystore_json = r#"{
            "version": 3,
            "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "address": "008aeeda4d805471d9ce51f053c6c1265d6a6ad9",
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccc4b3b6b0f6de5f1",
                "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
                "kdf": "scrypt",
                "kdfparams": {"dklen": 32, "n": 262144, "p": 8, "r": 1, "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},
                "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8ec01d476db6d3c960fcbfff"
            }
        }"#;
        let err = import_from_keystore(keystore_json, "testpassword")
            .expect_err("v3 import is a placeholder");
        assert!(err.to_string().contains("not yet fully implemented"));
    }

    #[test]
    fn export_to_keystore_is_not_yet_implemented() {
        let err = export_to_keystore(&[1u8; 32], "pw", None)
            .expect_err("keystore export is a placeholder");
        assert!(err
            .to_string()
            .contains("Keystore export not yet fully implemented"));
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
