// Wallet-specific encryption for private keys and mnemonics

use crate::crypto::encryption::{decrypt_data, encrypt_data};
use crate::crypto::wallet_crypto::{MasterKey, SecureMnemonic};
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
    let encrypted_data = encrypt_data(private_key, password.as_bytes())?;

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
    )?;

    Ok(decrypted)
}

/// Encrypt mnemonic phrase with user password
pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> PersonaResult<EncryptedMnemonic> {
    let encrypted_data = encrypt_data(mnemonic.as_bytes(), password.as_bytes())?;

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
    )?;

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

    if key_bytes.len() != 78 {
        return Err(PersonaError::Cryptography(
            "Invalid key length for master key".to_string(),
        ));
    }

    let mut key_array = [0u8; 78];
    key_array.copy_from_slice(&key_bytes);

    MasterKey::from_bytes(&key_array)
}

/// Validate wallet password by attempting decryption
pub fn validate_wallet_password(
    encrypted_key: &EncryptedWalletKey,
    password: &str,
) -> bool {
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
#[derive(Debug, Serialize, Deserialize)]
pub struct KeystoreV3 {
    pub version: u32,
    pub id: String,
    pub address: Option<String>,
    pub crypto: KeystoreCrypto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeystoreCrypto {
    pub cipher: String,
    pub ciphertext: String,
    pub cipherparams: CipherParams,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

/// Import from Ethereum keystore JSON
pub fn import_from_keystore(
    keystore_json: &str,
    password: &str,
) -> PersonaResult<Vec<u8>> {
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
    private_key: &[u8],
    password: &str,
    address: Option<String>,
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

    #[test]
    fn test_private_key_encryption() {
        let private_key = vec![0x42; 32];
        let password = "test_password_123";

        let encrypted = encrypt_private_key(&private_key, password).unwrap();
        assert!(encrypted.encrypted_data.len() > 0);

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
}
