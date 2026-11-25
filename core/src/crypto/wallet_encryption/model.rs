//! Wallet key wrapping: encryption, decryption, and password rotation for
//! private keys / mnemonics / master keys, plus the in-memory
//! `WalletKeyMaterial` payload.

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
