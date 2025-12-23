// Wallet import/export utilities

use crate::crypto::address_generator::{
    generate_bitcoin_address, generate_bitcoin_address_from_compressed_pubkey,
    generate_ethereum_address_checksummed, generate_ethereum_address_checksummed_from_compressed_pubkey,
    BitcoinAddressType,
};
use crate::crypto::wallet_crypto::{
    Bip44PathBuilder, CoinType, DerivedKey, MasterKey, MnemonicWordCount, SecureMnemonic,
};
use crate::crypto::wallet_encryption::{
    decrypt_mnemonic, encrypt_master_key, encrypt_mnemonic, EncryptedMnemonic, EncryptedWalletKey,
    WalletKeyMaterial,
};
use crate::models::wallet::{BlockchainNetwork, CryptoWallet, WalletType};
use crate::{PersonaError, PersonaResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Import format for wallet import
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    /// BIP39 mnemonic phrase
    Mnemonic,
    /// Raw private key (hex)
    PrivateKey,
    /// Ethereum keystore JSON
    Keystore,
    /// WIF (Wallet Import Format) for Bitcoin
    Wif,
}

/// Export format for wallet export
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// BIP39 mnemonic phrase
    Mnemonic,
    /// Raw private key (hex)
    PrivateKey,
    /// Extended public key only
    Xpub,
    /// Full JSON export
    Json,
}

/// Wallet export data
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletExport {
    pub version: u32,
    pub wallet_id: Uuid,
    pub name: String,
    pub network: String,
    pub wallet_type: String,
    pub derivation_path: Option<String>,
    pub mnemonic: Option<String>,
    pub private_keys: Option<HashMap<String, String>>,
    pub addresses: Vec<String>,
    pub created_at: String,
}

/// Import wallet from mnemonic phrase
pub fn import_from_mnemonic(
    identity_id: Uuid,
    name: String,
    mnemonic_phrase: &str,
    passphrase: &str,
    network: BlockchainNetwork,
    derivation_path: Option<String>,
    address_count: usize,
    password: &str,
) -> PersonaResult<CryptoWallet> {
    // Validate mnemonic
    let mnemonic = SecureMnemonic::from_phrase(mnemonic_phrase)?;

    // Create master key
    let master_key = MasterKey::from_mnemonic(&mnemonic, passphrase)?;

    // Determine derivation path
    let path = derivation_path.unwrap_or_else(|| {
        let coin_type = network_to_coin_type(&network);
        Bip44PathBuilder::new(coin_type).build()
    });

    // Encrypt master key
    let encrypted_key = encrypt_master_key(&master_key, password)?;

    // Encrypt mnemonic
    let encrypted_mnemonic_data = encrypt_mnemonic(mnemonic_phrase, password)?;

    // Create wallet
    let mut wallet = CryptoWallet::new(
        identity_id,
        name,
        network.clone(),
        WalletType::HierarchicalDeterministic {
            bip_version: crate::models::wallet::BipVersion::Bip44,
            address_count,
            gap_limit: 20,
        },
        serde_json::to_vec(&encrypted_key)
            .map_err(|e| PersonaError::Cryptography(format!("Serialization error: {}", e)))?,
    );

    wallet.derivation_path = Some(path.clone());
    wallet.extended_public_key = Some(master_key.to_xpub());
    wallet.encrypted_mnemonic = Some(
        serde_json::to_vec(&encrypted_mnemonic_data)
            .map_err(|e| PersonaError::Cryptography(format!("Serialization error: {}", e)))?,
    );

    // Derive addresses
    let addresses = derive_addresses(&master_key, &path, &network, address_count)?;
    wallet.addresses = addresses;

    Ok(wallet)
}

/// Import wallet from private key
pub fn import_from_private_key(
    identity_id: Uuid,
    name: String,
    private_key_hex: &str,
    network: BlockchainNetwork,
    password: &str,
) -> PersonaResult<CryptoWallet> {
    // Parse private key
    let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid hex private key: {}", e)))?;

    if private_key_bytes.len() != 32 {
        return Err(PersonaError::InvalidInput(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    // Encrypt private key
    let encrypted_key =
        crate::crypto::wallet_encryption::encrypt_private_key(&private_key_bytes, password)?;

    // Create wallet
    let mut wallet = CryptoWallet::new(
        identity_id,
        name,
        network,
        WalletType::SingleAddress,
        serde_json::to_vec(&encrypted_key)
            .map_err(|e| PersonaError::Cryptography(format!("Serialization error: {}", e)))?,
    );

    // Derive address from private key (secp256k1)
    let signing_key = k256::ecdsa::SigningKey::from_bytes(private_key_bytes.as_slice().into())
        .map_err(|e| PersonaError::Cryptography(format!("Invalid secp256k1 private key: {}", e)))?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(true);
    let compressed_bytes = encoded.as_bytes();
    let compressed: [u8; 33] = compressed_bytes
        .try_into()
        .map_err(|_| PersonaError::Cryptography("Invalid compressed pubkey".to_string()))?;

    let (address_string, address_type) = match wallet.network {
        BlockchainNetwork::Bitcoin => (
            generate_bitcoin_address_from_compressed_pubkey(
                &compressed,
                BitcoinAddressType::P2WPKH,
                false,
            )?,
            crate::models::wallet::AddressType::P2WPKH,
        ),
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => (
            generate_ethereum_address_checksummed_from_compressed_pubkey(&compressed)?,
            crate::models::wallet::AddressType::Ethereum,
        ),
        other => {
            return Err(PersonaError::Cryptography(format!(
                "Address generation not implemented for {:?}",
                other
            )))
        }
    };

    wallet.addresses.push(crate::models::wallet::WalletAddress {
        address: address_string,
        address_type,
        derivation_path: None,
        index: 0,
        used: false,
        balance: None,
        last_activity: None,
        metadata: HashMap::new(),
        created_at: chrono::Utc::now(),
    });

    Ok(wallet)
}

/// Export wallet mnemonic (requires password)
pub fn export_mnemonic(wallet: &CryptoWallet, password: &str) -> PersonaResult<String> {
    let encrypted_mnemonic_bytes = wallet
        .encrypted_mnemonic
        .as_ref()
        .ok_or_else(|| PersonaError::InvalidInput("Wallet has no mnemonic".to_string()))?;

    let encrypted_mnemonic: EncryptedMnemonic = serde_json::from_slice(encrypted_mnemonic_bytes)
        .map_err(|e| PersonaError::Cryptography(format!("Deserialization error: {}", e)))?;

    decrypt_mnemonic(&encrypted_mnemonic, password)
}

/// Export wallet private key (requires password)
pub fn export_private_key(wallet: &CryptoWallet, password: &str) -> PersonaResult<String> {
    let encrypted_key_bytes = &wallet.encrypted_private_key;

    let encrypted_key: EncryptedWalletKey = serde_json::from_slice(encrypted_key_bytes)
        .map_err(|e| PersonaError::Cryptography(format!("Deserialization error: {}", e)))?;

    let private_key_bytes =
        crate::crypto::wallet_encryption::decrypt_private_key(&encrypted_key, password)?;

    Ok(hex::encode(private_key_bytes))
}

/// Export extended public key (no password required)
pub fn export_xpub(wallet: &CryptoWallet) -> PersonaResult<String> {
    wallet
        .extended_public_key
        .clone()
        .ok_or_else(|| PersonaError::InvalidInput("Wallet has no extended public key".to_string()))
}

/// Export wallet to JSON (with optional private data)
pub fn export_to_json(
    wallet: &CryptoWallet,
    include_private: bool,
    password: Option<&str>,
) -> PersonaResult<String> {
    let mut export = WalletExport {
        version: 1,
        wallet_id: wallet.id,
        name: wallet.name.clone(),
        network: format!("{:?}", wallet.network),
        wallet_type: format!("{:?}", wallet.wallet_type),
        derivation_path: wallet.derivation_path.clone(),
        mnemonic: None,
        private_keys: None,
        addresses: wallet.addresses.iter().map(|a| a.address.clone()).collect(),
        created_at: wallet.created_at.to_rfc3339(),
    };

    if include_private {
        let password = password.ok_or_else(|| {
            PersonaError::InvalidInput("Password required for private data export".to_string())
        })?;

        // Export mnemonic if available
        if let Ok(mnemonic) = export_mnemonic(wallet, password) {
            export.mnemonic = Some(mnemonic);
        }

        // Export private keys if available
        // TODO: Implement address-specific private key export
    }

    serde_json::to_string_pretty(&export)
        .map_err(|e| PersonaError::Cryptography(format!("JSON serialization error: {}", e)))
}

/// Parse import format from string
pub fn parse_import_format(format_str: &str) -> PersonaResult<ImportFormat> {
    match format_str.to_lowercase().as_str() {
        "mnemonic" | "phrase" | "seed" => Ok(ImportFormat::Mnemonic),
        "privatekey" | "private_key" | "key" => Ok(ImportFormat::PrivateKey),
        "keystore" | "json" => Ok(ImportFormat::Keystore),
        "wif" => Ok(ImportFormat::Wif),
        _ => Err(PersonaError::InvalidInput(format!(
            "Unknown import format: {}",
            format_str
        ))),
    }
}

/// Parse export format from string
pub fn parse_export_format(format_str: &str) -> PersonaResult<ExportFormat> {
    match format_str.to_lowercase().as_str() {
        "mnemonic" | "phrase" | "seed" => Ok(ExportFormat::Mnemonic),
        "privatekey" | "private_key" | "key" => Ok(ExportFormat::PrivateKey),
        "xpub" | "extended_public_key" => Ok(ExportFormat::Xpub),
        "json" => Ok(ExportFormat::Json),
        _ => Err(PersonaError::InvalidInput(format!(
            "Unknown export format: {}",
            format_str
        ))),
    }
}

// Helper functions

fn network_to_coin_type(network: &BlockchainNetwork) -> CoinType {
    match network {
        BlockchainNetwork::Bitcoin => CoinType::Bitcoin,
        BlockchainNetwork::Ethereum => CoinType::Ethereum,
        BlockchainNetwork::Solana => CoinType::Solana,
        BlockchainNetwork::Litecoin => CoinType::Litecoin,
        BlockchainNetwork::Dogecoin => CoinType::Dogecoin,
        BlockchainNetwork::Polygon => CoinType::Polygon,
        BlockchainNetwork::Arbitrum => CoinType::Arbitrum,
        BlockchainNetwork::Optimism => CoinType::Optimism,
        BlockchainNetwork::BinanceSmartChain => CoinType::Binance,
        _ => CoinType::Bitcoin, // Default
    }
}

fn derive_addresses(
    master_key: &MasterKey,
    base_path: &str,
    network: &BlockchainNetwork,
    count: usize,
) -> PersonaResult<Vec<crate::models::wallet::WalletAddress>> {
    let mut addresses = Vec::new();

    // Parse base path and derive parent
    let parent_key = master_key.derive_path(base_path)?;

    for i in 0..count {
        let child_key = parent_key.derive_child(i as u32, false)?;
        let address_string = match network {
            BlockchainNetwork::Bitcoin => {
                generate_bitcoin_address(&child_key, BitcoinAddressType::P2WPKH, false)?
            }
            BlockchainNetwork::Ethereum
            | BlockchainNetwork::Polygon
            | BlockchainNetwork::Arbitrum
            | BlockchainNetwork::Optimism
            | BlockchainNetwork::BinanceSmartChain => {
                generate_ethereum_address_checksummed(&child_key)?
            }
            _ => {
                return Err(PersonaError::Cryptography(format!(
                    "Address generation not implemented for {:?}",
                    network
                )))
            }
        };

        let address = crate::models::wallet::WalletAddress {
            address: address_string,
            address_type: match network {
                BlockchainNetwork::Bitcoin => crate::models::wallet::AddressType::P2WPKH,
                _ => crate::models::wallet::AddressType::Ethereum,
            },
            derivation_path: Some(format!("{}/{}", base_path, i)),
            index: i as u32,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        };

        addresses.push(address);
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_from_mnemonic() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let identity_id = Uuid::new_v4();
        let password = "test_password";

        let wallet = import_from_mnemonic(
            identity_id,
            "Test Wallet".to_string(),
            test_mnemonic,
            "",
            BlockchainNetwork::Bitcoin,
            None,
            5,
            password,
        )
        .unwrap();

        assert_eq!(wallet.name, "Test Wallet");
        assert_eq!(wallet.addresses.len(), 5);
        assert!(wallet.extended_public_key.is_some());
        assert!(wallet.encrypted_mnemonic.is_some());
    }

    #[test]
    fn test_export_mnemonic() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let identity_id = Uuid::new_v4();
        let password = "test_password";

        let wallet = import_from_mnemonic(
            identity_id,
            "Test Wallet".to_string(),
            test_mnemonic,
            "",
            BlockchainNetwork::Ethereum,
            None,
            1,
            password,
        )
        .unwrap();

        let exported = export_mnemonic(&wallet, password).unwrap();
        assert_eq!(exported, test_mnemonic);
    }

    #[test]
    fn test_format_parsing() {
        assert_eq!(
            parse_import_format("mnemonic").unwrap(),
            ImportFormat::Mnemonic
        );
        assert_eq!(
            parse_import_format("private_key").unwrap(),
            ImportFormat::PrivateKey
        );
        assert_eq!(parse_export_format("json").unwrap(), ExportFormat::Json);
    }
}
