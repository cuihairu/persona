// Wallet import/export utilities

use crate::crypto::address_generator::{
    generate_bitcoin_address, generate_bitcoin_address_from_compressed_pubkey,
    generate_ethereum_address_checksummed,
    generate_ethereum_address_checksummed_from_compressed_pubkey, BitcoinAddressType,
};
use crate::crypto::wallet_crypto::{MasterKey, SecureMnemonic};
use crate::crypto::wallet_encryption::{
    decrypt_master_key, decrypt_mnemonic, decrypt_private_key, encrypt_master_key,
    encrypt_mnemonic, EncryptedMnemonic, EncryptedWalletKey,
};
use crate::models::wallet::{BlockchainNetwork, CryptoWallet, WalletType};
use crate::{PersonaError, PersonaResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Import format for wallet import
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    /// BIP39 mnemonic phrase
    Mnemonic,
    /// Raw private key (hex)
    PrivateKey,
    /// Persona wallet JSON export
    Json,
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
    /// Bitcoin WIF (Wallet Import Format)
    Wif,
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
    #[serde(default)]
    pub extended_public_key: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub watch_only: bool,
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
    let path =
        derivation_path.unwrap_or_else(|| CryptoWallet::recommended_derivation_path(&network, 0));

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

/// Import wallet from Bitcoin WIF (compressed mainnet only)
pub fn import_from_wif(
    identity_id: Uuid,
    name: String,
    wif: &str,
    password: &str,
) -> PersonaResult<CryptoWallet> {
    let decoded = bs58::decode(wif)
        .into_vec()
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid WIF encoding: {}", e)))?;

    if decoded.len() < 5 {
        return Err(PersonaError::InvalidInput("Invalid WIF length".to_string()));
    }

    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let expected_checksum = double_sha256(payload);
    if checksum != &expected_checksum[..4] {
        return Err(PersonaError::InvalidInput(
            "Invalid WIF checksum".to_string(),
        ));
    }

    let version = payload
        .first()
        .copied()
        .ok_or_else(|| PersonaError::InvalidInput("Missing WIF version byte".to_string()))?;

    if version == 0xEF {
        return Err(PersonaError::InvalidInput(
            "Bitcoin testnet WIF is not supported yet".to_string(),
        ));
    }

    if version != 0x80 {
        return Err(PersonaError::InvalidInput(format!(
            "Unsupported WIF version byte: 0x{version:02x}"
        )));
    }

    let compressed = match payload.len() {
        34 if payload[33] == 0x01 => true,
        33 => false,
        _ => {
            return Err(PersonaError::InvalidInput(
                "Unsupported WIF payload length".to_string(),
            ))
        }
    };

    if !compressed {
        return Err(PersonaError::InvalidInput(
            "Uncompressed WIF is not supported yet".to_string(),
        ));
    }

    let private_key_hex = hex::encode(&payload[1..33]);
    import_from_private_key(
        identity_id,
        name,
        &private_key_hex,
        BlockchainNetwork::Bitcoin,
        password,
    )
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
    let private_keys = export_private_keys(wallet, password)?;

    if let Some(first_private_key) = wallet
        .addresses
        .iter()
        .find_map(|address| private_keys.get(&address.address))
    {
        return Ok(first_private_key.clone());
    }

    private_keys.into_values().next().ok_or_else(|| {
        PersonaError::InvalidInput("Wallet does not contain an exportable private key".to_string())
    })
}

/// Export wallet private key as Bitcoin WIF (requires password)
pub fn export_to_wif(wallet: &CryptoWallet, password: &str) -> PersonaResult<String> {
    if wallet.watch_only {
        return Err(PersonaError::InvalidInput(
            "Watch-only wallets cannot export WIF".to_string(),
        ));
    }

    if wallet.network != BlockchainNetwork::Bitcoin {
        return Err(PersonaError::InvalidInput(
            "WIF export is only supported for Bitcoin wallets".to_string(),
        ));
    }

    if !matches!(wallet.wallet_type, WalletType::SingleAddress) {
        return Err(PersonaError::InvalidInput(
            "WIF export is only supported for single-address Bitcoin wallets".to_string(),
        ));
    }

    let encrypted_key: EncryptedWalletKey =
        serde_json::from_slice(&wallet.encrypted_private_key)
            .map_err(|e| PersonaError::Cryptography(format!("Deserialization error: {}", e)))?;
    let private_key_bytes = decrypt_private_key(&encrypted_key, password)?;
    let mut payload = Vec::with_capacity(38);
    payload.push(0x80);
    payload.extend_from_slice(&private_key_bytes);
    payload.push(0x01);

    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    Ok(bs58::encode(payload).into_string())
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
        extended_public_key: wallet.extended_public_key.clone(),
        description: wallet.description.clone(),
        watch_only: wallet.watch_only,
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

        let private_keys = export_private_keys(wallet, password)?;
        if !private_keys.is_empty() {
            export.private_keys = Some(private_keys);
        }
    }

    serde_json::to_string_pretty(&export)
        .map_err(|e| PersonaError::Cryptography(format!("JSON serialization error: {}", e)))
}

/// Import wallet from Persona JSON export
pub fn import_from_json(
    identity_id: Uuid,
    fallback_name: Option<String>,
    json: &str,
    password: &str,
) -> PersonaResult<CryptoWallet> {
    let export: WalletExport = serde_json::from_str(json)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid wallet JSON export: {}", e)))?;

    let wallet_name = fallback_name
        .or_else(|| (!export.name.trim().is_empty()).then(|| export.name.clone()))
        .ok_or_else(|| PersonaError::InvalidInput("Wallet export is missing a name".to_string()))?;
    let network = parse_network_name(&export.network)?;
    let address_count = export.addresses.len().max(1);

    let mut wallet = if let Some(mnemonic) = export.mnemonic.as_deref() {
        import_from_mnemonic(
            identity_id,
            wallet_name,
            mnemonic,
            "",
            network,
            export.derivation_path.clone(),
            address_count,
            password,
        )?
    } else if let Some(private_keys) = export.private_keys.as_ref() {
        let private_key = private_keys.values().next().ok_or_else(|| {
            PersonaError::InvalidInput(
                "Wallet export does not contain any private keys".to_string(),
            )
        })?;

        import_from_private_key(identity_id, wallet_name, private_key, network, password)?
    } else {
        return Err(PersonaError::InvalidInput(
            "Wallet JSON import requires mnemonic or private key data".to_string(),
        ));
    };

    wallet.description = export.description;
    wallet.extended_public_key = export.extended_public_key;

    Ok(wallet)
}

/// Parse import format from string
pub fn parse_import_format(format_str: &str) -> PersonaResult<ImportFormat> {
    match format_str.to_lowercase().as_str() {
        "mnemonic" | "phrase" | "seed" => Ok(ImportFormat::Mnemonic),
        "privatekey" | "private_key" | "key" => Ok(ImportFormat::PrivateKey),
        "json" => Ok(ImportFormat::Json),
        "keystore" => Ok(ImportFormat::Keystore),
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
        "wif" => Ok(ExportFormat::Wif),
        "xpub" | "extended_public_key" => Ok(ExportFormat::Xpub),
        "json" => Ok(ExportFormat::Json),
        _ => Err(PersonaError::InvalidInput(format!(
            "Unknown export format: {}",
            format_str
        ))),
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

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

fn parse_network_name(network: &str) -> PersonaResult<BlockchainNetwork> {
    match network.trim().to_lowercase().as_str() {
        "bitcoin" => Ok(BlockchainNetwork::Bitcoin),
        "ethereum" => Ok(BlockchainNetwork::Ethereum),
        "solana" => Ok(BlockchainNetwork::Solana),
        "bitcoincash" | "bitcoin cash" => Ok(BlockchainNetwork::BitcoinCash),
        "litecoin" => Ok(BlockchainNetwork::Litecoin),
        "dogecoin" => Ok(BlockchainNetwork::Dogecoin),
        "polygon" => Ok(BlockchainNetwork::Polygon),
        "arbitrum" => Ok(BlockchainNetwork::Arbitrum),
        "optimism" => Ok(BlockchainNetwork::Optimism),
        "binancesmartchain" | "binance smart chain" => Ok(BlockchainNetwork::BinanceSmartChain),
        other => Ok(BlockchainNetwork::Custom(other.to_string())),
    }
}

fn export_private_keys(
    wallet: &CryptoWallet,
    password: &str,
) -> PersonaResult<HashMap<String, String>> {
    if wallet.watch_only {
        return Ok(HashMap::new());
    }

    let encrypted_key: EncryptedWalletKey =
        serde_json::from_slice(&wallet.encrypted_private_key)
            .map_err(|e| PersonaError::Cryptography(format!("Deserialization error: {}", e)))?;

    match wallet.wallet_type {
        WalletType::HierarchicalDeterministic { .. } => {
            let master_key = decrypt_master_key(&encrypted_key, password)?;
            let mut private_keys = HashMap::new();

            for address in &wallet.addresses {
                let derivation_path = address.derivation_path.as_deref().ok_or_else(|| {
                    PersonaError::InvalidInput(format!(
                        "Wallet address {} is missing a derivation path",
                        address.address
                    ))
                })?;

                let derived_key = master_key.derive_path(derivation_path)?;
                private_keys.insert(
                    address.address.clone(),
                    hex::encode(derived_key.private_key_bytes()),
                );
            }

            Ok(private_keys)
        }
        _ => {
            let private_key_bytes = decrypt_private_key(&encrypted_key, password)?;
            let key = hex::encode(private_key_bytes);
            let export_key = wallet
                .addresses
                .first()
                .map(|address| address.address.clone())
                .unwrap_or_else(|| "primary".to_string());

            Ok(HashMap::from([(export_key, key)]))
        }
    }
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
        assert_eq!(wallet.derivation_path.as_deref(), Some("m/44'/0'/0'/0"));
        assert!(wallet.extended_public_key.is_some());
        assert!(wallet.encrypted_mnemonic.is_some());
        assert_eq!(
            wallet
                .addresses
                .first()
                .and_then(|address| address.derivation_path.as_deref()),
            Some("m/44'/0'/0'/0/0")
        );
        assert_eq!(
            wallet
                .addresses
                .get(1)
                .and_then(|address| address.derivation_path.as_deref()),
            Some("m/44'/0'/0'/0/1")
        );
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
        assert_eq!(parse_import_format("json").unwrap(), ImportFormat::Json);
        assert_eq!(parse_import_format("keystore").unwrap(), ImportFormat::Keystore);
        assert_eq!(parse_export_format("json").unwrap(), ExportFormat::Json);
    }

    #[test]
    fn test_export_private_key_for_single_address_wallet() {
        let identity_id = Uuid::new_v4();
        let password = "test_password";
        let private_key = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";

        let wallet = import_from_private_key(
            identity_id,
            "Single Address".to_string(),
            private_key,
            BlockchainNetwork::Ethereum,
            password,
        )
        .unwrap();

        let exported = export_private_key(&wallet, password).unwrap();
        assert_eq!(exported, private_key);
    }

    #[test]
    fn test_import_from_wif() {
        let identity_id = Uuid::new_v4();
        let password = "test_password";
        let private_key = [0x11u8; 32];
        let wif = encode_compressed_mainnet_wif(&private_key);

        let wallet =
            import_from_wif(identity_id, "WIF Wallet".to_string(), &wif, password).unwrap();

        assert_eq!(wallet.name, "WIF Wallet");
        assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
        assert_eq!(wallet.addresses.len(), 1);
    }

    #[test]
    fn test_export_to_wif_for_bitcoin_single_address_wallet() {
        let identity_id = Uuid::new_v4();
        let password = "test_password";
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";

        let wallet = import_from_private_key(
            identity_id,
            "BTC Wallet".to_string(),
            private_key,
            BlockchainNetwork::Bitcoin,
            password,
        )
        .unwrap();

        let exported = export_to_wif(&wallet, password).unwrap();
        let roundtrip =
            import_from_wif(identity_id, "Roundtrip".to_string(), &exported, password).unwrap();

        assert_eq!(roundtrip.network, BlockchainNetwork::Bitcoin);
        assert_eq!(
            export_private_key(&roundtrip, password).unwrap(),
            private_key
        );
    }

    #[test]
    fn test_export_json_includes_private_keys_for_hd_wallet() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let identity_id = Uuid::new_v4();
        let password = "test_password";

        let wallet = import_from_mnemonic(
            identity_id,
            "HD Wallet".to_string(),
            mnemonic,
            "",
            BlockchainNetwork::Ethereum,
            None,
            2,
            password,
        )
        .unwrap();

        let exported = export_to_json(&wallet, true, Some(password)).unwrap();
        let export: WalletExport = serde_json::from_str(&exported).unwrap();

        assert_eq!(export.mnemonic.as_deref(), Some(mnemonic));
        let private_keys = export.private_keys.expect("expected private keys");
        assert_eq!(private_keys.len(), 2);
        for address in &wallet.addresses {
            let exported_key = private_keys
                .get(&address.address)
                .expect("missing derived private key");
            assert_eq!(exported_key.len(), 64);
        }
    }

    #[test]
    fn test_import_from_json_roundtrip_for_hd_wallet() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let identity_id = Uuid::new_v4();
        let password = "test_password";

        let wallet = import_from_mnemonic(
            identity_id,
            "HD Wallet".to_string(),
            mnemonic,
            "",
            BlockchainNetwork::Bitcoin,
            None,
            3,
            password,
        )
        .unwrap();

        let exported = export_to_json(&wallet, true, Some(password)).unwrap();
        let imported = import_from_json(
            Uuid::new_v4(),
            Some("Imported HD".to_string()),
            &exported,
            password,
        )
        .unwrap();

        assert_eq!(imported.name, "Imported HD");
        assert_eq!(imported.network, BlockchainNetwork::Bitcoin);
        assert_eq!(imported.addresses.len(), 3);
        assert_eq!(export_mnemonic(&imported, password).unwrap(), mnemonic);
    }

    #[test]
    fn test_import_from_json_roundtrip_for_single_address_wallet() {
        let identity_id = Uuid::new_v4();
        let password = "test_password";
        let private_key = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";

        let wallet = import_from_private_key(
            identity_id,
            "Single Address".to_string(),
            private_key,
            BlockchainNetwork::Ethereum,
            password,
        )
        .unwrap();

        let exported = export_to_json(&wallet, true, Some(password)).unwrap();
        let imported = import_from_json(Uuid::new_v4(), None, &exported, password).unwrap();

        assert_eq!(imported.name, "Single Address");
        assert_eq!(imported.network, BlockchainNetwork::Ethereum);
        assert_eq!(
            export_private_key(&imported, password).unwrap(),
            private_key
        );
    }

    fn encode_compressed_mainnet_wif(private_key: &[u8; 32]) -> String {
        let mut payload = Vec::with_capacity(34);
        payload.push(0x80);
        payload.extend_from_slice(private_key);
        payload.push(0x01);

        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(payload).into_string()
    }
}
