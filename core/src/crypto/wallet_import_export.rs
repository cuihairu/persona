// Wallet import/export utilities

use crate::crypto::address_generator::{
    generate_bitcoin_address, generate_bitcoin_address_from_compressed_pubkey,
    generate_ethereum_address_checksummed,
    generate_ethereum_address_checksummed_from_compressed_pubkey, generate_solana_address,
    BitcoinAddressType,
};
use crate::crypto::transaction_signing::WalletSigningKey;
use crate::crypto::wallet_crypto::{Ed25519Key, MasterKey, SecureMnemonic};
use crate::crypto::wallet_encryption::{
    decrypt_master_key, decrypt_mnemonic, decrypt_private_key, encrypt_master_key,
    encrypt_mnemonic, encrypt_private_key, EncryptedMnemonic, EncryptedWalletKey,
};
use crate::models::wallet::{AddressType, BlockchainNetwork, CryptoWallet, WalletType};
use crate::{PersonaError, PersonaResult};
use k256::ecdsa::SigningKey;
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
#[allow(clippy::too_many_arguments)]
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

    // Determine derivation path
    let path =
        derivation_path.unwrap_or_else(|| CryptoWallet::recommended_derivation_path(&network, 0));

    // Encrypt mnemonic
    let encrypted_mnemonic_data = encrypt_mnemonic(mnemonic_phrase, password)?;

    let seed = mnemonic.to_seed(passphrase);
    let (encrypted_key, addresses, extended_public_key) = if network == BlockchainNetwork::Solana {
        // Solana keys are Ed25519 and cannot come from a secp256k1 XPrv;
        // derive them per SLIP-0010 straight from the seed. The 64-byte
        // root node (secret + chain code) is stored for later signing.
        let root = Ed25519Key::from_seed(&seed)?;
        let addresses = derive_solana_addresses(&root, &path, address_count)?;
        let (secret, chain_code) = root.to_parts();
        let mut root_material = Vec::with_capacity(64);
        root_material.extend_from_slice(&secret);
        root_material.extend_from_slice(&chain_code);
        let encrypted = encrypt_private_key(&root_material, password)?;
        (encrypted, addresses, None)
    } else {
        // Create master key (secp256k1 chains)
        let master_key = MasterKey::from_seed(&seed)?;
        let addresses = derive_addresses(&master_key, &path, &network, address_count)?;
        let encrypted = encrypt_master_key(&master_key, password)?;
        (encrypted, addresses, Some(master_key.to_xpub()))
    };

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
            .map_err(|e| PersonaError::CryptographicError(format!("Serialization error: {}", e)))?,
    );

    wallet.derivation_path = Some(path.clone());
    wallet.extended_public_key = extended_public_key;
    wallet.encrypted_mnemonic =
        Some(serde_json::to_vec(&encrypted_mnemonic_data).map_err(|e| {
            PersonaError::CryptographicError(format!("Serialization error: {}", e))
        })?);
    wallet.addresses = addresses;

    Ok(wallet)
}

/// Drop the last (address-index) component of a derivation path so children
/// can be appended for each address. `m/44'/501'/0'/0'` -> `m/44'/501'/0'`.
fn parent_derivation_path(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_else(|| path.to_string())
}

/// Derive Solana addresses from a SLIP-0010 root node, one hardened child
/// per address index (e.g. `m/44'/501'/0'/0'`, `m/44'/501'/0'/1'`, ...).
fn derive_solana_addresses(
    root: &Ed25519Key,
    base_path: &str,
    count: usize,
) -> PersonaResult<Vec<crate::models::wallet::WalletAddress>> {
    let parent_path = parent_derivation_path(base_path);
    let parent = root.derive_path(&parent_path)?;
    let mut addresses = Vec::with_capacity(count);

    for i in 0..count {
        let child = parent.derive_child_hardened(i as u32)?;
        addresses.push(crate::models::wallet::WalletAddress {
            address: generate_solana_address(&child.public_bytes())?,
            address_type: AddressType::Solana,
            derivation_path: Some(format!("{}/{}'", parent_path, i)),
            index: i as u32,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        });
    }

    Ok(addresses)
}

/// Derive the signing key for a specific wallet address, decrypting the
/// stored key material with `password`.
///
/// - Solana wallets store their SLIP-0010 root node; the address path is
///   re-derived from it.
/// - HD wallets store the secp256k1 master key.
/// - Single-address wallets store the raw private key.
pub fn signing_key_for_address(
    wallet: &CryptoWallet,
    password: &str,
    address: &str,
) -> PersonaResult<WalletSigningKey> {
    if wallet.watch_only {
        return Err(PersonaError::InvalidInput(
            "Watch-only wallets cannot sign transactions".to_string(),
        ));
    }

    let encrypted_key: EncryptedWalletKey = serde_json::from_slice(&wallet.encrypted_private_key)
        .map_err(|e| {
        PersonaError::CryptographicError(format!("Deserialization error: {}", e))
    })?;

    let stored_path = wallet
        .addresses
        .iter()
        .find(|entry| entry.address == address)
        .and_then(|entry| entry.derivation_path.clone())
        .or_else(|| wallet.derivation_path.clone());

    if wallet.network == BlockchainNetwork::Solana {
        let root_material = decrypt_private_key(&encrypted_key, password)?;
        let secret: [u8; 32] = root_material
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                PersonaError::CryptographicError("Invalid Solana key material length".to_string())
            })?;
        let chain_code: [u8; 32] = root_material
            .get(32..64)
            .and_then(|c| c.try_into().ok())
            .ok_or_else(|| {
                PersonaError::CryptographicError("Invalid Solana key material length".to_string())
            })?;
        let root = Ed25519Key::from_parts(secret, chain_code)?;
        let path = stored_path.ok_or_else(|| {
            PersonaError::InvalidInput("Wallet has no derivation path".to_string())
        })?;
        return Ok(WalletSigningKey::Ed25519(root.derive_path(&path)?));
    }

    match wallet.wallet_type {
        WalletType::HierarchicalDeterministic { .. } => {
            let master_key = decrypt_master_key(&encrypted_key, password)?;
            let path = stored_path.ok_or_else(|| {
                PersonaError::InvalidInput("Wallet has no derivation path".to_string())
            })?;
            Ok(WalletSigningKey::Secp256k1(
                master_key.derive_path(&path)?.to_signing_key()?,
            ))
        }
        _ => {
            let private_key_bytes = decrypt_private_key(&encrypted_key, password)?;
            let signing_key = SigningKey::from_slice(&private_key_bytes).map_err(|e| {
                PersonaError::CryptographicError(format!("Invalid private key: {}", e))
            })?;
            Ok(WalletSigningKey::Secp256k1(signing_key))
        }
    }
}

/// Import wallet from private key
/// A parsed WIF (Wallet Import Format) private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedWif {
    pub secret: [u8; 32],
    /// True when the payload carries the `0x01` compressed-pubkey suffix.
    pub compressed: bool,
    /// True for testnet WIFs (`0xef` version byte).
    pub testnet: bool,
}

/// Parse a Bitcoin WIF private key (`base58check(0x80|0xef || key [|| 0x01])`),
/// delegating decoding and validation to the `bitcoin` crate.
pub fn parse_wif(wif: &str) -> PersonaResult<ParsedWif> {
    let key = bitcoin::key::PrivateKey::from_wif(wif.trim())
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid WIF: {e}")))?;
    Ok(ParsedWif {
        secret: key.inner.secret_bytes(),
        compressed: key.compressed,
        testnet: !matches!(key.network, bitcoin::NetworkKind::Main),
    })
}

pub fn import_from_private_key(
    identity_id: Uuid,
    name: String,
    private_key_hex: &str,
    network: BlockchainNetwork,
    password: &str,
) -> PersonaResult<CryptoWallet> {
    // Parse private key: hex first, WIF (Bitcoin) as fallback.
    let private_key_bytes = match hex::decode(private_key_hex.trim_start_matches("0x")) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(_) => {
            return Err(PersonaError::InvalidInput(
                "Private key must be 32 bytes".to_string(),
            ))
        }
        Err(_) => {
            if !matches!(network, BlockchainNetwork::Bitcoin) {
                return Err(PersonaError::InvalidInput(
                    "Input is neither valid hex nor a WIF; WIF is only valid \
                     for Bitcoin wallets"
                        .to_string(),
                ));
            }
            parse_wif(private_key_hex)?.secret.to_vec()
        }
    };

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
            .map_err(|e| PersonaError::CryptographicError(format!("Serialization error: {}", e)))?,
    );

    // Derive address from private key (secp256k1)
    let signing_key = k256::ecdsa::SigningKey::from_bytes(private_key_bytes.as_slice().into())
        .map_err(|e| {
            PersonaError::CryptographicError(format!("Invalid secp256k1 private key: {}", e))
        })?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(true);
    let compressed_bytes = encoded.as_bytes();
    let compressed: [u8; 33] = compressed_bytes
        .try_into()
        .map_err(|_| PersonaError::CryptographicError("Invalid compressed pubkey".to_string()))?;

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
        BlockchainNetwork::Solana => {
            // A Solana private key is a 32-byte Ed25519 seed
            let secret: [u8; 32] = private_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PersonaError::InvalidInput("Invalid Ed25519 seed".to_string()))?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
            (
                generate_solana_address(&signing_key.verifying_key().to_bytes())?,
                crate::models::wallet::AddressType::Solana,
            )
        }
        other => {
            return Err(PersonaError::CryptographicError(format!(
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
    let parsed = parse_wif(wif)?;

    if parsed.testnet {
        return Err(PersonaError::InvalidInput(
            "Bitcoin testnet WIF is not supported yet".to_string(),
        ));
    }
    if !parsed.compressed {
        return Err(PersonaError::InvalidInput(
            "Uncompressed WIF is not supported yet".to_string(),
        ));
    }

    import_from_private_key(
        identity_id,
        name,
        &hex::encode(parsed.secret),
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
        .map_err(|e| PersonaError::CryptographicError(format!("Deserialization error: {}", e)))?;

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

    let encrypted_key: EncryptedWalletKey = serde_json::from_slice(&wallet.encrypted_private_key)
        .map_err(|e| {
        PersonaError::CryptographicError(format!("Deserialization error: {}", e))
    })?;
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
        .map_err(|e| PersonaError::CryptographicError(format!("JSON serialization error: {}", e)))
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
                return Err(PersonaError::CryptographicError(format!(
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

    let encrypted_key: EncryptedWalletKey = serde_json::from_slice(&wallet.encrypted_private_key)
        .map_err(|e| {
        PersonaError::CryptographicError(format!("Deserialization error: {}", e))
    })?;

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
    fn test_import_from_mnemonic_solana() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "test_password";

        let mut wallet = import_from_mnemonic(
            Uuid::new_v4(),
            "sol".to_string(),
            test_mnemonic,
            "",
            BlockchainNetwork::Solana,
            None,
            3,
            password,
        )
        .unwrap();

        // Solana address paths follow the hardened leaf convention
        assert_eq!(
            wallet
                .addresses
                .first()
                .and_then(|a| a.derivation_path.as_deref()),
            Some("m/44'/501'/0'/0'")
        );
        assert_eq!(
            wallet
                .addresses
                .get(2)
                .and_then(|a| a.derivation_path.as_deref()),
            Some("m/44'/501'/0'/2'")
        );
        for address in &wallet.addresses {
            assert!(crate::crypto::address_generator::validate_solana_address(
                &address.address
            ));
        }

        // The signing key derived for the first address must reproduce it
        let first_address = wallet.addresses[0].address.clone();
        let key = signing_key_for_address(&wallet, password, &first_address).unwrap();
        let WalletSigningKey::Ed25519(ed_key) = key else {
            panic!("expected Ed25519 signing key");
        };
        let derived_address =
            crate::crypto::address_generator::generate_solana_address(&ed_key.public_bytes())
                .unwrap();
        assert_eq!(derived_address, first_address);

        // A different address must derive a different key
        let second_address = wallet.addresses[1].address.clone();
        let key2 = signing_key_for_address(&wallet, password, &second_address).unwrap();
        let WalletSigningKey::Ed25519(ed_key2) = key2 else {
            panic!("expected Ed25519 signing key");
        };
        assert_ne!(ed_key.public_bytes(), ed_key2.public_bytes());

        // Wrong password must not decrypt
        assert!(signing_key_for_address(&wallet, "wrong", &first_address).is_err());

        // Cleanup sensitive clone we made for assertions
        wallet.addresses.clear();
    }

    #[test]
    fn test_import_from_private_key_solana() {
        let secret = [9u8; 32];
        let wallet = import_from_private_key(
            Uuid::new_v4(),
            "sol-single".to_string(),
            &hex::encode(secret),
            BlockchainNetwork::Solana,
            "pw",
        )
        .unwrap();

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let expected = crate::crypto::address_generator::generate_solana_address(
            &signing_key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(wallet.addresses[0].address, expected);
    }

    #[test]
    fn test_parse_wif() {
        // Canonical mainnet compressed WIF for private key 1 (well-known pair).
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let parsed = parse_wif(wif).unwrap();
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(parsed.secret, one);
        assert!(parsed.compressed);
        assert!(!parsed.testnet);

        // Uncompressed variant drops the 0x01 suffix byte.
        let wif_uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let parsed = parse_wif(wif_uncompressed).unwrap();
        assert_eq!(
            parsed.secret,
            hex::decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
                .unwrap()
                .as_slice()
        );
        assert!(!parsed.compressed);

        // Checksum tampering must be rejected.
        let mut bad = wif.to_string();
        bad.replace_range(0..1, if wif.starts_with('K') { "L" } else { "K" });
        assert!(parse_wif(&bad).is_err());

        // Invalid version byte (address instead of key).
        assert!(parse_wif("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_err());
    }

    #[test]
    fn test_import_from_private_key_accepts_wif() {
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let wallet = import_from_private_key(
            Uuid::new_v4(),
            "btc-wif".to_string(),
            wif,
            BlockchainNetwork::Bitcoin,
            "pw",
        )
        .unwrap();

        // Key 0x01..01 compressed -> known P2WPKH address derived from
        // pubkey 0279BE667E... (the generator point).
        assert_eq!(wallet.addresses.len(), 1);
        assert!(wallet.addresses[0].address.starts_with("bc1q"));

        // Signing must round-trip back to the same secret (key = 1).
        let key = signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address).unwrap();
        let WalletSigningKey::Secp256k1(signing) = key else {
            panic!("expected secp256k1");
        };
        let mut one = [0u8; 32];
        one[31] = 1;
        let expected = k256::ecdsa::SigningKey::from_bytes(&one.into()).unwrap();
        assert_eq!(
            signing.to_bytes().as_slice(),
            expected.to_bytes().as_slice()
        );

        // WIF is Bitcoin-specific.
        assert!(import_from_private_key(
            Uuid::new_v4(),
            "eth-wif".to_string(),
            wif,
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .is_err());
    }

    #[test]
    fn test_signing_key_for_eth_hd_matches_address() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "test_password";

        let mut wallet = import_from_mnemonic(
            Uuid::new_v4(),
            "eth".to_string(),
            test_mnemonic,
            "",
            BlockchainNetwork::Ethereum,
            None,
            2,
            password,
        )
        .unwrap();

        let first_address = wallet.addresses[0].address.clone();
        let key = signing_key_for_address(&wallet, password, &first_address).unwrap();
        let WalletSigningKey::Secp256k1(signing_key) = key else {
            panic!("expected secp256k1 signing key");
        };
        let derived =
            crate::crypto::address_generator::generate_ethereum_address_checksummed_from_compressed_pubkey(
                &{
                    let encoded = signing_key.verifying_key().to_encoded_point(true);
                    encoded.as_bytes().try_into().unwrap()
                },
            )
            .unwrap();
        assert_eq!(derived.to_lowercase(), first_address.to_lowercase());

        wallet.addresses.clear();
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
        assert_eq!(
            parse_import_format("keystore").unwrap(),
            ImportFormat::Keystore
        );
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

    /// `WalletSigningKey` is not `Debug`, so `expect_err` cannot be used.
    fn expect_sign_err(result: PersonaResult<WalletSigningKey>, msg: &str) -> PersonaError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("{msg}"),
        }
    }

    fn hd_wallet(network: BlockchainNetwork, count: usize) -> CryptoWallet {
        import_from_mnemonic(
            Uuid::new_v4(),
            "HD".to_string(),
            TEST_PHRASE,
            "",
            network,
            None,
            count,
            "pw",
        )
        .unwrap()
    }

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const ETH_KEY: &str = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";

    #[test]
    fn import_from_mnemonic_rejects_invalid_phrase() {
        let err = import_from_mnemonic(
            Uuid::new_v4(),
            "bad".to_string(),
            "not a valid mnemonic at all",
            "",
            BlockchainNetwork::Bitcoin,
            None,
            1,
            "pw",
        )
        .expect_err("invalid mnemonic must be rejected");
        assert!(err.to_string().contains("Invalid mnemonic"));
    }

    #[test]
    fn import_from_mnemonic_honors_explicit_derivation_path() {
        let wallet = import_from_mnemonic(
            Uuid::new_v4(),
            "custom path".to_string(),
            TEST_PHRASE,
            "passphrase",
            BlockchainNetwork::Bitcoin,
            Some("m/84'/0'/7'/0".to_string()),
            2,
            "pw",
        )
        .unwrap();
        assert_eq!(wallet.derivation_path.as_deref(), Some("m/84'/0'/7'/0"));
        assert_eq!(
            wallet.addresses[0].derivation_path.as_deref(),
            Some("m/84'/0'/7'/0/0")
        );
        // A BIP-84 path yields bech32 (P2WPKH) addresses.
        assert!(wallet.addresses[0].address.starts_with("bc1q"));
    }

    #[test]
    fn signing_key_for_address_rejects_watch_only() {
        let mut wallet = import_from_private_key(
            Uuid::new_v4(),
            "watch".to_string(),
            ETH_KEY,
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .unwrap();
        wallet.watch_only = true;
        let err = expect_sign_err(
            signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address),
            "watch-only wallets must not sign",
        );
        assert!(err.to_string().contains("Watch-only wallets cannot sign"));
    }

    #[test]
    fn signing_key_for_address_requires_a_derivation_path() {
        // HD secp256k1 wallet without any path information.
        let mut wallet = hd_wallet(BlockchainNetwork::Bitcoin, 1);
        let address = wallet.addresses[0].address.clone();
        wallet.addresses.clear();
        wallet.derivation_path = None;
        let err = expect_sign_err(
            signing_key_for_address(&wallet, "pw", &address),
            "HD wallet without a path must be rejected",
        );
        assert!(err.to_string().contains("Wallet has no derivation path"));

        // Same for the Solana (Ed25519) branch.
        let mut sol = hd_wallet(BlockchainNetwork::Solana, 1);
        let sol_address = sol.addresses[0].address.clone();
        sol.addresses.clear();
        sol.derivation_path = None;
        let err = expect_sign_err(
            signing_key_for_address(&sol, "pw", &sol_address),
            "Solana wallet without a path must be rejected",
        );
        assert!(err.to_string().contains("Wallet has no derivation path"));
    }

    #[test]
    fn signing_key_for_address_rejects_corrupt_key_payload() {
        let mut wallet = hd_wallet(BlockchainNetwork::Bitcoin, 1);
        wallet.encrypted_private_key = b"corrupt".to_vec();
        let err = expect_sign_err(
            signing_key_for_address(&wallet, "pw", "anything"),
            "corrupt payload must be rejected",
        );
        assert!(err.to_string().contains("Deserialization error"));
    }

    #[test]
    fn import_from_private_key_rejects_bad_lengths_and_formats() {
        // 31-byte hex payload.
        let err = import_from_private_key(
            Uuid::new_v4(),
            "short".to_string(),
            &"ab".repeat(31),
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .expect_err("31-byte key must be rejected");
        assert!(err.to_string().contains("Private key must be 32 bytes"));

        // 33-byte hex payload.
        assert!(import_from_private_key(
            Uuid::new_v4(),
            "long".to_string(),
            &"ab".repeat(33),
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .is_err());

        // Neither hex nor WIF, on a non-Bitcoin network.
        let err = import_from_private_key(
            Uuid::new_v4(),
            "junk".to_string(),
            "zzz-not-hex",
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .expect_err("non-hex must be rejected outside Bitcoin");
        assert!(err.to_string().contains("neither valid hex nor a WIF"));

        // On Bitcoin it falls through to WIF parsing, which also fails.
        let err = import_from_private_key(
            Uuid::new_v4(),
            "junk-btc".to_string(),
            "zzz-not-hex",
            BlockchainNetwork::Bitcoin,
            "pw",
        )
        .expect_err("garbage input must fail WIF parsing too");
        assert!(err.to_string().contains("Invalid WIF"));
    }

    #[test]
    fn import_from_private_key_rejects_unsupported_networks() {
        let err = import_from_private_key(
            Uuid::new_v4(),
            "custom".to_string(),
            ETH_KEY,
            BlockchainNetwork::Custom("fantasy".to_string()),
            "pw",
        )
        .expect_err("custom networks have no address scheme");
        assert!(err.to_string().contains("not implemented for"));
    }

    #[test]
    fn import_from_wif_rejects_testnet_and_uncompressed() {
        // Testnet WIF: version byte 0xef, compressed suffix.
        let mut payload = vec![0xefu8];
        payload.extend_from_slice(&[0x22u8; 32]);
        payload.push(0x01);
        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[..4]);
        let testnet_wif = bs58::encode(payload).into_string();

        let err = import_from_wif(Uuid::new_v4(), "t".to_string(), &testnet_wif, "pw")
            .expect_err("testnet WIF must be rejected");
        assert!(err.to_string().contains("testnet WIF is not supported"));

        // Uncompressed mainnet WIF (no 0x01 suffix).
        let uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let err = import_from_wif(Uuid::new_v4(), "u".to_string(), uncompressed, "pw")
            .expect_err("uncompressed WIF must be rejected");
        assert!(err
            .to_string()
            .contains("Uncompressed WIF is not supported"));
    }

    #[test]
    fn export_mnemonic_requires_stored_mnemonic() {
        let wallet = import_from_private_key(
            Uuid::new_v4(),
            "single".to_string(),
            ETH_KEY,
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .unwrap();
        let err = export_mnemonic(&wallet, "pw").expect_err("single-key wallets have no mnemonic");
        assert!(err.to_string().contains("Wallet has no mnemonic"));
    }

    #[test]
    fn export_private_key_falls_back_to_any_stored_key() {
        let mut wallet = import_from_private_key(
            Uuid::new_v4(),
            "single".to_string(),
            ETH_KEY,
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .unwrap();
        // With the address list cleared, the per-address lookup misses and the
        // export falls back to the only stored key ("primary" bucket).
        wallet.addresses.clear();
        let exported = export_private_key(&wallet, "pw").unwrap();
        assert_eq!(exported, ETH_KEY);
    }

    #[test]
    fn export_private_keys_requires_paths_for_hd_addresses() {
        let mut wallet = hd_wallet(BlockchainNetwork::Ethereum, 2);
        wallet.addresses[1].derivation_path = None;
        let err = export_private_key(&wallet, "pw")
            .expect_err("HD address without a derivation path must fail");
        assert!(err.to_string().contains("missing a derivation path"));
    }

    #[test]
    fn export_to_wif_guardrails() {
        let password = "pw";

        // Watch-only.
        let mut watch = import_from_private_key(
            Uuid::new_v4(),
            "w".to_string(),
            ETH_KEY,
            BlockchainNetwork::Bitcoin,
            password,
        )
        .unwrap();
        watch.watch_only = true;
        let err = export_to_wif(&watch, password).expect_err("watch-only must not export WIF");
        assert!(err
            .to_string()
            .contains("Watch-only wallets cannot export WIF"));

        // Non-Bitcoin network.
        let eth = import_from_private_key(
            Uuid::new_v4(),
            "e".to_string(),
            ETH_KEY,
            BlockchainNetwork::Ethereum,
            password,
        )
        .unwrap();
        let err = export_to_wif(&eth, password).expect_err("WIF is Bitcoin-only");
        assert!(err.to_string().contains("only supported for Bitcoin"));

        // HD Bitcoin wallet.
        let hd = hd_wallet(BlockchainNetwork::Bitcoin, 1);
        let err = export_to_wif(&hd, password).expect_err("HD wallets must not export WIF");
        assert!(err.to_string().contains("single-address Bitcoin wallets"));

        // Wrong password.
        let btc = import_from_private_key(
            Uuid::new_v4(),
            "b".to_string(),
            ETH_KEY,
            BlockchainNetwork::Bitcoin,
            password,
        )
        .unwrap();
        assert!(export_to_wif(&btc, "wrong").is_err());
    }

    #[test]
    fn export_xpub_presence() {
        let hd = hd_wallet(BlockchainNetwork::Bitcoin, 1);
        let xpub = export_xpub(&hd).unwrap();
        assert!(xpub.starts_with("xpub"));

        let single = import_from_private_key(
            Uuid::new_v4(),
            "s".to_string(),
            ETH_KEY,
            BlockchainNetwork::Ethereum,
            "pw",
        )
        .unwrap();
        let err = export_xpub(&single).expect_err("single-key wallets have no xpub");
        assert!(err.to_string().contains("no extended public key"));
    }

    #[test]
    fn export_to_json_requires_password_for_private_data() {
        let wallet = hd_wallet(BlockchainNetwork::Bitcoin, 1);
        let err = export_to_json(&wallet, true, None)
            .expect_err("private export without a password must fail");
        assert!(err.to_string().contains("Password required"));

        // Public-only export needs no password and omits secrets.
        let public = export_to_json(&wallet, false, None).unwrap();
        let parsed: WalletExport = serde_json::from_str(&public).unwrap();
        assert!(parsed.mnemonic.is_none());
        assert!(parsed.private_keys.is_none());
        assert_eq!(parsed.addresses.len(), 1);
    }

    #[test]
    fn import_from_json_error_paths() {
        // Malformed JSON.
        let err = import_from_json(Uuid::new_v4(), None, "{nope", "pw")
            .expect_err("malformed export must be rejected");
        assert!(err.to_string().contains("Invalid wallet JSON export"));

        // Neither mnemonic nor private keys.
        let bare = r#"{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"bare","network":"bitcoin","wallet_type":"HD","addresses":[],"created_at":"2024-01-01T00:00:00Z"}"#;
        let err = import_from_json(Uuid::new_v4(), None, bare, "pw")
            .expect_err("export without key material must be rejected");
        assert!(err
            .to_string()
            .contains("requires mnemonic or private key data"));

        // Empty private-keys map.
        let empty_keys = r#"{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"empty","network":"bitcoin","wallet_type":"single","addresses":[],"private_keys":{},"created_at":"2024-01-01T00:00:00Z"}"#;
        let err = import_from_json(Uuid::new_v4(), None, empty_keys, "pw")
            .expect_err("empty private key map must be rejected");
        assert!(err
            .to_string()
            .contains("does not contain any private keys"));

        // Missing name and no fallback.
        let nameless = r#"{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"  ","network":"bitcoin","wallet_type":"hd","addresses":[],"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about","created_at":"2024-01-01T00:00:00Z"}"#;
        let err = import_from_json(Uuid::new_v4(), None, nameless, "pw")
            .expect_err("missing name must be rejected");
        assert!(err.to_string().contains("missing a name"));
    }

    #[test]
    fn import_from_json_defaults_optional_fields() {
        // extended_public_key / description / watch_only are serde-defaulted.
        let minimal = format!(
            r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"minimal","network":"polygon","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["a"],"created_at":"2024-01-01T00:00:00Z"}}"#
        );
        let wallet = import_from_json(Uuid::new_v4(), None, &minimal, "pw").unwrap();
        assert_eq!(wallet.network, BlockchainNetwork::Polygon);
        assert!(!wallet.watch_only);
        assert_eq!(wallet.addresses.len(), 1);
        assert!(wallet.addresses[0].address.starts_with("0x"));
    }

    #[test]
    fn parse_network_name_covers_all_known_networks() {
        let password = "pw";
        // Non-EVM, non-Bitcoin networks parse but cannot derive addresses.
        for network in ["bitcoincash", "bitcoin cash", "litecoin", "dogecoin"] {
            let json = format!(
                r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"n","network":"{network}","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["a"],"created_at":"2024-01-01T00:00:00Z"}}"#
            );
            let err = import_from_json(Uuid::new_v4(), None, &json, password)
                .expect_err("unsupported address scheme must fail");
            assert!(err.to_string().contains("not implemented for"), "{network}");
        }

        // Unknown network strings become Custom and fail the same way.
        let custom = format!(
            r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"n","network":"Some Chain","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["a"],"created_at":"2024-01-01T00:00:00Z"}}"#
        );
        let err = import_from_json(Uuid::new_v4(), None, &custom, password).unwrap_err();
        assert!(err.to_string().contains("Custom"));

        // EVM networks succeed end-to-end.
        for network in [
            "polygon",
            "arbitrum",
            "optimism",
            "binancesmartchain",
            "binance smart chain",
        ] {
            let json = format!(
                r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"n","network":"{network}","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["a"],"created_at":"2024-01-01T00:00:00Z"}}"#
            );
            let wallet = import_from_json(Uuid::new_v4(), None, &json, password)
                .unwrap_or_else(|e| panic!("{network} must import: {e}"));
            assert_eq!(wallet.addresses.len(), 1);
        }
    }

    #[test]
    fn format_parsing_covers_every_variant_and_is_case_insensitive() {
        use ExportFormat as E;
        use ImportFormat as F;

        for (s, expected) in [
            ("MNEMONIC", F::Mnemonic),
            ("phrase", F::Mnemonic),
            ("Seed", F::Mnemonic),
            ("privatekey", F::PrivateKey),
            ("PRIVATE_KEY", F::PrivateKey),
            ("key", F::PrivateKey),
            ("JSON", F::Json),
            ("keystore", F::Keystore),
            ("WIF", F::Wif),
        ] {
            assert_eq!(parse_import_format(s).unwrap(), expected, "{s}");
        }
        assert!(parse_import_format("yaml")
            .err()
            .unwrap()
            .to_string()
            .contains("Unknown import format"));

        for (s, expected) in [
            ("mnemonic", E::Mnemonic),
            ("PHRASE", E::Mnemonic),
            ("seed", E::Mnemonic),
            ("privatekey", E::PrivateKey),
            ("private_key", E::PrivateKey),
            ("KEY", E::PrivateKey),
            ("wif", E::Wif),
            ("xpub", E::Xpub),
            ("extended_public_key", E::Xpub),
            ("json", E::Json),
        ] {
            assert_eq!(parse_export_format(s).unwrap(), expected, "{s}");
        }
        assert!(parse_export_format("csv")
            .err()
            .unwrap()
            .to_string()
            .contains("Unknown export format"));
    }

    #[test]
    fn signing_key_for_solana_rejects_short_key_material() {
        let mut wallet = hd_wallet(BlockchainNetwork::Solana, 1);
        wallet.encrypted_private_key =
            serde_json::to_vec(&encrypt_private_key(&[7u8; 16], "pw").unwrap()).unwrap();
        let err = expect_sign_err(
            signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address),
            "16-byte Solana key material must be rejected",
        );
        assert!(err
            .to_string()
            .contains("Invalid Solana key material length"));
    }

    #[test]
    fn signing_key_for_solana_rejects_oversized_key_material() {
        // 40 bytes yield a 32-byte secret but only an 8-byte chain code.
        let mut wallet = hd_wallet(BlockchainNetwork::Solana, 1);
        wallet.encrypted_private_key =
            serde_json::to_vec(&encrypt_private_key(&[7u8; 40], "pw").unwrap()).unwrap();
        let err = expect_sign_err(
            signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address),
            "40-byte Solana key material must be rejected",
        );
        assert!(err
            .to_string()
            .contains("Invalid Solana key material length"));
    }

    #[test]
    fn test_import_bitcoin_private_key_yields_p2wkh_address() {
        let identity_id = Uuid::new_v4();
        let password = "test_password";
        let private_key = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";

        let wallet = import_from_private_key(
            identity_id,
            "BTC Single".to_string(),
            private_key,
            BlockchainNetwork::Bitcoin,
            password,
        )
        .unwrap();

        assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
        assert_eq!(wallet.addresses.len(), 1);
        assert_eq!(
            wallet.addresses[0].address_type,
            crate::models::wallet::AddressType::P2WPKH
        );
        assert!(
            wallet.addresses[0].address.starts_with("bc1q"),
            "bech32 P2WPKH address, got {}",
            wallet.addresses[0].address
        );

        // The key round-trips through WIF export (compressed mainnet).
        let wif = export_to_wif(&wallet, password).unwrap();
        assert!(wif.starts_with('K') || wif.starts_with('L'));
    }

    #[test]
    fn export_private_key_fails_for_watch_only_wallet() {
        // Watch-only wallets export no keys at all, so the per-address lookup
        // and the fallback both miss.
        let mut wallet = hd_wallet(BlockchainNetwork::Ethereum, 1);
        wallet.watch_only = true;
        let err = export_private_key(&wallet, "pw")
            .expect_err("watch-only wallets expose no private keys");
        assert!(err
            .to_string()
            .contains("does not contain an exportable private key"));
    }
}
