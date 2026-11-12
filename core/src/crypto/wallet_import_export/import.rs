//! 钱包导入实现（LAY-018 拆分）：mnemonic/private key/WIF/JSON 导入与
//! HD/Solana 地址派生、签名密钥解析。`parse_network_name`、`WalletExport` 自枢纽引入。

use super::{parse_network_name, WalletExport};
use crate::crypto::address_generator::{
    generate_bitcoin_address, generate_bitcoin_address_from_compressed_pubkey,
    generate_ethereum_address_checksummed,
    generate_ethereum_address_checksummed_from_compressed_pubkey, generate_solana_address,
    BitcoinAddressType,
};
use crate::crypto::transaction_signing::WalletSigningKey;
use crate::crypto::wallet_crypto::{Ed25519Key, MasterKey, SecureMnemonic};
use crate::crypto::wallet_encryption::{
    decrypt_master_key, decrypt_private_key, encrypt_master_key, encrypt_mnemonic,
    encrypt_private_key, EncryptedWalletKey,
};
use crate::models::wallet::{AddressType, BlockchainNetwork, CryptoWallet, WalletType};
use crate::{PersonaError, PersonaResult};
use k256::ecdsa::SigningKey;
use std::collections::HashMap;
use uuid::Uuid;

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
    let signing_key =
        k256::ecdsa::SigningKey::from_slice(private_key_bytes.as_slice()).map_err(|e| {
            PersonaError::CryptographicError(format!("Invalid secp256k1 private key: {}", e))
        })?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_sec1_point(true);
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
