//! 钱包导出实现（LAY-018 拆分）：mnemonic/private key/keystore/WIF/xpub/JSON 导出
//! 与 HD 地址私钥批量导出。`double_sha256`、`WalletExport` 自枢纽引入。

use super::{double_sha256, WalletExport};
use crate::crypto::wallet_encryption::{
    decrypt_master_key, decrypt_mnemonic, decrypt_private_key, EncryptedMnemonic,
    EncryptedWalletKey,
};
use crate::models::wallet::{BlockchainNetwork, CryptoWallet, WalletType};
use crate::{PersonaError, PersonaResult};
use std::collections::HashMap;

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

/// Export the wallet's primary private key as a Web3 Secret Storage v3
/// keystore JSON (geth-standard scrypt work factors). Ethereum wallets only:
/// the keystore format is defined over secp256k1 keys.
pub fn export_keystore(wallet: &CryptoWallet, password: &str) -> PersonaResult<String> {
    if wallet.watch_only {
        return Err(PersonaError::InvalidInput(
            "Watch-only wallets cannot export keystore".to_string(),
        ));
    }
    if wallet.network != BlockchainNetwork::Ethereum {
        return Err(PersonaError::InvalidInput(format!(
            "Keystore export requires an Ethereum wallet (this wallet is {:?})",
            wallet.network
        )));
    }
    let key_hex = export_private_key(wallet, password)?;
    let key = hex::decode(key_hex.trim())
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid stored key encoding: {e}")))?;
    let address = wallet.addresses.first().map(|a| {
        a.address
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_lowercase()
    });
    crate::crypto::wallet_encryption::export_to_keystore(&key, password, address)
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
