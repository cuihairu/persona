//! 钱包导入/导出（LAY-018 拆分）：`ImportFormat`/`ExportFormat`/`WalletExport`
//! 公共类型、格式字符串解析与网络名解析留在枢纽；导入/导出实现分别在
//! import/export 子模块，经 `pub use` 保持原外部路径零改动。

use crate::models::wallet::BlockchainNetwork;
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
    /// Ethereum keystore JSON (Web3 Secret Storage v3)
    Keystore,
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
        "keystore" => Ok(ExportFormat::Keystore),
        _ => Err(PersonaError::InvalidInput(format!(
            "Unknown export format: {}",
            format_str
        ))),
    }
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

mod export;
mod import;

pub use export::*;
pub use import::*;

#[cfg(test)]
mod tests;
