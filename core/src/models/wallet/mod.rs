//! 钱包主实体：`CryptoWallet` 行模型与领域方法（构造、地址管理、
//! 安全分、校验、推导路径）。
//!
//! # 模块布局
//!
//! 链/钱包类型枚举在 [`network`]，地址与元数据在 [`address`]，备份与
//! 安全设置在 [`security`]，交易模型在 [`transaction`]；此处只留主实体。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod address;
mod network;
mod security;
mod transaction;

pub use address::*;
pub use network::*;
pub use security::*;
pub use transaction::*;

#[cfg(test)]
mod tests;

/// Cryptocurrency wallet information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoWallet {
    /// Unique identifier
    pub id: Uuid,

    /// Identity this wallet belongs to
    pub identity_id: Uuid,

    /// Wallet name
    pub name: String,

    /// Wallet description
    pub description: Option<String>,

    /// Blockchain network
    pub network: BlockchainNetwork,

    /// Wallet type
    pub wallet_type: WalletType,

    /// HD wallet derivation path (BIP-32/44)
    pub derivation_path: Option<String>,

    /// Extended public key (xpub) for address generation
    pub extended_public_key: Option<String>,

    /// Encrypted private key data
    pub encrypted_private_key: Vec<u8>,

    /// Encrypted mnemonic phrase (if available)
    pub encrypted_mnemonic: Option<Vec<u8>>,

    /// Derivation addresses
    pub addresses: Vec<WalletAddress>,

    /// Metadata
    pub metadata: WalletMetadata,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Whether this wallet is watch-only (no private key)
    pub watch_only: bool,

    /// Security level
    pub security_level: WalletSecurityLevel,
}

impl CryptoWallet {
    /// Create a new crypto wallet
    pub fn new(
        identity_id: Uuid,
        name: String,
        network: BlockchainNetwork,
        wallet_type: WalletType,
        encrypted_private_key: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            identity_id,
            name,
            description: None,
            network,
            wallet_type,
            derivation_path: None,
            extended_public_key: None,
            encrypted_private_key,
            encrypted_mnemonic: None,
            addresses: Vec::new(),
            metadata: WalletMetadata::default(),
            created_at: now,
            updated_at: now,
            watch_only: false,
            security_level: WalletSecurityLevel::Medium,
        }
    }

    /// Create a watch-only wallet
    pub fn new_watch_only(
        identity_id: Uuid,
        name: String,
        network: BlockchainNetwork,
        extended_public_key: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            identity_id,
            name,
            description: Some("Watch-only wallet".to_string()),
            network,
            wallet_type: WalletType::HierarchicalDeterministic {
                bip_version: BipVersion::Bip44,
                address_count: 20,
                gap_limit: 20,
            },
            derivation_path: None,
            extended_public_key: Some(extended_public_key),
            encrypted_private_key: Vec::new(),
            encrypted_mnemonic: None,
            addresses: Vec::new(),
            metadata: WalletMetadata::default(),
            created_at: now,
            updated_at: now,
            watch_only: true,
            security_level: WalletSecurityLevel::Low,
        }
    }

    /// Add an address to the wallet
    pub fn add_address(&mut self, address: WalletAddress) {
        self.addresses.push(address);
        self.updated_at = Utc::now();
    }

    /// Get address by index
    pub fn get_address_by_index(&self, index: u32) -> Option<&WalletAddress> {
        self.addresses.iter().find(|addr| addr.index == index)
    }

    /// Get unused addresses
    pub fn get_unused_addresses(&self) -> Vec<&WalletAddress> {
        self.addresses.iter().filter(|addr| !addr.used).collect()
    }

    /// Update address usage status
    pub fn mark_address_used(&mut self, address: &str) -> bool {
        if let Some(addr) = self.addresses.iter_mut().find(|a| a.address == address) {
            addr.used = true;
            addr.last_activity = Some(Utc::now());
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Calculate security score (0-100)
    pub fn security_score(&self) -> u8 {
        let mut score = 50u8;

        // Security level contribution
        match self.security_level {
            WalletSecurityLevel::Maximum => score += 35,
            WalletSecurityLevel::High => score += 25,
            WalletSecurityLevel::Medium => score += 10,
            WalletSecurityLevel::Low => score -= 10,
        }

        // Watch-only wallets get lower score
        if self.watch_only {
            score -= 20;
        }

        // Encrypted mnemonic provides additional security
        if self.encrypted_mnemonic.is_some() {
            score += 10;
        }

        // Multi-signature provides additional security
        if matches!(self.wallet_type, WalletType::MultiSignature { .. }) {
            score += 15;
        }

        // Hardware wallet provides additional security
        if matches!(self.wallet_type, WalletType::Hardware { .. }) {
            score += 10;
        }

        // Backup verification
        if let Some(backup_info) = &self.metadata.backup_info {
            if backup_info.backup_verified {
                score += 5;
            }
        }

        score.clamp(0, 100)
    }

    /// Validate wallet configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Wallet name cannot be empty".to_string());
        }

        if !self.watch_only && self.encrypted_private_key.is_empty() {
            return Err("Non-watch-only wallet must have encrypted private key".to_string());
        }

        if self.watch_only && self.extended_public_key.is_none() {
            return Err("Watch-only wallet must have extended public key".to_string());
        }

        if let WalletType::MultiSignature {
            required_signatures,
            total_signers,
            ..
        } = &self.wallet_type
        {
            if required_signatures > total_signers {
                return Err("Required signatures cannot exceed total signers".to_string());
            }
            if *required_signatures == 0 {
                return Err("Required signatures must be at least 1".to_string());
            }
        }

        // Validate derivation path format if present
        if let Some(path) = &self.derivation_path {
            if !path.starts_with("m/") {
                return Err("Invalid derivation path format".to_string());
            }
        }

        Ok(())
    }

    /// Get recommended derivation path for network
    pub fn recommended_derivation_path(network: &BlockchainNetwork, account: u32) -> String {
        match network {
            BlockchainNetwork::Bitcoin => format!("m/44'/0'/{}'/0", account),
            BlockchainNetwork::BitcoinCash => format!("m/44'/145'/{}'/0", account),
            BlockchainNetwork::Litecoin => format!("m/44'/2'/{}'/0", account),
            BlockchainNetwork::Dogecoin => format!("m/44'/3'/{}'/0", account),
            BlockchainNetwork::Ethereum => format!("m/44'/60'/{}'/0", account),
            BlockchainNetwork::Polygon => format!("m/44'/137'/{}'/0", account),
            BlockchainNetwork::Arbitrum => format!("m/44'/42161'/{}'/0", account),
            BlockchainNetwork::Optimism => format!("m/44'/10'/{}'/0", account),
            BlockchainNetwork::BinanceSmartChain => format!("m/44'/714'/{}'/0", account),
            BlockchainNetwork::Solana => format!("m/44'/501'/{}'/0'", account),
            BlockchainNetwork::Custom(_) => format!("m/44'/0'/{}'/0", account),
        }
    }
}
