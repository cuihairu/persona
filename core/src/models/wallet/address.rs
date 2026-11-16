//! 派生地址与钱包元数据：地址条目、地址类型、标签/备注元数据。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::security::{WalletBackupInfo, WalletSecuritySettings};

/// Individual wallet address
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletAddress {
    /// Address string
    pub address: String,

    /// Address type
    pub address_type: AddressType,

    /// Derivation path (for HD wallets)
    pub derivation_path: Option<String>,

    /// Address index
    pub index: u32,

    /// Whether this address is used (has transactions)
    pub used: bool,

    /// Balance (if available)
    pub balance: Option<String>,

    /// Last activity timestamp
    pub last_activity: Option<DateTime<Utc>>,

    /// Metadata
    pub metadata: HashMap<String, String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Address types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AddressType {
    /// P2PKH (Pay to Public Key Hash) - Bitcoin
    P2PKH,
    /// P2SH (Pay to Script Hash) - Bitcoin
    P2SH,
    /// P2WPKH (Pay to Witness Public Key Hash) - Bitcoin SegWit
    P2WPKH,
    /// P2TR (Pay to Taproot) - Bitcoin Taproot
    P2TR,
    /// Ethereum address (0x...)
    Ethereum,
    /// Solana address (base58)
    Solana,
    /// Custom address type
    Custom(String),
}

/// Wallet metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct WalletMetadata {
    /// Tags for wallet organization
    pub tags: Vec<String>,

    /// Notes about the wallet
    pub notes: Option<String>,

    /// Exchange or platform where this wallet is used
    pub platform: Option<String>,

    /// Purpose of this wallet (trading, savings, etc.)
    pub purpose: Option<String>,

    /// Associated services or dApps
    pub associated_services: Vec<String>,

    /// Backup information
    pub backup_info: Option<WalletBackupInfo>,

    /// Security settings
    pub security_settings: WalletSecuritySettings,

    /// Custom key-value metadata
    pub custom_data: HashMap<String, String>,
}
