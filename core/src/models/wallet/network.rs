//! Chains and wallet types: supported networks, wallet forms and BIP versions
//! (stored strings round-tripped through Display).

use serde::{Deserialize, Serialize};

/// Blockchain networks supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BlockchainNetwork {
    /// Bitcoin (BTC)
    Bitcoin,
    /// Ethereum (ETH)
    Ethereum,
    /// Solana (SOL)
    Solana,
    /// Bitcoin Cash (BCH)
    BitcoinCash,
    /// Litecoin (LTC)
    Litecoin,
    /// Dogecoin (DOGE)
    Dogecoin,
    /// Polygon (MATIC)
    Polygon,
    /// Arbitrum (ARB)
    Arbitrum,
    /// Optimism (OP)
    Optimism,
    /// Binance Smart Chain (BSC)
    BinanceSmartChain,
    /// Custom network
    Custom(String),
}

impl std::fmt::Display for BlockchainNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockchainNetwork::Bitcoin => write!(f, "Bitcoin"),
            BlockchainNetwork::Ethereum => write!(f, "Ethereum"),
            BlockchainNetwork::Solana => write!(f, "Solana"),
            BlockchainNetwork::BitcoinCash => write!(f, "Bitcoin Cash"),
            BlockchainNetwork::Litecoin => write!(f, "Litecoin"),
            BlockchainNetwork::Dogecoin => write!(f, "Dogecoin"),
            BlockchainNetwork::Polygon => write!(f, "Polygon"),
            BlockchainNetwork::Arbitrum => write!(f, "Arbitrum"),
            BlockchainNetwork::Optimism => write!(f, "Optimism"),
            BlockchainNetwork::BinanceSmartChain => write!(f, "Binance Smart Chain"),
            BlockchainNetwork::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Wallet types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WalletType {
    /// Hierarchical Deterministic (HD) wallet
    HierarchicalDeterministic {
        /// BIP standard version
        bip_version: BipVersion,
        /// Number of addresses to derive/display
        address_count: usize,
        /// Gap limit for address derivation
        gap_limit: usize,
    },
    /// Single address wallet
    SingleAddress,
    /// Multi-signature wallet
    MultiSignature {
        /// Required signatures
        required_signatures: usize,
        /// Total signers
        total_signers: usize,
        /// Redeem script
        redeem_script: Option<String>,
    },
    /// Hardware wallet (Trezor, Ledger, etc.)
    Hardware {
        /// Hardware wallet type
        device_type: String,
        /// Device fingerprint
        device_fingerprint: Option<String>,
    },
}

/// BIP (Bitcoin Improvement Proposal) versions for HD wallets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BipVersion {
    /// BIP-32 (original HD wallets)
    Bip32,
    /// BIP-44 (multi-account hierarchy)
    Bip44,
    /// BIP-49 (P2SH wrapped SegWit)
    Bip49,
    /// BIP-84 (Native SegWit)
    Bip84,
    /// BIP-86 (Taproot)
    Bip86,
    /// SLIP-44 (Coin-specific)
    Slip44,
}

impl std::fmt::Display for BipVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BipVersion::Bip32 => write!(f, "32"),
            BipVersion::Bip44 => write!(f, "44"),
            BipVersion::Bip49 => write!(f, "49"),
            BipVersion::Bip84 => write!(f, "84"),
            BipVersion::Bip86 => write!(f, "86"),
            BipVersion::Slip44 => write!(f, "SLIP-44"),
        }
    }
}
