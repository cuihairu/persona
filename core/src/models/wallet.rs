use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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

/// Wallet backup information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletBackupInfo {
    /// Backup location type
    pub backup_location: BackupLocation,

    /// Last backup timestamp
    pub last_backup_at: Option<DateTime<Utc>>,

    /// Backup verification status
    pub backup_verified: bool,

    /// Number of backup copies
    pub backup_copies: usize,

    /// Recovery phrase backup method
    pub recovery_phrase_backup_method: Option<RecoveryPhraseBackupMethod>,
}

/// Backup location types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupLocation {
    /// Local file system
    LocalFileSystem,
    /// Encrypted cloud storage
    EncryptedCloudStorage,
    /// Paper backup
    PaperBackup,
    /// Metal backup
    MetalBackup,
    /// Hardware device
    HardwareDevice,
    /// Split storage (Shamir's Secret Sharing)
    SplitStorage {
        /// Number of shares required
        required_shares: usize,
        /// Total number of shares
        total_shares: usize,
    },
}

/// Recovery phrase backup methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoveryPhraseBackupMethod {
    /// Written on paper
    Paper,
    /// Engraved on metal
    Metal,
    /// Stored in password manager
    PasswordManager,
    /// Split into multiple secure locations
    SplitLocations,
    /// Hardware security module
    HardwareSecurityModule,
}

/// Wallet security settings
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct WalletSecuritySettings {
    /// Require biometric authentication for transactions
    pub require_biometric: bool,

    /// Require password for transactions
    pub require_password: bool,

    /// Maximum transaction amount without additional verification
    pub max_unverified_amount: Option<String>,

    /// Require 2FA for transactions above threshold
    pub require_2fa_above: Option<String>,

    /// Transaction notifications enabled
    pub transaction_notifications: bool,

    /// Address book only transactions
    pub address_book_only: bool,

    /// Address whitelist
    pub address_whitelist: Vec<String>,

    /// Address blacklist
    pub address_blacklist: Vec<String>,

    /// Time-based transaction limits
    pub daily_transaction_limit: Option<String>,
    pub weekly_transaction_limit: Option<String>,
    pub monthly_transaction_limit: Option<String>,

    /// Spending freeze until timestamp
    pub spending_frozen_until: Option<DateTime<Utc>>,

    /// Spending freeze with password recovery
    pub spending_frozen_with_recovery: Option<String>,
}

/// Wallet security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WalletSecurityLevel {
    /// Maximum security (hardware wallet, multi-sig, etc.)
    Maximum,
    /// High security (encrypted wallet with strong authentication)
    High,
    /// Medium security (standard encrypted wallet)
    Medium,
    /// Low security (watch-only, limited authentication)
    Low,
}

impl std::fmt::Display for WalletSecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletSecurityLevel::Maximum => write!(f, "Maximum"),
            WalletSecurityLevel::High => write!(f, "High"),
            WalletSecurityLevel::Medium => write!(f, "Medium"),
            WalletSecurityLevel::Low => write!(f, "Low"),
        }
    }
}

/// Transaction request for wallet signing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionRequest {
    /// Transaction ID
    pub id: Uuid,

    /// Wallet ID
    pub wallet_id: Uuid,

    /// Network
    pub network: BlockchainNetwork,

    /// From address
    pub from_address: String,

    /// To address
    pub to_address: String,

    /// Amount (in smallest unit - satoshis, wei, etc.)
    pub amount: String,

    /// Fee (in smallest unit)
    pub fee: String,

    /// Gas price or fee rate
    pub gas_price: Option<String>,

    /// Gas limit (for EVM chains)
    pub gas_limit: Option<u64>,

    /// Nonce (for EVM chains)
    pub nonce: Option<u64>,

    /// Memo or note
    pub memo: Option<String>,

    /// Raw transaction data
    pub raw_transaction_data: Option<Vec<u8>>,

    /// Required signatures
    pub required_signatures: usize,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,

    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Signed transaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedTransaction {
    /// Transaction ID
    pub id: Uuid,

    /// Original request
    pub request: TransactionRequest,

    /// Signature(s)
    pub signatures: Vec<TransactionSignature>,

    /// Raw signed transaction
    pub raw_signed_transaction: Vec<u8>,

    /// Transaction hash
    pub transaction_hash: String,

    /// Signed timestamp
    pub signed_at: DateTime<Utc>,

    /// Broadcasting status
    pub broadcast_status: BroadcastStatus,
}

/// Transaction signature
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionSignature {
    /// Signer address
    pub signer_address: String,

    /// Signature data
    pub signature: Vec<u8>,

    /// Public key
    pub public_key: Vec<u8>,

    /// Signature scheme
    pub signature_scheme: SignatureScheme,

    /// Signed timestamp
    pub signed_at: DateTime<Utc>,
}

/// Signature schemes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureScheme {
    /// ECDSA (secp256k1) - Bitcoin, Ethereum
    ECDSA,
    /// EdDSA (ed25519) - Solana, Ed25519
    EdDSA,
    /// Schnorr - Bitcoin Taproot
    Schnorr,
    /// BLS - Ethereum 2.0
    BLS,
}

/// Transaction broadcast status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BroadcastStatus {
    /// Not yet broadcast
    NotBroadcast,
    /// Broadcasting
    Broadcasting,
    /// Broadcast successful
    BroadcastSuccess {
        /// Transaction hash
        hash: String,
        /// Block height (if confirmed)
        block_height: Option<u64>,
        /// Confirmations count
        confirmations: u64,
        /// Confirmed timestamp
        confirmed_at: Option<DateTime<Utc>>,
    },
    /// Broadcast failed
    BroadcastFailed {
        /// Error message
        error: String,
        /// Retry count
        retry_count: u32,
    },
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
            WalletSecurityLevel::Maximum => score += 30,
            WalletSecurityLevel::High => score += 20,
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

        if let WalletType::MultiSignature { required_signatures, total_signers, .. } = &self.wallet_type {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let identity_id = Uuid::new_v4();
        let wallet = CryptoWallet::new(
            identity_id,
            "Test Wallet".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4], // Encrypted private key placeholder
        );

        assert_eq!(wallet.name, "Test Wallet");
        assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
        assert!(!wallet.watch_only);
        assert_eq!(wallet.security_level, WalletSecurityLevel::Medium);
        assert!(wallet.validate().is_ok());
    }

    #[test]
    fn test_watch_only_wallet() {
        let identity_id = Uuid::new_v4();
        let wallet = CryptoWallet::new_watch_only(
            identity_id,
            "Watch Only".to_string(),
            BlockchainNetwork::Ethereum,
            "xpub...".to_string(),
        );

        assert_eq!(wallet.name, "Watch Only");
        assert!(wallet.watch_only);
        assert_eq!(wallet.security_level, WalletSecurityLevel::Low);
        assert!(wallet.validate().is_ok());
    }

    #[test]
    fn test_wallet_security_score() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );
        wallet.security_level = WalletSecurityLevel::High;

        let score = wallet.security_score();
        assert!(score > 70); // Should be quite secure

        wallet.security_level = WalletSecurityLevel::Maximum;
        let higher_score = wallet.security_score();
        assert!(higher_score > score); // Should be even more secure
    }

    #[test]
    fn test_recommended_derivation_path() {
        let btc_path = CryptoWallet::recommended_derivation_path(&BlockchainNetwork::Bitcoin, 0);
        assert_eq!(btc_path, "m/44'/0'/0'/0");

        let eth_path = CryptoWallet::recommended_derivation_path(&BlockchainNetwork::Ethereum, 1);
        assert_eq!(eth_path, "m/44'/60'/1'/0");

        let sol_path = CryptoWallet::recommended_derivation_path(&BlockchainNetwork::Solana, 0);
        assert_eq!(sol_path, "m/44'/501'/0'/0'");
    }

    #[test]
    fn test_address_management() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );

        let address = WalletAddress {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            address_type: AddressType::P2PKH,
            derivation_path: None,
            index: 0,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        };

        wallet.add_address(address);
        assert_eq!(wallet.addresses.len(), 1);
        assert!(wallet.get_unused_addresses().len() == 1);

        let mark_used = wallet.mark_address_used("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(mark_used);
        assert!(wallet.get_unused_addresses().is_empty());
    }

    #[test]
    fn test_wallet_validation() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "".to_string(), // Empty name
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );

        assert!(wallet.validate().is_err());

        wallet.name = "Valid Wallet".to_string();
        assert!(wallet.validate().is_ok());
    }

    #[test]
    fn test_multi_signature_validation() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Multi-sig".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::MultiSignature {
                required_signatures: 3,
                total_signers: 2, // Invalid: required > total
                redeem_script: None,
            },
            vec![1, 2, 3, 4],
        );

        assert!(wallet.validate().is_err());
    }
}