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
        let wallet = CryptoWallet::new(
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

    fn roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn test_blockchain_network_display() {
        assert_eq!(BlockchainNetwork::Bitcoin.to_string(), "Bitcoin");
        assert_eq!(BlockchainNetwork::Ethereum.to_string(), "Ethereum");
        assert_eq!(BlockchainNetwork::Solana.to_string(), "Solana");
        assert_eq!(BlockchainNetwork::BitcoinCash.to_string(), "Bitcoin Cash");
        assert_eq!(BlockchainNetwork::Litecoin.to_string(), "Litecoin");
        assert_eq!(BlockchainNetwork::Dogecoin.to_string(), "Dogecoin");
        assert_eq!(BlockchainNetwork::Polygon.to_string(), "Polygon");
        assert_eq!(BlockchainNetwork::Arbitrum.to_string(), "Arbitrum");
        assert_eq!(BlockchainNetwork::Optimism.to_string(), "Optimism");
        assert_eq!(
            BlockchainNetwork::BinanceSmartChain.to_string(),
            "Binance Smart Chain"
        );
        assert_eq!(
            BlockchainNetwork::Custom("Foo Chain".to_string()).to_string(),
            "Foo Chain"
        );
    }

    #[test]
    fn test_bip_version_display() {
        assert_eq!(BipVersion::Bip32.to_string(), "32");
        assert_eq!(BipVersion::Bip44.to_string(), "44");
        assert_eq!(BipVersion::Bip49.to_string(), "49");
        assert_eq!(BipVersion::Bip84.to_string(), "84");
        assert_eq!(BipVersion::Bip86.to_string(), "86");
        assert_eq!(BipVersion::Slip44.to_string(), "SLIP-44");
    }

    #[test]
    fn test_wallet_security_level_display_and_order() {
        assert_eq!(WalletSecurityLevel::Maximum.to_string(), "Maximum");
        assert_eq!(WalletSecurityLevel::High.to_string(), "High");
        assert_eq!(WalletSecurityLevel::Medium.to_string(), "Medium");
        assert_eq!(WalletSecurityLevel::Low.to_string(), "Low");

        // Derived Ord follows declaration order, so Maximum sorts lowest.
        assert!(WalletSecurityLevel::Maximum < WalletSecurityLevel::High);
        assert!(WalletSecurityLevel::High < WalletSecurityLevel::Medium);
        assert!(WalletSecurityLevel::Medium < WalletSecurityLevel::Low);
    }

    #[test]
    fn test_get_address_by_index() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );

        for index in [0u32, 5] {
            wallet.add_address(WalletAddress {
                address: format!("addr-{}", index),
                address_type: AddressType::P2PKH,
                derivation_path: None,
                index,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: Utc::now(),
            });
        }

        assert_eq!(
            wallet.get_address_by_index(5).map(|a| a.address.as_str()),
            Some("addr-5")
        );
        assert!(wallet.get_address_by_index(42).is_none());
    }

    #[test]
    fn test_mark_address_used_missing_returns_false() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );

        assert!(!wallet.mark_address_used("unknown-address"));
    }

    #[test]
    fn test_security_score_components() {
        // Default: Medium (+10) on a base of 50.
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );
        assert_eq!(wallet.security_score(), 60);

        // Low level subtracts 10.
        wallet.security_level = WalletSecurityLevel::Low;
        assert_eq!(wallet.security_score(), 40);

        // Maximum (+35) combined with watch-only (-20).
        wallet.security_level = WalletSecurityLevel::Maximum;
        wallet.watch_only = true;
        assert_eq!(wallet.security_score(), 65);
        wallet.watch_only = false;

        // High (+25) plus encrypted mnemonic (+10).
        wallet.security_level = WalletSecurityLevel::High;
        wallet.encrypted_mnemonic = Some(vec![9, 9]);
        assert_eq!(wallet.security_score(), 85);

        // Hardware wallet (+10) on top of Medium and mnemonic.
        wallet.security_level = WalletSecurityLevel::Medium;
        wallet.wallet_type = WalletType::Hardware {
            device_type: "Ledger Nano S".to_string(),
            device_fingerprint: Some("fp".to_string()),
        };
        assert_eq!(wallet.security_score(), 80);

        // Backup info present but unverified adds nothing.
        wallet.security_level = WalletSecurityLevel::High;
        wallet.encrypted_mnemonic = None;
        wallet.wallet_type = WalletType::SingleAddress;
        wallet.metadata.backup_info = Some(WalletBackupInfo {
            backup_location: BackupLocation::PaperBackup,
            last_backup_at: None,
            backup_verified: false,
            backup_copies: 1,
            recovery_phrase_backup_method: None,
        });
        assert_eq!(wallet.security_score(), 75);
    }

    #[test]
    fn test_security_score_clamps_at_100() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::MultiSignature {
                required_signatures: 2,
                total_signers: 3,
                redeem_script: None,
            },
            vec![1, 2, 3, 4],
        );
        wallet.security_level = WalletSecurityLevel::Maximum;
        wallet.encrypted_mnemonic = Some(vec![1]);
        wallet.metadata.backup_info = Some(WalletBackupInfo {
            backup_location: BackupLocation::MetalBackup,
            last_backup_at: Some(Utc::now()),
            backup_verified: true,
            backup_copies: 2,
            recovery_phrase_backup_method: Some(RecoveryPhraseBackupMethod::Metal),
        });

        // 50 + 35 + 10 + 15 + 5 = 115, clamped to 100.
        assert_eq!(wallet.security_score(), 100);
    }

    #[test]
    fn test_validate_hot_wallet_without_private_key() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            Vec::new(),
        );

        assert!(wallet.validate().is_err());

        wallet.encrypted_private_key = vec![1];
        assert!(wallet.validate().is_ok());
    }

    #[test]
    fn test_validate_watch_only_without_xpub() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );
        wallet.watch_only = true;
        wallet.encrypted_private_key.clear();

        assert!(wallet.validate().is_err());

        wallet.extended_public_key = Some("xpub661MyMw".to_string());
        assert!(wallet.validate().is_ok());
    }

    #[test]
    fn test_validate_multisig_zero_required_signatures() {
        let wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Multi-sig".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::MultiSignature {
                required_signatures: 0,
                total_signers: 3,
                redeem_script: None,
            },
            vec![1, 2, 3, 4],
        );

        assert!(wallet.validate().is_err());
    }

    #[test]
    fn test_validate_multisig_valid_configuration() {
        let wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Multi-sig".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::MultiSignature {
                required_signatures: 2,
                total_signers: 3,
                redeem_script: Some("script".to_string()),
            },
            vec![1, 2, 3, 4],
        );

        assert!(wallet.validate().is_ok());
    }

    #[test]
    fn test_validate_derivation_path_format() {
        let mut wallet = CryptoWallet::new(
            Uuid::new_v4(),
            "Test".to_string(),
            BlockchainNetwork::Bitcoin,
            WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );

        wallet.derivation_path = Some("44'/0'/0'/0".to_string());
        assert!(wallet.validate().is_err());

        wallet.derivation_path = Some("m/44'/0'/0'/0".to_string());
        assert!(wallet.validate().is_ok());
    }

    #[test]
    fn test_recommended_derivation_path_all_networks() {
        let cases = [
            (BlockchainNetwork::BitcoinCash, "m/44'/145'/7'/0"),
            (BlockchainNetwork::Litecoin, "m/44'/2'/7'/0"),
            (BlockchainNetwork::Dogecoin, "m/44'/3'/7'/0"),
            (BlockchainNetwork::Polygon, "m/44'/137'/7'/0"),
            (BlockchainNetwork::Arbitrum, "m/44'/42161'/7'/0"),
            (BlockchainNetwork::Optimism, "m/44'/10'/7'/0"),
            (BlockchainNetwork::BinanceSmartChain, "m/44'/714'/7'/0"),
            (
                BlockchainNetwork::Custom("MyChain".to_string()),
                "m/44'/0'/7'/0",
            ),
        ];
        for (network, expected) in cases {
            assert_eq!(
                CryptoWallet::recommended_derivation_path(&network, 7),
                expected
            );
        }
    }

    #[test]
    fn test_wallet_type_serde_roundtrip() {
        let types = vec![
            WalletType::HierarchicalDeterministic {
                bip_version: BipVersion::Bip84,
                address_count: 10,
                gap_limit: 5,
            },
            WalletType::SingleAddress,
            WalletType::MultiSignature {
                required_signatures: 2,
                total_signers: 3,
                redeem_script: Some("script".to_string()),
            },
            WalletType::Hardware {
                device_type: "Trezor".to_string(),
                device_fingerprint: None,
            },
        ];
        for wallet_type in types {
            assert_eq!(roundtrip(&wallet_type), wallet_type);
        }
    }

    #[test]
    fn test_wallet_serde_roundtrip() {
        let mut wallet = CryptoWallet::new_watch_only(
            Uuid::new_v4(),
            "Roundtrip".to_string(),
            BlockchainNetwork::Ethereum,
            "xpub-roundtrip".to_string(),
        );
        wallet.description = Some("kept".to_string());
        wallet.derivation_path = Some("m/44'/60'/0'/0".to_string());
        wallet.encrypted_mnemonic = Some(vec![7, 8, 9]);
        wallet.metadata.tags = vec!["cold".to_string()];
        wallet.metadata.notes = Some("note".to_string());
        wallet.metadata.platform = Some("Ledger".to_string());
        wallet.metadata.purpose = Some("savings".to_string());
        wallet.metadata.associated_services = vec!["dapp.example".to_string()];
        wallet.metadata.backup_info = Some(WalletBackupInfo {
            backup_location: BackupLocation::SplitStorage {
                required_shares: 2,
                total_shares: 3,
            },
            last_backup_at: Some(Utc::now()),
            backup_verified: true,
            backup_copies: 3,
            recovery_phrase_backup_method: Some(RecoveryPhraseBackupMethod::SplitLocations),
        });
        wallet.metadata.security_settings = WalletSecuritySettings {
            require_biometric: true,
            require_password: true,
            max_unverified_amount: Some("0.1".to_string()),
            require_2fa_above: Some("1.0".to_string()),
            transaction_notifications: true,
            address_book_only: true,
            address_whitelist: vec!["0xabc".to_string()],
            address_blacklist: vec!["0xdead".to_string()],
            daily_transaction_limit: Some("2".to_string()),
            weekly_transaction_limit: Some("10".to_string()),
            monthly_transaction_limit: Some("40".to_string()),
            spending_frozen_until: Some(Utc::now()),
            spending_frozen_with_recovery: Some("recover".to_string()),
        };
        wallet
            .metadata
            .custom_data
            .insert("k".to_string(), "v".to_string());

        let decoded: CryptoWallet = roundtrip(&wallet);
        assert_eq!(decoded, wallet);
    }

    #[test]
    fn test_wallet_address_serde_roundtrip() {
        let addresses = vec![
            WalletAddress {
                address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
                address_type: AddressType::P2PKH,
                derivation_path: Some("m/44'/0'/0'/0/0".to_string()),
                index: 0,
                used: true,
                balance: Some("0.5".to_string()),
                last_activity: Some(Utc::now()),
                metadata: HashMap::new(),
                created_at: Utc::now(),
            },
            WalletAddress {
                address: "addr".to_string(),
                address_type: AddressType::P2SH,
                derivation_path: None,
                index: 1,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: Utc::now(),
            },
            WalletAddress {
                address: "addr".to_string(),
                address_type: AddressType::P2WPKH,
                derivation_path: None,
                index: 2,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: Utc::now(),
            },
            WalletAddress {
                address: "addr".to_string(),
                address_type: AddressType::P2TR,
                derivation_path: None,
                index: 3,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: Utc::now(),
            },
            WalletAddress {
                address: "0x0000000000000000000000000000000000000000".to_string(),
                address_type: AddressType::Ethereum,
                derivation_path: None,
                index: 4,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: Utc::now(),
            },
            WalletAddress {
                address: "sol-addr".to_string(),
                address_type: AddressType::Solana,
                derivation_path: None,
                index: 5,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: Utc::now(),
            },
            WalletAddress {
                address: "custom-addr".to_string(),
                address_type: AddressType::Custom("Bech32".to_string()),
                derivation_path: None,
                index: 6,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: Utc::now(),
            },
        ];
        for address in addresses {
            assert_eq!(roundtrip(&address), address);
        }
    }

    #[test]
    fn test_transaction_serde_roundtrip() {
        let schemes = vec![
            SignatureScheme::ECDSA,
            SignatureScheme::EdDSA,
            SignatureScheme::Schnorr,
            SignatureScheme::BLS,
        ];
        for scheme in schemes {
            assert_eq!(roundtrip(&scheme), scheme);
        }

        let request = TransactionRequest {
            id: Uuid::new_v4(),
            wallet_id: Uuid::new_v4(),
            network: BlockchainNetwork::Polygon,
            from_address: "0xfrom".to_string(),
            to_address: "0xto".to_string(),
            amount: "1000000".to_string(),
            fee: "21000".to_string(),
            gas_price: Some("30".to_string()),
            gas_limit: Some(21000),
            nonce: Some(7),
            memo: Some("memo".to_string()),
            raw_transaction_data: Some(vec![1, 2]),
            required_signatures: 1,
            created_at: Utc::now(),
            expires_at: Some(Utc::now()),
            metadata: HashMap::new(),
        };
        let request_decoded: TransactionRequest = roundtrip(&request);
        assert_eq!(request_decoded, request);

        let statuses = vec![
            BroadcastStatus::NotBroadcast,
            BroadcastStatus::Broadcasting,
            BroadcastStatus::BroadcastSuccess {
                hash: "0xhash".to_string(),
                block_height: Some(18_000_000),
                confirmations: 12,
                confirmed_at: Some(Utc::now()),
            },
            BroadcastStatus::BroadcastFailed {
                error: "nonce too low".to_string(),
                retry_count: 2,
            },
        ];
        for status in statuses {
            let signed = SignedTransaction {
                id: Uuid::new_v4(),
                request: request.clone(),
                signatures: vec![TransactionSignature {
                    signer_address: "0xfrom".to_string(),
                    signature: vec![1, 1, 1],
                    public_key: vec![2, 2, 2],
                    signature_scheme: SignatureScheme::ECDSA,
                    signed_at: Utc::now(),
                }],
                raw_signed_transaction: vec![9, 9],
                transaction_hash: "0xhash".to_string(),
                signed_at: Utc::now(),
                broadcast_status: status,
            };
            let decoded: SignedTransaction = roundtrip(&signed);
            assert_eq!(decoded, signed);
        }
    }

    #[test]
    fn test_backup_info_serde_roundtrip() {
        let locations = vec![
            BackupLocation::LocalFileSystem,
            BackupLocation::EncryptedCloudStorage,
            BackupLocation::PaperBackup,
            BackupLocation::MetalBackup,
            BackupLocation::HardwareDevice,
            BackupLocation::SplitStorage {
                required_shares: 3,
                total_shares: 5,
            },
        ];
        for backup_location in locations {
            let info = WalletBackupInfo {
                backup_location,
                last_backup_at: Some(Utc::now()),
                backup_verified: true,
                backup_copies: 2,
                recovery_phrase_backup_method: Some(RecoveryPhraseBackupMethod::Paper),
            };
            assert_eq!(roundtrip(&info), info);
        }

        let methods = vec![
            RecoveryPhraseBackupMethod::Paper,
            RecoveryPhraseBackupMethod::Metal,
            RecoveryPhraseBackupMethod::PasswordManager,
            RecoveryPhraseBackupMethod::SplitLocations,
            RecoveryPhraseBackupMethod::HardwareSecurityModule,
        ];
        for method in methods {
            assert_eq!(roundtrip(&method), method);
        }
    }

    #[test]
    fn test_wallet_metadata_defaults() {
        let metadata = WalletMetadata::default();
        assert!(metadata.tags.is_empty());
        assert!(metadata.notes.is_none());
        assert!(metadata.platform.is_none());
        assert!(metadata.purpose.is_none());
        assert!(metadata.associated_services.is_empty());
        assert!(metadata.backup_info.is_none());
        assert!(metadata.custom_data.is_empty());

        let settings = WalletSecuritySettings::default();
        assert!(!settings.require_biometric);
        assert!(!settings.require_password);
        assert!(settings.max_unverified_amount.is_none());
        assert!(settings.require_2fa_above.is_none());
        assert!(!settings.transaction_notifications);
        assert!(!settings.address_book_only);
        assert!(settings.address_whitelist.is_empty());
        assert!(settings.address_blacklist.is_empty());
        assert!(settings.daily_transaction_limit.is_none());
        assert!(settings.weekly_transaction_limit.is_none());
        assert!(settings.monthly_transaction_limit.is_none());
        assert!(settings.spending_frozen_until.is_none());
        assert!(settings.spending_frozen_with_recovery.is_none());
    }
}
