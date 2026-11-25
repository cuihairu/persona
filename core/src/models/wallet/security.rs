//! Backup and security: backup info/location/mnemonic backup method, security
//! settings and security levels.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
