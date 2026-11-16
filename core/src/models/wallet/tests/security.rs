use super::*;

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
