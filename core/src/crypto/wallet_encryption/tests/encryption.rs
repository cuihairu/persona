use super::*;

#[test]
fn test_private_key_encryption() {
    let private_key = vec![0x42; 32];
    let password = "test_password_123";

    let encrypted = encrypt_private_key(&private_key, password).unwrap();
    assert!(!encrypted.encrypted_data.is_empty());

    let decrypted = decrypt_private_key(&encrypted, password).unwrap();
    assert_eq!(decrypted, private_key);
}

#[test]
fn test_mnemonic_encryption() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "secure_password";

    let encrypted = encrypt_mnemonic(mnemonic, password).unwrap();
    let decrypted = decrypt_mnemonic(&encrypted, password).unwrap();

    assert_eq!(decrypted, mnemonic);
}

#[test]
fn test_password_validation() {
    let private_key = vec![0x99; 32];
    let password = "correct_password";

    let encrypted = encrypt_private_key(&private_key, password).unwrap();

    assert!(validate_wallet_password(&encrypted, password));
    assert!(!validate_wallet_password(&encrypted, "wrong_password"));
}

#[test]
fn test_password_change() {
    let private_key = vec![0xAB; 32];
    let old_password = "old_pass";
    let new_password = "new_pass";

    let encrypted = encrypt_private_key(&private_key, old_password).unwrap();
    let re_encrypted = change_wallet_password(&encrypted, old_password, new_password).unwrap();

    // Old password should not work
    assert!(!validate_wallet_password(&re_encrypted, old_password));

    // New password should work
    assert!(validate_wallet_password(&re_encrypted, new_password));

    // Data should be intact
    let decrypted = decrypt_private_key(&re_encrypted, new_password).unwrap();
    assert_eq!(decrypted, private_key);
}

#[test]
fn mnemonic_password_change_rewraps_with_fresh_salt() {
    let phrase = "test wave barrel tea";

    let encrypted = encrypt_mnemonic(phrase, "old_pass").unwrap();
    let re_encrypted = change_mnemonic_password(&encrypted, "old_pass", "new_pass").unwrap();

    // Old password no longer decrypts; new one restores the phrase.
    assert!(decrypt_mnemonic(&re_encrypted, "old_pass").is_err());
    assert_eq!(decrypt_mnemonic(&re_encrypted, "new_pass").unwrap(), phrase);

    // Fresh salt/nonce: the ciphertext is not byte-identical to the old one.
    assert_ne!(re_encrypted.salt, encrypted.salt);
    assert_ne!(re_encrypted.nonce, encrypted.nonce);

    // Wrong old password is rejected without producing a new blob.
    assert!(change_mnemonic_password(&encrypted, "wrong", "new_pass").is_err());
}

#[test]
fn test_master_key_encryption() {
    let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
    let master_key = MasterKey::from_mnemonic(&mnemonic, "").unwrap();
    let password = "master_password";

    let encrypted = encrypt_master_key(&master_key, password).unwrap();
    let decrypted = decrypt_master_key(&encrypted, password).unwrap();

    // Verify keys match by comparing xpub
    assert_eq!(master_key.to_xpub(), decrypted.to_xpub());
}
