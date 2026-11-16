use super::*;

#[test]
fn wallet_key_material_constructors() {
    let from_key = WalletKeyMaterial::from_private_key(vec![1u8; 32]);
    assert!(!from_key.has_mnemonic());
    assert_eq!(from_key.private_key, vec![1u8; 32]);
    assert!(from_key.derivation_path.is_none());

    let from_mnemonic = WalletKeyMaterial::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            Some("m/44'/60'/0'/0/0".to_string()),
        );
    assert!(from_mnemonic.has_mnemonic());
    assert!(from_mnemonic.private_key.is_empty());
    assert_eq!(
        from_mnemonic.derivation_path.as_deref(),
        Some("m/44'/60'/0'/0/0")
    );
}
