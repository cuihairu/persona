use super::*;

#[test]
fn keystore_export_roundtrips_through_keystore_import() {
    let wallet = hd_wallet(BlockchainNetwork::Ethereum, 1);
    let json = export_keystore(&wallet, "pw").expect("ethereum export must succeed");
    let secret = crate::crypto::wallet_encryption::import_from_keystore(&json, "pw")
        .unwrap_or_else(|e| panic!("roundtrip import must succeed: {e}"));
    let stored = export_private_key(&wallet, "pw").unwrap();
    assert_eq!(
        hex::encode(&*secret),
        stored.trim().trim_start_matches("0x").to_lowercase(),
        "roundtrip must recover the same key"
    );
}

#[test]
fn keystore_export_rejects_watch_only_and_non_ethereum() {
    let mut wallet = hd_wallet(BlockchainNetwork::Bitcoin, 1);
    let err = export_keystore(&wallet, "pw").expect_err("bitcoin wallet must not export keystore");
    assert!(err.to_string().contains("Ethereum"));
    wallet.network = BlockchainNetwork::Ethereum;
    wallet.watch_only = true;
    let err =
        export_keystore(&wallet, "pw").expect_err("watch-only wallet must not export keystore");
    assert!(err.to_string().contains("Watch-only"));
}
