use super::*;
use crate::crypto::wallet_encryption::encrypt_private_key;

#[test]
fn test_signing_key_for_eth_hd_matches_address() {
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "test_password";

    let mut wallet = import_from_mnemonic(
        Uuid::new_v4(),
        "eth".to_string(),
        test_mnemonic,
        "",
        BlockchainNetwork::Ethereum,
        None,
        2,
        password,
    )
    .unwrap();

    let first_address = wallet.addresses[0].address.clone();
    let key = signing_key_for_address(&wallet, password, &first_address).unwrap();
    let WalletSigningKey::Secp256k1(signing_key) = key else {
        panic!("expected secp256k1 signing key");
    };
    let derived =
            crate::crypto::address_generator::generate_ethereum_address_checksummed_from_compressed_pubkey(
                &{
                    let encoded = signing_key.verifying_key().to_sec1_point(true);
                    encoded.as_bytes().try_into().unwrap()
                },
            )
            .unwrap();
    assert_eq!(derived.to_lowercase(), first_address.to_lowercase());

    wallet.addresses.clear();
}

#[test]
fn signing_key_for_address_rejects_watch_only() {
    let mut wallet = import_from_private_key(
        Uuid::new_v4(),
        "watch".to_string(),
        ETH_KEY,
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .unwrap();
    wallet.watch_only = true;
    let err = expect_sign_err(
        signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address),
        "watch-only wallets must not sign",
    );
    assert!(err.to_string().contains("Watch-only wallets cannot sign"));
}

#[test]
fn signing_key_for_address_requires_a_derivation_path() {
    // HD secp256k1 wallet without any path information.
    let mut wallet = hd_wallet(BlockchainNetwork::Bitcoin, 1);
    let address = wallet.addresses[0].address.clone();
    wallet.addresses.clear();
    wallet.derivation_path = None;
    let err = expect_sign_err(
        signing_key_for_address(&wallet, "pw", &address),
        "HD wallet without a path must be rejected",
    );
    assert!(err.to_string().contains("Wallet has no derivation path"));

    // Same for the Solana (Ed25519) branch.
    let mut sol = hd_wallet(BlockchainNetwork::Solana, 1);
    let sol_address = sol.addresses[0].address.clone();
    sol.addresses.clear();
    sol.derivation_path = None;
    let err = expect_sign_err(
        signing_key_for_address(&sol, "pw", &sol_address),
        "Solana wallet without a path must be rejected",
    );
    assert!(err.to_string().contains("Wallet has no derivation path"));
}

#[test]
fn signing_key_for_solana_rejects_short_key_material() {
    let mut wallet = hd_wallet(BlockchainNetwork::Solana, 1);
    wallet.encrypted_private_key =
        serde_json::to_vec(&encrypt_private_key(&[7u8; 16], "pw").unwrap()).unwrap();
    let err = expect_sign_err(
        signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address),
        "16-byte Solana key material must be rejected",
    );
    assert!(err
        .to_string()
        .contains("Invalid Solana key material length"));
}

#[test]
fn signing_key_for_solana_rejects_oversized_key_material() {
    // 40 bytes yield a 32-byte secret but only an 8-byte chain code.
    let mut wallet = hd_wallet(BlockchainNetwork::Solana, 1);
    wallet.encrypted_private_key =
        serde_json::to_vec(&encrypt_private_key(&[7u8; 40], "pw").unwrap()).unwrap();
    let err = expect_sign_err(
        signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address),
        "40-byte Solana key material must be rejected",
    );
    assert!(err
        .to_string()
        .contains("Invalid Solana key material length"));
}
