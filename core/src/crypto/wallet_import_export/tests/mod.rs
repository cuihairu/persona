//! Test hub for the wallet_import_export split (LAY-018): shared constants and
//! helpers plus topic-grouped test modules. Each group pulls them in via
//! `use super::*` (the constants, helpers and hub imports stay visible to
//! descendants).

use super::*;
// expect_sign_err's signature references WalletSigningKey and hd_wallet
// returns CryptoWallet, but the hub no longer imports those types wholesale.
use crate::crypto::transaction_signing::WalletSigningKey;
use crate::models::wallet::CryptoWallet;

mod export;
mod format;
mod import;
mod keystore;
mod network;
mod signing;

fn encode_compressed_mainnet_wif(private_key: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(0x80);
    payload.extend_from_slice(private_key);
    payload.push(0x01);

    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}

/// `WalletSigningKey` is not `Debug`, so `expect_err` cannot be used.
fn expect_sign_err(result: PersonaResult<WalletSigningKey>, msg: &str) -> PersonaError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("{msg}"),
    }
}

fn hd_wallet(network: BlockchainNetwork, count: usize) -> CryptoWallet {
    import_from_mnemonic(
        Uuid::new_v4(),
        "HD".to_string(),
        TEST_PHRASE,
        "",
        network,
        None,
        count,
        "pw",
    )
    .unwrap()
}

const TEST_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ETH_KEY: &str = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";
