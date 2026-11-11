use super::*;
use crate::crypto::wallet_crypto::{MasterKey, SecureMnemonic};
use alloy_consensus::SignableTransaction;
use alloy_primitives::B256;
use bitcoin::absolute::LockTime;
use bitcoin::amount::Amount;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Txid};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::signature::SignatureEncoding;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use super::btc::{
    create_bitcoin_sighash, parse_btc_inputs, parse_satoshis, script_pubkey_for_address,
    sign_with_secp256k1, MAX_MONEY_SATS, SIGHASH_ALL,
};
use super::ethereum::{
    build_eip155_raw_transaction_with, chain_id, eip1559_tx, evm_tx_type, legacy_tx,
    minimal_be_bytes, recovery_id_for, EvmTxType,
};
use super::verify::{address_from_verifying_key, decode_varuint};

use std::collections::HashMap;

fn create_test_signing_key() -> SigningKey {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = SecureMnemonic::from_phrase(phrase).unwrap();
    let seed = mnemonic.to_seed("");

    let master_key = MasterKey::from_seed(&seed).unwrap();
    master_key
        .derive_path("m/44'/60'/0'/0/0")
        .unwrap()
        .to_signing_key()
        .unwrap()
}

fn test_key_from_raw(raw: [u8; 32]) -> SigningKey {
    SigningKey::from_slice(&raw).unwrap()
}

/// Build a `Txid` from wire-order bytes (the order txids appear inside
/// a raw transaction), which is how BIP-143 vectors list them.
fn wire_order_txid(hex_str: &str) -> Txid {
    Txid::from_byte_array(hex::decode(hex_str).unwrap().try_into().unwrap())
}

fn eth_request(nonce: u64) -> TransactionRequest {
    TransactionRequest {
        id: uuid::Uuid::new_v4(),
        wallet_id: uuid::Uuid::new_v4(),
        network: BlockchainNetwork::Ethereum,
        from_address: "0x0000000000000000000000000000000000000000".to_string(),
        to_address: "0x3535353535353535353535353535353535353535".to_string(),
        amount: "1000000000000000000".to_string(), // 1 ETH in wei
        fee: "0".to_string(),
        gas_price: Some("20000000000".to_string()), // 20 gwei
        gas_limit: Some(21000),
        nonce: Some(nonce),
        memo: None,
        raw_transaction_data: None,
        required_signatures: 1,
        created_at: Utc::now(),
        expires_at: None,
        metadata: HashMap::new(),
    }
}

fn eip1559_request(nonce: u64) -> TransactionRequest {
    let mut request = eth_request(nonce);
    request.gas_price = None; // legacy fee field must not be needed
    request.metadata.insert(
        "max_fee_per_gas".to_string(),
        "30000000000".to_string(), // 30 gwei
    );
    request.metadata.insert(
        "max_priority_fee_per_gas".to_string(),
        "2000000000".to_string(), // 2 gwei
    );
    request
}

fn btc_request(from: String, to: String) -> TransactionRequest {
    TransactionRequest {
        network: BlockchainNetwork::Bitcoin,
        from_address: from,
        to_address: to,
        amount: "100000".to_string(),
        fee: "1000".to_string(),
        ..eth_request(0)
    }
}

#[test]
fn k256_error_converts_into_persona_error() {
    // k256's ecdsa::Error is signature::Error; the From impl wraps its
    // message into a cryptographic PersonaError.
    let converted: PersonaError = k256::ecdsa::Error::new().into();
    assert!(!converted.to_string().is_empty());
}

#[test]
fn sign_transaction_rejects_mismatched_key_curve() {
    // Bitcoin with an Ed25519 key.
    let ed = WalletSigningKey::Ed25519(Ed25519Key::from_seed(&[7u8; 64]).unwrap());
    let err = sign_transaction(
        &btc_request(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        ),
        &ed,
    )
    .expect_err("Bitcoin requires secp256k1");
    assert!(err.to_string().contains("No matching signing key curve"));

    // Solana with a secp256k1 key.
    let secp = WalletSigningKey::Secp256k1(create_test_signing_key());
    let mut sol_request = eth_request(0);
    sol_request.network = BlockchainNetwork::Solana;
    sol_request.raw_transaction_data = Some(b"msg".to_vec());
    assert!(sign_transaction(&sol_request, &secp).is_err());
}

#[test]
fn sign_transaction_covers_solana_dispatch() {
    let ed_key = Ed25519Key::from_seed(&[7u8; 64]).unwrap();
    let message = b"solana wire message".to_vec();
    let mut request = eth_request(0);
    request.network = BlockchainNetwork::Solana;
    request.from_address = bs58::encode(ed_key.public_bytes()).into_string();
    request.raw_transaction_data = Some(message.clone());

    let sig = sign_transaction(&request, &WalletSigningKey::Ed25519(ed_key.clone())).unwrap();
    assert_eq!(sig.signature_scheme, SignatureScheme::EdDSA);
    assert_eq!(sig.public_key, ed_key.public_bytes().to_vec());
    assert_eq!(sig.signature.len(), 64);
    assert!(verify_solana_transaction(&sig, &message).unwrap());
}

#[test]
fn build_raw_transaction_rejects_wrong_curves_and_networks() {
    let secp = WalletSigningKey::Secp256k1(create_test_signing_key());
    let ed = WalletSigningKey::Ed25519(Ed25519Key::from_seed(&[7u8; 64]).unwrap());

    // Bitcoin requires secp256k1.
    let err = build_raw_transaction(
        &btc_request(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        ),
        &ed,
    )
    .expect_err("Bitcoin requires secp256k1");
    assert!(err.to_string().contains("Bitcoin requires a secp256k1"));

    // Ethereum requires secp256k1.
    let err = build_raw_transaction(&eth_request(0), &ed).expect_err("Ethereum requires secp256k1");
    assert!(err.to_string().contains("Ethereum requires a secp256k1"));

    // Solana requires Ed25519.
    let mut sol = eth_request(0);
    sol.network = BlockchainNetwork::Solana;
    sol.raw_transaction_data = Some(b"msg".to_vec());
    let err = build_raw_transaction(&sol, &secp).expect_err("Solana requires Ed25519");
    assert!(err.to_string().contains("Solana requires an Ed25519"));

    // Other networks have no raw assembly.
    let mut other = eth_request(0);
    other.network = BlockchainNetwork::BitcoinCash;
    let err = build_raw_transaction(&other, &secp).expect_err("raw assembly is network-limited");
    assert!(err.to_string().contains("not supported"));
}

#[test]
fn secp_compressed_pubkey_prefixes_by_parity() {
    // Key 1 has even-y pubkey 0279BE667E...
    let one = test_key_from_raw({
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    });
    let compressed = secp_compressed_pubkey(&one);
    assert_eq!(compressed[0], 0x02);
    assert_eq!(
        hex::encode(&compressed[1..]),
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
}

#[test]
fn sign_transaction_dispatches_ethereum_secp256k1() {
    let mut request = eth_request(0);
    let key = test_key_from_raw([0x46u8; 32]);
    let expected_address = address_from_verifying_key(key.verifying_key()).unwrap();
    request.from_address = expected_address.clone();

    let signature = sign_transaction(&request, &WalletSigningKey::Secp256k1(key)).unwrap();
    assert_eq!(signature.signature_scheme, SignatureScheme::ECDSA);
    assert!(signature.signature.len() >= 65 && signature.signature.len() <= 67);
    assert_eq!(signature.signer_address, expected_address);
    assert!(verify_ethereum_transaction(&request, &signature).unwrap());
}

mod btc;
mod eth;
mod solana;
mod verify;
