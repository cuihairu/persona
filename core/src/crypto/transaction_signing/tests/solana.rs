use super::*;

#[test]
fn test_solana_transaction_signing() {
    let seed = [7u8; 64];
    let ed_key = Ed25519Key::from_seed(&seed).unwrap();
    let message = b"serialized solana message".to_vec();
    let request = TransactionRequest {
        network: BlockchainNetwork::Solana,
        from_address: bs58::encode(ed_key.public_bytes()).into_string(),
        raw_transaction_data: Some(message.clone()),
        ..eth_request(0)
    };

    let (signature, scheme) = sign_solana_transaction(&request, &ed_key).unwrap();
    assert_eq!(scheme, SignatureScheme::EdDSA);
    assert_eq!(signature.len(), 64);

    let tx_signature = signature_for(
        &request.from_address,
        signature,
        ed_key.public_bytes().to_vec(),
        SignatureScheme::EdDSA,
        Utc::now(),
    );
    assert!(verify_solana_transaction(&tx_signature, &message).unwrap());
}

#[test]
fn test_solana_signing_requires_message() {
    let ed_key = Ed25519Key::from_seed(&[7u8; 64]).unwrap();
    let request = TransactionRequest {
        network: BlockchainNetwork::Solana,
        ..eth_request(0)
    };
    assert!(sign_solana_transaction(&request, &ed_key).is_err());
}

#[test]
fn build_raw_transaction_covers_solana() {
    let ed_key = Ed25519Key::from_seed(&[7u8; 64]).unwrap();
    let message = b"serialized solana message".to_vec();
    let mut request = eth_request(0);
    request.network = BlockchainNetwork::Solana;
    request.from_address = bs58::encode(ed_key.public_bytes()).into_string();
    request.raw_transaction_data = Some(message.clone());

    let signed =
        build_raw_transaction(&request, &WalletSigningKey::Ed25519(ed_key.clone())).unwrap();
    // Wire format: 1 signature || 64-byte sig || message.
    assert_eq!(signed.raw[0], 1);
    assert_eq!(&signed.raw[1..65], &ed_key.sign(&message)[..]);
    assert_eq!(&signed.raw[65..], &message[..]);
    // Hash is the base58 signature.
    assert_eq!(signed.hash, bs58::encode(&signed.raw[1..65]).into_string());
}
