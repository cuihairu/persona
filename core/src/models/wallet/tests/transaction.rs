use super::*;

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
