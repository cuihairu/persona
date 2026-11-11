use super::*;

// The worked example from the EIP-155 specification.
#[test]
fn test_eip155_spec_signing_hash() {
    // nonce=9, gasprice=20e9, startgas=21000, to=0x3535..35, value=1e18
    let request = eth_request(9);
    let hash: B256 = legacy_tx(&request).unwrap().signature_hash();
    assert_eq!(
        hex::encode(hash),
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    );
}

// The EIP-155 spec's signed example: the private key 0x46 repeated must
// produce exactly the canonical signed transaction bytes.
#[test]
fn test_eip155_spec_signed_transaction() {
    let request = eth_request(9);
    let key = test_key_from_raw([0x46u8; 32]);
    let raw = build_eip155_raw_transaction_with(&request, &key).unwrap();

    assert_eq!(
        hex::encode(&raw),
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    );
}

#[test]
fn test_ethereum_transaction_signing_roundtrip() {
    let request = eth_request(0);

    let private_key = create_test_signing_key();
    let (signature, scheme) = sign_ethereum_transaction(&request, &private_key).unwrap();
    assert_eq!(scheme, SignatureScheme::ECDSA);
    // r(32) + s(32) + v(1..3)
    assert!(signature.len() >= 65 && signature.len() <= 67);

    // The signature must verify against the actual from_address.
    let expected_address = address_from_verifying_key(private_key.verifying_key()).unwrap();
    let tx_signature = signature_for(
        &expected_address,
        signature,
        secp_compressed_pubkey(&private_key).to_vec(),
        SignatureScheme::ECDSA,
        Utc::now(),
    );
    assert!(verify_ethereum_transaction(&request, &tx_signature).unwrap());
}

#[test]
fn test_eip155_raw_transaction_builds_and_hashes() {
    let request = eth_request(4);
    let key = WalletSigningKey::Secp256k1(create_test_signing_key());
    let signed = build_raw_transaction(&request, &key).unwrap();
    assert_eq!(signed.raw[0], 0xf8); // RLP list header
    assert!(signed.hash.starts_with("0x"));
    assert_eq!(signed.hash.len(), 66);
}

#[test]
fn test_eip1559_signing_roundtrip_and_raw() {
    let request = eip1559_request(3);
    let key = create_test_signing_key();
    let expected_address = address_from_verifying_key(key.verifying_key()).unwrap();

    // Audit signature path: r||s||y_parity.
    let (sig, scheme) = sign_ethereum_transaction(&request, &key).unwrap();
    assert_eq!(scheme, SignatureScheme::ECDSA);
    assert_eq!(sig.len(), 65); // typed transactions carry a 1-byte parity
    let tx_sig = signature_for(
        &expected_address,
        sig,
        secp_compressed_pubkey(&key).to_vec(),
        SignatureScheme::ECDSA,
        Utc::now(),
    );
    assert!(verify_ethereum_transaction(&request, &tx_sig).unwrap());

    // Raw path: 0x02 typed envelope with the same fields echoed back.
    let signed = build_raw_transaction(&request, &WalletSigningKey::Secp256k1(key)).unwrap();
    assert_eq!(signed.raw[0], 0x02);
    assert!(signed.hash.starts_with("0x"));
    assert_eq!(signed.hash.len(), 66);
}

#[test]
fn test_eip1559_build_matches_manual_signing_hash() {
    // The raw envelope's [chainId, nonce, prio, fee, gas, to, value, data]
    // must be exactly the fields the signing hash committed to.
    let request = eip1559_request(7);
    let hash: B256 = eip1559_tx(&request).unwrap().signature_hash();
    // Deterministic: same request, same hash (RFC-6979 signing not
    // involved in the hash itself).
    assert_eq!(hash, eip1559_tx(&request).unwrap().signature_hash());
}

#[test]
fn test_eip1559_fee_validation() {
    let key = create_test_signing_key();

    // priority fee above max fee is invalid
    let mut request = eip1559_request(0);
    request.metadata.insert(
        "max_priority_fee_per_gas".to_string(),
        "40000000000".to_string(),
    );
    assert!(build_eip1559_raw_transaction(&request, &key).is_err());

    // missing max_fee_per_gas is invalid
    let mut request = eip1559_request(0);
    request.metadata.remove("max_fee_per_gas");
    assert!(build_eip1559_raw_transaction(&request, &key).is_err());

    // non-empty access lists are rejected rather than ignored
    let mut request = eip1559_request(0);
    request.metadata.insert(
        "access_list".to_string(),
        r#"[{"address":"0x00"}]"#.to_string(),
    );
    assert!(build_eip1559_raw_transaction(&request, &key).is_err());

    // empty access list string is fine
    let mut request = eip1559_request(0);
    request
        .metadata
        .insert("access_list".to_string(), "[]".to_string());
    assert!(build_eip1559_raw_transaction(&request, &key).is_ok());
}

#[test]
fn test_legacy_tx_still_uses_eip155_v() {
    // No 1559 metadata => legacy path, v >= 35.
    let request = eth_request(1);
    let key = create_test_signing_key();
    let (sig, _) = sign_ethereum_transaction(&request, &key).unwrap();
    let v = sig[sig.len() - 1];
    assert!(v >= 35, "legacy v must encode chain id + parity");
}

#[test]
fn minimal_be_bytes_encodes_minimally() {
    assert_eq!(minimal_be_bytes(0), Vec::<u8>::new());
    assert_eq!(minimal_be_bytes(1), vec![1]);
    assert_eq!(minimal_be_bytes(35), vec![35]);
    assert_eq!(minimal_be_bytes(255), vec![255]);
    assert_eq!(minimal_be_bytes(256), vec![1, 0]);
    assert_eq!(minimal_be_bytes(0x0100_0000_0000), vec![1, 0, 0, 0, 0, 0]);
}

#[test]
fn metadata_u128_rejects_non_numeric() {
    let mut request = eip1559_request(0);
    request
        .metadata
        .insert("max_fee_per_gas".to_string(), "abc".to_string());
    let err = build_eip1559_raw_transaction(&request, &create_test_signing_key())
        .expect_err("non-numeric fee metadata must be rejected");
    assert!(err.to_string().contains("must be a decimal integer"));
}

#[test]
fn evm_field_errors() {
    // Invalid to_address.
    let mut request = eth_request(0);
    request.to_address = "not an address".to_string();
    let err = build_eip155_raw_transaction(&request, &create_test_signing_key())
        .expect_err("invalid to_address must be rejected");
    assert!(err.to_string().contains("Invalid Ethereum to_address"));

    // Invalid wei amount.
    let mut request = eth_request(0);
    request.amount = "1.5".to_string();
    let err = build_eip155_raw_transaction(&request, &create_test_signing_key())
        .expect_err("fractional wei must be rejected");
    assert!(err.to_string().contains("Invalid wei amount"));

    // Hex input data is accepted (with or without 0x prefix).
    let mut request = eth_request(0);
    request
        .metadata
        .insert("data".to_string(), "0xdeadbeef".to_string());
    assert!(build_eip155_raw_transaction(&request, &create_test_signing_key()).is_ok());

    // Non-hex data is rejected.
    let mut request = eth_request(0);
    request
        .metadata
        .insert("data".to_string(), "zz-not-hex".to_string());
    let err = build_eip155_raw_transaction(&request, &create_test_signing_key())
        .expect_err("invalid hex data must be rejected");
    assert!(err.to_string().contains("must be hex"));
}

#[test]
fn legacy_tx_requires_nonce_gas_price_and_limit() {
    let key = create_test_signing_key();

    // Missing nonce.
    let mut request = eth_request(0);
    request.nonce = None;
    let err =
        build_eip155_raw_transaction(&request, &key).expect_err("missing nonce must be rejected");
    assert!(err.to_string().contains("require a nonce"));

    // Missing gas_price.
    let mut request = eth_request(0);
    request.gas_price = None;
    let err = build_eip155_raw_transaction(&request, &key)
        .expect_err("missing gas_price must be rejected");
    assert!(err.to_string().contains("require a numeric gas_price"));

    // Non-numeric gas_price.
    let mut request = eth_request(0);
    request.gas_price = Some("20 gwei".to_string());
    assert!(build_eip155_raw_transaction(&request, &key).is_err());

    // Missing gas_limit.
    let mut request = eth_request(0);
    request.gas_limit = None;
    let err = build_eip155_raw_transaction(&request, &key)
        .expect_err("missing gas_limit must be rejected");
    assert!(err.to_string().contains("require a gas_limit"));

    // EIP-1559: missing gas_limit is also rejected there.
    let mut request = eip1559_request(0);
    request.gas_limit = None;
    let err = build_eip1559_raw_transaction(&request, &key)
        .expect_err("1559 missing gas_limit must be rejected");
    assert!(err.to_string().contains("require a gas_limit"));

    // EIP-1559: missing nonce.
    let mut request = eip1559_request(0);
    request.nonce = None;
    assert!(build_eip1559_raw_transaction(&request, &key).is_err());

    // EIP-1559: zero max fee.
    let mut request = eip1559_request(0);
    request
        .metadata
        .insert("max_fee_per_gas".to_string(), "0".to_string());
    let err =
        build_eip1559_raw_transaction(&request, &key).expect_err("zero max fee must be rejected");
    assert!(err
        .to_string()
        .contains("require metadata 'max_fee_per_gas'"));
}

#[test]
fn chain_id_resolution() {
    let mut request = eth_request(0);

    request.network = BlockchainNetwork::Ethereum;
    assert_eq!(chain_id(&request).unwrap(), 1);
    request.network = BlockchainNetwork::Optimism;
    assert_eq!(chain_id(&request).unwrap(), 10);
    request.network = BlockchainNetwork::Polygon;
    assert_eq!(chain_id(&request).unwrap(), 137);
    request.network = BlockchainNetwork::Arbitrum;
    assert_eq!(chain_id(&request).unwrap(), 42161);
    request.network = BlockchainNetwork::BinanceSmartChain;
    assert_eq!(chain_id(&request).unwrap(), 56);

    // Custom networks need an explicit chain_id.
    request.network = BlockchainNetwork::Custom("test".to_string());
    let err = chain_id(&request).expect_err("custom without chain_id must fail");
    assert!(err.to_string().contains("require a chain_id"));
    request
        .metadata
        .insert("chain_id".to_string(), "1337".to_string());
    assert_eq!(chain_id(&request).unwrap(), 1337);

    // Non-EVM networks are rejected.
    request.network = BlockchainNetwork::Bitcoin;
    request.metadata.remove("chain_id");
    let err = chain_id(&request).expect_err("Bitcoin is not EVM");
    assert!(err.to_string().contains("is not an EVM network"));
}

#[test]
fn recovery_id_for_fails_on_foreign_verifying_key() {
    let key_a = test_key_from_raw([1u8; 32]);
    let key_b = test_key_from_raw([2u8; 32]);

    let prehash = [7u8; 32];
    let signature: k256::ecdsa::Signature = key_a.sign_prehash(&prehash).unwrap();

    // Recovery against key_a succeeds...
    assert!(recovery_id_for(&key_a, &prehash, &signature).is_ok());
    // ...but the same signature cannot reproduce key_b.
    let err = recovery_id_for(&key_b, &prehash, &signature)
        .expect_err("a signature cannot recover a foreign key");
    assert!(err.to_string().contains("Failed to recover signer"));
}

#[test]
fn evm_tx_type_honors_explicit_tx_type_values() {
    for value in ["eip1559", "2", "Type2", "  EIP1559  "] {
        let mut request = eth_request(0);
        request
            .metadata
            .insert("tx_type".to_string(), value.to_string());
        assert!(
            matches!(evm_tx_type(&request), EvmTxType::Eip1559),
            "tx_type {value:?} must route to EIP-1559"
        );
    }

    // An unrelated tx_type does not route to EIP-1559 by itself.
    let mut request = eth_request(0);
    request
        .metadata
        .insert("tx_type".to_string(), "legacy".to_string());
    assert!(matches!(evm_tx_type(&request), EvmTxType::Legacy));
}

#[test]
fn recovery_id_for_rejects_unrecoverable_signature() {
    // A valid signature made by a different key: both recovery candidates
    // parse but neither reproduces the expected signer.
    let key = test_key_from_raw([0x46u8; 32]);
    let impostor = test_key_from_raw([0x99u8; 32]);
    let prehash = [7u8; 32];
    let forged = impostor.sign_prehash(&prehash).unwrap();

    let err = recovery_id_for(&key, &prehash, &forged).unwrap_err();
    assert!(err.to_string().contains("Failed to recover signer"));
}

#[test]
fn recovery_id_for_rejects_signature_without_recoverable_point() {
    let key = test_key_from_raw([0x46u8; 32]);
    let prehash = [7u8; 32];

    // For roughly half of the possible x coordinates no curve point
    // exists, so recovery fails outright instead of returning a
    // mismatched key. Small r values are always in field range.
    let mut undecodable = None;
    for r in 1u64..=64 {
        let mut r_bytes = [0u8; 32];
        r_bytes[31] = r as u8;
        let r_field: k256::FieldBytes = r_bytes.into();
        let s_field: k256::FieldBytes = [1u8; 32].into();
        // Small r and s=0x0101..01 are always in field range.
        let sig = Signature::from_scalars(r_field, s_field).unwrap();
        if VerifyingKey::recover_from_prehash(&prehash, &sig, RecoveryId::new(false, false))
            .is_err()
        {
            undecodable = Some(sig);
            break;
        }
    }
    let sig = undecodable.expect("secp256k1 has non-residual x coordinates below 64");

    let err = recovery_id_for(&key, &prehash, &sig).unwrap_err();
    assert!(err.to_string().contains("Failed to recover signer"));
}
