use super::*;

#[test]
fn verify_transaction_signature_dispatch() {
    let key = create_test_signing_key();
    let message = b"some message";

    // ECDSA round trip.
    let signature = sign_with_secp256k1(&key, message).unwrap();
    let tx_sig = signature_for(
        "addr",
        signature.to_der().to_vec(),
        secp_compressed_pubkey(&key).to_vec(),
        SignatureScheme::ECDSA,
        Utc::now(),
    );
    assert!(verify_transaction_signature(&tx_sig, message).unwrap());
    assert!(!verify_transaction_signature(&tx_sig, b"other").unwrap());

    // Unsupported scheme.
    let mut unsupported = tx_sig.clone();
    unsupported.signature_scheme = SignatureScheme::Schnorr;
    let err =
        verify_transaction_signature(&unsupported, message).expect_err("Schnorr has no verifier");
    assert!(err.to_string().contains("Signature verification"));
    unsupported.signature_scheme = SignatureScheme::BLS;
    assert!(verify_transaction_signature(&unsupported, message).is_err());

    // Malformed public key / signature.
    let mut bad = tx_sig.clone();
    bad.public_key = vec![1, 2, 3];
    let err =
        verify_transaction_signature(&bad, message).expect_err("short public key must be rejected");
    assert!(err.to_string().contains("Invalid public key"));

    let mut bad = tx_sig.clone();
    bad.signature = vec![0xFF; 10];
    let err = verify_transaction_signature(&bad, message)
        .expect_err("non-DER signature must be rejected");
    assert!(err.to_string().contains("Invalid signature"));
}

#[test]
fn verify_ed25519_signature_error_paths() {
    let ed_key = Ed25519Key::from_seed(&[9u8; 64]).unwrap();
    let message = b"solana message";
    let tx_sig = signature_for(
        "addr",
        ed_key.sign(message).to_vec(),
        ed_key.public_bytes().to_vec(),
        SignatureScheme::EdDSA,
        Utc::now(),
    );

    assert!(verify_transaction_signature(&tx_sig, message).unwrap());
    // Wrong message verifies to false (not an error).
    assert!(!verify_transaction_signature(&tx_sig, b"tampered").unwrap());

    // Public key of the wrong length.
    let mut bad = tx_sig.clone();
    bad.public_key = vec![0u8; 31];
    let err = verify_transaction_signature(&bad, message)
        .expect_err("31-byte Ed25519 key must be rejected");
    assert!(err.to_string().contains("must be 32 bytes"));

    // Signature of the wrong length.
    let mut bad = tx_sig.clone();
    bad.signature = vec![0u8; 63];
    let err = verify_transaction_signature(&bad, message)
        .expect_err("63-byte Ed25519 signature must be rejected");
    assert!(err.to_string().contains("must be 64 bytes"));
}

#[test]
fn verify_ethereum_legacy_rejects_malformed_signatures() {
    let request = eth_request(0);
    let key = create_test_signing_key();
    let real_address = address_from_verifying_key(key.verifying_key()).unwrap();

    let (sig, _) = sign_ethereum_transaction(&request, &key).unwrap();
    let make_sig = |signature: Vec<u8>, signer: String| {
        signature_for(
            &signer,
            signature,
            secp_compressed_pubkey(&key).to_vec(),
            SignatureScheme::ECDSA,
            Utc::now(),
        )
    };

    // Happy path.
    assert!(
        verify_ethereum_transaction(&request, &make_sig(sig.clone(), real_address.clone()))
            .unwrap()
    );

    // Too short.
    assert!(!verify_ethereum_transaction(
        &request,
        &make_sig(sig[..64].to_vec(), real_address.clone())
    )
    .unwrap());

    // 73-byte signature: v section longer than 8 bytes is undecodable.
    let mut long = sig.clone();
    long.extend_from_slice(&[0u8; 8]);
    let err = verify_ethereum_transaction(&request, &make_sig(long, real_address.clone()))
        .expect_err("undecodable v must error");
    assert!(err.to_string().contains("Invalid Ethereum signature v"));

    // v = 0 is below the EIP-155 floor.
    let mut v0 = sig[..64].to_vec();
    v0.push(0);
    assert!(!verify_ethereum_transaction(&request, &make_sig(v0, real_address.clone())).unwrap());

    // v = 36 encodes a chain id below Ethereum's.
    let mut low_v = sig[..64].to_vec();
    low_v.push(36);
    assert!(
        !verify_ethereum_transaction(&request, &make_sig(low_v, real_address.clone())).unwrap()
    );

    // r = 0 is an invalid scalar.
    let mut zero_r = sig.clone();
    zero_r[..32].fill(0);
    let err = verify_ethereum_transaction(&request, &make_sig(zero_r, real_address.clone()))
        .expect_err("r=0 must error");
    assert!(err.to_string().contains("Invalid r/s"));

    // Valid signature attributed to a different address.
    assert!(!verify_ethereum_transaction(
        &request,
        &make_sig(
            sig,
            "0x1111111111111111111111111111111111111111".to_string()
        )
    )
    .unwrap());
}

#[test]
fn verify_ethereum_typed_rejects_malformed_signatures() {
    let request = eip1559_request(0);
    let key = create_test_signing_key();
    let real_address = address_from_verifying_key(key.verifying_key()).unwrap();

    let (sig, _) = sign_ethereum_transaction(&request, &key).unwrap();
    assert_eq!(sig.len(), 65);
    let make_sig = |signature: Vec<u8>, signer: String| {
        signature_for(
            &signer,
            signature,
            secp_compressed_pubkey(&key).to_vec(),
            SignatureScheme::ECDSA,
            Utc::now(),
        )
    };

    assert!(
        verify_ethereum_transaction(&request, &make_sig(sig.clone(), real_address.clone()))
            .unwrap()
    );

    // Wrong lengths.
    assert!(!verify_ethereum_transaction(
        &request,
        &make_sig(sig[..64].to_vec(), real_address.clone())
    )
    .unwrap());
    let mut long = sig.clone();
    long.push(0);
    assert!(!verify_ethereum_transaction(&request, &make_sig(long, real_address.clone())).unwrap());

    // Invalid r scalar.
    let mut zero_r = sig.clone();
    zero_r[..32].fill(0);
    let err = verify_ethereum_transaction(&request, &make_sig(zero_r, real_address.clone()))
        .expect_err("r=0 must error");
    assert!(err.to_string().contains("Invalid r/s"));

    // Different signer.
    assert!(!verify_ethereum_transaction(
        &request,
        &make_sig(
            sig,
            "0x1111111111111111111111111111111111111111".to_string()
        )
    )
    .unwrap());
}

#[test]
fn decode_varuint_boundaries() {
    assert_eq!(decode_varuint(&[]), None);
    assert_eq!(decode_varuint(&[1, 2]), Some(0x0102));
    assert_eq!(decode_varuint(&[0xFFu8; 8]), Some(u64::MAX));
    assert_eq!(decode_varuint(&[0xFFu8; 9]), None);
}
