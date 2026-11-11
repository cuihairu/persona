use super::*;

#[test]
fn test_bitcoin_raw_requires_inputs() {
    let request = TransactionRequest {
        network: BlockchainNetwork::Bitcoin,
        from_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        to_address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        amount: "100000".to_string(),
        fee: "1000".to_string(),
        ..eth_request(0)
    };
    let key = WalletSigningKey::Secp256k1(create_test_signing_key());

    // The audit signature still works...
    let sig = sign_transaction(&request, &key).unwrap();
    assert_eq!(sig.signature_scheme, SignatureScheme::ECDSA);
    assert!(!sig.signature.is_empty());
    // ...but raw assembly needs the UTXO inputs to sign for real.
    assert!(build_raw_transaction(&request, &key).is_err());
}

// BIP-143 native P2WPKH example: input index 1, via rust-bitcoin's
// SighashCache. The spec's txid strings appear in the unsigned tx hex,
// i.e. internal (wire) byte order, so they are loaded with
// `Txid::from_byte_array` rather than parsed as display-order ids.
#[test]
fn test_bip143_spec_sighash() {
    let privkey = test_key_from_raw(
        hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let pubkey = secp_compressed_pubkey(&privkey);
    assert_eq!(
        hex::encode(pubkey),
        "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
    );
    let pubkey_hash = crate::crypto::address_generator::hash160(&pubkey);

    let txid0 = wire_order_txid("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f");
    let txid1 = wire_order_txid("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a");
    // Both inputs participate in hashPrevouts/hashSequence with their
    // own sequence; the script type of input 0 does not affect the
    // P2WPKH sighash for input 1.
    let tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::from_consensus(17),
        input: vec![
            TxIn {
                previous_output: OutPoint::new(txid0, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0xffff_ffee),
                witness: Default::default(),
            },
            TxIn {
                previous_output: OutPoint::new(txid1, 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Default::default(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(112_340_000),
                script_pubkey: ScriptBuf::from_bytes(
                    hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac").unwrap(),
                ),
            },
            TxOut {
                value: Amount::from_sat(223_450_000),
                script_pubkey: ScriptBuf::from_bytes(
                    hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac").unwrap(),
                ),
            },
        ],
    };

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            1,
            p2wpkh_output_script(&pubkey_hash).as_script(),
            Amount::from_sat(600_000_000),
            EcdsaSighashType::All,
        )
        .unwrap();
    assert_eq!(
        hex::encode(sighash.to_byte_array()),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    );
}

// BIP-143 example: RFC-6979 deterministic signing must reproduce the
// spec's DER signature byte for byte.
#[test]
fn test_bip143_spec_signature() {
    let privkey = test_key_from_raw(
        hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let sighash: [u8; 32] =
        hex::decode("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
            .unwrap()
            .try_into()
            .unwrap();

    let signature: k256::ecdsa::Signature = privkey.sign_prehash(&sighash).unwrap();
    let mut der = signature.to_der().to_vec();
    der.push(SIGHASH_ALL);

    assert_eq!(
        hex::encode(&der),
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a\
         0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
            .replace(' ', "")
    );
}

// Full segwit assembly: structure, witness contents and txid shape.
#[test]
fn test_bitcoin_p2wpkh_raw_transaction() {
    use crate::crypto::address_generator::{
        generate_bitcoin_address_from_compressed_pubkey, BitcoinAddressType,
    };

    let key = create_test_signing_key();
    let pubkey = secp_compressed_pubkey(&key);
    let from_address =
        generate_bitcoin_address_from_compressed_pubkey(&pubkey, BitcoinAddressType::P2WPKH, false)
            .unwrap();
    let to_address = generate_bitcoin_address_from_compressed_pubkey(
        &[0x02u8; 33],
        BitcoinAddressType::P2WPKH,
        false,
    )
    .unwrap();

    // 2 inputs, single output, no change: total_in must equal amount+fee.
    let inputs_json = format!(
        r#"[
        {{"txid":"{}","vout":0,"amount":"100000"}},
        {{"txid":"{}","vout":1,"amount":"200000"}}
    ]"#,
        "11".repeat(32),
        "22".repeat(32),
    );
    let request = TransactionRequest {
        network: BlockchainNetwork::Bitcoin,
        from_address,
        to_address,
        amount: "280000".to_string(),
        fee: "20000".to_string(),
        metadata: HashMap::from([("inputs".to_string(), inputs_json)]),
        ..eth_request(0)
    };

    let signed =
        build_raw_transaction(&request, &WalletSigningKey::Secp256k1(key.clone())).unwrap();

    // Header: version 2, segwit marker+flag, 2 inputs, 1 output.
    assert_eq!(&signed.raw[..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // txid is 64 hex chars
    assert_eq!(signed.hash.len(), 64);

    // Witness item 1 must be the BIP-143 signature over the recomputed
    // sighash; item 2 is the compressed pubkey.
    let pubkey_hash = crate::crypto::address_generator::hash160(&pubkey);
    let inputs = parse_btc_inputs(&request).unwrap();
    let template = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(0),
        input: inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: i.sequence,
                witness: Default::default(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(280_000),
            script_pubkey: script_pubkey_for_address(&request.to_address).unwrap(),
        }],
    };
    let mut cache = SighashCache::new(&template);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            p2wpkh_output_script(&pubkey_hash).as_script(),
            Amount::from_sat(inputs[0].amount),
            EcdsaSighashType::All,
        )
        .unwrap();
    let sig: k256::ecdsa::Signature = key.sign_prehash(&sighash.to_byte_array()).unwrap();
    let mut expected_item = sig.to_der().to_vec();
    expected_item.push(SIGHASH_ALL);

    // Find the witness section: after outputs, each input has 2 items.
    // Cheap structural check: the raw tx must contain the pubkey and
    // the signature bytes.
    let raw_hex = hex::encode(&signed.raw);
    assert!(raw_hex.contains(&hex::encode(pubkey)));
    assert!(raw_hex.contains(&hex::encode(&expected_item)));
}

#[test]
fn test_bitcoin_from_address_must_match_key() {
    use crate::crypto::address_generator::{
        generate_bitcoin_address_from_compressed_pubkey, BitcoinAddressType,
    };

    let key = create_test_signing_key();
    // Address of a DIFFERENT key.
    let from_address = generate_bitcoin_address_from_compressed_pubkey(
        &[0x03u8; 33],
        BitcoinAddressType::P2WPKH,
        false,
    )
    .unwrap();
    let inputs_json = format!(r#"[{{"txid":"{}","vout":0,"amount":1}}]"#, "aa".repeat(32));
    let request = TransactionRequest {
        network: BlockchainNetwork::Bitcoin,
        from_address,
        to_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        amount: "1".to_string(),
        fee: "1".to_string(),
        metadata: HashMap::from([("inputs".to_string(), inputs_json.to_string())]),
        ..eth_request(0)
    };
    assert!(build_bitcoin_raw_transaction(&request, &key).is_err());
}

#[test]
fn bitcoin_sighash_binds_request_fields() {
    let mut request = btc_request(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    );
    request.amount = "100".to_string();
    request.fee = "10".to_string();

    let baseline = create_bitcoin_sighash(&request).unwrap();
    // Deterministic.
    assert_eq!(create_bitcoin_sighash(&request).unwrap(), baseline);

    // Changing any bound field changes the hash.
    let mut other = request.clone();
    other.to_address = "1FC9gffSsyaMNCmZ3CuktoAjs.IdFjdNv".to_string();
    assert_ne!(create_bitcoin_sighash(&other).unwrap(), baseline);
    let mut other = request.clone();
    other.amount = "101".to_string();
    assert_ne!(create_bitcoin_sighash(&other).unwrap(), baseline);
    let mut other = request.clone();
    other.fee = "11".to_string();
    assert_ne!(create_bitcoin_sighash(&other).unwrap(), baseline);

    // Non-numeric amounts are skipped from the hash rather than erroring.
    let mut other = request.clone();
    other.amount = "not-a-number".to_string();
    let skipped = create_bitcoin_sighash(&other).unwrap();
    assert_ne!(skipped, baseline);
    let mut without_amount = request.clone();
    without_amount.amount = "garbage too".to_string();
    assert_eq!(create_bitcoin_sighash(&without_amount).unwrap(), skipped);
}

#[test]
fn parse_satoshis_validates_range_and_format() {
    assert_eq!(parse_satoshis(" 100 ", "amount").unwrap(), 100);
    assert_eq!(
        parse_satoshis("2100000000000000", "amount").unwrap(),
        MAX_MONEY_SATS
    );

    let err = parse_satoshis("1.5", "amount").expect_err("fractional satoshis must be rejected");
    assert!(err.to_string().contains("must be decimal satoshis"));

    let err = parse_satoshis("2100000000000001", "amount")
        .expect_err("above the money supply must be rejected");
    assert!(err.to_string().contains("exceeds the max money supply"));
}

#[test]
fn parse_btc_inputs_error_paths() {
    let base = btc_request(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    );
    let with_inputs = |json: &str| {
        let mut request = base.clone();
        request
            .metadata
            .insert("inputs".to_string(), json.to_string());
        parse_btc_inputs(&request)
    };

    // Missing inputs field entirely.
    let err = parse_btc_inputs(&base).expect_err("missing inputs must be rejected");
    assert!(err
        .to_string()
        .contains("requires an 'inputs' metadata field"));

    // Invalid JSON.
    let err = with_inputs("[").expect_err("invalid JSON must be rejected");
    assert!(err.to_string().contains("not valid JSON"));

    // Empty array.
    let err = with_inputs("[]").expect_err("empty inputs must be rejected");
    assert!(err.to_string().contains("at least one input"));

    // Missing txid.
    let err = with_inputs(r#"[{"vout":0,"amount":1}]"#).expect_err("missing txid must be rejected");
    assert!(err.to_string().contains("missing 'txid'"));

    // Malformed txid.
    let err = with_inputs(r#"[{"txid":"nothex","vout":0,"amount":1}]"#)
        .expect_err("bad txid must be rejected");
    assert!(err.to_string().contains("64-hex txid"));

    // Missing vout.
    let err = with_inputs(format!(r#"[{{"txid":"{}","amount":1}}]"#, "11".repeat(32)).as_str())
        .expect_err("missing vout must be rejected");
    assert!(err.to_string().contains("missing numeric 'vout'"));

    // vout overflowing u32.
    let err = with_inputs(
        format!(
            r#"[{{"txid":"{}","vout":4294967296,"amount":1}}]"#,
            "11".repeat(32)
        )
        .as_str(),
    )
    .expect_err("vout above u32 must be rejected");
    assert!(err.to_string().contains("missing numeric 'vout'"));

    // Missing amount.
    let err = with_inputs(format!(r#"[{{"txid":"{}","vout":0}}]"#, "11".repeat(32)).as_str())
        .expect_err("missing amount must be rejected");
    assert!(err.to_string().contains("missing numeric 'amount'"));

    // Numeric amount above the money supply (but inside u64).
    let err = with_inputs(
        format!(
            r#"[{{"txid":"{}","vout":0,"amount":9000000000000000}}]"#,
            "11".repeat(32)
        )
        .as_str(),
    )
    .expect_err("amount above the money supply must be rejected");
    assert!(err.to_string().contains("exceeds the max money supply"));

    // Happy path: string amounts and numeric amounts both parse.
    let inputs = with_inputs(
        r#"[{"txid":"11ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","vout":0,"amount":"100"},
            {"txid":"22ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","vout":1,"amount":200}]"#,
    )
    .unwrap();
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0].amount, 100);
    assert_eq!(inputs[1].amount, 200);
    assert_eq!(inputs[1].sequence, Sequence::MAX);
}

#[test]
fn script_pubkey_for_address_shapes() {
    // P2PKH: version + push20 + hash + check = 25 bytes.
    let p2pkh = script_pubkey_for_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
    assert_eq!(p2pkh.len(), 25);
    assert_eq!(p2pkh.as_bytes()[0], 0x76); // OP_DUP

    // P2SH: hash160 script = 23 bytes.
    let p2sh = script_pubkey_for_address("3P14159f73E4gFr7JterCCQh9QjiTjiZrG").unwrap();
    assert_eq!(p2sh.len(), 23);
    assert_eq!(p2sh.as_bytes()[0], 0xa9); // OP_HASH160

    // Bech32 P2WPKH.
    let bech32 = script_pubkey_for_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    assert_eq!(bech32.as_bytes()[..2], [0x00, 0x14]);

    // Testnet addresses are rejected (Persona signs mainnet only).
    let err = script_pubkey_for_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")
        .expect_err("testnet address must be rejected");
    assert!(err.to_string().contains("Unsupported or invalid mainnet"));

    // Garbage.
    assert!(script_pubkey_for_address("hello").is_err());
}

#[test]
fn bitcoin_raw_rejects_non_p2wpkh_from_address() {
    let key = create_test_signing_key();
    // Taproot from_address: witness version 1.
    let p2tr_from =
        crate::crypto::address_generator::generate_bitcoin_address_from_compressed_pubkey(
            &secp_compressed_pubkey(&key),
            crate::crypto::address_generator::BitcoinAddressType::P2TR,
            false,
        )
        .unwrap();
    let mut request = btc_request(p2tr_from, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string());
    request.metadata.insert(
        "inputs".to_string(),
        format!(
            r#"[{{"txid":"{}","vout":0,"amount":200000}}]"#,
            "11".repeat(32)
        ),
    );
    let err = build_bitcoin_raw_transaction(&request, &key)
        .expect_err("taproot inputs are not supported yet");
    assert!(
        err.to_string().contains("only P2WPKH inputs"),
        "unexpected error: {err}"
    );
}

#[test]
fn bitcoin_raw_change_address_paths() {
    let key = create_test_signing_key();
    let from_address =
        crate::crypto::address_generator::generate_bitcoin_address_from_compressed_pubkey(
            &secp_compressed_pubkey(&key),
            crate::crypto::address_generator::BitcoinAddressType::P2WPKH,
            false,
        )
        .unwrap();
    let to_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();

    let make_request = |amount: &str, fee: &str, extra: Vec<(&str, String)>| {
        let mut request = btc_request(from_address.clone(), to_address.clone());
        request.amount = amount.to_string();
        request.fee = fee.to_string();
        request.metadata.insert(
            "inputs".to_string(),
            format!(
                r#"[{{"txid":"{}","vout":0,"amount":300000}}]"#,
                "11".repeat(32)
            ),
        );
        for (k, v) in extra {
            request.metadata.insert(k.to_string(), v);
        }
        request
    };

    // Without a change address the inputs must equal amount + fee exactly.
    let err = build_bitcoin_raw_transaction(&make_request("100000", "1000", vec![]), &key)
        .expect_err("surplus without change address must be rejected");
    assert!(
        err.to_string().contains("Inputs do not equal amount + fee"),
        "unexpected error: {err}"
    );

    // With a change address, zero change collapses to a single output.
    let signed = build_bitcoin_raw_transaction(
        &make_request(
            "299000",
            "1000",
            vec![(
                "change_address",
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            )],
        ),
        &key,
    )
    .unwrap();
    // Header: version 2, segwit marker+flag; and byte 48 (after the
    // single input) is the output count.
    assert_eq!(&signed.raw[..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(signed.raw[48], 1);
    // Default sequence is 0xffffffff.
    assert_eq!(&signed.raw[44..48], &[0xff, 0xff, 0xff, 0xff]);
    // Default locktime 0 closes the transaction.
    assert_eq!(
        &signed.raw[signed.raw.len() - 4..],
        &[0x00, 0x00, 0x00, 0x00]
    );

    // Positive change produces a second output.
    let signed = build_bitcoin_raw_transaction(
        &make_request(
            "100000",
            "1000",
            vec![(
                "change_address",
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            )],
        ),
        &key,
    )
    .unwrap();
    assert_eq!(signed.raw[48], 2);

    // Fee exceeding inputs-minus-amount is rejected.
    let err = build_bitcoin_raw_transaction(
        &make_request(
            "299999",
            "2000",
            vec![(
                "change_address",
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            )],
        ),
        &key,
    )
    .expect_err("fee above inputs-minus-amount must be rejected");
    assert!(err.to_string().contains("Fee exceeds"));

    // RBF signalling and a custom locktime land in the transaction.
    let signed = build_bitcoin_raw_transaction(
        &make_request(
            "299000",
            "1000",
            vec![
                ("rbf", "true".to_string()),
                ("locktime", "800000".to_string()),
            ],
        ),
        &key,
    )
    .unwrap();
    // RBF sequence 0xfffffffd (little-endian on the wire) and locktime
    // 800000 = 0x0c3500 as the trailing 4 consensus bytes.
    assert_eq!(&signed.raw[44..48], &[0xfd, 0xff, 0xff, 0xff]);
    assert_eq!(
        &signed.raw[signed.raw.len() - 4..],
        &[0x00, 0x35, 0x0c, 0x00]
    );
}

#[test]
fn p2wpkh_output_script_shape() {
    let script = p2wpkh_output_script(&[0xABu8; 20]);
    let mut expected = vec![0x00, 0x14];
    expected.extend_from_slice(&[0xABu8; 20]);
    assert_eq!(script.as_bytes(), expected.as_slice());
}
