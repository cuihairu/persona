use super::*;

#[test]
fn parse_network_name_covers_all_known_networks() {
    let password = "pw";
    // Non-EVM, non-Bitcoin networks parse but cannot derive addresses.
    for network in ["bitcoincash", "bitcoin cash", "litecoin", "dogecoin"] {
        let json = format!(
            r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"n","network":"{network}","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["a"],"created_at":"2024-01-01T00:00:00Z"}}"#
        );
        let err = import_from_json(Uuid::new_v4(), None, &json, password)
            .expect_err("unsupported address scheme must fail");
        assert!(err.to_string().contains("not implemented for"), "{network}");
    }

    // Unknown network strings become Custom and fail the same way.
    let custom = format!(
        r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"n","network":"Some Chain","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["a"],"created_at":"2024-01-01T00:00:00Z"}}"#
    );
    let err = import_from_json(Uuid::new_v4(), None, &custom, password).unwrap_err();
    assert!(err.to_string().contains("Custom"));

    // EVM networks succeed end-to-end. 地址必须写真实派生值：恢复一致性
    // 核对（2026-11-13 深审 Critical 修复）会拒绝与助记词派生不符的地址。
    for network in [
        "polygon",
        "arbitrum",
        "optimism",
        "binancesmartchain",
        "binance smart chain",
    ] {
        let parsed = parse_network_name(network).unwrap();
        let reference = import_from_mnemonic(
            Uuid::new_v4(),
            "Ref".to_string(),
            TEST_PHRASE,
            "",
            parsed,
            None,
            1,
            password,
        )
        .unwrap();
        let first = reference.addresses[0].address.clone();
        let json = format!(
            r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"n","network":"{network}","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["{first}"],"created_at":"2024-01-01T00:00:00Z"}}"#
        );
        let wallet = import_from_json(Uuid::new_v4(), None, &json, password)
            .unwrap_or_else(|e| panic!("{network} must import: {e}"));
        assert_eq!(wallet.addresses.len(), 1);
    }
}
