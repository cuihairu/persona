use super::*;

#[test]
fn wire_round_trip_preserves_put() {
    let op = sample_put();
    let back = wire_to_op(op_to_wire(&op)).unwrap();
    assert_eq!(back, op);
}

#[test]
fn wire_round_trip_preserves_delete_tombstone() {
    let op = sample_delete();
    let back = wire_to_op(op_to_wire(&op)).unwrap();
    assert_eq!(back, op);
    assert!(back.is_tombstone());
}

#[test]
fn unknown_kind_survives_wire_as_unknown() {
    let mut op = sample_put();
    op.kind = ItemKind::Unknown;
    let back = wire_to_op(op_to_wire(&op)).unwrap();
    assert_eq!(back.kind, ItemKind::Unknown);

    // 前向兼容主场景：未来客户端的新 kind 字符串 → Unknown，不跳过
    assert_eq!(kind_from_wire("totp_seed_v9"), ItemKind::Unknown);
}

#[test]
fn corrupt_entries_are_skipped_not_fatal() {
    // 坏 UUID
    let mut wire = op_to_wire(&sample_put());
    wire.op_id = "not-a-uuid".to_string();
    assert!(op_from_wire(to_in(wire)).is_none());

    // 坏 base64 载荷
    let mut wire = op_to_wire(&sample_put());
    wire.payload.as_mut().unwrap().ciphertext = "!!!".to_string();
    assert!(op_from_wire(to_in(wire)).is_none());

    // put 无载荷 / delete 带载荷：形状矛盾
    let mut wire = op_to_wire(&sample_put());
    wire.payload = None;
    assert!(op_from_wire(to_in(wire)).is_none());
    let mut wire = op_to_wire(&sample_delete());
    wire.payload = Some(WirePayloadOut {
        ciphertext: "AAAA".to_string(),
        wrapped_item_key: "AAAA".to_string(),
    });
    assert!(op_from_wire(to_in(wire)).is_none());

    // 未知 op 类型字符串
    let mut wire = op_to_wire(&sample_put());
    wire.op = "merge".to_string();
    assert!(op_from_wire(to_in(wire)).is_none());
}

#[test]
fn bad_timestamp_degrades_to_none_not_skip() {
    let mut wire = op_to_wire(&sample_put());
    wire.timestamp = Some("yesterday-ish".to_string());
    let back = op_from_wire(to_in(wire)).unwrap();
    assert_eq!(back.timestamp, None);
}

#[test]
fn kind_to_wire_covers_identity_and_passkey() {
    for kind in [ItemKind::Identity, ItemKind::Passkey] {
        let mut op = sample_put();
        op.kind = kind;
        let back = wire_to_op(op_to_wire(&op)).unwrap();
        assert_eq!(back.kind, kind);
    }
}
