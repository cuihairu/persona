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

    // The main forward-compatibility case: a new kind string from a future client -> Unknown, never skipped
    assert_eq!(kind_from_wire("totp_seed_v9"), ItemKind::Unknown);
}

#[test]
fn corrupt_entries_are_skipped_not_fatal() {
    // A bad UUID
    let mut wire = op_to_wire(&sample_put());
    wire.op_id = "not-a-uuid".to_string();
    assert!(op_from_wire(to_in(wire)).is_none());

    // A payload with bad base64
    let mut wire = op_to_wire(&sample_put());
    wire.payload.as_mut().unwrap().ciphertext = "!!!".to_string();
    assert!(op_from_wire(to_in(wire)).is_none());

    // A put without a payload / a delete with one: a shape contradiction
    let mut wire = op_to_wire(&sample_put());
    wire.payload = None;
    assert!(op_from_wire(to_in(wire)).is_none());
    let mut wire = op_to_wire(&sample_delete());
    wire.payload = Some(WirePayloadOut {
        ciphertext: "AAAA".to_string(),
        wrapped_item_key: "AAAA".to_string(),
    });
    assert!(op_from_wire(to_in(wire)).is_none());

    // An unknown op type string
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
