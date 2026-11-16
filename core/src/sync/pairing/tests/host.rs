use super::*;

#[test]
fn accept_join_rejects_illegal_public_values() {
    let (mut host, _invite) = PairingHost::new_invite().unwrap();
    // 空 client_public → BigUint 0 ≡ 0 (mod N) → 拒绝
    assert!(host.accept_join(&[]).is_err());
    let (mut host2, _invite) = PairingHost::new_invite().unwrap();
    // 全零 client_public 同款拒绝
    assert!(host2.accept_join(&[0u8; 64]).is_err());
}

#[test]
fn double_join_is_rejected() {
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let (guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
    host.accept_join(&offer.client_public).unwrap();
    let (guest2, offer2) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
    let err = host.accept_join(&offer2.client_public).unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
    drop((guest, guest2));
}
