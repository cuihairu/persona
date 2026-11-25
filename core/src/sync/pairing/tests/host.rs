use super::*;

#[test]
fn accept_join_rejects_illegal_public_values() {
    let (mut host, _invite) = PairingHost::new_invite().unwrap();
    // Empty client_public → BigUint 0 ≡ 0 (mod N) → rejected
    assert!(host.accept_join(&[]).is_err());
    let (mut host2, _invite) = PairingHost::new_invite().unwrap();
    // An all-zero client_public is rejected the same way
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
