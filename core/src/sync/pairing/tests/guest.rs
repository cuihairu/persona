use super::*;

#[test]
fn guest_finish_twice_is_rejected() {
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
    let host_offer = host.accept_join(&offer.client_public).unwrap();
    guest.finish(&host_offer.server_public).unwrap();
    let err = guest.finish(&host_offer.server_public).unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
}
