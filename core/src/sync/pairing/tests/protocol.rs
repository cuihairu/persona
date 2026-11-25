use super::*;

#[test]
fn full_handshake_delivers_group_key_and_fingerprints_match() {
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let normalized = normalize_pairing_code(&invite.code);
    assert_eq!(normalized, invite.code, "生成的码应已是规范形");
    let (mut guest, offer) = PairingGuest::start(&normalized, &invite.salt).unwrap();
    let host_offer = host.accept_join(&offer.client_public).unwrap();
    let guest_proof = guest.finish(&host_offer.server_public).unwrap();

    assert_eq!(host_offer.fingerprint, guest_proof.fingerprint);
    assert_eq!(host_offer.fingerprint.len(), FINGERPRINT_LEN);
    assert!(
        host_offer.fingerprint.chars().all(|c| c.is_ascii_digit()),
        "指纹应为 6 位数字: {}",
        host_offer.fingerprint
    );

    let group_key: [u8; 32] = rand::random();
    let handoff = host
        .complete(&group_key, &guest_proof.client_proof)
        .unwrap();
    assert_eq!(handoff.wrapped_group_key.len(), WRAPPED_GROUP_KEY_LEN);
    let got = guest
        .accept_handoff(&handoff.server_proof, &handoff.wrapped_group_key)
        .unwrap();
    assert_eq!(got, group_key);
}

#[test]
fn wrong_code_yields_mismatched_fingerprint_and_rejected_proof() {
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    // guest mistypes the last digit (a legal substitution inside Crockford)
    let wrong: String = invite
        .code
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == PAIRING_CODE_LEN - 1 {
                if c == 'A' {
                    'B'
                } else {
                    'A'
                }
            } else {
                c
            }
        })
        .collect();
    assert_ne!(wrong, invite.code);
    let (mut guest, offer) = PairingGuest::start(&wrong, &invite.salt).unwrap();
    let host_offer = host.accept_join(&offer.client_public).unwrap();
    let guest_proof = guest.finish(&host_offer.server_public).unwrap();
    assert_ne!(host_offer.fingerprint, guest_proof.fingerprint);

    // A fingerprint mismatch should have been stopped by the human comparison;
    // even if it were submitted by mistake, M1 verification must reject it
    let group_key: [u8; 32] = rand::random();
    let err = host
        .complete(&group_key, &guest_proof.client_proof)
        .unwrap_err();
    assert!(matches!(err, PersonaError::AuthenticationFailed(_)));
    // Same rejection on the guest side: the host never released a handoff, so
    // the guest just receives a bogus M2
    let err = guest
        .accept_handoff(&[0u8; 32], &[0u8; WRAPPED_GROUP_KEY_LEN])
        .unwrap_err();
    assert!(matches!(err, PersonaError::AuthenticationFailed(_)));
}

#[test]
fn tampered_handoff_fails_to_open() {
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
    let host_offer = host.accept_join(&offer.client_public).unwrap();
    let guest_proof = guest.finish(&host_offer.server_public).unwrap();
    let group_key: [u8; 32] = rand::random();
    let handoff = host
        .complete(&group_key, &guest_proof.client_proof)
        .unwrap();

    let mut tampered = handoff.wrapped_group_key.clone();
    tampered[20] ^= 0x40;
    let err = guest
        .accept_handoff(&handoff.server_proof, &tampered)
        .unwrap_err();
    assert!(matches!(err, PersonaError::CryptographicError(_)));

    // A tampered M2 is rejected too (independent handshake: the failure above
    // already consumed the guest's handshake state)
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
    let host_offer = host.accept_join(&offer.client_public).unwrap();
    let guest_proof = guest.finish(&host_offer.server_public).unwrap();
    let handoff = host
        .complete(&group_key, &guest_proof.client_proof)
        .unwrap();
    let mut bad_proof = handoff.server_proof.clone();
    bad_proof[0] ^= 0x01;
    let err = guest
        .accept_handoff(&bad_proof, &handoff.wrapped_group_key)
        .unwrap_err();
    assert!(matches!(err, PersonaError::AuthenticationFailed(_)));
}

#[test]
fn handoff_is_single_use_on_both_sides() {
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
    let host_offer = host.accept_join(&offer.client_public).unwrap();
    let guest_proof = guest.finish(&host_offer.server_public).unwrap();
    let group_key: [u8; 32] = rand::random();
    let handoff = host
        .complete(&group_key, &guest_proof.client_proof)
        .unwrap();

    assert!(guest
        .accept_handoff(&handoff.server_proof, &handoff.wrapped_group_key)
        .is_ok());
    // A second handoff: the handshake state is already consumed
    let err = guest
        .accept_handoff(&handoff.server_proof, &handoff.wrapped_group_key)
        .unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));

    // The host-side complete is single-use as well
    let err = host
        .complete(&group_key, &guest_proof.client_proof)
        .unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
}
