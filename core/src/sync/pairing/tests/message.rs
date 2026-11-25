use super::*;

#[test]
fn wire_messages_round_trip_through_relay_payloads() {
    // Messages go through serde JSON (the relay only moves bytes); both sides
    // consume them in order
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let (mut guest, offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();

    let json = serde_json::to_string(&PairingMessage::client_public(&offer)).unwrap();
    let msg: PairingMessage = serde_json::from_str(&json).unwrap();
    let PairingMessage::ClientPublic { client_public } = msg else {
        panic!("首条应为 client_public");
    };
    let host_offer = host
        .accept_join(&wire::decode(&client_public).unwrap())
        .unwrap();

    let json = serde_json::to_string(&PairingMessage::server_offer(&host_offer)).unwrap();
    let PairingMessage::ServerOffer { server_public } = serde_json::from_str(&json).unwrap() else {
        panic!("应答应为 server_offer");
    };
    let guest_proof = guest
        .finish(&wire::decode(&server_public).unwrap())
        .unwrap();

    let json = serde_json::to_string(&PairingMessage::client_proof(&guest_proof)).unwrap();
    let PairingMessage::ClientProof { client_proof } = serde_json::from_str(&json).unwrap() else {
        panic!("第三条应为 client_proof");
    };
    let group_key: [u8; 32] = rand::random();
    let handoff = host
        .complete(&group_key, &wire::decode(&client_proof).unwrap())
        .unwrap();

    let json = serde_json::to_string(&PairingMessage::handoff(&handoff)).unwrap();
    let PairingMessage::Handoff {
        server_proof,
        wrapped_group_key,
    } = serde_json::from_str(&json).unwrap()
    else {
        panic!("末条应为 handoff");
    };
    let got = guest
        .accept_handoff(
            &wire::decode(&server_proof).unwrap(),
            &wire::decode(&wrapped_group_key).unwrap(),
        )
        .unwrap();
    assert_eq!(got, group_key);
}

#[test]
fn message_driver_rejects_wrong_direction_and_completes_pairing() {
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let (mut guest, guest_msg) = PairingGuest::start_message(&invite.code, &invite.salt).unwrap();

    // The guest's first message sent back to itself: rejected
    assert!(guest.handle_message(guest_msg.clone()).is_err());

    let group_key: [u8; 32] = rand::random();
    // host takes the first message → ServerOffer
    let Some(reply) = host.handle_message(guest_msg, &group_key).unwrap() else {
        panic!("host 应答 ServerOffer");
    };
    // guest takes ServerOffer → ClientProof
    let Some(reply) = guest.handle_message(reply).unwrap() else {
        panic!("guest 应答 ClientProof");
    };
    // host takes ClientProof → Handoff
    let Some(reply) = host.handle_message(reply, &group_key).unwrap() else {
        panic!("host 应答 Handoff");
    };
    // guest takes Handoff → None (complete); the group key is captured
    assert!(guest.handle_message(reply).unwrap().is_none());
    assert_eq!(guest.group_key(), Some(&group_key));

    // Any further message to the host after completion: the handshake is
    // consumed, so it is rejected
    let (guest2, msg2) = PairingGuest::start_message(&invite.code, &invite.salt).unwrap();
    drop(guest2);
    assert!(host.handle_message(msg2, &group_key).is_err());
}

#[test]
fn protocol_rejects_wrong_direction_messages() {
    let group_key: [u8; 32] = rand::random();

    // The host side only accepts ClientPublic/ClientProof: Handoff is rejected
    let (mut host, invite) = PairingHost::new_invite().unwrap();
    let err = host
        .handle_message(
            PairingMessage::Handoff {
                server_proof: "AA".into(),
                wrapped_group_key: "AA".into(),
            },
            &group_key,
        )
        .unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));

    // The guest side only accepts ServerOffer/Handoff: ClientProof is rejected
    let (mut guest, _offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
    let err = guest
        .handle_message(PairingMessage::ClientProof {
            client_proof: "AA".into(),
        })
        .unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
}

#[test]
fn invite_link_decode_rejects_bad_version() {
    // Unsupported version prefix
    let err = PairingInviteLink::decode("persona-pair-0.eyJhIjoxfQ").unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
    // Missing version segment
    let err = PairingInviteLink::decode("no-dot-here").unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
}
