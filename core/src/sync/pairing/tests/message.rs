use super::*;

#[test]
fn wire_messages_round_trip_through_relay_payloads() {
    // 消息经 serde JSON 序列化（中转只搬 bytes），双端按序消费
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

    // guest 首条消息误投回自己：拒绝
    assert!(guest.handle_message(guest_msg.clone()).is_err());

    let group_key: [u8; 32] = rand::random();
    // host 收首条 → ServerOffer
    let Some(reply) = host.handle_message(guest_msg, &group_key).unwrap() else {
        panic!("host 应答 ServerOffer");
    };
    // guest 收 ServerOffer → ClientProof
    let Some(reply) = guest.handle_message(reply).unwrap() else {
        panic!("guest 应答 ClientProof");
    };
    // host 收 ClientProof → Handoff
    let Some(reply) = host.handle_message(reply, &group_key).unwrap() else {
        panic!("host 应答 Handoff");
    };
    // guest 收 Handoff → None（完成），组密钥落袋
    assert!(guest.handle_message(reply).unwrap().is_none());
    assert_eq!(guest.group_key(), Some(&group_key));

    // 完成后 host 再收任何消息：握手已消耗，拒绝
    let (guest2, msg2) = PairingGuest::start_message(&invite.code, &invite.salt).unwrap();
    drop(guest2);
    assert!(host.handle_message(msg2, &group_key).is_err());
}

#[test]
fn protocol_rejects_wrong_direction_messages() {
    let group_key: [u8; 32] = rand::random();

    // host 侧只收 ClientPublic/ClientProof：Handoff 拒收
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

    // guest 侧只收 ServerOffer/Handoff：ClientProof 拒收
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
    // 版本前缀不支持
    let err = PairingInviteLink::decode("persona-pair-0.eyJhIjoxfQ").unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
    // 缺版本段
    let err = PairingInviteLink::decode("no-dot-here").unwrap_err();
    assert!(matches!(err, PersonaError::InvalidInput(_)));
}
