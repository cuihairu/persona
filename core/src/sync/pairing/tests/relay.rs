#[cfg(feature = "remote-auth")]
use super::*;

#[cfg(feature = "remote-auth")]
mod relay_tests {
    #[cfg(feature = "remote-auth")]
    use super::*;
    use crate::sync::pairing::relay::{PairingRelayClient, POLL_EVERY};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    struct CapturedRequest {
        method: String,
        path: String,
        body: String,
    }

    /// In-memory two-way mailbox (the mock relay's state surface; tests use the
    /// handle to inject errors/messages directly).
    #[derive(Default)]
    struct Mailbox {
        salt: Option<Vec<u8>>,
        to_host: Vec<Vec<u8>>,
        to_guest: Vec<Vec<u8>>,
    }

    /// One-shot TCP mock relay: an in-memory two-way mailbox whose routes match
    /// the server's /pairing/*. Returns (base_url, mailbox handle).
    fn spawn_mock_relay() -> (String, Arc<Mutex<Mailbox>>) {
        use base64::Engine as _;
        let state = Arc::new(Mutex::new(Mailbox::default()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_state = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    buf.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let request_line = head.lines().next().unwrap_or_default().to_string();
                let content_length: usize = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split_once(':')?.1.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = stream.read_exact(&mut body);
                }
                let req = CapturedRequest {
                    method: request_line
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string(),
                    path: request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string(),
                    body: String::from_utf8_lossy(&body).into_owned(),
                };
                let (status, resp_body) = {
                    let mut st = server_state.lock().unwrap();
                    let b64d =
                        |v: &str| base64::engine::general_purpose::STANDARD.decode(v).unwrap();
                    let b64e = |v: &[u8]| base64::engine::general_purpose::STANDARD.encode(v);
                    if req.method == "POST" && req.path == "/api/v1/pairing/sessions" {
                        let json: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                        st.salt = Some(b64d(json["salt"].as_str().unwrap()));
                        (
                            201,
                            r#"{"session_id":"sess-1","expires_in_secs":600}"#.to_string(),
                        )
                    } else if req.method == "GET" && req.path == "/api/v1/pairing/sessions/sess-1" {
                        let json = serde_json::json!({
                            "salt": b64e(st.salt.as_deref().unwrap_or_default()),
                            "expires_in_secs": 600,
                            "to_host_len": st.to_host.len() as i64,
                            "to_guest_len": st.to_guest.len() as i64,
                        });
                        (200, json.to_string())
                    } else if req.path.ends_with("/messages/to-host") && req.method == "POST" {
                        let json: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                        st.to_host.push(b64d(json["payload"].as_str().unwrap()));
                        (202, "{}".to_string())
                    } else if req.path.ends_with("/messages/to-guest") && req.method == "POST" {
                        let json: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                        st.to_guest.push(b64d(json["payload"].as_str().unwrap()));
                        (202, "{}".to_string())
                    } else if req.path.ends_with("/messages/to-host") {
                        let msgs: Vec<String> = st.to_host.drain(..).map(|m| b64e(&m)).collect();
                        (200, serde_json::json!({ "messages": msgs }).to_string())
                    } else if req.path.ends_with("/messages/to-guest") {
                        let msgs: Vec<String> = st.to_guest.drain(..).map(|m| b64e(&m)).collect();
                        (200, serde_json::json!({ "messages": msgs }).to_string())
                    } else if req.method == "DELETE" {
                        (204, String::new())
                    } else {
                        (404, String::new())
                    }
                };
                let reason = if status == 204 { "" } else { "OK" };
                let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), state)
    }

    #[tokio::test]
    async fn relay_client_drives_full_pairing_over_http_mock() {
        let (base_url, _mailbox) = spawn_mock_relay();
        let client = PairingRelayClient::new(&base_url).unwrap();

        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (session_id, _ttl) = client.create_session(&invite.salt).await.unwrap();
        let link = PairingInviteLink {
            code: invite.code.clone(),
            relay_url: base_url,
            session_id: session_id.clone(),
        };
        // Invite link round trip
        let decoded = PairingInviteLink::decode(&link.encode()).unwrap();
        assert_eq!(decoded, link);

        let group_key: [u8; 32] = rand::random();
        let host_client = PairingRelayClient::new(&link.relay_url).unwrap();
        let host_session = link.session_id.clone();
        let host_task = tokio::spawn(async move {
            host_client
                .drive_host(&mut host, &group_key, &host_session)
                .await
        });

        let guest_client = PairingRelayClient::new(&link.relay_url).unwrap();
        let (mut guest, guest_fp) = guest_client.join_begin(&link).await.unwrap();
        // Confirm first (drive_host is waiting for ClientProof; awaiting it
        // first would deadlock until timeout)
        guest_client
            .join_confirm(&mut guest, &link.session_id)
            .await
            .unwrap();
        assert_eq!(guest.group_key(), Some(&group_key));
        // Once the host side has wrapped up, fetch and compare fingerprints
        let host_fp = host_task.await.unwrap().unwrap();
        assert_eq!(host_fp, guest_fp, "双侧指纹必须一致（UI 比对基础）");
    }

    #[tokio::test]
    async fn relay_poll_interval_is_sane() {
        assert!(POLL_EVERY.as_millis() >= 100);
    }

    #[test]
    fn relay_client_rejects_cleartext_http_on_non_loopback() {
        assert!(PairingRelayClient::new("http://example.com").is_err());
        assert!(PairingRelayClient::new("http://192.168.1.10").is_err());
        // Loopback http:// stays allowed for the local test relay.
        assert!(PairingRelayClient::new("http://127.0.0.1:8000").is_ok());
        assert!(PairingRelayClient::new("http://localhost:8000").is_ok());
        assert!(PairingRelayClient::new("http://[::1]:8000").is_ok());
        // https:// always allowed.
        assert!(PairingRelayClient::new("https://relay.example.com").is_ok());
        // The URL itself cannot be parsed → configuration error
        assert!(PairingRelayClient::new("not a url at all").is_err());
    }

    #[tokio::test]
    async fn join_begin_rejects_wrong_salt_length() {
        let (base_url, mailbox) = spawn_mock_relay();
        let client = PairingRelayClient::new(&base_url).unwrap();
        let (_host, invite) = PairingHost::new_invite().unwrap();
        let (session_id, _ttl) = client.create_session(&invite.salt).await.unwrap();

        // Relay tampering: session_info returns a short salt → join_begin
        // rejects it
        mailbox.lock().unwrap().salt = Some(vec![0u8; 8]);
        let link = PairingInviteLink {
            code: invite.code,
            relay_url: base_url,
            session_id,
        };
        let Err(err) = client.join_begin(&link).await else {
            panic!("join_begin must fail on wrong salt length");
        };
        assert!(err.to_string().contains("salt"), "got: {err}");
    }

    #[tokio::test]
    async fn join_confirm_without_begin_is_rejected() {
        let (base_url, _mailbox) = spawn_mock_relay();
        let client = PairingRelayClient::new(&base_url).unwrap();
        let (_host, invite) = PairingHost::new_invite().unwrap();
        let (session_id, _ttl) = client.create_session(&invite.salt).await.unwrap();

        // join_begin never ran: the guest holds no pending M1 → join_confirm
        // rejects
        let (mut guest, _offer) = PairingGuest::start(&invite.code, &invite.salt).unwrap();
        let err = client
            .join_confirm(&mut guest, &session_id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("join_begin"), "got: {err}");
    }

    #[tokio::test]
    async fn drive_host_rejects_out_of_order_message() {
        let (base_url, _mailbox) = spawn_mock_relay();
        let client = PairingRelayClient::new(&base_url).unwrap();
        let (mut host, invite) = PairingHost::new_invite().unwrap();
        let (session_id, _ttl) = client.create_session(&invite.salt).await.unwrap();

        // Post a message with the wrong direction/ordering straight into the
        // to-host mailbox → drive_host errors out
        client
            .post_to_host(
                &session_id,
                &PairingMessage::Handoff {
                    server_proof: "AA".into(),
                    wrapped_group_key: "AA".into(),
                },
            )
            .await
            .unwrap();
        let group_key: [u8; 32] = rand::random();
        let err = client
            .drive_host(&mut host, &group_key, &session_id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("不接受"), "got: {err}");
    }
}
