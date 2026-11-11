use super::*;

#[test]
fn wrap_packet_prepends_big_endian_length() {
    let out = wrap_packet(vec![1u8, 2, 3]);
    assert_eq!(out, vec![0, 0, 0, 3, 1, 2, 3]);
}

#[test]
fn ssh_string_roundtrip() {
    let mut buf = Vec::new();
    write_ssh_string(&mut buf, b"hello").unwrap();
    write_ssh_string(&mut buf, b"world").unwrap();

    let mut slice: &[u8] = &buf;
    let a = read_ssh_string(&mut slice).unwrap();
    let b = read_ssh_string(&mut slice).unwrap();
    assert_eq!(a, b"hello");
    assert_eq!(b, b"world");
    assert!(slice.is_empty());
}

#[test]
fn ssh_string_out_of_bounds_errors() {
    let mut buf = Vec::new();
    // length=10, but only 1 byte of payload
    buf.extend_from_slice(&10u32.to_be_bytes());
    buf.push(1u8);
    let mut slice: &[u8] = &buf;
    assert!(read_ssh_string(&mut slice).is_err());
}

#[test]
fn parse_public_line_to_blob_accepts_ed25519() {
    let (_, blob) = openssh_pub_line([5u8; 32]);
    let line = format!("ssh-ed25519 {} comment", BASE64.encode(&blob));
    assert_eq!(parse_public_line_to_blob(&line), Some(blob));
}

#[test]
fn parse_public_line_to_blob_accepts_rsa_and_ecdsa() {
    let rsa_key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Rsa { hash: None },
    )
    .unwrap();
    let line = rsa_key.public_key().to_openssh().unwrap();
    let blob = parse_public_line_to_blob(&line).expect("rsa public line parses");
    assert_eq!(public_key_algorithm(&blob).as_deref(), Some("ssh-rsa"));

    let ecdsa_key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let line = ecdsa_key.public_key().to_openssh().unwrap();
    let blob = parse_public_line_to_blob(&line).expect("ecdsa public line parses");
    assert_eq!(
        public_key_algorithm(&blob).as_deref(),
        Some("ecdsa-sha2-nistp256")
    );
}

#[test]
fn current_target_host_prefers_explicit_vars() {
    let _guard = env_lock();

    std::env::remove_var("PERSONA_AGENT_TARGET_HOST_HINT");
    std::env::remove_var("PERSONA_AGENT_SSH_DEST");
    std::env::remove_var("SSH_CONNECTION");
    std::env::remove_var("SSH_CLIENT");
    std::env::remove_var("PERSONA_AGENT_SSH_COMMAND");
    std::env::remove_var("SSH_ORIGINAL_COMMAND");
    std::env::remove_var("GIT_SSH_COMMAND");

    std::env::set_var("PERSONA_AGENT_TARGET_HOST", "github.com");
    assert_eq!(current_target_host().as_deref(), Some("github.com"));

    std::env::set_var("PERSONA_AGENT_TARGET_HOST", "");
    std::env::set_var("PERSONA_AGENT_TARGET_HOST_HINT", "gitlab.com");
    assert_eq!(current_target_host().as_deref(), Some("gitlab.com"));

    std::env::remove_var("PERSONA_AGENT_TARGET_HOST");
    std::env::remove_var("PERSONA_AGENT_TARGET_HOST_HINT");
    std::env::set_var("SSH_CONNECTION", "1.2.3.4 123 5.6.7.8 22");
    assert_eq!(current_target_host().as_deref(), Some("1.2.3.4"));

    std::env::remove_var("SSH_CONNECTION");
    std::env::set_var("GIT_SSH_COMMAND", "ssh -T git@github.com");
    assert_eq!(current_target_host().as_deref(), Some("github.com"));
}

#[test]
fn is_host_in_known_hosts_uses_custom_file() {
    let _guard = env_lock();

    let dir = tempfile::tempdir().unwrap();
    let known_hosts_path = dir.path().join("known_hosts");
    std::fs::write(
        &known_hosts_path,
        "\
# comment
github.com ssh-ed25519 AAAA
gitlab.com,192.0.2.1 ssh-rsa AAAA
",
    )
    .unwrap();

    std::env::set_var("PERSONA_KNOWN_HOSTS_FILE", &known_hosts_path);

    assert!(is_host_in_known_hosts("github.com"));
    assert!(is_host_in_known_hosts("gitlab.com"));
    assert!(!is_host_in_known_hosts("example.com"));
}

#[test]
fn identities_answer_encodes_count_and_comments() {
    let (k1, _) = make_ed25519_key("Key One");
    let (k2, _) = make_ed25519_key("Key Two");
    let agent = make_test_agent(vec![k1.clone(), k2.clone()]);

    let pkt = agent.identities_answer().unwrap();
    assert!(pkt.len() >= 4 + 1 + 4);
    let len = u32::from_be_bytes(pkt[0..4].try_into().unwrap()) as usize;
    assert_eq!(len, pkt.len() - 4);
    assert_eq!(pkt[4], 12u8);
    let count = u32::from_be_bytes(pkt[5..9].try_into().unwrap());
    assert_eq!(count, 2);
}

#[cfg(unix)]
#[tokio::test]
async fn handle_connection_request_identities_roundtrip() {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::transport::AgentListener;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("persona-agent-e2e.sock");

    let mut listener = AgentListener::bind(&sock_path).await.unwrap();
    let (k, _) = make_ed25519_key("Key One");
    let mut agent = make_test_agent(vec![k]);

    let mut server_task = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        handle_connection(&mut agent, stream).await.unwrap();
    });

    let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let mut req = vec![0u8; 5];
    BigEndian::write_u32(&mut req[0..4], 1);
    req[4] = 11u8;
    client.write_all(&req).await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 12u8);

    drop(client);
    // server exits when stream closes
    match tokio::time::timeout(std::time::Duration::from_secs(1), &mut server_task).await {
        Ok(res) => res.unwrap(),
        Err(_) => {
            server_task.abort();
            let _ = server_task.await;
        }
    }
}

#[tokio::test]
async fn sign_response_produces_verifiable_signature() {
    let _guard = env_lock();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    std::env::set_var("PERSONA_DB_PATH", &db_path);

    let (key, verifying) = make_ed25519_key("Key One");
    let agent = make_test_agent(vec![key.clone()]);

    let data = b"data-to-sign";
    let mut payload = Vec::new();
    write_ssh_string(&mut payload, &key.public_blob).unwrap();
    write_ssh_string(&mut payload, data).unwrap();
    payload.extend_from_slice(&0u32.to_be_bytes()); // flags

    let pkt = agent.sign_response(&payload).await.unwrap();
    let len = u32::from_be_bytes(pkt[0..4].try_into().unwrap()) as usize;
    assert_eq!(len, pkt.len() - 4);
    assert_eq!(pkt[4], 14u8);

    let mut slice: &[u8] = &pkt[5..];
    let sig_blob = read_ssh_string(&mut slice).unwrap();
    assert!(slice.is_empty());

    let mut sig_slice: &[u8] = &sig_blob;
    let algo = read_ssh_string(&mut sig_slice).unwrap();
    let sig_bytes = read_ssh_string(&mut sig_slice).unwrap();
    assert!(sig_slice.is_empty());
    assert_eq!(algo, b"ssh-ed25519");

    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    verifying.verify_strict(data, &sig).unwrap();
}

// ------------------------------------------------------------------
// Agent construction / env-based key loading
// ------------------------------------------------------------------

#[test]
fn agent_default_and_clone_shallow_share_policy() {
    let agent = Agent::default();
    assert!(agent.keys.is_empty());

    let (k, _) = make_ed25519_key("shared");
    let with_key = Agent {
        keys: vec![k],
        ..Agent::default()
    };
    let clone = with_key.clone_shallow();
    assert_eq!(clone.keys.len(), 1);
    assert_eq!(clone.keys[0].comment, "shared");
    assert!(Arc::ptr_eq(&with_key.policy, &clone.policy));
    assert!(Arc::ptr_eq(
        &with_key.biometric_provider,
        &clone.biometric_provider
    ));
}

#[test]
fn default_agent_biometric_is_deny() {
    // The default provider must be unavailable and fail, so a
    // `require_biometric` policy denies instead of silently passing.
    let agent = Agent::default();
    assert!(!agent.biometric_provider.is_available(detect_platform()));
    let prompt = BiometricPrompt {
        user_id: uuid::Uuid::new_v4(),
        reason: "default-deny probe".to_string(),
        platform: detect_platform(),
    };
    assert!(agent.biometric_provider.authenticate(&prompt).is_err());
}

#[test]
fn with_biometric_provider_overrides_default() {
    let provider = stub_biometric(true, StubOutcome::Succeed(true));
    let agent = Agent::default().with_biometric_provider(provider);
    assert!(agent.biometric_provider.is_available(detect_platform()));
    let prompt = BiometricPrompt {
        user_id: uuid::Uuid::new_v4(),
        reason: "override probe".to_string(),
        platform: detect_platform(),
    };
    assert!(
        agent
            .biometric_provider
            .authenticate(&prompt)
            .unwrap()
            .verified
    );
}
