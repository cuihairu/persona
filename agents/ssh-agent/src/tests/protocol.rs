#[cfg(unix)]
use super::*;

#[cfg(unix)]
#[tokio::test]
async fn handle_connection_replies_failure_for_unsupported_type() {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("unsupported.sock");
    let mut listener = crate::transport::AgentListener::bind(&sock_path)
        .await
        .unwrap();
    let mut agent = make_test_agent(vec![]);

    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        handle_connection(&mut agent, stream).await
    });

    let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    // Empty payload is skipped entirely.
    client.write_all(&0u32.to_be_bytes()).await.unwrap();
    // Unsupported type (9) gets a failure packet (5).
    let mut req = vec![0u8; 5];
    BigEndian::write_u32(&mut req[0..4], 1);
    req[4] = 9u8;
    client.write_all(&req).await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let mut resp = vec![0u8; BigEndian::read_u32(&len_buf) as usize];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 5u8);

    // Truncated packet body (declared 16, sent 2) -> connection errors out.
    client.write_all(&16u32.to_be_bytes()).await.unwrap();
    client.write_all(b"xy").await.unwrap();
    drop(client);

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    let handler = result.expect("server should finish").unwrap();
    assert!(handler.is_err(), "truncated body must surface an error");
}

// ------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn handle_connection_sign_request_roundtrip() {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    std::env::set_var("PERSONA_DB_PATH", &db_path);
    std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

    let sock_path = dir.path().join("sign.sock");
    let mut listener = crate::transport::AgentListener::bind(&sock_path)
        .await
        .unwrap();
    let (k, verifying) = make_ed25519_key("signer");
    let mut agent = make_test_agent(vec![k.clone()]);

    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        handle_connection(&mut agent, stream).await
    });

    let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let payload = sign_payload_for(&k, b"frame-payload");
    let mut req = Vec::new();
    req.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    req.push(13u8); // SSH_AGENTC_SIGN_REQUEST
    req.extend_from_slice(&payload);
    client.write_all(&req).await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let mut resp = vec![0u8; BigEndian::read_u32(&len_buf) as usize];
    client.read_exact(&mut resp).await.unwrap();
    std::env::remove_var("PERSONA_DB_PATH");
    drop(client);

    assert_eq!(resp[0], 14u8, "signature answer");
    let mut slice: &[u8] = &resp[1..];
    let sig_blob = read_ssh_string(&mut slice).unwrap();
    let mut s: &[u8] = &sig_blob;
    let algo = read_ssh_string(&mut s).unwrap();
    let sig_bytes = read_ssh_string(&mut s).unwrap();
    assert_eq!(algo, b"ssh-ed25519");
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    verifying.verify_strict(b"frame-payload", &sig).unwrap();

    let handler = tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("server should finish")
        .unwrap();
    handler.unwrap();
}
