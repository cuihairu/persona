//! End-to-End tests for Persona SSH Agent
//!
//! These tests verify SSH Agent functionality:
//! 1. SSH protocol encoding/decoding
//! 2. Policy enforcement logic
//! 3. Integration with Persona vault
//!
//! NOTE: Full E2E tests with actual socket communication are marked as #[ignore]
//! because they require running the full agent binary.

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

/// Encode ed25519 public key in OpenSSH wire format
fn encode_ssh_ed25519_public(public_key: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    // Write algorithm name
    blob.write_u32::<BigEndian>(11).unwrap(); // Length of "ssh-ed25519"
    blob.extend_from_slice(b"ssh-ed25519");
    // Write public key
    blob.write_u32::<BigEndian>(32).unwrap();
    blob.extend_from_slice(public_key);
    blob
}

/// Parse SSH string from buffer
fn read_ssh_string(cursor: &mut Cursor<&[u8]>) -> std::io::Result<Vec<u8>> {
    let len = cursor.read_u32::<BigEndian>()? as usize;
    let mut data = vec![0u8; len];
    std::io::Read::read_exact(cursor, &mut data)?;
    Ok(data)
}

#[test]
fn test_ssh_protocol_format() {
    // Test SSH wire protocol encoding/decoding
    let mut buffer = Vec::new();

    // Write string
    buffer.write_u32::<BigEndian>(5).unwrap();
    buffer.extend_from_slice(b"hello");

    // Read string
    let mut cursor = Cursor::new(&buffer[..]);
    let len = cursor.read_u32::<BigEndian>().unwrap();
    assert_eq!(len, 5);

    let mut data = vec![0u8; len as usize];
    std::io::Read::read_exact(&mut cursor, &mut data).unwrap();
    assert_eq!(&data, b"hello");
}

#[test]
fn test_ed25519_public_key_encoding() {
    // Test encoding ed25519 public key in OpenSSH format
    let test_key = [0x42u8; 32]; // Dummy key
    let encoded = encode_ssh_ed25519_public(&test_key);

    // Verify encoding
    let mut cursor = Cursor::new(&encoded[..]);

    // Algorithm name
    let algo_len = cursor.read_u32::<BigEndian>().unwrap();
    assert_eq!(algo_len, 11);
    let mut algo = vec![0u8; algo_len as usize];
    std::io::Read::read_exact(&mut cursor, &mut algo).unwrap();
    assert_eq!(&algo, b"ssh-ed25519");

    // Public key
    let key_len = cursor.read_u32::<BigEndian>().unwrap();
    assert_eq!(key_len, 32);
    let mut key = vec![0u8; key_len as usize];
    std::io::Read::read_exact(&mut cursor, &mut key).unwrap();
    assert_eq!(&key[..], &test_key[..]);
}

#[test]
fn test_ssh_agent_message_types() {
    // Verify SSH agent protocol constants
    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    const SSH_AGENT_FAILURE: u8 = 5;

    // Test request identities message
    let request = vec![SSH_AGENTC_REQUEST_IDENTITIES];
    assert_eq!(request[0], 11);

    // Test sign request format
    let mut sign_request = Vec::new();
    sign_request.push(SSH_AGENTC_SIGN_REQUEST);
    assert_eq!(sign_request[0], 13);

    // Test response types
    assert_eq!(SSH_AGENT_IDENTITIES_ANSWER, 12);
    assert_eq!(SSH_AGENT_SIGN_RESPONSE, 14);
    assert_eq!(SSH_AGENT_FAILURE, 5);
}

#[test]
fn test_policy_config_format() {
    // Test that policy TOML format is correct
    let policy_toml = r#"
[global]
require_confirm = false
min_interval_ms = 1000
enforce_known_hosts = false
confirm_on_unknown_host = true
max_signatures_per_hour = 100
deny_all = false
"#;

    let parsed: Result<toml::Value, _> = toml::from_str(policy_toml);
    assert!(parsed.is_ok(), "Policy TOML should parse correctly");

    let value = parsed.unwrap();
    let global = value.get("global").expect("Should have global section");
    assert_eq!(
        global.get("require_confirm").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        global.get("min_interval_ms").and_then(|v| v.as_integer()),
        Some(1000)
    );
}

#[test]
fn test_read_ssh_string_function() {
    // Test the read_ssh_string helper
    let mut buffer = Vec::new();
    buffer.write_u32::<BigEndian>(11).unwrap();
    buffer.extend_from_slice(b"ssh-ed25519");

    let mut cursor = Cursor::new(&buffer[..]);
    let result = read_ssh_string(&mut cursor).unwrap();

    assert_eq!(result.len(), 11);
    assert_eq!(&result, b"ssh-ed25519");
}

#[test]
fn test_identities_answer_format() {
    // Test SSH_AGENT_IDENTITIES_ANSWER message format
    let mut response = Vec::new();

    // Message type
    response.push(12u8); // SSH_AGENT_IDENTITIES_ANSWER

    // Number of keys
    response.write_u32::<BigEndian>(1).unwrap();

    // Key 1 blob
    let key_blob = encode_ssh_ed25519_public(&[0x42; 32]);
    response
        .write_u32::<BigEndian>(key_blob.len() as u32)
        .unwrap();
    response.extend_from_slice(&key_blob);

    // Key 1 comment
    let comment = b"Test Key";
    response
        .write_u32::<BigEndian>(comment.len() as u32)
        .unwrap();
    response.extend_from_slice(comment);

    // Parse it back
    let mut cursor = Cursor::new(&response[..]);
    let msg_type = cursor.read_u8().unwrap();
    assert_eq!(msg_type, 12);

    let key_count = cursor.read_u32::<BigEndian>().unwrap();
    assert_eq!(key_count, 1);

    let parsed_key_blob = read_ssh_string(&mut cursor).unwrap();
    assert_eq!(parsed_key_blob, key_blob);

    let parsed_comment = read_ssh_string(&mut cursor).unwrap();
    assert_eq!(parsed_comment, comment);
}

#[cfg(unix)]
#[test]
#[ignore] // Run with `cargo test -- --ignored` when agent is running
fn test_agent_request_identities() {
    // E2E test: Query running agent for identities
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let sock_path = std::env::var("SSH_AUTH_SOCK")
        .expect("SSH_AUTH_SOCK not set. Start agent first.");

    let mut stream = UnixStream::connect(&sock_path)
        .expect("Failed to connect to agent. Is it running?");

    // Send SSH_AGENTC_REQUEST_IDENTITIES (type 11)
    let mut request = Vec::new();
    request.write_u32::<BigEndian>(1).unwrap(); // Payload length
    request.push(11u8); // Message type

    stream.write_all(&request).unwrap();

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let resp_len = BigEndian::read_u32(&len_buf) as usize;

    // Read response
    let mut response = vec![0u8; resp_len];
    stream.read_exact(&mut response).unwrap();

    // Verify response type
    assert!(
        !response.is_empty(),
        "Response should not be empty"
    );
    assert_eq!(
        response[0], 12,
        "Response should be SSH_AGENT_IDENTITIES_ANSWER (12)"
    );

    // Parse key count
    if response.len() >= 5 {
        let key_count = BigEndian::read_u32(&response[1..5]);
        println!("Agent has {} keys loaded", key_count);
        // Key count should be valid (any non-negative u32)
    }
}

#[cfg(unix)]
#[test]
#[ignore] // Run with `cargo test -- --ignored` and setup
fn test_ssh_github_connection() {
    // Full E2E test: Test SSH connection to GitHub using the agent
    // Prerequisites:
    // 1. Agent is running with SSH_AUTH_SOCK set
    // 2. A valid GitHub SSH key is loaded in the agent
    // 3. The key is authorized on GitHub

    use std::process::Command;

    let sock_path = std::env::var("SSH_AUTH_SOCK")
        .expect("SSH_AUTH_SOCK not set. Start agent first.");

    println!("Using agent at: {}", sock_path);

    // Test with ssh -T git@github.com
    let output = Command::new("ssh")
        .arg("-T")
        .arg("-o")
        .arg("StrictHostKeyChecking=no") // Skip host key verification for test
        .arg("git@github.com")
        .env("SSH_AUTH_SOCK", &sock_path)
        .output()
        .expect("Failed to execute ssh command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("SSH stdout: {}", stdout);
    println!("SSH stderr: {}", stderr);

    // GitHub responds with "Hi <username>!" on successful auth
    // Exit code is 1 even on success (since we used -T)
    assert!(
        stderr.contains("Hi ") || stderr.contains("successfully authenticated"),
        "Expected GitHub authentication message, got: {}",
        stderr
    );
}

#[test]
fn test_sign_request_format() {
    // Test SSH_AGENTC_SIGN_REQUEST message format
    let mut request = Vec::new();
    request.push(13u8); // SSH_AGENTC_SIGN_REQUEST

    // Key blob
    let key_blob = encode_ssh_ed25519_public(&[0x42; 32]);
    request.write_u32::<BigEndian>(key_blob.len() as u32).unwrap();
    request.extend_from_slice(&key_blob);

    // Data to sign
    let data = b"test data to sign";
    request.write_u32::<BigEndian>(data.len() as u32).unwrap();
    request.extend_from_slice(data);

    // Flags
    request.write_u32::<BigEndian>(0).unwrap();

    // Verify format
    let mut cursor = Cursor::new(&request[..]);
    let msg_type = cursor.read_u8().unwrap();
    assert_eq!(msg_type, 13);

    let parsed_key_blob = read_ssh_string(&mut cursor).unwrap();
    assert_eq!(parsed_key_blob, key_blob);

    let parsed_data = read_ssh_string(&mut cursor).unwrap();
    assert_eq!(parsed_data, data);

    let flags = cursor.read_u32::<BigEndian>().unwrap();
    assert_eq!(flags, 0);
}

#[cfg(unix)]
mod unix_e2e {
    use super::{encode_ssh_ed25519_public, read_ssh_string};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
    use persona_ssh_agent::{handle_connection, transport::AgentStream, Agent};
    use std::{
        env,
        io::{Cursor, Read, Write},
        os::unix::net::UnixStream as StdUnixStream,
        path::PathBuf,
        thread,
    };
    use tokio::{net::UnixStream, runtime::Runtime};

    #[test]
    fn test_agent_process_handles_identity_and_signing() {
        let rt = Runtime::new().expect("runtime");
        let key_comment = "Persona Test Key";
        let seed = [0x42u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let verifying_bytes = signing.verifying_key().to_bytes();
        let expected_blob = encode_ssh_ed25519_public(&verifying_bytes);
        let seed_b64 = BASE64.encode(seed);

        env::set_var("PERSONA_AGENT_TEST_KEY_SEED", &seed_b64);
        env::set_var("PERSONA_AGENT_TEST_KEY_COMMENT", key_comment);
        let db_path = PathBuf::from("/tmp/persona-agent-test.db");

        let mut agent = Agent::new();
        rt.block_on(async {
            agent
                .load_keys_from_persona(&db_path)
                .await
                .expect("load test key");
        });

        let (server_std, mut client) = StdUnixStream::pair().expect("stream pair");
        server_std
            .set_nonblocking(true)
            .expect("server nonblocking");
        client
            .set_nonblocking(false)
            .expect("client blocking");
        let mut agent_clone = agent.clone_shallow();
        let agent_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(1)
                .thread_name("agent-test")
                .build()
                .expect("agent runtime");
            runtime.block_on(async move {
                let server_stream =
                    UnixStream::from_std(server_std).expect("to tokio stream");
                handle_connection(&mut agent_clone, AgentStream::Unix(server_stream))
                    .await
                    .expect("handle connection");
            });
        });

        let (key_blob, comment) = request_agent_identities(&mut client);
        assert_eq!(key_blob, expected_blob);
        assert_eq!(comment, key_comment);

        let payload = b"persona agent e2e verification";
        let signature = request_signature(&mut client, &key_blob, payload);
        verify_signature(&signature, &verifying_bytes, payload);

        drop(client);
        agent_thread.join().expect("agent thread finished");

        env::remove_var("PERSONA_AGENT_TEST_KEY_SEED");
        env::remove_var("PERSONA_AGENT_TEST_KEY_COMMENT");
    }

    fn request_agent_identities(stream: &mut StdUnixStream) -> (Vec<u8>, String) {
        let mut request = vec![0u8; 5];
        BigEndian::write_u32(&mut request[0..4], 1);
        request[4] = 11;
        stream.write_all(&request).expect("write request");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).expect("len");
        let resp_len = BigEndian::read_u32(&len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).expect("payload");

        assert_eq!(resp.first().copied(), Some(12));
        let mut cursor = Cursor::new(&resp[1..]);
        let key_count = cursor.read_u32::<BigEndian>().expect("count");
        assert_eq!(key_count, 1);
        let key_blob = read_ssh_string(&mut cursor).expect("key blob");
        let comment_bytes = read_ssh_string(&mut cursor).expect("comment");
        let comment = String::from_utf8(comment_bytes).expect("utf8 comment");
        (key_blob, comment)
    }

    fn request_signature(stream: &mut StdUnixStream, key_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(13u8);
        write_ssh_string_bytes(&mut payload, key_blob);
        write_ssh_string_bytes(&mut payload, data);
        payload.write_u32::<BigEndian>(0).expect("flags");

        let mut packet = Vec::new();
        packet
            .write_u32::<BigEndian>(payload.len() as u32)
            .expect("len");
        packet.extend_from_slice(&payload);
        stream.write_all(&packet).expect("send sign request");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).expect("sig len");
        let resp_len = BigEndian::read_u32(&len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).expect("sig payload");
        assert_eq!(resp.first().copied(), Some(14));

        let mut cursor = Cursor::new(&resp[1..]);
        let sig_blob = read_ssh_string(&mut cursor).expect("sig blob");
        let mut sig_cursor = Cursor::new(&sig_blob[..]);
        let algo = read_ssh_string(&mut sig_cursor).expect("sig algo");
        assert_eq!(algo, b"ssh-ed25519");
        read_ssh_string(&mut sig_cursor).expect("signature bytes")
    }

    fn verify_signature(signature: &[u8], key_bytes: &[u8; 32], data: &[u8]) {
        let verifying_key = VerifyingKey::from_bytes(key_bytes).expect("verifying key");
        let sig_array: [u8; 64] = signature
            .try_into()
            .expect("signature must be 64 bytes");
        let sig = Signature::from_bytes(&sig_array);
        verifying_key
            .verify(data, &sig)
            .expect("signature verification failed");
    }

    fn write_ssh_string_bytes(buf: &mut Vec<u8>, data: &[u8]) {
        buf.write_u32::<BigEndian>(data.len() as u32)
            .expect("write len");
        buf.extend_from_slice(data);
    }
}
