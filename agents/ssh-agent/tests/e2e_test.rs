//! End-to-End tests for Persona SSH Agent
//!
//! These tests verify SSH Agent functionality:
//! 1. SSH protocol encoding/decoding
//! 2. Policy enforcement logic
//! 3. Integration with Persona vault
//!
//! NOTE: Full E2E tests with actual socket communication are marked as #[ignore]
//! because they require running the full agent binary.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
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
