#![cfg(unix)]
//! Integration tests for the daemon event loop (`run_agent_with_approval`).
//!
//! The daemon is driven through its real socket: paths, state directory and
//! the ed25519 key are injected via environment variables, a scripted
//! `ApprovalHandler` replaces the TTY prompt, and the never-returning accept
//! loop is shut down by aborting the spawned task.
//!
//! The daemon initializes the global tracing subscriber on startup, and a
//! process only accepts one global subscriber — so this binary runs exactly
//! one daemon startup. All scenarios are chained through that single run.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use persona_ssh_agent::approval::{ApprovalHandler, ApprovalRequest};
use persona_ssh_agent::run_agent_with_approval;
use std::{
    collections::VecDeque,
    env,
    io::Cursor,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::net::UnixStream;

/// Environment variables this test binary touches; cleared on drop so a
/// failing assertion cannot leak them into anything that runs afterwards.
///
/// The guard also holds a process-wide lock for its whole lifetime: these
/// tests share one environment, and a second test replacing the variables
/// mid-run would silently redirect the first one's daemon to the wrong
/// socket path (observed as a 5 s connect timeout and a panic).
struct EnvGuard {
    vars: &'static [&'static str],
    _lock: MutexGuard<'static, ()>,
}

static ENV_MUTEX: Mutex<()> = Mutex::new(());

impl EnvGuard {
    fn acquire(vars: &'static [&'static str]) -> Self {
        let lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for name in vars {
            env::remove_var(name);
        }
        Self { vars, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for name in self.vars {
            env::remove_var(name);
        }
    }
}

/// Approval handler with a scripted decision queue that records every request
/// it was asked to approve.
#[derive(Clone)]
struct ScriptedApproval {
    decisions: Arc<Mutex<VecDeque<bool>>>,
    requests: Arc<Mutex<Vec<ApprovalRequest>>>,
}

impl ScriptedApproval {
    fn new(decisions: Vec<bool>) -> Self {
        Self {
            decisions: Arc::new(Mutex::new(decisions.into())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn captured_requests(&self) -> Vec<ApprovalRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ApprovalHandler for ScriptedApproval {
    async fn confirm(&self, request: &ApprovalRequest) -> anyhow::Result<bool> {
        self.requests.lock().unwrap().push(request.clone());
        match self.decisions.lock().unwrap().pop_front() {
            Some(decision) => Ok(decision),
            None => Ok(false),
        }
    }
}

#[tokio::test]
async fn daemon_serves_clients_and_gates_signatures_behind_approval() {
    const ENV_VARS: &[&str] = &[
        "PERSONA_AGENT_SOCKET_PATH",
        "PERSONA_DB_PATH",
        "PERSONA_AGENT_STATE_DIR",
        "PERSONA_AGENT_TEST_KEY_SEED",
        "PERSONA_AGENT_TEST_KEY_COMMENT",
        "PERSONA_AGENT_REQUIRE_CONFIRM",
    ];
    let _env = EnvGuard::acquire(ENV_VARS);

    let dirs = tempfile::tempdir().expect("temp dir for socket + state");
    let socket_path = dirs.path().join("agent.sock");
    let state_dir = dirs.path().join("state");
    let db_path = dirs.path().join("persona.db");

    let seed = [0x42u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let verifying_bytes = signing.verifying_key().to_bytes();
    let expected_blob = encode_ssh_ed25519_public(&verifying_bytes);
    let key_comment = "daemon-test-key".to_string();

    env::set_var("PERSONA_AGENT_SOCKET_PATH", &socket_path);
    env::set_var("PERSONA_DB_PATH", &db_path);
    env::set_var("PERSONA_AGENT_STATE_DIR", &state_dir);
    env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(seed));
    env::set_var("PERSONA_AGENT_TEST_KEY_COMMENT", &key_comment);
    env::set_var("PERSONA_AGENT_REQUIRE_CONFIRM", "1");

    // Every signature consults the handler: first allow, then deny.
    let handler = ScriptedApproval::new(vec![true, false]);
    let daemon = tokio::spawn(run_agent_with_approval(Some(Arc::new(handler.clone()))));

    let mut client = connect_with_retry(&socket_path).await;

    // Identities: the env-injected key is served.
    let (key_blob, comment) = request_identities(&mut client).await;
    assert_eq!(key_blob, expected_blob);
    assert_eq!(comment, key_comment);

    // First signature: approval allows -> valid ed25519 signature comes back.
    let payload = b"persona daemon loop: allow";
    let signature = request_signature(&mut client, &key_blob, payload).await;
    verify_signature(&signature, &verifying_bytes, payload);

    // Second signature: approval denies -> SSH_AGENT_FAILURE (5).
    let resp = send_sign_request(&mut client, &key_blob, b"persona daemon loop: deny").await;
    assert_eq!(resp.first().copied(), Some(5), "denied sign must fail");

    // The handler saw exactly the two requests above, with sane display data.
    let requests = handler.captured_requests();
    assert_eq!(requests.len(), 2, "one approval per signature");
    for request in &requests {
        assert_eq!(request.operation, "sign");
        assert!(request.fingerprint.starts_with("SHA256:"));
        assert!(request.prompt.contains("Allow SSH signature"));
        assert!(!request.key_id.is_empty());
    }

    // Truncated packet: the declared length never arrives, so that connection
    // dies — but the accept loop keeps serving new clients.
    use tokio::io::AsyncWriteExt;
    client
        .write_all(&16u32.to_be_bytes())
        .await
        .expect("declare truncated length");
    let _ = client.shutdown().await;
    drop(client);

    let mut next_client = connect_with_retry(&socket_path).await;
    let (key_blob_again, _) = request_identities(&mut next_client).await;
    assert_eq!(key_blob_again, expected_blob, "loop survives bad input");

    // State files: the endpoint and PID are published for `persona ssh`.
    let sock_endpoint =
        std::fs::read_to_string(state_dir.join("ssh-agent.sock")).expect("sock state file");
    assert_eq!(sock_endpoint, socket_path.display().to_string());
    let pid = std::fs::read_to_string(state_dir.join("ssh-agent.pid")).expect("pid state file");
    assert_eq!(pid, std::process::id().to_string());

    daemon.abort();
}

/// Spawns the real agent binary exactly like `persona ssh add-to-agent`
/// does (piped stdout), then closes the parent-side pipe ends right after
/// consuming the SSH_AUTH_SOCK line — simulating the parent CLI exiting.
/// A connection-level `warn!` must not kill the daemon: with the default
/// SIGPIPE disposition the first stdout write after the parent's exit
/// terminated it silently.
#[tokio::test]
async fn daemon_survives_parent_pipe_death_after_socket_line() {
    const ENV_VARS: &[&str] = &[
        "PERSONA_AGENT_SOCKET_PATH",
        "PERSONA_AGENT_STATE_DIR",
        "PERSONA_AGENT_TEST_KEY_SEED",
        "PERSONA_AGENT_TEST_KEY_COMMENT",
        "PERSONA_DB_PATH",
    ];
    let _env = EnvGuard::acquire(ENV_VARS);

    let dirs = tempfile::tempdir().expect("temp dir for socket + state");
    let socket_path = dirs.path().join("orphan.sock");
    env::set_var("PERSONA_AGENT_SOCKET_PATH", &socket_path);
    env::set_var("PERSONA_AGENT_STATE_DIR", dirs.path().join("state"));
    let seed = [0x24u8; 32];
    env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(seed));
    env::set_var("PERSONA_AGENT_TEST_KEY_COMMENT", "orphan-test-key");
    // The test-key override short-circuits before the db is ever touched;
    // prove the daemon needs none.
    env::remove_var("PERSONA_DB_PATH");

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_persona-ssh-agent"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn persona-ssh-agent binary");

    // Consume stdout until the socket line, then orphan the pipe: the child
    // keeps the write ends while every read end is gone.
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    loop {
        line.clear();
        let n = std::io::BufRead::read_line(&mut stdout, &mut line).expect("read agent stdout");
        assert!(n > 0, "agent stdout closed before SSH_AUTH_SOCK line");
        if line.starts_with("SSH_AUTH_SOCK=") {
            break;
        }
    }
    drop(stdout);
    drop(child.stderr.take());

    // Unsupported message type: the handler warns (a stdout write) before
    // answering failure (5). Against the dead pipe this is the SIGPIPE trip.
    let mut first = connect_with_retry(&socket_path).await;
    let resp = send_request(&mut first, &[0x7fu8]).await;
    assert_eq!(
        resp.first().copied(),
        Some(5),
        "failure answer after orphaned stdout"
    );
    drop(first);

    // The daemon must still serve a fresh client afterwards.
    let mut second = connect_with_retry(&socket_path).await;
    let (key_blob, comment) = request_identities(&mut second).await;
    let signing = SigningKey::from_bytes(&seed);
    let expected_blob = encode_ssh_ed25519_public(&signing.verifying_key().to_bytes());
    assert_eq!(key_blob, expected_blob, "test key still served");
    assert_eq!(comment, "orphan-test-key");

    let _ = child.kill();
    let _ = child.wait();
}

async fn connect_with_retry(path: &Path) -> UnixStream {
    for _ in 0..100 {
        if let Ok(stream) = UnixStream::connect(path).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "agent socket never accepted a connection at {}",
        path.display()
    );
}

async fn read_response(stream: &mut UnixStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .expect("read response length");
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.expect("read response");
    resp
}

async fn request_identities(stream: &mut UnixStream) -> (Vec<u8>, String) {
    let resp = send_request(stream, &[11u8]).await;
    assert_eq!(resp.first().copied(), Some(12), "identities answer");
    let mut cursor = Cursor::new(&resp[1..]);
    let key_count = cursor.read_u32::<BigEndian>().expect("key count");
    assert_eq!(key_count, 1);
    let key_blob = read_ssh_string(&mut cursor).expect("key blob");
    let comment = String::from_utf8(read_ssh_string(&mut cursor).expect("comment"))
        .expect("comment is utf-8");
    (key_blob, comment)
}

async fn send_sign_request(stream: &mut UnixStream, key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut payload = vec![13u8];
    write_ssh_string_bytes(&mut payload, key_blob);
    write_ssh_string_bytes(&mut payload, data);
    payload.write_u32::<BigEndian>(0).expect("flags");
    send_request(stream, &payload).await
}

async fn request_signature(stream: &mut UnixStream, key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let resp = send_sign_request(stream, key_blob, data).await;
    assert_eq!(resp.first().copied(), Some(14), "signature answer");
    let mut cursor = Cursor::new(&resp[1..]);
    let sig_blob = read_ssh_string(&mut cursor).expect("signature blob");
    let mut sig_cursor = Cursor::new(&sig_blob[..]);
    let algo = read_ssh_string(&mut sig_cursor).expect("signature algo");
    assert_eq!(algo, b"ssh-ed25519");
    read_ssh_string(&mut sig_cursor).expect("signature bytes")
}

async fn send_request(stream: &mut UnixStream, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet
        .write_u32::<BigEndian>(payload.len() as u32)
        .expect("request length");
    packet.extend_from_slice(payload);
    tokio::io::AsyncWriteExt::write_all(stream, &packet)
        .await
        .expect("send request");
    tokio::io::AsyncWriteExt::flush(stream)
        .await
        .expect("flush request");
    read_response(stream).await
}

fn verify_signature(signature: &[u8], key_bytes: &[u8], data: &[u8]) {
    let verifying_key = VerifyingKey::from_bytes(key_bytes.try_into().expect("32-byte key"))
        .expect("verifying key");
    let sig_array: [u8; 64] = signature.try_into().expect("signature must be 64 bytes");
    verifying_key
        .verify(data, &Signature::from_bytes(&sig_array))
        .expect("signature verification failed");
}

fn encode_ssh_ed25519_public(verifying_bytes: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.write_u32::<BigEndian>(b"ssh-ed25519".len() as u32)
        .expect("algo length");
    blob.extend_from_slice(b"ssh-ed25519");
    blob.write_u32::<BigEndian>(verifying_bytes.len() as u32)
        .expect("key length");
    blob.extend_from_slice(verifying_bytes);
    blob
}

fn read_ssh_string(cursor: &mut Cursor<&[u8]>) -> Option<Vec<u8>> {
    use std::io::Read;

    let mut len_buf = [0u8; 4];
    cursor.read_exact(&mut len_buf).ok()?;
    let len = BigEndian::read_u32(&len_buf) as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn write_ssh_string_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.write_u32::<BigEndian>(data.len() as u32)
        .expect("string length");
    buf.extend_from_slice(data);
}
