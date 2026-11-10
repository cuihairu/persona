#[cfg(unix)]
use super::super::agent::is_persona_agent_process;
#[cfg(windows)]
use super::super::agent::open_named_pipe_with_retry;
use super::super::agent::{
    format_sock_export_lines, query_agent_identities, stop_agent_pid, StopOutcome,
};
use super::super::host::current_or_stored_agent_socket;
use super::super::keys::{decode_seed, encode_ssh_ed25519_public};
use super::*;

/// `decode_seed` 的两个守卫分支：非法 base64、种子长度不是 32 字节。
#[test]
fn decode_seed_rejects_non_base64_and_wrong_length() {
    let key = |private_key: String| SshKeyData {
        private_key,
        public_key: String::new(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    };

    let err = decode_seed(&key("!!! not base64 !!!".to_string())).unwrap_err();
    assert!(
        err.to_string()
            .contains("private material is not valid base64"),
        "{err}"
    );

    let err = decode_seed(&key(BASE64.encode(b"too short"))).unwrap_err();
    assert!(err.to_string().contains("must be 32 bytes, got 9"), "{err}");
}

fn build_identities_answer(count: u32) -> Vec<u8> {
    use byteorder::{BigEndian, ByteOrder};
    let mut payload = Vec::with_capacity(1 + 4);
    payload.push(12u8);
    let mut count_buf = [0u8; 4];
    BigEndian::write_u32(&mut count_buf, count);
    payload.extend_from_slice(&count_buf);

    let mut out = Vec::with_capacity(4 + payload.len());
    let mut len_buf = [0u8; 4];
    BigEndian::write_u32(&mut len_buf, payload.len() as u32);
    out.extend_from_slice(&len_buf);
    out.extend_from_slice(&payload);
    out
}

#[test]
fn encode_ssh_ed25519_public_has_expected_prefix_and_blob() {
    let pubkey = [7u8; 32];
    let line = encode_ssh_ed25519_public(&pubkey, Some("comment"));
    assert!(line.starts_with("ssh-ed25519 "));
    assert!(line.ends_with(" comment"));

    let parts: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(parts.len(), 3);

    let decoded = BASE64.decode(parts[1]).unwrap();
    assert!(decoded.len() >= 4 + b"ssh-ed25519".len() + 4 + 32);
}

#[cfg(unix)]
#[test]
fn format_sock_export_lines_unix() {
    let lines = format_sock_export_lines("/tmp/persona.sock");
    assert_eq!(
        lines,
        vec!["  export SSH_AUTH_SOCK=/tmp/persona.sock".to_string()]
    );
}

#[cfg(windows)]
#[test]
fn format_sock_export_lines_windows() {
    let lines = format_sock_export_lines(r"\\.\pipe\persona-test");
    assert_eq!(
        lines,
        vec![
            "  # PowerShell".to_string(),
            "  $env:SSH_AUTH_SOCK = '\\\\.\\pipe\\persona-test'".to_string(),
            "  # cmd.exe".to_string(),
            "  set SSH_AUTH_SOCK=\\\\.\\pipe\\persona-test".to_string(),
        ]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn query_agent_identities_unix_mock_server() {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("persona-test-agent.sock");
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let req_len = BigEndian::read_u32(&len_buf) as usize;
        let mut req = vec![0u8; req_len];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(req, vec![11u8]);

        let resp = build_identities_answer(0);
        stream.write_all(&resp).await.unwrap();
    });

    let count = query_agent_identities(sock_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(count, 0);
    server_task.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
#[allow(unused_mut)]
async fn query_agent_identities_windows_mock_server() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = format!(r"\\.\pipe\persona-test-agent-{}", Uuid::new_v4());
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .unwrap();

    let server_task = tokio::spawn(async move {
        server.connect().await.unwrap();

        let mut len_buf = [0u8; 4];
        server.read_exact(&mut len_buf).await.unwrap();
        let req_len = u32::from_be_bytes(len_buf) as usize;
        let mut req = vec![0u8; req_len];
        server.read_exact(&mut req).await.unwrap();
        assert_eq!(req, vec![11u8]);

        let resp = build_identities_answer(0);
        server.write_all(&resp).await.unwrap();
    });

    let count = query_agent_identities(&pipe_name).await.unwrap();
    assert_eq!(count, 0);
    server_task.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
#[allow(unused_mut)]
async fn open_named_pipe_with_retry_waits_for_server() {
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = format!(r"\\.\pipe\persona-test-retry-{}", Uuid::new_v4());

    let pipe_name_for_client = pipe_name.clone();
    let client_task = tokio::spawn(async move {
        open_named_pipe_with_retry(&pipe_name_for_client, 50, Duration::from_millis(10))
            .await
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .unwrap();
    server.connect().await.unwrap();

    let _client = client_task.await.unwrap();
}

#[cfg(unix)]
#[test]
fn stop_agent_pid_nonexistent_is_already_gone() {
    assert_eq!(
        stop_agent_pid("99999999").unwrap(),
        StopOutcome::AlreadyGone
    );
}

#[cfg(windows)]
#[test]
fn stop_agent_pid_nonexistent_is_already_gone() {
    // tasklist 探测不到进程 → 按"陈旧 pidfile"处理（与 Unix 一致）。
    assert_eq!(
        stop_agent_pid("99999999").unwrap(),
        StopOutcome::AlreadyGone
    );
}

#[cfg(unix)]
pub(crate) async fn serve_one_identity_query(listener: tokio::net::UnixListener, count: u32) {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _) = listener.accept().await.unwrap();
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let req_len = BigEndian::read_u32(&len_buf) as usize;
    let mut req = vec![0u8; req_len];
    stream.read_exact(&mut req).await.unwrap();
    assert_eq!(req, vec![11u8]);
    let resp = build_identities_answer(count);
    stream.write_all(&resp).await.unwrap();
}

/// Mock agent that replies with an arbitrary payload.
#[cfg(unix)]
async fn serve_raw_reply(listener: tokio::net::UnixListener, payload: Vec<u8>) {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _) = listener.accept().await.unwrap();
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let req_len = BigEndian::read_u32(&len_buf) as usize;
    let mut req = vec![0u8; req_len];
    stream.read_exact(&mut req).await.unwrap();
    assert_eq!(req, vec![11u8]);

    let mut out = Vec::with_capacity(4 + payload.len());
    let mut len_buf = [0u8; 4];
    BigEndian::write_u32(&mut len_buf, payload.len() as u32);
    out.extend_from_slice(&len_buf);
    out.extend_from_slice(&payload);
    stream.write_all(&out).await.unwrap();
}

/// Mock agent that lies about the response length (u32::MAX), then closes.
/// 客户端必须在分配前拒绝（BUG-1 同法长度上限），否则会尝试分配 4GiB。
#[cfg(unix)]
async fn serve_oversized_length(listener: tokio::net::UnixListener) {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _) = listener.accept().await.unwrap();
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let req_len = BigEndian::read_u32(&len_buf) as usize;
    let mut req = vec![0u8; req_len];
    stream.read_exact(&mut req).await.unwrap();
    assert_eq!(req, vec![11u8]);

    let mut out = [0u8; 4];
    BigEndian::write_u32(&mut out, u32::MAX);
    stream.write_all(&out).await.unwrap();
    let _ = stream.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn query_agent_identities_rejects_oversized_length() {
    use tokio::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("oversize.sock")).unwrap();
    let server = tokio::spawn(serve_oversized_length(listener));
    let err = query_agent_identities(dir.path().join("oversize.sock").to_str().unwrap())
        .await
        .expect_err("oversized length prefix must fail before allocation");
    assert!(err.to_string().contains("exceeds limit"), "{err}");
    server.await.unwrap();
}

#[cfg(unix)]
#[test]
fn stop_agent_pid_verification_distinguishes_stale_and_reused() {
    // 一个必然不存在的 PID：/proc 下无此进程 → None（陈旧 pidfile 判据）。
    assert_eq!(is_persona_agent_process("999999999"), None);
    // 自己这个测试进程存在，但不是 persona-ssh-agent → Some(false)
    // （PID 被复用时的拒绝判据）。
    let me = std::process::id().to_string();
    assert_eq!(is_persona_agent_process(&me), Some(false));
}

#[cfg(unix)]
#[tokio::test]
async fn query_agent_identities_rejects_bad_responses() {
    use tokio::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();

    // A response with an unexpected type byte is refused.
    let listener = UnixListener::bind(dir.path().join("bad-type.sock")).unwrap();
    let server = tokio::spawn(serve_raw_reply(listener, vec![6u8]));
    let err = query_agent_identities(dir.path().join("bad-type.sock").to_str().unwrap())
        .await
        .expect_err("wrong response type must fail");
    assert!(err.to_string().contains("Unexpected agent response"));
    server.await.unwrap();

    // A truncated identities answer is refused.
    let listener = UnixListener::bind(dir.path().join("short.sock")).unwrap();
    let server = tokio::spawn(serve_raw_reply(listener, vec![12u8]));
    let err = query_agent_identities(dir.path().join("short.sock").to_str().unwrap())
        .await
        .expect_err("truncated response must fail");
    assert!(err.to_string().contains("Malformed agent response"));
    server.await.unwrap();
}

// ------------------------------------------------------------------
// run-with-host and socket resolution.
// ------------------------------------------------------------------

#[test]
fn current_or_stored_agent_socket_prefers_env_then_file() {
    let _env = lock_process_env();
    let _sock = EnvVarGuard::remove("SSH_AUTH_SOCK");
    let dir = TempDir::new().unwrap();
    let state = dir.path();
    let sock_file = state.join("ssh-agent.sock");

    // Nothing recorded: no socket.
    assert_eq!(current_or_stored_agent_socket(state), None);

    // A stored sock file is picked up.
    std::fs::write(&sock_file, "/tmp/persona-stored.sock\n").unwrap();
    assert_eq!(
        current_or_stored_agent_socket(state).as_deref(),
        Some("/tmp/persona-stored.sock")
    );

    // A whitespace-only file counts as absent.
    std::fs::write(&sock_file, "   \n").unwrap();
    assert_eq!(current_or_stored_agent_socket(state), None);

    // A non-empty env var wins over the file…
    std::fs::write(&sock_file, "/tmp/persona-stored.sock").unwrap();
    let _env_sock = EnvVarGuard::set("SSH_AUTH_SOCK", "/tmp/persona-env.sock");
    assert_eq!(
        current_or_stored_agent_socket(state).as_deref(),
        Some("/tmp/persona-env.sock")
    );

    // …while a whitespace-only env falls back to the file.
    let _env_blank = EnvVarGuard::set("SSH_AUTH_SOCK", "   ");
    assert_eq!(
        current_or_stored_agent_socket(state).as_deref(),
        Some("/tmp/persona-stored.sock")
    );
}
