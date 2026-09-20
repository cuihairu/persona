//! Desktop-side approval server for bridge passkey requests.
//!
//! `persona bridge` connects to a local Unix socket
//! (`agent_state_dir()/passkey-approval.sock`) for every gated passkey
//! request; this module answers those connections. The wire protocol is one
//! JSON line per direction, one request per connection (see
//! docs/BRIDGE_PROTOCOL.md, "Desktop approval"):
//!
//! ```text
//! {"v":1,"op":"passkey_assert","origin":"https://…","item_id":"…"}
//! -> {"approved":true} | {"approved":false,"reason":"locked"}
//! ```
//!
//! Unlocked sessions escalate to the GUI (`persona://passkey-approval`
//! event answered by the `passkey_approval_respond` command), reusing the
//! SSH approval oneshot-map pattern. A locked/absent vault answers `locked`
//! directly — the bridge treats any denial as a hard stop for the request.
//!
//! Unix-only: the socket concept does not exist on Windows, where the
//! bridge's `require` mode fails closed and `auto` falls back to the
//! gesture gate.

use crate::approval::PendingApprovals;
use crate::types::PasskeyApprovalRequest;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, Runtime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Socket filename under the agent state dir, matching the bridge's default.
pub const APPROVAL_SOCKET_NAME: &str = "passkey-approval.sock";

/// How long a popped-up approval may sit unanswered. Must stay below the
/// bridge's client-side timeout (150 s) so the desktop always answers first.
pub const APPROVAL_TIMEOUT: Duration = crate::approval::APPROVAL_TIMEOUT;

/// One line sent by the bridge (mirrors `bridge.rs` DesktopApprovalRequest).
#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
pub struct BridgeApprovalQuery {
    pub v: u8,
    pub op: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    pub origin: String,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub item_id: Option<String>,
}

/// One line answered by the desktop (mirrors `bridge.rs` DesktopApprovalResponse).
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct ApprovalDecision {
    pub approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ApprovalDecision {
    pub fn approve() -> Self {
        Self {
            approved: true,
            reason: None,
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            approved: false,
            reason: Some(reason.to_string()),
        }
    }
}

/// How the server hands a pending approval to the GUI.
///
/// Abstracted so tests can capture payloads without spinning up a Tauri
/// app (whose mock runtime poisons the test's tokio reactor).
pub trait PasskeyApprovalSink: Send + Sync + 'static {
    fn emit_request(&self, payload: &PasskeyApprovalRequest) -> anyhow::Result<()>;
}

/// Production sink: emits `persona://passkey-approval` to the frontend.
pub struct TauriApprovalSink<R: Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: Runtime> TauriApprovalSink<R> {
    pub fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: Runtime> PasskeyApprovalSink for TauriApprovalSink<R> {
    fn emit_request(&self, payload: &PasskeyApprovalRequest) -> anyhow::Result<()> {
        self.app
            .emit("persona://passkey-approval", payload)
            .map_err(|e| anyhow::anyhow!("failed to emit approval event: {e}"))
    }
}

/// Validate one bridge request line; `Err` is the decision to send back.
fn parse_query(line: &str) -> Result<BridgeApprovalQuery, ApprovalDecision> {
    let query: BridgeApprovalQuery =
        serde_json::from_str(line).map_err(|_| ApprovalDecision::deny("unsupported"))?;
    if query.v != 1 {
        return Err(ApprovalDecision::deny("unsupported"));
    }
    // passkey_list is not gated (non-sensitive): a query for it here is
    // a protocol misuse, answered as unsupported rather than approved.
    if query.op != "passkey_create" && query.op != "passkey_assert" {
        return Err(ApprovalDecision::deny("unsupported"));
    }
    Ok(query)
}

/// Socket path under the agent state dir (same rule as the bridge's default).
pub fn approval_socket_path() -> PathBuf {
    crate::commands::agent_state_dir().join(APPROVAL_SOCKET_NAME)
}

/// Bind the approval socket and serve bridge connections until shut down.
///
/// Spawned from `main` setup: it runs whether or not the vault is unlocked,
/// because locked sessions answer `locked` instead of bubbling to the GUI.
/// 关停通路：`shutdown` 收到信号（或 sender 被 drop）即退出 accept loop、
/// 清掉 socket 文件并丢弃未应答审批——工作区关掉 passkeys 开关立即生效。
pub async fn run_passkey_approval_server<R: Runtime>(
    app: tauri::AppHandle<R>,
    pending: PendingApprovals,
    service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let sink = TauriApprovalSink::new(app);
    run_passkey_approval_server_with(sink, pending, service, shutdown).await
}

/// [`run_passkey_approval_server`] with an injected sink (tests use a fake).
pub async fn run_passkey_approval_server_with<S: PasskeyApprovalSink>(
    sink: S,
    pending: PendingApprovals,
    service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let path = approval_socket_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A leftover socket from a crashed previous run would fail bind.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Only this user's processes may consult the desktop.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!("passkey approval socket listening at {}", path.display());
    serve_on(
        listener,
        Arc::new(sink),
        pending.clone(),
        service,
        APPROVAL_TIMEOUT,
        shutdown,
    )
    .await?;
    // 正常退出（收到关停信号）：socket 文件随之移除，bridge 侧 connect
    // 立即失败而不是挂在一个无人应答的端点上。
    let _ = std::fs::remove_file(&path);
    // 丢弃未应答审批：sender drop 后 bridge 侧 oneshot 收到断连 → 拒绝
    if let Ok(mut map) = pending.lock() {
        map.clear();
    }
    Ok(())
}

/// Accept loop, split out from [`run_passkey_approval_server`] so tests can
/// bind their own listener (temp dir, short timeout). Returns when the
/// shutdown signal fires (sender dropped counts as fired).
async fn serve_on<S: PasskeyApprovalSink>(
    listener: UnixListener,
    sink: Arc<S>,
    pending: PendingApprovals,
    service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>>,
    timeout: Duration,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let next_id = Arc::new(AtomicU64::new(1));
    loop {
        let (stream, _addr) = tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("passkey approval server shutting down");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!("passkey approval accept failed: {e}");
                    continue;
                }
            }
        };
        let sink = sink.clone();
        let pending = pending.clone();
        let service = service.clone();
        let next_id = next_id.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, &*sink, &pending, &service, &next_id, timeout).await
            {
                tracing::debug!("passkey approval connection ended: {e}");
            }
        });
    }
}

/// Serve one bridge connection: read a request line, answer one decision line.
///
/// Generic over the IO type so tests can drive it over an in-memory duplex
/// instead of a real Unix socket.
async fn handle_connection<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    K: PasskeyApprovalSink,
>(
    stream: S,
    sink: &K,
    pending: &PendingApprovals,
    service: &Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>>,
    next_id: &AtomicU64,
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        anyhow::bail!("bridge closed before sending a request");
    }

    let decision = match parse_query(&line) {
        Err(deny) => deny,
        Ok(query) => {
            let unlocked = {
                let guard = service.lock().await;
                guard.as_ref().map(|s| s.is_unlocked()).unwrap_or(false)
            };
            if !unlocked {
                ApprovalDecision::deny("locked")
            } else {
                ask_frontend(sink, pending, next_id, query, timeout).await
            }
        }
    };

    let writer = reader.get_mut();
    let mut answer = serde_json::to_string(&decision)?;
    answer.push('\n');
    writer.write_all(answer.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Register a oneshot, emit the GUI event, and wait out the answer or
/// timeout (mirrors `approval.rs` DesktopApprovalHandler::confirm).
async fn ask_frontend<K: PasskeyApprovalSink>(
    sink: &K,
    pending: &PendingApprovals,
    next_id: &AtomicU64,
    query: BridgeApprovalQuery,
    timeout: Duration,
) -> ApprovalDecision {
    let request_id = format!("passkey-{}", next_id.fetch_add(1, Ordering::SeqCst));
    let payload = PasskeyApprovalRequest {
        request_id: request_id.clone(),
        operation: query.op,
        rp_id: query.rp_id,
        origin: query.origin,
        user_name: query.user_name,
        item_id: query.item_id,
    };
    let (tx, rx) = tokio::sync::oneshot::channel();

    {
        let mut map = match pending.lock() {
            Ok(map) => map,
            Err(_) => return ApprovalDecision::deny("denied"),
        };
        map.insert(request_id.clone(), tx);
    }
    if let Err(e) = sink.emit_request(&payload) {
        if let Ok(mut map) = pending.lock() {
            map.remove(&request_id);
        }
        tracing::warn!("failed to emit passkey approval event: {e}");
        return ApprovalDecision::deny("denied");
    }

    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(true)) => ApprovalDecision::approve(),
        // explicit deny, dropped responder (app teardown) — both deny
        Ok(Ok(false)) | Ok(Err(_)) => ApprovalDecision::deny("denied"),
        Err(_elapsed) => {
            if let Ok(mut map) = pending.lock() {
                map.remove(&request_id);
            }
            tracing::warn!("passkey approval {request_id} timed out; denying");
            ApprovalDecision::deny("timeout")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::resolve_from_map;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// Payloads the fake sink "emitted", serialized as sent to the frontend.
    type CapturedPayloads = Arc<StdMutex<Vec<String>>>;

    /// Test sink: captures emitted payloads instead of talking to a GUI.
    ///
    /// This sidesteps `tauri::test::mock_app` entirely — its mock runtime
    /// poisons the test's tokio reactor (any socket/duplex IO after creating
    /// it never wakes), so no tauri app is spun up in these tests. The emit
    /// path itself is tauri framework surface, same as the SSH approval's.
    #[derive(Clone)]
    struct FakeSink {
        payloads: CapturedPayloads,
    }

    impl PasskeyApprovalSink for FakeSink {
        fn emit_request(&self, payload: &PasskeyApprovalRequest) -> anyhow::Result<()> {
            self.payloads
                .lock()
                .unwrap()
                .push(serde_json::to_string(payload).unwrap());
            Ok(())
        }
    }

    /// Drive one connection through an in-memory duplex: request line in,
    /// answer line out (bounded so a broken server cannot hang the test).
    async fn ask_handle(io: &mut DuplexStream, line: &str) -> String {
        let turn = async {
            io.write_all(line.as_bytes()).await.unwrap();
            let mut answer = Vec::new();
            // read until EOF (handle_connection drops its side after answering)
            io.read_to_end(&mut answer).await.unwrap();
            String::from_utf8(answer).unwrap()
        };
        tokio::time::timeout(Duration::from_secs(3), turn)
            .await
            .unwrap_or_else(|_| panic!("server did not answer within 3s"))
    }

    /// Full server side of one connection over a duplex pair.
    async fn serve_one(
        sink: FakeSink,
        pending: PendingApprovals,
        service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>>,
        io: DuplexStream,
        timeout: Duration,
    ) {
        let next_id = AtomicU64::new(1);
        let _ = handle_connection(io, &sink, &pending, &service, &next_id, timeout).await;
        // dropping io closes the client's read side
    }

    /// One full duplex round trip; returns the answer, captured payloads and
    /// the pending map for assertions.
    async fn roundtrip(
        service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>>,
        timeout: Duration,
        request_line: &str,
    ) -> (String, CapturedPayloads, PendingApprovals) {
        let sink = FakeSink {
            payloads: Arc::new(StdMutex::new(Vec::new())),
        };
        let payloads = sink.payloads.clone();
        let pending: PendingApprovals = Arc::new(StdMutex::new(HashMap::new()));
        let (mut client, server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(serve_one(sink, pending.clone(), service, server, timeout));
        let answer = ask_handle(&mut client, request_line).await;
        server_task.await.unwrap();
        (answer, payloads, pending)
    }

    /// Unlocked PersonaService backed by a throwaway database.
    async fn unlocked_service() -> persona_core::PersonaService {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = persona_core::storage::Database::from_file(db_path.to_str().unwrap())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = persona_core::PersonaService::new(db).await.unwrap();
        service
            .initialize_user("correct horse battery staple")
            .await
            .unwrap();
        service
    }

    /// Wait for the first emitted payload and resolve it through the pending
    /// map, exactly as the `passkey_approval_respond` command would.
    async fn answer_first_payload(
        payloads: CapturedPayloads,
        pending: PendingApprovals,
        allow: bool,
    ) -> serde_json::Value {
        loop {
            let payload = {
                let payloads = payloads.lock().unwrap();
                payloads.first().cloned()
            };
            let payload: serde_json::Value = match payload {
                Some(json) => serde_json::from_str(&json).unwrap(),
                None => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            };
            let request_id = payload["request_id"].as_str().unwrap().to_string();
            assert!(
                resolve_from_map(&pending, &request_id, allow),
                "request must be pending when the event fires"
            );
            return payload;
        }
    }

    #[test]
    fn parse_query_rejects_bad_versions_and_ops() {
        let good = r#"{"v":1,"op":"passkey_assert","origin":"https://github.com"}"#;
        assert!(parse_query(good).is_ok());

        assert_eq!(
            parse_query("not json"),
            Err(ApprovalDecision::deny("unsupported"))
        );
        assert_eq!(
            parse_query(r#"{"v":2,"op":"passkey_assert","origin":"https://x"}"#),
            Err(ApprovalDecision::deny("unsupported"))
        );
        // passkey_list is not gated — a query for it is a protocol misuse.
        assert_eq!(
            parse_query(r#"{"v":1,"op":"passkey_list","origin":"https://x"}"#),
            Err(ApprovalDecision::deny("unsupported"))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn locked_service_answers_locked_without_bubbling_to_gui() {
        let service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (answer, payloads, pending) = roundtrip(
            service,
            Duration::from_secs(5),
            concat!(
                r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#,
                "\n"
            ),
        )
        .await;

        assert_eq!(answer.trim(), r#"{"approved":false,"reason":"locked"}"#);
        assert!(
            payloads.lock().unwrap().is_empty(),
            "locked vault must not pop the GUI"
        );
        assert!(
            pending.lock().unwrap().is_empty(),
            "locked vault must not register pending approvals"
        );
    }

    /// End-to-end over a real Unix socket: serve_on's accept loop hands
    /// connections to handle_connection, answers each client, and survives
    /// a client that hangs up without sending anything. This module never
    /// creates a mock app, so the tokio reactor stays healthy for socket IO.
    #[tokio::test(flavor = "multi_thread")]
    async fn serve_on_accepts_real_sockets_and_survives_silent_clients() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("serve-on.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        let service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let pending: PendingApprovals = Arc::new(StdMutex::new(HashMap::new()));
        let sink = FakeSink {
            payloads: Arc::new(StdMutex::new(Vec::new())),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_on(
            listener,
            Arc::new(sink),
            pending,
            service,
            Duration::from_secs(5),
            shutdown_rx,
        ));

        // A silent client: connect, send nothing, hang up.
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::UnixStream::connect(&sock_path),
        )
        .await
        .expect("connect 1")
        .unwrap();

        // A real query still gets answered afterwards.
        let mut client = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::UnixStream::connect(&sock_path),
        )
        .await
        .expect("connect 2")
        .unwrap();
        client
            .write_all(
                concat!(
                    r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#,
                    "\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut answer))
            .await
            .expect("server answered in time")
            .unwrap();
        assert_eq!(
            String::from_utf8(answer).unwrap().trim(),
            r#"{"approved":false,"reason":"locked"}"#,
            "locked vault denies over the real socket"
        );

        // shutdown 信号 → accept loop 优雅退出（join 完成）
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("serve_on exits after the shutdown signal")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn frontend_allow_reaches_the_bridge() {
        let service = Arc::new(tokio::sync::Mutex::new(Some(unlocked_service().await)));
        let sink = FakeSink {
            payloads: Arc::new(StdMutex::new(Vec::new())),
        };
        let payloads = sink.payloads.clone();
        let pending: PendingApprovals = Arc::new(StdMutex::new(HashMap::new()));
        let (mut client, server) = tokio::io::duplex(1024);

        let responder = {
            let payloads = payloads.clone();
            let pending = pending.clone();
            tokio::spawn(answer_first_payload(payloads, pending, true))
        };
        let server_task = tokio::spawn(serve_one(
            sink,
            pending,
            service,
            server,
            Duration::from_secs(5),
        ));

        let answer = ask_handle(
            &mut client,
            concat!(
                r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#,
                "\n"
            ),
        )
        .await;
        let payload = responder.await.unwrap();
        server_task.await.unwrap();
        assert_eq!(payload["request_id"], "passkey-1");
        assert_eq!(payload["operation"], "passkey_assert");
        assert_eq!(payload["origin"], "https://github.com");
        assert_eq!(payload["item_id"], "abc");

        assert_eq!(answer.trim(), "{\"approved\":true}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn frontend_deny_is_forwarded_with_reason() {
        let service = Arc::new(tokio::sync::Mutex::new(Some(unlocked_service().await)));
        let sink = FakeSink {
            payloads: Arc::new(StdMutex::new(Vec::new())),
        };
        let payloads = sink.payloads.clone();
        let pending: PendingApprovals = Arc::new(StdMutex::new(HashMap::new()));
        let (mut client, server) = tokio::io::duplex(1024);

        let responder = {
            let payloads = payloads.clone();
            let pending = pending.clone();
            tokio::spawn(answer_first_payload(payloads, pending, false))
        };
        let server_task = tokio::spawn(serve_one(
            sink,
            pending,
            service,
            server,
            Duration::from_secs(5),
        ));

        let answer = ask_handle(
            &mut client,
            concat!(r#"{"v":1,"op":"passkey_create","origin":"https://example.com","rp_id":"example.com","user_name":"alice"}"#, "\n"),
        )
        .await;
        let payload = responder.await.unwrap();
        server_task.await.unwrap();
        assert_eq!(payload["operation"], "passkey_create");
        assert_eq!(payload["rp_id"], "example.com");

        assert_eq!(answer.trim(), r#"{"approved":false,"reason":"denied"}"#);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unanswered_requests_deny_after_timeout() {
        let service = Arc::new(tokio::sync::Mutex::new(Some(unlocked_service().await)));
        let (answer, payloads, pending) = roundtrip(
            service,
            Duration::from_millis(80),
            concat!(
                r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#,
                "\n"
            ),
        )
        .await;

        assert_eq!(answer.trim(), r#"{"approved":false,"reason":"timeout"}"#);
        assert!(
            pending.lock().unwrap().is_empty(),
            "timed-out request must be removed from the map"
        );
        assert_eq!(
            payloads.lock().unwrap().len(),
            1,
            "the GUI was asked exactly once"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_lines_are_answered_unsupported() {
        let service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (answer, _payloads, _pending) =
            roundtrip(service, Duration::from_secs(5), "not json\n").await;
        assert_eq!(
            answer.trim(),
            r#"{"approved":false,"reason":"unsupported"}"#
        );

        // zero-byte write: connection closed with no answer (read hits EOF)
        let service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let sink = FakeSink {
            payloads: Arc::new(StdMutex::new(Vec::new())),
        };
        let pending: PendingApprovals = Arc::new(StdMutex::new(HashMap::new()));
        let (mut client, server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(serve_one(
            sink,
            pending,
            service,
            server,
            Duration::from_secs(5),
        ));
        client.write_all(b"").await.unwrap();
        client.shutdown().await.unwrap();
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.unwrap();
        server_task.await.unwrap();
        assert!(
            answer.is_empty(),
            "empty request must be closed, not answered"
        );
    }

    /// emit 失败（GUI 通道断开）→ 回复 deny 且 pending map 不留悬挂条目
    ///（ask_frontend 的 emit-request 错误臂）。
    #[tokio::test]
    async fn failing_sink_denies_and_cleans_pending() {
        struct BrokenSink;

        impl PasskeyApprovalSink for BrokenSink {
            fn emit_request(&self, _payload: &PasskeyApprovalRequest) -> anyhow::Result<()> {
                Err(anyhow::anyhow!("gui channel gone"))
            }
        }

        let service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>> =
            Arc::new(tokio::sync::Mutex::new(Some(unlocked_service().await)));
        let pending: PendingApprovals = Arc::new(StdMutex::new(HashMap::new()));
        let (mut client, server) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            client
                .write_all(concat!(r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#, "\n").as_bytes())
                .await
                .unwrap();
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).await.unwrap();
            String::from_utf8(answer).unwrap()
        });
        let next_id = AtomicU64::new(1);
        let _ = handle_connection(
            server,
            &BrokenSink,
            &pending,
            &service,
            &next_id,
            Duration::from_secs(5),
        )
        .await;
        let answer = tokio::time::timeout(Duration::from_secs(3), writer)
            .await
            .expect("server answered in time")
            .unwrap();

        let decision: serde_json::Value =
            serde_json::from_str(answer.trim()).expect("decision line");
        assert_eq!(decision["approved"], serde_json::Value::Bool(false));
        assert_eq!(decision["reason"], "denied");
        assert!(
            pending.lock().unwrap().is_empty(),
            "failed emit must remove the pending entry"
        );
    }

    /// run_passkey_approval_server_with 全链路：bind 到 sandbox 状态目录、
    /// 设置 0600 权限、清掉遗留 socket，真实连接得到 locked 应答。
    #[tokio::test]
    async fn approval_server_binds_sandbox_socket_with_owner_permissions() {
        let dir = tempfile::tempdir().unwrap();
        // 与 agent 测试同一把进程级锁：env 是全局的，并行测试会互相改道。
        let _guard = crate::command_layer_tests::StateDirGuard::sandbox(&dir);

        let service: Arc<tokio::sync::Mutex<Option<persona_core::PersonaService>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let pending: PendingApprovals = Arc::new(StdMutex::new(HashMap::new()));

        // 预先放一个遗留 socket 文件：server 必须清掉再 bind。
        let stale = dir.path().join(APPROVAL_SOCKET_NAME);
        std::fs::write(&stale, b"stale").unwrap();

        let sink = FakeSink {
            payloads: Arc::new(StdMutex::new(Vec::new())),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(run_passkey_approval_server_with(
            sink,
            pending,
            service,
            shutdown_rx,
        ));

        // 等待 socket 就绪并完成一次 locked 应答。
        let answer = {
            let mut client = None;
            for _ in 0..100 {
                // 尚未就绪（连接拒绝/超时）时让出调度权后重试
                if let Ok(Ok(c)) = tokio::time::timeout(
                    Duration::from_millis(50),
                    tokio::net::UnixStream::connect(dir.path().join(APPROVAL_SOCKET_NAME)),
                )
                .await
                {
                    client = Some(c);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let mut client = client.expect("socket became connectable");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            client
                .write_all(concat!(
                    r#"{"v":1,"op":"passkey_assert","origin":"https://github.com","item_id":"abc"}"#,
                    "\n"
                )
                .as_bytes())
                .await
                .unwrap();
            let mut buf = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut buf))
                .await
                .expect("answer in time")
                .unwrap();
            String::from_utf8(buf).unwrap()
        };

        assert_eq!(
            answer.trim(),
            r#"{"approved":false,"reason":"locked"}"#,
            "locked service answers locked"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(APPROVAL_SOCKET_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "socket must be owner-only");
        }

        // 优雅关停：信号 → server 退出 + socket 文件移除（bridge 侧 connect
        // 立即失败而不是挂在无人应答的端点上）
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("server exits after the shutdown signal")
            .unwrap()
            .unwrap();
        assert!(
            !dir.path().join(APPROVAL_SOCKET_NAME).exists(),
            "socket file must be removed on shutdown"
        );
    }
}
