//! HTTP client orchestration for SRP device authentication (feature `remote-auth`):
//! wires the SRP-6a math from [`super::srp`] to the three
//! `/api/v1/auth/*` endpoints of persona-server. The authoritative wire
//! contract is defined in `server/src/api/auth.rs`: base64 STANDARD, the
//! error envelope `{"error":{"code","message",...}}`, and the 423 locked
//! account status.
//!
//! Division of labor with the mock trait in [`super::remote`] (the UI seam):
//! the mock's two-step shape (begin/finalize exchanging proof strings) cannot
//! carry real SRP's state flow — computing M1 needs the password, and `a_priv`
//! must stay with a single holder from A generation through M2 verification
//! without being split apart at a trait boundary. The real client is
//! therefore its own type: the login session state is held explicitly by
//! [`PendingRemoteLogin`] (including the transport handle), which `finish`
//! consumes. A future OPAQUE migration (E2EE_SYNC_DESIGN DR-2) replaces exactly
//! this file's orchestration; the math layer and caller semantics stay put.
//!
//! fail-closed posture: any non-2xx becomes
//! [`PersonaError::AuthenticationFailed`], carrying only the HTTP status and a
//! server error digest — unregistered devices and failed handshakes are already
//! the same 401 on the server side, so the client layers on no guesses; 423
//! (locked account) is called out separately so the upper layer can decide
//! whether to suggest waiting. When the server proof M2 fails verification, the
//! token is **not** delivered upward (verify before use; the client-side
//! counterpart of the server VerifyResponse field comments).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::{PersonaError, Result};

use super::srp::{register_verifier, SrpClientLogin, SrpClientProof};

/// POST /api/v1/auth/challenge response (only the needed fields).
#[derive(serde::Deserialize)]
struct ChallengeWire {
    session_id: String,
    salt: String,
    server_public: String,
}

/// POST /api/v1/auth/verify response.
#[derive(serde::Deserialize)]
struct VerifyWire {
    server_proof: String,
    token: String,
    expires_in_secs: u64,
}

/// SRP client for the persona-server `/api/v1/auth/*` endpoints. No internal
/// mutable state: the login session state lives in [`PendingRemoteLogin`], and
/// the caller holds the token.
#[derive(Clone, Debug)]
pub struct HttpRemoteAuthProvider {
    base_url: String,
    http: reqwest::Client,
}

impl HttpRemoteAuthProvider {
    /// `base_url` looks like `http://127.0.0.1:8080` (a trailing `/` is
    /// tolerated). Request timeout is 30s: the handshake includes the Argon2id
    /// pre-hash (19 MiB), far below the backup chain's 300s, but it still has
    /// to cover slow server round trips.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("HTTP client init failed: {e}"))
            })?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Bootstrap registration: generates salt/verifier and
    /// `POST /auth/register`. Requires an existing Bearer (the bootstrap
    /// chain token) — server-side registration is the bootstrap entry into the
    /// authentication system, not an unauthenticated operation.
    pub async fn register_device(
        &self,
        bearer: &str,
        device_name: &str,
        password: &str,
    ) -> Result<()> {
        let reg = register_verifier(device_name, password)?;
        let resp = self
            .post("/auth/register", Some(bearer))
            .json(&serde_json::json!({
                "device_name": device_name,
                "salt": B64.encode(&reg.salt),
                "verifier": B64.encode(&reg.verifier),
            }))
            .send()
            .await
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("register request failed: {e}"))
            })?;
        ensure_success(resp, "register").await.map(|_| ())
    }

    /// Login step one: generates the ephemeral key pair locally, requests the
    /// challenge with public value `A`, and the server replies with salt and
    /// `B`. The server-side handshake cache lasts 120s and is one-shot — the
    /// returned [`PendingRemoteLogin`] is bound to that session, so `finish`
    /// must complete within the window.
    pub async fn begin_login(&self, device_name: &str) -> Result<PendingRemoteLogin> {
        let login = SrpClientLogin::new()?;
        let resp = self
            .post("/auth/challenge", None)
            .json(&serde_json::json!({
                "device_name": device_name,
                "client_public": B64.encode(login.public_ephemeral()),
            }))
            .send()
            .await
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("challenge request failed: {e}"))
            })?;
        let resp = ensure_success(resp, "challenge").await?;
        let wire: ChallengeWire = resp
            .json()
            .await
            .map_err(|_| malformed_wire("challenge response"))?;
        Ok(PendingRemoteLogin {
            provider: self.clone(),
            device_name: device_name.to_string(),
            login,
            session_id: wire.session_id,
            salt_b64: wire.salt,
            server_public_b64: wire.server_public,
        })
    }

    /// Unified request construction (path hangs off `/api/v1`; `bearer` is only set on the register step).
    fn post(&self, path: &str, bearer: Option<&str>) -> reqwest::RequestBuilder {
        let builder = self.http.post(format!("{}/api/v1{}", self.base_url, path));
        match bearer {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }
}

/// In-progress SRP login session: `finish` consumes self (`SrpClientLogin` is
/// one-shot), state is cleared on success; on timeout or failure just drop and
/// rebuild (the server-side handshake cache expires along with it).
#[derive(Debug)]
pub struct PendingRemoteLogin {
    provider: HttpRemoteAuthProvider,
    device_name: String,
    login: SrpClientLogin,
    session_id: String,
    salt_b64: String,
    server_public_b64: String,
}

impl PendingRemoteLogin {
    /// Login completion step: password -> SRP private key x (Argon2id
    /// pre-hash) -> M1 -> `POST /verify` -> verify the server proof M2 ->
    /// deliver the short-lived token and session key. The order cannot be
    /// swapped: the token is trustworthy only after M2 verification passes.
    pub async fn finish(self, password: &str) -> Result<RemoteLoginOutcome> {
        let salt = B64
            .decode(&self.salt_b64)
            .map_err(|_| malformed_wire("salt"))?;
        let server_public = B64
            .decode(&self.server_public_b64)
            .map_err(|_| malformed_wire("server_public"))?;
        let proof: SrpClientProof =
            self.login
                .process(&self.device_name, password, &salt, &server_public)?;
        let resp = self
            .provider
            .post("/auth/verify", None)
            .json(&serde_json::json!({
                "session_id": self.session_id,
                "client_proof": B64.encode(proof.client_proof()),
            }))
            .send()
            .await
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("verify request failed: {e}"))
            })?;
        let resp = ensure_success(resp, "verify").await?;
        let wire: VerifyWire = resp
            .json()
            .await
            .map_err(|_| malformed_wire("verify response"))?;
        let server_proof = B64
            .decode(&wire.server_proof)
            .map_err(|_| malformed_wire("server_proof"))?;
        // M2 verification failed (MITM / server confusion) — premaster is out of reach, token not delivered
        let session_key = proof.verify_server(&server_proof)?;
        let fingerprint = hex::encode(Sha256::digest(&session_key));
        Ok(RemoteLoginOutcome {
            token: wire.token,
            expires_in_secs: wire.expires_in_secs,
            session_key_fingerprint: fingerprint,
            session_key,
        })
    }
}

/// Login success artifacts: a short-lived Bearer token plus a session fingerprint each side can derive.
#[derive(Debug)]
pub struct RemoteLoginOutcome {
    /// Short-lived Bearer token (server TTL 15min); the caller holds it and re-logs in before expiry.
    pub token: String,
    /// Remaining validity of the token in seconds, from the server response.
    pub expires_in_secs: u64,
    /// SHA-256(premaster) hex — client and server independently compute it
    /// over the same premaster, so it works as a session binding check (the
    /// concrete realization of the mock trait's `session_key_fingerprint`
    /// semantics).
    pub session_key_fingerprint: String,
    /// Raw premaster bytes (4096-bit group = 512B); use when the upper layer
    /// needs the session key. If not needed, discard it — the fingerprint is
    /// enough.
    pub session_key: Vec<u8>,
}

/// Any non-2xx is uniformly converted to
/// [`PersonaError::AuthenticationFailed`]: 423 calls out the locked account
/// explicitly, the others carry the status code and a digest of the server's
/// error.message (omitted when absent). On success the Response is returned
/// unchanged so the caller can continue decoding JSON.
async fn ensure_success(resp: reqwest::Response, step: &str) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        });
    if status.as_u16() == 423 {
        return Err(PersonaError::AuthenticationFailed(
            "remote auth failed: device locked (HTTP 423); retry later".to_string(),
        )
        .into());
    }
    match detail {
        Some(message) => Err(PersonaError::AuthenticationFailed(format!(
            "remote auth {step} failed (HTTP {status}): {message}"
        ))
        .into()),
        None => Err(PersonaError::AuthenticationFailed(format!(
            "remote auth {step} failed (HTTP {status})"
        ))
        .into()),
    }
}

fn malformed_wire(field: &str) -> PersonaError {
    PersonaError::AuthenticationFailed(format!("remote auth: malformed wire field {field:?}"))
}

#[cfg(all(test, feature = "remote-auth"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::super::srp::{server_challenge, server_verify, SRP_SALT_LEN};

    /// One request received by the mock server (path + raw headers + JSON body).
    struct CapturedRequest {
        path: String,
        headers: String,
        body: serde_json::Value,
    }

    /// Hand-written HTTP mock: replays a fixed script over real TCP. core's
    /// dev-deps have no ready-made HTTP mock (wiremock and friends), and reqwest
    /// is entirely adequate against hand-written TCP responses — one request per
    /// connection, then a `Connection: close` reply per handler. The handler
    /// returns (HTTP status code, JSON body string); status 0 = no reply, just
    /// disconnect (simulating a server that drops the connection mid-request).
    type Handler = Arc<dyn Fn(CapturedRequest) -> (u16, String) + Send + Sync>;

    /// The SRP session held by the mock server between challenge and verify: (b_priv, a_pub).
    type SrpServerState = Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>>;

    /// Starts a local mock server and returns the base_url
    /// (`http://127.0.0.1:<port>`). The accept loop rides on a background task
    /// of the multi_thread runtime and is discarded together with the runtime
    /// when the test ends (the listener is never explicitly closed; the OS
    /// reclaims the port).
    async fn spawn_mock(handler: Handler) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Some(req) = read_request(&mut stream).await {
                        let (status, body) = handler(req);
                        // Convention: status 0 — no response, just disconnect (request-send failure path)
                        if status == 0 {
                            return;
                        }
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {body}",
                            body.len(),
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                    let _ = stream.flush().await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// Read one complete HTTP request (headers + Content-Length-delimited body).
    /// reqwest uses one connection per `Connection: close` request, so a single request suffices.
    async fn read_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let header_end;
        loop {
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let path = headers.split_whitespace().nth(1)?.to_string();
        let content_length: usize = headers
            .to_ascii_lowercase()
            .lines()
            .find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let body = serde_json::from_str(&String::from_utf8_lossy(&buf[header_end..]))
            .unwrap_or(serde_json::Value::Null);
        Some(CapturedRequest {
            path,
            headers,
            body,
        })
    }

    /// (salt, verifier) of a registered device, for the mock server to play the SRP side.
    fn fixture_verifier(password: &str) -> (Vec<u8>, Vec<u8>) {
        let reg = register_verifier("laptop", password).unwrap();
        (reg.salt, reg.verifier)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn register_posts_verifier_with_bearer_and_tolerates_trailing_slash() {
        let captured: std::sync::Arc<Mutex<Vec<CapturedRequest>>> = Default::default();
        let sink = captured.clone();
        // base_url trailing `/` tolerance: the mock address deliberately carries a slash
        let base = format!(
            "{}/",
            spawn_mock(Arc::new(move |req| {
                sink.lock().unwrap().push(req);
                (200, "{}".to_string())
            }))
            .await
        );
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        provider
            .register_device("bootstrap-tok", "laptop", "pw")
            .await
            .unwrap();

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        // Bootstrap registration must carry an existing Bearer (registration is the entry into the authentication system, not an unauthenticated operation)
        assert!(
            req.headers.contains("authorization: Bearer bootstrap-tok"),
            "missing bearer: {}",
            req.headers
        );
        assert_eq!(req.path, "/api/v1/auth/register");
        assert_eq!(req.body["device_name"], "laptop");
        // salt/verifier are both raw bytes encoded as base64 STANDARD
        assert_eq!(
            B64.decode(req.body["salt"].as_str().unwrap())
                .unwrap()
                .len(),
            SRP_SALT_LEN
        );
        assert!(!B64
            .decode(req.body["verifier"].as_str().unwrap())
            .unwrap()
            .is_empty());
    }

    /// Any non-2xx is uniformly converted to AuthenticationFailed, with the
    /// step name, status code, and a digest of the server's error.message
    /// (the client-side view of the wire contract).
    #[tokio::test(flavor = "multi_thread")]
    async fn http_error_surfaces_step_status_and_server_message() {
        let base = spawn_mock(Arc::new(|_req| {
            (
                401,
                r#"{"error":{"code":"unknown_device","message":"no such device"}}"#.to_string(),
            )
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("register"), "{msg}");
        assert!(msg.contains("HTTP 401"), "{msg}");
        assert!(msg.contains("no such device"), "{msg}");
    }

    /// 423 (locked account) is called out separately for the upper layer to decide whether to suggest waiting — the server message is not passed through.
    #[tokio::test(flavor = "multi_thread")]
    async fn device_lock_is_called_out_on_423() {
        let base = spawn_mock(Arc::new(|_req| {
            (423, r#"{"error":{"message":"locked"}}"#.to_string())
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("device locked (HTTP 423)"), "{msg}");
        // The fixed locked-account wording does not mix in the server digest
        assert!(!msg.contains("locked\""), "{msg}");
    }

    /// When the server response is not a JSON envelope (e.g. a reverse-proxy 502 HTML page), the digest is omitted and only the status remains.
    #[tokio::test(flavor = "multi_thread")]
    async fn non_json_error_body_omits_detail() {
        let base = spawn_mock(Arc::new(|_req| {
            (502, "<html>bad gateway</html>".to_string())
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("HTTP 502"), "{msg}");
        assert!(!msg.contains("bad gateway"), "{msg}");
    }

    /// Challenge response missing fields / bad JSON: fail-closed, never enters finish.
    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_challenge_response_is_rejected() {
        let base = spawn_mock(Arc::new(|_req| {
            (200, "{\"session_id\":\"s1\"}".to_string())
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider.begin_login("laptop").await.unwrap_err();
        assert!(err.to_string().contains("malformed wire field"), "{err}");
    }

    /// Illegal B (valid base64, but B mod N = 0 — the only shape the SRP layer
    /// rejects): the orchestration layer passes it through unchanged as
    /// AuthenticationFailed (guards against a malicious server downgrade).
    #[tokio::test(flavor = "multi_thread")]
    async fn illegal_server_public_value_is_rejected() {
        let (salt, _verifier) = fixture_verifier("pw");
        let illegal_b = super::super::srp::srp_group().n.to_bytes_be();
        let base = spawn_mock(Arc::new(move |_req| {
            (
                200,
                serde_json::json!({
                    "session_id": "s1",
                    "salt": B64.encode(&salt),
                    "server_public": B64.encode(&illegal_b),
                })
                .to_string(),
            )
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish("pw").await.unwrap_err();
        assert!(
            err.to_string().contains("rejected server public value"),
            "{err}"
        );
    }

    /// Full flow (the mock server actually runs the SRP server side): token
    /// delivery + fingerprint = sha256(session_key) hex + premaster 512B
    /// (4096-bit group).
    #[tokio::test(flavor = "multi_thread")]
    async fn full_login_delivers_token_with_matching_fingerprint() {
        use sha2::Digest as _;

        let password = "correct horse battery staple";
        let (salt, verifier) = fixture_verifier(password);
        // Server session between challenge and verify: (b_priv, a_pub)
        let state: SrpServerState = Default::default();
        let srv = state.clone();
        let base = spawn_mock(Arc::new(move |req| {
            let mut st = srv.lock().unwrap();
            match req.path.as_str() {
                "/api/v1/auth/challenge" => {
                    let a = B64
                        .decode(req.body["client_public"].as_str().unwrap())
                        .unwrap();
                    let ch = server_challenge(&verifier).unwrap();
                    *st = Some((ch.b_priv, a));
                    (
                        200,
                        serde_json::json!({
                            "session_id": "sess-1",
                            "salt": B64.encode(&salt),
                            "server_public": B64.encode(ch.b_pub),
                        })
                        .to_string(),
                    )
                }
                "/api/v1/auth/verify" => {
                    let (b_priv, a) = st.take().unwrap();
                    assert_eq!(req.body["session_id"], "sess-1");
                    let m1 = B64
                        .decode(req.body["client_proof"].as_str().unwrap())
                        .unwrap();
                    match server_verify(&b_priv, &verifier, &a, &m1) {
                        Ok(out) => (
                            200,
                            serde_json::json!({
                                "server_proof": B64.encode(out.server_proof),
                                "token": "tok-1",
                                "expires_in_secs": 900,
                            })
                            .to_string(),
                        ),
                        Err(_) => (
                            401,
                            r#"{"error":{"message":"client proof mismatch"}}"#.to_string(),
                        ),
                    }
                }
                other => panic!("unexpected path {other}"),
            }
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let outcome = provider
            .begin_login("laptop")
            .await
            .unwrap()
            .finish(password)
            .await
            .unwrap();

        assert_eq!(outcome.token, "tok-1");
        assert_eq!(outcome.expires_in_secs, 900);
        assert_eq!(outcome.session_key.len(), 512);
        assert_eq!(
            outcome.session_key_fingerprint,
            hex::encode(Sha256::digest(&outcome.session_key))
        );
    }

    /// Tampered M2 (MITM / server confusion): the core security semantics — token not delivered.
    #[tokio::test(flavor = "multi_thread")]
    async fn tampered_server_proof_withholds_token() {
        let password = "another stable passphrase";
        let (salt, verifier) = fixture_verifier(password);
        let state: SrpServerState = Default::default();
        let srv = state.clone();
        let base = spawn_mock(Arc::new(move |req| {
            let mut st = srv.lock().unwrap();
            match req.path.as_str() {
                "/api/v1/auth/challenge" => {
                    let a = B64
                        .decode(req.body["client_public"].as_str().unwrap())
                        .unwrap();
                    let ch = server_challenge(&verifier).unwrap();
                    *st = Some((ch.b_priv, a));
                    (
                        200,
                        serde_json::json!({
                            "session_id": "sess-1",
                            "salt": B64.encode(&salt),
                            "server_public": B64.encode(ch.b_pub),
                        })
                        .to_string(),
                    )
                }
                "/api/v1/auth/verify" => {
                    let (b_priv, a) = st.take().unwrap();
                    let m1 = B64
                        .decode(req.body["client_proof"].as_str().unwrap())
                        .unwrap();
                    let mut out = server_verify(&b_priv, &verifier, &a, &m1).unwrap();
                    out.server_proof[0] ^= 0xFF; // A single byte flip fails verification
                    (
                        200,
                        serde_json::json!({
                            "server_proof": B64.encode(out.server_proof),
                            "token": "must-not-be-delivered",
                            "expires_in_secs": 900,
                        })
                        .to_string(),
                    )
                }
                other => panic!("unexpected path {other}"),
            }
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish(password).await.unwrap_err();
        assert!(err.to_string().contains("server proof mismatch"), "{err}");
    }

    /// The salt issued by the challenge is not valid base64: fail-closed on the finish side.
    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_salt_b64_is_rejected() {
        let base = spawn_mock(Arc::new(|_req| {
            (
                200,
                serde_json::json!({
                    "session_id": "s1",
                    "salt": "!!not-base64!!",
                    "server_public": B64.encode([0x02u8; 8]),
                })
                .to_string(),
            )
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish("pw").await.unwrap_err();
        assert!(
            err.to_string().contains(r#"malformed wire field "salt""#),
            "{err}"
        );
    }

    /// Connection refused: each step's send failure carries an
    /// AuthenticationFailed with the step name (fail-closed, errors are never
    /// swallowed). register and challenge point at an unlistened port; verify
    /// is triggered by the "challenge replies normally, verify drops the
    /// connection" mock.
    #[tokio::test(flavor = "multi_thread")]
    async fn connection_failures_surface_with_step_names() {
        // Unlistened port: dropped right after bind, so there is necessarily no service on the port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);
        let provider = HttpRemoteAuthProvider::new(format!("http://{dead_addr}")).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("register request failed"), "{err}");

        let err = provider.begin_login("laptop").await.unwrap_err();
        assert!(
            err.to_string().contains("challenge request failed"),
            "{err}"
        );

        // verify step: challenge replies normally, the verify connection is dropped by the server outright
        let password = "pw-verify-drop";
        let (salt, verifier) = fixture_verifier(password);
        let base = spawn_mock(Arc::new(move |req| match req.path.as_str() {
            "/api/v1/auth/challenge" => (
                200,
                serde_json::json!({
                    "session_id": "sess-1",
                    "salt": B64.encode(&salt),
                    "server_public": B64.encode(server_challenge(&verifier).unwrap().b_pub),
                })
                .to_string(),
            ),
            _ => (0, String::new()),
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();
        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish(password).await.unwrap_err();
        assert!(err.to_string().contains("verify request failed"), "{err}");
    }

    /// Verify response missing fields: M1 is already sent out and the token still cannot be obtained (fail-closed).
    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_verify_response_is_rejected() {
        let password = "pw-for-wire";
        let (salt, verifier) = fixture_verifier(password);
        let state: SrpServerState = Default::default();
        let srv = state.clone();
        let base = spawn_mock(Arc::new(move |req| {
            let mut st = srv.lock().unwrap();
            match req.path.as_str() {
                "/api/v1/auth/challenge" => {
                    let a = B64
                        .decode(req.body["client_public"].as_str().unwrap())
                        .unwrap();
                    let ch = server_challenge(&verifier).unwrap();
                    *st = Some((ch.b_priv, a));
                    (
                        200,
                        serde_json::json!({
                            "session_id": "sess-1",
                            "salt": B64.encode(&salt),
                            "server_public": B64.encode(ch.b_pub),
                        })
                        .to_string(),
                    )
                }
                // M1 is legal but the response is missing the server_proof/token fields
                "/api/v1/auth/verify" => (200, "{}".to_string()),
                other => panic!("unexpected path {other}"),
            }
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish(password).await.unwrap_err();
        assert!(err.to_string().contains("malformed wire field"), "{err}");
    }
}
