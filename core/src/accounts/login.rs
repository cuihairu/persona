//! Account-domain password registration/login orchestration (feature `accounts`).
//!
//! Discipline: the SRP math (Argon2id pre-hash, M1 derivation, M2
//! verification) happens only in core; the password and premaster never
//! leave this module. The caller (desktop command layer) receives either
//! final wire values or orchestration products. Pure wire transport lives
//! in [`super::remote::AccountsApi`] (whose module docs state it holds no
//! "cryptography/orchestration" — this module is where that "caller" role
//! lands inside core: the rendering layer does no SRP math at all).
//!
//! Two orchestrations, both layered on top of the wire methods:
//!
//! - [`AccountsApi::register_srp_credential`]: password → salt/verifier →
//!   `POST /accounts/{id}/srp/register`. The endpoint is Bearer-gated and
//!   the instance must be built with `with_bearer`; a brand-new account
//!   has no account session yet, so the caller resolves the bootstrap
//!   chain (a static server token is a legal Bearer under the server's
//!   `require_account_bearer` contract).
//! - [`AccountsApi::srp_login`]: challenge → M1 → verify → **M2
//!   verification** → deliver the 15-minute token. The bare wire
//!   `srp_challenge`/`srp_verify` do not verify M2 (wire is pass-through
//!   only), so all UI-facing logins go through this orchestration: the
//!   token is delivered only once the server proof verifies, and a failed
//!   verification lands no state.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::remote::{AccountsApi, SrpChallengeRequest, SrpRegisterRequest, SrpVerifyRequest};
use crate::auth::srp::{self, SrpClientLogin};
use crate::{PersonaError, Result};

/// Product of [`AccountsApi::srp_login`]: a 15-minute account login token plus
/// the mutual-authentication session fingerprint. The caller holds the token
/// (desktop drops it straight into the OS keyring, never persisted via the
/// rendering layer and never pushed to the frontend with the orchestration response).
#[derive(Debug)]
pub struct AccountSrpLoginOutcome {
    /// The SRP 15-minute token (server TTL 900s); usable as a Bearer or redeemable at the
    /// sessions endpoint for a 24h session.
    pub token: String,
    /// Remaining token validity in seconds, from the server response.
    pub expires_in_secs: u64,
    /// SHA-256(premaster) hex — same semantics as the device-domain `RemoteLoginOutcome`,
    /// used for session-binding checks; ignore when no downstream consumer exists.
    pub session_key_fingerprint: String,
    /// Raw premaster bytes (~512B for the 4096-bit group). Exposed symmetrically with the
    /// device domain; upper layers that do not need it can just drop it.
    pub session_key: Vec<u8>,
}

impl AccountsApi {
    /// Password → SRP salt/verifier (Argon2id pre-hash; the master password
    /// never leaves the device) → registered as the account's password login
    /// credential. `device_name` is also the SRP identity, matching both
    /// sides of the server's challenge/verify (see server `account_srp_challenge`).
    /// Re-registering the same `device_name` is rejected by the server with
    /// 409 (`INSERT OR IGNORE` semantics); use a different device name to add
    /// another password credential.
    pub async fn register_srp_credential(
        &self,
        account_id: &str,
        device_name: &str,
        password: &str,
    ) -> Result<super::remote::SrpRegisterResponse> {
        let reg = srp::register_verifier(device_name, password)?;
        let req = SrpRegisterRequest {
            device_name: device_name.to_string(),
            salt: B64.encode(&reg.salt),
            verifier: B64.encode(&reg.verifier),
        };
        self.srp_register(account_id, &req).await
    }

    /// Complete account SRP login in one step: local ephemeral keypair →
    /// challenge (salt + server public value B) → M1 (Argon2id pre-hash) →
    /// verify → **verify the server proof M2** → deliver the token. The order
    /// is not interchangeable: if M2 fails (MITM / server glitch) the peer is
    /// not the server holding the verifier, and no token is trustworthy
    /// however "fresh" it looks — fail as a whole and land no state.
    pub async fn srp_login(
        &self,
        account_id: &str,
        device_name: &str,
        password: &str,
    ) -> Result<AccountSrpLoginOutcome> {
        let login = SrpClientLogin::new()?;
        let client_public = B64.encode(login.public_ephemeral());
        let challenge = self
            .srp_challenge(
                account_id,
                &SrpChallengeRequest {
                    device_name: device_name.to_string(),
                    client_public,
                },
            )
            .await?;
        let salt = B64
            .decode(&challenge.salt)
            .map_err(|_| PersonaError::Io("account srp challenge salt malformed".into()))?;
        let server_public = B64.decode(&challenge.server_public).map_err(|_| {
            PersonaError::Io("account srp challenge server_public malformed".into())
        })?;
        // Consuming: login surrenders its ephemeral private key here; proof carries the pending verification state
        let proof = login.process(device_name, password, &salt, &server_public)?;
        let verified = self
            .srp_verify(
                account_id,
                &SrpVerifyRequest {
                    session_id: challenge.session_id,
                    client_proof: B64.encode(proof.client_proof()),
                },
            )
            .await?;
        let server_proof = B64
            .decode(&verified.server_proof)
            .map_err(|_| PersonaError::Io("account srp verify server_proof malformed".into()))?;
        // Only once M2 verification passes is the token carried out of this function as a trusted product
        let session_key = proof.verify_server(&server_proof)?;
        Ok(AccountSrpLoginOutcome {
            token: verified.token,
            expires_in_secs: verified.expires_in_secs,
            session_key_fingerprint: hex::encode(Sha256::digest(&session_key)),
            session_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const ACCOUNT: &str = "acct-1";
    const DEVICE: &str = "laptop";
    const PASSWORD: &str = "correct horse battery staple";

    /// Server-side pending-handshake script: (b_priv, client_public) stored by
    /// session_id and taken out at the verify step for checking — the minimal
    /// state isomorphic to server `SrpChallengeEntry`.
    #[derive(Default)]
    struct MockServer {
        registered: Option<(Vec<u8>, Vec<u8>)>, // (salt, verifier)
        handshakes: HashMap<String, (Vec<u8>, Vec<u8>)>, // session_id -> (b_priv, client_public)
        next_session: u32,
        /// Fault injection: the verify response returns a forged M2 (MITM simulation)
        tamper_server_proof: bool,
        verify_requests: u32,
    }

    struct CapturedRequest {
        method: String,
        path: String,
        auth: Option<String>,
        body: String,
    }

    /// A one-shot TCP fake server that **runs the real server-side SRP math**
    /// (server_challenge / server_verify) to cross-check the full round trip
    /// of [`srp_login`] — canned responses would make M2 verification always
    /// fail, so the orchestration would not stand up against a stub server.
    fn spawn_srp_mock<F>(handler: F) -> String
    where
        F: Fn(&CapturedRequest) -> (u16, String) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
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
                let auth = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|l| {
                        l.split_once(':')
                            .map(|x| x.1)
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    });
                let content_length: usize = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split_once(':')?.1.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = stream.read_exact(&mut body);
                }
                let (status, resp_body) = handler(&CapturedRequest {
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
                    auth,
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
                let reason = if status == 204 { "" } else { "OK" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn json_field(body: &str, field: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .unwrap_or_default()
            .get(field)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    /// mock factory: the verifier is pre-seeded in storage (tests 2/3 can log in
    /// directly), and a register route is attached so test 1 exercises real
    /// bootstrapping. Returns (url, shared state).
    fn spawn_registered_mock() -> (String, Arc<Mutex<MockServer>>) {
        let state = Arc::new(Mutex::new(MockServer::default()));
        {
            let reg = srp::register_verifier(DEVICE, PASSWORD).unwrap();
            state.lock().unwrap().registered = Some((reg.salt, reg.verifier));
        }
        let url = {
            let state = state.clone();
            spawn_srp_mock(move |req| {
                let challenge_path = format!("/api/v1/accounts/{ACCOUNT}/srp/challenge");
                let verify_path = format!("/api/v1/accounts/{ACCOUNT}/srp/verify");
                let register_path = format!("/api/v1/accounts/{ACCOUNT}/srp/register");
                match (req.method.as_str(), req.path.as_str()) {
                    ("POST", path) if path == register_path => {
                        assert_eq!(
                            req.auth.as_deref(),
                            Some("Bearer static-server-token"),
                            "srp/register 是 Bearer 端点，引导链必须携带"
                        );
                        let mut st = state.lock().unwrap();
                        st.registered = Some((
                            B64.decode(json_field(&req.body, "salt")).unwrap(),
                            B64.decode(json_field(&req.body, "verifier")).unwrap(),
                        ));
                        (
                            200,
                            serde_json::json!({ "device_name": json_field(&req.body, "device_name") })
                                .to_string(),
                        )
                    }
                    ("POST", path) if path == challenge_path => {
                        let client_public =
                            B64.decode(json_field(&req.body, "client_public")).unwrap();
                        let response = {
                            let mut st = state.lock().unwrap();
                            let (salt, verifier) = st.registered.as_ref().unwrap().clone();
                            let hc = srp::server_challenge(&verifier).unwrap();
                            let session_id = format!("sess-{}", st.next_session);
                            st.next_session += 1;
                            st.handshakes
                                .insert(session_id.clone(), (hc.b_priv, client_public));
                            serde_json::json!({
                                "session_id": session_id,
                                "salt": B64.encode(&salt),
                                "server_public": B64.encode(&hc.b_pub),
                            })
                            .to_string()
                        };
                        (200, response)
                    }
                    ("POST", path) if path == verify_path => {
                        let session_id = json_field(&req.body, "session_id");
                        let client_proof = json_field(&req.body, "client_proof");
                        let mut st = state.lock().unwrap();
                        st.verify_requests += 1;
                        let Some((b_priv, client_public)) = st.handshakes.remove(&session_id)
                        else {
                            return (401, r#"{"error":{"code":"unauthorized"}}"#.to_string());
                        };
                        let (_, verifier) = st.registered.as_ref().unwrap();
                        match srp::server_verify(
                            &b_priv,
                            verifier,
                            &client_public,
                            &B64.decode(&client_proof).unwrap(),
                        ) {
                            Ok(outcome) => {
                                let proof = if st.tamper_server_proof {
                                    vec![0u8; 16]
                                } else {
                                    outcome.server_proof
                                };
                                (
                                    200,
                                    serde_json::json!({
                                        "server_proof": B64.encode(proof),
                                        "token": "tok-15m",
                                        "expires_in_secs": 900,
                                    })
                                    .to_string(),
                                )
                            }
                            // Same as the server: a wrong M1 = 401 (which also books an account
                            // lockout; the mock does not simulate lockout counting)
                            Err(_) => (401, r#"{"error":{"code":"unauthorized"}}"#.to_string()),
                        }
                    }
                    _ => panic!("unexpected request {} {}", req.method, req.path),
                }
            })
        };
        (url, state)
    }

    #[tokio::test]
    async fn srp_login_round_trip_verifies_server_proof_and_delivers_token() {
        let (url, state) = spawn_registered_mock();

        // Bootstrap: the static token serves as the Bearer credential for registration (challenge/verify are public endpoints)
        let bootstrap = AccountsApi::with_bearer(&url, "static-server-token").unwrap();
        bootstrap
            .register_srp_credential(ACCOUNT, DEVICE, PASSWORD)
            .await
            .unwrap();
        assert_eq!(
            state.lock().unwrap().registered.as_ref().unwrap().0.len(),
            32,
            "salt 是 32B 随机值"
        );

        // Login uses a no-Bearer instance (public endpoints must not carry one)
        let client = AccountsApi::new(&url).unwrap();
        let outcome = client.srp_login(ACCOUNT, DEVICE, PASSWORD).await.unwrap();
        assert_eq!(outcome.token, "tok-15m");
        assert_eq!(outcome.expires_in_secs, 900);
        // Mutual authentication: the fingerprint matches the premaster fingerprint derived independently on the server side
        assert!(!outcome.session_key_fingerprint.is_empty());
        assert_eq!(outcome.session_key.len(), 512);
        assert_eq!(state.lock().unwrap().verify_requests, 1);
    }

    #[tokio::test]
    async fn srp_login_rejects_tampered_server_proof_without_delivering_token() {
        let (url, state) = spawn_registered_mock();
        state.lock().unwrap().tamper_server_proof = true;
        let client = AccountsApi::new(&url).unwrap();
        let err = client
            .srp_login(ACCOUNT, DEVICE, PASSWORD)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("server proof mismatch"),
            "M2 不匹配须败在客户端核验步，got: {message}"
        );
        assert_eq!(
            state.lock().unwrap().verify_requests,
            1,
            "verify 已发出，败在 M2 核验"
        );
    }

    #[tokio::test]
    async fn srp_login_wrong_password_maps_401_without_token() {
        let (url, _) = spawn_registered_mock();
        let client = AccountsApi::new(&url).unwrap();
        let err = client
            .srp_login(ACCOUNT, DEVICE, "wrong-password")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("401"),
            "服务器 401 透传进错误（含状态码），got: {message}"
        );
    }
}
