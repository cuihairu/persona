//! SRP device authentication endpoints (`/api/v1/auth/*`, E2EE sync track phase 1).
//!
//! The flow (design doc E2EE_SYNC_DESIGN DR-2; all SRP math lives in core's
//! `auth::srp`, this file only does HTTP orchestration and admission):
//!
//! 1. `POST /auth/register` (**requires an existing Bearer** — a static token or an
//!    already-logged-in SRP token forms the bootstrap chain): the client generates
//!    (salt, verifier) locally and uploads them; the server stores them — the password
//!    and its Argon2 derivative never leave the machine.
//! 2. `POST /auth/challenge`: the client sends the device name + public value A; the
//!    server generates B from the verifier and caches the pending handshake for 120s.
//! 3. `POST /auth/verify`: the client sends session_id + proof M1; the server verifies
//!    and issues a short-term Bearer token (15 minutes, see [`crate::auth`]).
//!
//! Fail-closed: when the auth system is not enabled (`state.auth` is None) all three
//! endpoints 503 together — static tokens and SRP are enabled and disabled as one.
//! Lockout: 5 consecutive failures lock the device for 15 minutes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD};
use base64::Engine as _;
use persona_core::auth::srp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ApiError;
use crate::auth::{DeviceName, SrpChallengeEntry, SRP_CHALLENGE_TTL};
use crate::state::AppState;

/// SRP salt byte limit (in practice 32B; headroom is kept to reject abnormally large
/// payloads).
const MAX_SALT_BYTES: usize = 64;
/// verifier byte limit (the 4096-bit group's N is 512B, plus headroom).
const MAX_VERIFIER_BYTES: usize = 544;
/// Public value limit (client a is 64B, server B is on the order of 512B — both far
/// below this).
const MAX_PUBLIC_BYTES: usize = 768;

#[derive(Deserialize)]
pub struct RegisterRequest {
    device_name: String,
    /// The salt, base64-encoded (standard, with padding).
    salt: String,
    /// The SRP verifier, base64-encoded.
    verifier: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub device_name: String,
}

/// POST /api/v1/auth/register — bootstrap registration: requires an existing Bearer.
pub async fn register(
    State(state): State<AppState>,
    axum::Extension(operator): axum::Extension<DeviceName>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // fail-closed check: registration is likewise unavailable when the auth system is
    // not enabled (the bound name serves this purpose only)
    let _ = state.srp.as_ref().ok_or_else(ApiError::disabled)?;
    let name = validate_device_name(&req.device_name)?;
    let salt = decode_field("salt", &req.salt, MAX_SALT_BYTES)?;
    let verifier = decode_field("verifier", &req.verifier, MAX_VERIFIER_BYTES)?;

    let id = Uuid::new_v4().to_string();
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO auth_devices (id, device_name, salt, verifier) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&salt)
    .bind(&verifier)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::rejection(
            StatusCode::CONFLICT,
            format!("device {name:?} is already registered"),
        ));
    }
    tracing::info!(operator = %operator.0, device = %name, "SRP device registered");
    Ok(Json(RegisterResponse { device_name: name }))
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    device_name: String,
    /// The client's public value A, base64-encoded.
    client_public: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub session_id: String,
    /// The salt, base64-encoded.
    pub salt: String,
    /// The server's public value B, base64-encoded.
    pub server_public: String,
}

/// POST /api/v1/auth/challenge — no Bearer required (this is itself the first step of
/// login).
pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;
    let name = validate_device_name(&req.device_name)?;
    let client_public = decode_field("client_public", &req.client_public, MAX_PUBLIC_BYTES)?;

    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT salt, verifier FROM auth_devices WHERE device_name = ?",
    )
    .bind(&name)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?
    // A missing device is shaped like any other failure (401 with no distinguishing
    // information) — the registration status is not exposed
    .ok_or_else(ApiError::unauthorized)?;

    let hc = srp::server_challenge(&row.1).map_err(ApiError::internal)?;
    let session_id = Uuid::new_v4().to_string();
    srp_state.store_challenge(
        session_id.clone(),
        SrpChallengeEntry {
            device_name: name,
            verifier: row.1,
            b_priv: hc.b_priv,
            client_public,
            expires_at: std::time::Instant::now() + SRP_CHALLENGE_TTL,
        },
    );
    Ok(Json(ChallengeResponse {
        session_id,
        salt: B64.encode(row.0),
        server_public: B64.encode(hc.b_pub),
    }))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    session_id: String,
    /// The client's proof M1, base64-encoded.
    client_proof: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    /// The server's proof M2, base64-encoded (login counts as successful only once the
    /// client has verified it).
    pub server_proof: String,
    /// The short-term Bearer token (the client should use it only **after** verifying M2).
    pub token: String,
    pub expires_in_secs: u64,
}

/// POST /api/v1/auth/verify — no Bearer required; the lockout pre-check and failure
/// accounting both happen here.
pub async fn verify(
    State(state): State<AppState>,
    axum::Extension(peer): axum::Extension<super::PeerIp>,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let srp_state = state.srp.as_ref().ok_or_else(ApiError::disabled)?;

    // Take the pending handshake first (one entry per handshake; outside the TTL it
    // simply does not exist)
    let entry = srp_state
        .take_challenge(&req.session_id)
        .ok_or_else(ApiError::unauthorized)?;

    if srp_state.is_locked(&entry.device_name) {
        // 423 Locked: tell the client plainly to wait rather than an ambiguous 401
        // (matching the local lockout feedback)
        return Err(ApiError::rejection(
            StatusCode::LOCKED,
            "account locked after repeated failures; retry later",
        ));
    }

    let client_proof = decode_field("client_proof", &req.client_proof, MAX_PUBLIC_BYTES)?;
    match srp::server_verify(
        &entry.b_priv,
        &entry.verifier,
        &entry.client_public,
        &client_proof,
    ) {
        Ok(outcome) => {
            srp_state.clear_failures(&entry.device_name);
            let token = srp_state.issue_token(&entry.device_name);
            tracing::info!(device = %entry.device_name, "SRP login OK");
            state
                .login_watch
                .record_login(&entry.device_name, true, &peer.0);
            Ok(Json(VerifyResponse {
                server_proof: B64.encode(outcome.server_proof),
                token,
                expires_in_secs: crate::auth::SRP_TOKEN_TTL.as_secs(),
            }))
        }
        Err(_) => {
            srp_state.register_failure(&entry.device_name);
            state
                .login_watch
                .record_login(&entry.device_name, false, &peer.0);
            Err(ApiError::unauthorized())
        }
    }
}

/// GET /api/v1/auth/devices — the login-awareness device registry
/// (PERSONA-DEVALERT-001): device name, first/last sighting, last IP and
/// location label, per-location sighting counts, success/failure counters.
/// In-memory by design (a restart re-arms first-sighting detection).
pub async fn devices(State(state): State<AppState>) -> impl IntoResponse {
    let devices: Vec<crate::login_watch::DeviceRecord> = state.login_watch.snapshot_devices();
    axum::Json(serde_json::json!({ "devices": devices }))
}

/// The device-name rules align with `PERSONA_SERVER_TOKENS`'s name constraints
/// (non-empty, at most 64 bytes, no whitespace).
fn validate_device_name(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(char::is_whitespace) {
        return Err(ApiError::validation(
            "invalid device_name",
            vec![super::ErrorItem::batch(
                "device_name",
                "must be 1-64 bytes, no whitespace",
            )],
        ));
    }
    Ok(trimmed.to_owned())
}

/// base64 field decoding + length cap (padding-tolerant — the client may use either
/// variant).
fn decode_field(field: &str, raw: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let decoded = B64
        .decode(raw.trim())
        .or_else(|_| STANDARD_NO_PAD.decode(raw.trim()))
        .map_err(|_| {
            ApiError::validation(
                format!("invalid base64 in {field}"),
                vec![super::ErrorItem::batch(field, "not valid base64")],
            )
        })?;
    if decoded.len() > max_bytes {
        return Err(ApiError::validation(
            format!("{field} too large"),
            vec![super::ErrorItem::batch(field, "exceeds length limit")],
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use crate::test_support::{event_json, get_events, post_events, request, send, setup};
    use axum::http::StatusCode;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use persona_core::auth::srp;

    /// The static token used for the bootstrap chain (registering via /auth/register
    /// requires it).
    const BOOTSTRAP: &str = "bootstrap-token";
    const DEVICE: &str = "test-laptop";
    const PASSWORD: &str = "correct horse battery staple";

    fn register_body() -> String {
        let reg = srp::register_verifier(DEVICE, PASSWORD).unwrap();
        format!(
            r#"{{"device_name":"{DEVICE}","salt":"{}","verifier":"{}"}}"#,
            B64.encode(reg.salt),
            B64.encode(reg.verifier)
        )
    }

    async fn register_device(router: &axum::Router) {
        let (status, body) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/register",
                Some(&format!("Bearer {BOOTSTRAP}")),
                Some("application/json"),
                &register_body(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["device_name"], DEVICE);
    }

    /// One full handshake; when `password` is wrong, verify lands on 401 (mathematically
    /// the client can always compute M1 under SRP, so the rejection happens on the server
    /// side).
    async fn attempt_login(
        router: &axum::Router,
        password: &str,
    ) -> (StatusCode, serde_json::Value) {
        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let body = format!(
            r#"{{"device_name":"{DEVICE}","client_public":"{}"}}"#,
            B64.encode(&a_pub)
        );
        let (status, resp) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                &body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();

        let proof = login
            .process(DEVICE, password, &salt, &server_public)
            .unwrap();
        let body = format!(
            r#"{{"session_id":"{session_id}","client_proof":"{}"}}"#,
            B64.encode(proof.client_proof())
        );
        send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/verify",
                None,
                Some("application/json"),
                &body,
            ),
        )
        .await
    }

    #[tokio::test]
    async fn register_requires_bearer() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        let (status, body) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/register",
                None,
                Some("application/json"),
                &register_body(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn register_conflicting_device_name_returns_409() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;
        let (status, body) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/register",
                Some(&format!("Bearer {BOOTSTRAP}")),
                Some("application/json"),
                &register_body(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn register_rejects_non_base64_salt() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        let body =
            format!(r#"{{"device_name":"{DEVICE}","salt":"!!not-b64!!","verifier":"AAAA"}}"#);
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/register",
                Some(&format!("Bearer {BOOTSTRAP}")),
                Some("application/json"),
                &body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(resp["error"]["items"][0]["field"], "salt");
    }

    #[tokio::test]
    async fn challenge_hides_registration_state_for_unknown_device() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;
        let body = r#"{"device_name":"ghost-device","client_public":"AAAA"}"#;
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                body,
            ),
        )
        .await;
        // An unregistered device and an invalid public value are shaped the same: 401,
        // never leaking "whether that device exists"
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn full_login_issues_token_that_grants_api_access() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        let (status, resp) = attempt_login(&router, PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let token = resp["token"].as_str().unwrap();
        assert_eq!(resp["expires_in_secs"], 900);

        // The short-term token issued by SRP has the same standing as a static token when
        // accessing protected endpoints
        let events = format!(r#"{{"events":[{}]}}"#, event_json("e1", "login"));
        let (status, body) = send(router.clone(), post_events(&events, Some(token))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (status, _) = send(router, get_events("/api/v1/events", BOOTSTRAP)).await;
        assert!(status.is_success());
    }

    #[tokio::test]
    async fn server_proof_verifies_on_client_side() {
        // The client half of mutual authentication: the M2 in the verify response must
        // pass SrpClientProof::verify_server, and both sides' session keys must match
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let body = format!(
            r#"{{"device_name":"{DEVICE}","client_public":"{}"}}"#,
            B64.encode(&a_pub)
        );
        let (_, resp) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                &body,
            ),
        )
        .await;
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();
        let proof = login
            .process(DEVICE, PASSWORD, &salt, &server_public)
            .unwrap();

        let verify_body = format!(
            r#"{{"session_id":"{session_id}","client_proof":"{}"}}"#,
            B64.encode(proof.client_proof())
        );
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/verify",
                None,
                Some("application/json"),
                &verify_body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let server_proof = B64.decode(resp["server_proof"].as_str().unwrap()).unwrap();
        let session_key = proof.verify_server(&server_proof).unwrap();
        // The theoretical length of the premaster = the modulus's byte length (4096-bit
        // group -> 512B), but the srp crate's big-integer output strips leading zeros: when
        // the shared secret's first byte is exactly 0 (probability 1/256) it is 511B —
        // client and server receive the same zero-stripped bytes, so the key material is
        // unaffected; the caller runs it through a KDF before using it as key material
        // (design doc: envelope encryption takes a separate KDF chain)
        assert!((1..=512).contains(&session_key.len()));
        assert!(
            session_key.iter().any(|&b| b != 0),
            "session key must not be all-zero"
        );
    }

    #[tokio::test]
    async fn wrong_password_returns_401_and_does_not_lock_after_one_failure() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        let (status, body) = attempt_login(&router, "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");

        // A single failure does not trigger lockout: the correct password still logs in
        let (status, resp) = attempt_login(&router, PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
    }

    #[tokio::test]
    async fn five_consecutive_failures_lock_even_correct_password() {
        let (router, _) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        for _ in 0..5 {
            let (status, _) = attempt_login(&router, "wrong-password").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // Within the lockout period the correct password is likewise 423 Locked
        let (status, body) = attempt_login(&router, PASSWORD).await;
        assert_eq!(status, StatusCode::LOCKED, "{body}");
    }

    /// One full handshake with a spoofable client IP (the login-awareness
    /// ledger reads X-Forwarded-For when no ConnectInfo exists — exactly
    /// what a reverse-proxy deployment and this oneshot harness share).
    async fn attempt_login_from(
        router: &axum::Router,
        password: &str,
        forwarded_for: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let login = srp::SrpClientLogin::new().unwrap();
        let a_pub = login.public_ephemeral().to_vec();
        let body = format!(
            r#"{{"device_name":"{DEVICE}","client_public":"{}"}}"#,
            B64.encode(&a_pub)
        );
        let (status, resp) = send(
            router.clone(),
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                &body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
        let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
        let session_id = resp["session_id"].as_str().unwrap().to_owned();

        let proof = login
            .process(DEVICE, password, &salt, &server_public)
            .unwrap();
        let body = format!(
            r#"{{"session_id":"{session_id}","client_proof":"{}"}}"#,
            B64.encode(proof.client_proof())
        );
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/auth/verify")
            .header("content-type", "application/json");
        if let Some(ip) = forwarded_for {
            builder = builder.header("x-forwarded-for", ip);
        }
        let req = builder.body(body).unwrap();
        send(router.clone(), req).await
    }

    // ---- Login awareness (PERSONA-DEVALERT-001) ----

    #[tokio::test]
    async fn login_attempts_are_ledgered_and_devices_endpoint_lists_them() {
        let (router, app_state) = setup(Some(BOOTSTRAP)).await;
        register_device(&router).await;

        // Success from a routable address -> the registry knows the device.
        let (status, _) = attempt_login_from(&router, PASSWORD, Some("203.0.113.7")).await;
        assert_eq!(status, StatusCode::OK);
        // Failure (wrong password) -> ledgered with the failure counter.
        let (status, _) = attempt_login_from(&router, "wrong-password", Some("203.0.113.7")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let devices = app_state.login_watch.snapshot_devices();
        assert_eq!(devices.len(), 1);
        let laptop = &devices[0];
        assert_eq!(laptop.device, DEVICE);
        assert_eq!(laptop.ok_count, 1);
        assert_eq!(laptop.fail_count, 1);
        assert_eq!(laptop.last_geo, "v4-203.0.113");
        assert_eq!(laptop.geo_counts.get("v4-203.0.113"), Some(&2));

        // Bearer-gated registry read over the wire shape.
        let (status, body) = send(
            router.clone(),
            request(
                "GET",
                "/api/v1/auth/devices",
                Some(&format!("Bearer {BOOTSTRAP}")),
                None,
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["devices"][0]["device"], DEVICE);
        assert_eq!(body["devices"][0]["last_geo"], "v4-203.0.113");
        assert_eq!(body["devices"][0]["ok_count"], 1);
        assert_eq!(body["devices"][0]["fail_count"], 1);

        let (status, body) = send(
            router,
            request("GET", "/api/v1/auth/devices", None, None, ""),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn auth_endpoints_fail_closed_without_tokens() {
        // TOKENS unset = the auth system is not enabled at all: the SRP endpoints are
        // likewise 503
        let (router, _) = setup(None).await;
        let body = r#"{"device_name":"x","client_public":"AAAA"}"#;
        let (status, resp) = send(
            router,
            request(
                "POST",
                "/api/v1/auth/challenge",
                None,
                Some("application/json"),
                body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp["error"]["code"], "api_disabled");
    }

    // ---- Cross-end integration: core HttpRemoteAuthProvider <-> this router (real TCP) ----
    // E2EE_SYNC_DESIGN phase 1 acceptance point "cross-end (CLI <-> server) handshake
    // integration test": the client's wire orchestration (remote_http.rs) and the server's
    // three endpoints interoperate on a real HTTP stack, and the issued SRP token passes
    // require_bearer (coexisting with static tokens).

    #[tokio::test(flavor = "multi_thread")]
    async fn http_provider_full_round_trip_over_real_tcp() {
        use persona_core::auth::remote_http::HttpRemoteAuthProvider;

        let (router, _) = setup(Some(BOOTSTRAP)).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        let provider = HttpRemoteAuthProvider::new(format!("http://{addr}")).unwrap();
        provider
            .register_device(BOOTSTRAP, DEVICE, PASSWORD)
            .await
            .unwrap();

        let outcome = provider
            .begin_login(DEVICE)
            .await
            .unwrap()
            .finish(PASSWORD)
            .await
            .unwrap();
        assert!(!outcome.token.is_empty());
        assert_eq!(outcome.expires_in_secs, 900);
        // The premaster is 512B (4096-bit group); the fingerprint = 64 characters of
        // sha256 hex
        assert_eq!(outcome.session_key.len(), 512);
        assert_eq!(outcome.session_key_fingerprint.len(), 64);

        // An SRP-issued token goes through require_bearer: after missing the static
        // TOKENS it consults the SRP table -> 200 (token coexistence does not disturb
        // the existing chain)
        let probe = reqwest::Client::new()
            .get(format!("http://{addr}/api/v1/events?limit=1"))
            .bearer_auth(&outcome.token)
            .send()
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::OK, "{probe:?}");

        // Wrong password -> the server returns 401 (shaped like unregistered), and the
        // client converts it to AuthenticationFailed
        let err = provider
            .begin_login(DEVICE)
            .await
            .unwrap()
            .finish("totally wrong")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("HTTP 401"), "{err}");

        task.abort();
    }
}
