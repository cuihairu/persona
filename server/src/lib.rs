//! Persona sync server library: router and handlers.
//!
//! Kept in a library target so the handlers stay unit-testable; the binary in
//! `main.rs` only wires configuration and binds the listener (and is excluded
//! from coverage measurement).
//!
//! Endpoints: `/`, `/health` and `/metrics` are unauthenticated; `/api/v1/events`
//! (POST ingest / GET query) and `/api/v1/backups` (encrypted backup custody:
//! POST upload / GET list / GET single download / DELETE) require a Bearer
//! token (503 fail-closed when unconfigured); see [`auth`] and [`api`].

mod api;
pub mod auth;
pub mod metrics;
pub mod state;

use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Router};

pub use state::AppState;

/// Build the application router (full surface: events/backups/auth/
/// accounts/sync/pairing). `persona-server` entry.
pub fn build_router(state: AppState) -> Router {
    with_base(full_api(&state), state)
}

/// Build the relay-only router (`persona-relay` entry): just the E2EE sync
/// and pairing mailbox surfaces — a dumb encrypted courier. The base
/// endpoints `/`, `/health` and `/metrics` plus the metrics/CORS layers
/// stay so probes and monitoring keep working; the account/backup/auth/
/// event surfaces are absent by construction (the relay crate never
/// serves them).
pub fn build_relay_router(state: AppState) -> Router {
    let api = Router::new()
        .nest("/sync", sync_routes(&state))
        .nest("/pairing", pairing_routes());
    with_base(api, state)
}

/// Full `/api/v1` sub-routes: events/backups/auth/accounts/sync/pairing.
/// Request order is payload_size_guard -> require_bearer -> RequestDecompressionLayer
/// -> handler (a later `.layer` is the outer one). Body limits: payload_size_guard
/// pre-checks wire bytes by Content-Length (the real cap for gzip transport);
/// DefaultBodyLimit applies via extensions to the body the extractor reads — placed
/// inside the decompression layer it becomes the "post-decompression plaintext"
/// limit (guards against decompression bombs and also covers chunked requests
/// without Content-Length).
fn full_api(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/events", post(api::ingest).get(api::query))
        .layer(DefaultBodyLimit::max(api::MAX_DECOMPRESSED_BODY_BYTES))
        .layer(tower_http::decompression::RequestDecompressionLayer::new())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_bearer,
        ))
        .layer(middleware::from_fn(api::payload_size_guard))
        // Backup sub-routes: independent middleware stack (layer order: size_guard (CL
        // pre-check 256 MiB) -> require_bearer -> DefaultBodyLimit). No decompression
        // layer: ciphertext is incompressible, and it avoids a second decompression-bomb
        // surface; the limit equals the on-disk limit (AppState.max_backup_bytes).
        .nest(
            "/backups",
            Router::new()
                .route("/", post(api::upload).get(api::list))
                .route("/{id}", get(api::download).delete(api::delete))
                .layer(DefaultBodyLimit::max(state.max_backup_bytes))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth::require_bearer,
                ))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    api::size_guard,
                )),
        )
        // SRP device authentication sub-routes (E2EE sync track, phase 1): challenge/verify
        // are Bearer-exempt (they are the login steps that obtain the token); register
        // requires an existing Bearer (bootstrap chain). Independent middleware stack
        // (outside the api-wide require_bearer), with a 64 KiB body limit — salt/verifier/
        // public values are all far smaller than that, guarding against abnormal payloads.
        .nest(
            "/auth",
            Router::new()
                .route(
                    "/register",
                    post(api::auth_register).route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        auth::require_bearer,
                    )),
                )
                .route("/challenge", post(api::auth_challenge))
                .route("/verify", post(api::auth_verify))
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        // Account system (M2): registration/login (passkey + SRP fallback), recovery
        // codes, device authorization. Account registration is unauthenticated; everything
        // else goes through require_account_bearer — static token / SRP short-lived token /
        // account session token (an account_sessions row, only on paths belonging to the
        // owning account; this is M2's token-consumer wiring, see the auth module).
        .nest(
            "/accounts",
            Router::new()
                .route("/register", post(api::register_account))
                // Passkey registration flow (public endpoints for WebAuthn ceremony)
                .route(
                    "/{account_id}/passkeys/create-options",
                    post(api::passkey_create_options),
                )
                .route(
                    "/{account_id}/passkeys/register",
                    post(api::passkey_register),
                )
                // First step of the passkey login ceremony (Bearer-exempt — this IS the login)
                .route(
                    "/{account_id}/passkeys/login-options",
                    post(api::passkey_login_options),
                )
                // SRP password fallback (scoped to account)
                .route(
                    "/{account_id}/srp/register",
                    post(api::account_srp_register).route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        auth::require_account_bearer,
                    )),
                )
                .route(
                    "/{account_id}/srp/challenge",
                    post(api::account_srp_challenge),
                )
                .route("/{account_id}/srp/verify", post(api::account_srp_verify))
                // Recovery codes
                .route(
                    "/{account_id}/recovery-codes",
                    post(api::generate_recovery_codes).route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        auth::require_account_bearer,
                    )),
                )
                .route(
                    "/{account_id}/recovery-codes/verify",
                    post(api::verify_recovery_code),
                )
                // Device management (account-scoped)
                .route(
                    "/{account_id}/devices",
                    post(api::authorize_device)
                        .get(api::list_account_devices)
                        .route_layer(middleware::from_fn_with_state(
                            state.clone(),
                            auth::require_account_bearer,
                        )),
                )
                .route(
                    "/{account_id}/devices/{device_id}",
                    delete(api::revoke_account_device).route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        auth::require_account_bearer,
                    )),
                )
                // Account sessions
                .route(
                    "/{account_id}/sessions",
                    post(api::create_account_session).route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        auth::require_account_bearer,
                    )),
                )
                .route(
                    "/{account_id}/sessions/{session_token}",
                    delete(api::revoke_account_session).route_layer(
                        middleware::from_fn_with_state(state.clone(), auth::require_account_bearer),
                    ),
                )
                .layer(DefaultBodyLimit::max(api::MAX_BODY_BYTES)),
        )
        .nest("/sync", sync_routes(state))
        .nest("/pairing", pairing_routes())
}

/// E2EE sync sub-routes (phase 2 batch 3, E2EE_SYNC_DESIGN §5/§6): ciphertext relay +
/// device/envelope registration. Independent middleware stack (outside the api-wide
/// require_bearer): no decompression layer (ciphertext is incompressible, and this avoids
/// a second decompression-bomb surface); body limit follows the events wire limit of
/// 1 MiB — credential ciphertext is KB-sized, so 500 per batch is enough (attachments go
/// through the backup channel, a §11 v2 topic).
fn sync_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/devices",
            post(api::sync_register_device).get(api::sync_list_devices),
        )
        .route("/devices/{id}", delete(api::sync_delete_device))
        .route("/devices/remark", put(api::sync_put_device_remark))
        .route(
            "/group-keys",
            get(api::sync_get_group_keys).put(api::sync_put_group_key),
        )
        .route("/group-key/rotate-begin", post(api::sync_rotate_begin))
        .route("/oplog", post(api::sync_push).get(api::sync_pull))
        .route(
            "/snapshot",
            put(api::sync_put_snapshot).get(api::sync_get_snapshot),
        )
        .route("/status", get(api::sync_status))
        .layer(DefaultBodyLimit::max(api::MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_bearer,
        ))
}

/// Sync-group pairing relay (S1, docs/sync-group-mode.md): an account-less mailbox with
/// no Bearer (the pairing peers by definition have no shared credentials yet); the payload
/// is a client-encrypted protocol message (SRP public message + AEAD ciphertext), so the
/// relay is zero-knowledge. TTL/queue limits/payload limits are enforced in the handlers.
fn pairing_routes() -> Router<AppState> {
    Router::new()
        .route("/sessions", post(api::pairing_create_session))
        .route(
            "/sessions/{id}",
            get(api::pairing_session_info).delete(api::pairing_delete_session),
        )
        .route(
            "/sessions/{id}/messages/to-host",
            post(api::pairing_post_to_host).get(api::pairing_take_to_host),
        )
        .route(
            "/sessions/{id}/messages/to-guest",
            post(api::pairing_post_to_guest).get(api::pairing_take_to_guest),
        )
        .layer(DefaultBodyLimit::max(api::MAX_BODY_BYTES))
}

/// Top level (a later `.layer` is the outer one): track_metrics is attached inside
/// CORS — preflight OPTIONS short-circuits in CORS and is not counted; Router::layer runs
/// after routing, so MatchedPath is available. The fallback is wrapped by the same layer,
/// so a 404 without MatchedPath naturally counts as "unmatched" (405 passes through no
/// layer at all — a bounded omission).
fn with_base(api: Router<AppState>, state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler))
        .nest("/api/v1", api)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), track_metrics))
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

/// Request counting: the route template is the label (falls back to "unmatched" when no
/// MatchedPath exists), accumulated by the actual status code after `next.run()`.
async fn track_metrics(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", |matched| matched.as_str())
        .to_owned();
    let response = next.run(request).await;
    state
        .metrics
        .record_http(method.as_str(), &route, response.status().as_u16());
    response
}

/// GET /metrics: Prometheus text, unauthenticated (standard scraper practice, registered in THREAT_MODEL).
async fn metrics_handler(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        state.metrics.render(),
    )
        .into_response()
}

/// 404 fallback response body. No counting needed here: the fallback is also wrapped by
/// Router::layer, and track_metrics finds no MatchedPath so it naturally lands on "unmatched".
async fn not_found() -> impl IntoResponse {
    api::ApiError::not_found()
}

async fn root() -> &'static str {
    "Persona Server"
}

async fn health_check() -> &'static str {
    "OK"
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt as _;

    pub(crate) async fn setup(token: Option<&str>) -> (Router, AppState) {
        let app_state = state::test_state(token).await;
        (build_router(app_state.clone()), app_state)
    }

    /// Retention-policy test harness: a test stand-in for `PERSONA_SERVER_*_RETENTION_DAYS`
    /// (0 = no cleanup).
    pub(crate) async fn setup_with_retention(
        token: Option<&str>,
        oplog_days: u32,
        events_days: u32,
    ) -> (Router, AppState) {
        let app_state = state::test_state(token)
            .await
            .with_retention_settings(oplog_days, events_days);
        (build_router(app_state.clone()), app_state)
    }

    /// Backup-endpoint test harness: multi-device token spec + tempdir backup directory + a
    /// shrinkable byte limit (generating the real 256 MiB limit per test is not practical).
    /// The caller owns the TempDir (the Router only stores the path, and dropping the dir
    /// wipes it).
    pub(crate) async fn setup_with_backups(
        spec: &str,
        max_versions: usize,
        max_backup_bytes: usize,
    ) -> (Router, AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut app_state = AppState::new(
            state::test_pool().await,
            Some(crate::auth::AuthTokens::parse(spec).unwrap()),
            std::sync::Arc::new(crate::metrics::Metrics::new(0)),
        )
        .with_backup_settings(dir.path().to_path_buf(), max_versions);
        app_state.max_backup_bytes = max_backup_bytes;
        (build_router(app_state.clone()), app_state, dir)
    }

    pub(crate) async fn send(
        router: Router,
        request: HttpRequest<String>,
    ) -> (StatusCode, serde_json::Value) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        // Plain-text endpoints (/, /health) parse to Null; JSON endpoint cases all assert
        // specific fields, so an unexpectedly non-JSON response shows up as Null and fails.
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// Binary response (backup download): returns status code + full body bytes.
    pub(crate) async fn send_binary(
        router: Router,
        request: HttpRequest<axum::body::Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, headers, body)
    }

    pub(crate) fn request(
        method: &str,
        uri: &str,
        authorization: Option<&str>,
        content_type: Option<&str>,
        body: &str,
    ) -> HttpRequest<String> {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        if let Some(auth) = authorization {
            builder = builder.header("authorization", auth);
        }
        if let Some(content_type) = content_type {
            builder = builder.header("content-type", content_type);
        }
        builder.body(body.to_owned()).unwrap()
    }

    pub(crate) fn post_events(body: &str, token: Option<&str>) -> HttpRequest<String> {
        request(
            "POST",
            "/api/v1/events",
            token.map(|t| format!("Bearer {t}")).as_deref(),
            Some("application/json"),
            body,
        )
    }

    pub(crate) fn get_events(uri: &str, token: &str) -> HttpRequest<String> {
        request("GET", uri, Some(&format!("Bearer {token}")), None, "")
    }

    pub(crate) fn post_backup(body: &str, token: &str) -> HttpRequest<String> {
        request(
            "POST",
            "/api/v1/backups",
            Some(&format!("Bearer {token}")),
            Some("application/octet-stream"),
            body,
        )
    }

    pub(crate) fn get_backups(uri: &str, token: &str) -> HttpRequest<String> {
        request("GET", uri, Some(&format!("Bearer {token}")), None, "")
    }

    pub(crate) fn delete_backup(id: &str, token: &str) -> HttpRequest<String> {
        request(
            "DELETE",
            &format!("/api/v1/backups/{id}"),
            Some(&format!("Bearer {token}")),
            None,
            "",
        )
    }

    /// Downloads use the binary response (send_binary asserts bytes and ETag).
    pub(crate) fn get_backup_download(id: &str, token: &str) -> HttpRequest<axum::body::Body> {
        HttpRequest::builder()
            .method("GET")
            .uri(format!("/api/v1/backups/{id}"))
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    /// A single valid event as JSON.
    pub(crate) fn event_json(id: &str, action: &str) -> String {
        format!(
            r#"{{"id":"{id}","action":"{action}","resource_type":"user","success":true,"timestamp":"2026-01-01T00:00:00Z"}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::{build_relay_router, state};
    use tower::ServiceExt as _;

    const TOKEN: &str = "test-token";

    #[tokio::test]
    async fn root_responds_with_server_name() {
        let (router, _) = setup(None).await;
        let (status, _) = send(router, request("GET", "/", None, None, "")).await;
        assert!(status.is_success());
    }

    #[tokio::test]
    async fn health_check_responds_with_ok() {
        let (router, _) = setup(None).await;
        let (status, body) = send(router, request("GET", "/health", None, None, "")).await;
        assert!(status.is_success());
        assert_eq!(body, serde_json::Value::Null); // plain text, not JSON
    }

    #[tokio::test]
    async fn root_and_health_require_no_auth() {
        let (router, _) = setup(Some(TOKEN)).await;
        for uri in ["/", "/health"] {
            let (status, _) = send(router.clone(), request("GET", uri, None, None, "")).await;
            assert!(status.is_success(), "{uri} should not require auth");
        }
    }

    #[tokio::test]
    async fn api_disabled_returns_503_when_token_unset() {
        let (router, _) = setup(None).await;
        let (post_status, post_body) = send(
            router.clone(),
            post_events(&event_json("e1", "login"), None),
        )
        .await;
        assert_eq!(post_status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(post_body["error"]["code"], "api_disabled");

        let (get_status, get_body) = send(router, get_events("/api/v1/events", "whatever")).await;
        assert_eq!(get_status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(get_body["error"]["code"], "api_disabled");
    }

    #[tokio::test]
    async fn api_disabled_takes_precedence_over_bad_credentials() {
        let (router, _) = setup(None).await;
        let (status, body) = send(
            router,
            post_events(&event_json("e1", "login"), Some("wrong")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "api_disabled");
    }

    #[tokio::test]
    async fn missing_authorization_returns_401_with_www_authenticate() {
        let (router, _) = setup(Some(TOKEN)).await;
        let response = router
            .oneshot(request(
                "POST",
                "/api/v1/events",
                None,
                Some("application/json"),
                &event_json("e1", "login"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer")
        );
    }

    #[tokio::test]
    async fn wrong_token_returns_401() {
        let (router, _) = setup(Some(TOKEN)).await;
        let (status, body) = send(
            router,
            post_events(&event_json("e1", "login"), Some("wrong")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[tokio::test]
    async fn correct_token_allows_ingest_and_query() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e1", "login"));
        let (status, body) = send(router.clone(), post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(body["accepted"], 1);
        assert_eq!(body["duplicates"], 0);

        let (status, body) = send(router, get_events("/api/v1/events", TOKEN)).await;
        assert!(status.is_success());
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["action"], "login");

        // Counter linkage (/metrics rendering was wired in a later commit)
        let (_, ingested, duplicates, rejected, _, _) = app_state.metrics.snapshot();
        assert_eq!((ingested, duplicates, rejected), (1, 0, 0));
    }

    #[tokio::test]
    async fn metrics_endpoint_is_public_and_prometheus_shaped() {
        let (router, _) = setup(Some(TOKEN)).await;
        let response = router
            .oneshot(request("GET", "/metrics", None, None, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("# TYPE http_requests_total counter"));
        assert!(text.contains("# TYPE persona_events_ingested_total counter"));
    }

    #[tokio::test]
    async fn http_counters_use_route_templates_and_fallback_counts_404() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        // Hits the route table: the label is the route template, not the actual path with query string
        let (status, _) = send(router.clone(), get_events("/api/v1/events?limit=1", TOKEN)).await;
        assert!(status.is_success());
        // Outside the route table -> the fallback counts "unmatched"
        let (status, body) = send(router, request("GET", "/nope", None, None, "")).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");

        let (http, _, _, _, _, _) = app_state.metrics.snapshot();
        assert!(http.contains(&("GET".to_owned(), "/api/v1/events".to_owned(), 200, 1)));
        assert!(http.contains(&("GET".to_owned(), "unmatched".to_owned(), 404, 1)));
    }

    #[tokio::test]
    async fn event_counters_flow_into_render() {
        let (router, app_state) = setup(Some(TOKEN)).await;
        let body = format!(r#"{{"events":[{}]}}"#, event_json("e1", "login"));
        let (status, _) = send(router, post_events(&body, Some(TOKEN))).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);

        let rendered = app_state.metrics.render();
        assert!(rendered.contains("persona_events_ingested_total 1"));
        assert!(rendered.contains("persona_events_duplicates_total 0"));
        assert!(rendered.contains("process_uptime_seconds"));
    }

    // -------------------------------------------------------------------
    // persona-relay route whitelist (deliverable 3): the sync/pairing surfaces are
    // present, every other API surface is entirely absent; the baseline endpoints
    // (/, /health, /metrics) and the Bearer gate are unchanged.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn relay_router_serves_only_sync_and_pairing_surfaces() {
        let app_state = state::test_state(Some(TOKEN)).await;
        let router = build_relay_router(app_state);

        // Baseline endpoints are present (monitoring probes unchanged)
        for uri in ["/", "/health", "/metrics"] {
            let (status, _) = send(router.clone(), request("GET", uri, None, None, "")).await;
            assert!(status.is_success(), "relay must keep serving {uri}");
        }

        // The sync surface is reachable (Bearer token + empty db -> head_seq 0)
        let (status, body) = send(
            router.clone(),
            request(
                "GET",
                "/api/v1/sync/status",
                Some(&format!("Bearer {TOKEN}")),
                None,
                "",
            ),
        )
        .await;
        assert!(status.is_success(), "relay must serve /api/v1/sync/status");
        assert_eq!(body["head_seq"], 0);

        // Non-relay surfaces are entirely absent (404 fallback) — accounts/events/backups/
        // auth are the full persona-server surface; the relay is a dumb relay and never exposes them.
        for uri in [
            "/api/v1/accounts",
            "/api/v1/accounts/register",
            "/api/v1/events",
            "/api/v1/backups",
            "/api/v1/auth/challenge",
        ] {
            let (status, body) = send(
                router.clone(),
                request("GET", uri, Some(&format!("Bearer {TOKEN}")), None, ""),
            )
            .await;
            assert_eq!(
                status,
                axum::http::StatusCode::NOT_FOUND,
                "{uri} must be absent on the relay router"
            );
            assert_eq!(body["error"]["code"], "not_found");
        }
    }

    #[tokio::test]
    async fn relay_router_requires_bearer_on_sync_surfaces() {
        let app_state = state::test_state(Some(TOKEN)).await;
        let router = build_relay_router(app_state);
        let (status, body) = send(
            router,
            request("GET", "/api/v1/sync/status", None, None, ""),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }
}
