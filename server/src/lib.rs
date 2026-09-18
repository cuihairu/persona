//! Persona sync server library: router and handlers.
//!
//! Kept in a library target so the handlers stay unit-testable; the binary in
//! `main.rs` only wires configuration and binds the listener (and is excluded
//! from coverage measurement).
//!
//! 端点：`/`、`/health` 免认证；`/api/v1/events`（POST 接入 / GET 查询）
//! 走 Bearer 令牌（未配置即 503 fail-closed），见 [`auth`] 与 [`api`]。

mod api;
mod auth;
pub mod metrics;
pub mod state;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{middleware, Router};

pub use state::AppState;

/// Build the application router.
pub fn build_router(state: AppState) -> Router {
    // /api 子路由：请求顺序 payload_size_guard → require_bearer → 处理器
    // （后 .layer 的在外层）。body 上限两层：Content-Length 预检出确定性
    // 413，DefaultBodyLimit 兜底 chunked。
    let api = Router::new()
        .route("/events", post(api::ingest).get(api::query))
        .layer(DefaultBodyLimit::max(api::MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_bearer,
        ))
        .layer(middleware::from_fn(api::payload_size_guard));

    Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .nest("/api/v1", api)
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
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

    pub(crate) async fn send(
        router: Router,
        request: HttpRequest<String>,
    ) -> (StatusCode, serde_json::Value) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        // 纯文本端点（/、/health）解析为 Null；JSON 端点的用例都会断言具体
        // 字段，若响应意外非 JSON 会以 Null 显形失败。
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
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

    /// 单条合法事件 JSON。
    pub(crate) fn event_json(id: &str, action: &str) -> String {
        format!(
            r#"{{"id":"{id}","action":"{action}","resource_type":"user","success":true,"timestamp":"2026-01-01T00:00:00Z"}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
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
        assert_eq!(body, serde_json::Value::Null); // 纯文本，非 JSON
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

        // 计数器联动（/metrics 渲染在后续 commit 接线）
        let (_, ingested, duplicates, rejected) = app_state.metrics.snapshot();
        assert_eq!((ingested, duplicates, rejected), (1, 0, 0));
    }
}
