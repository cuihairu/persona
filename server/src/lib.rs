//! Persona sync server library: router and handlers.
//!
//! Kept in a library target so the handlers stay unit-testable; the binary in
//! `main.rs` only wires configuration and binds the listener (and is excluded
//! from coverage measurement).

use axum::{routing::get, Router};

/// Build the application router.
pub fn build_router() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .layer(tower_http::cors::CorsLayer::permissive())
}

// Basic handler that responds with a static string
async fn root() -> &'static str {
    "Persona Server"
}

// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn root_responds_with_server_name() {
        let response = build_router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(String::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"Persona Server");
    }

    #[tokio::test]
    async fn health_check_responds_with_ok() {
        let response = build_router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(String::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK");
    }
}
