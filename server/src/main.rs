use axum::{routing::get, Router};
use persona_core::RedactedLoggerBuilder;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tracing::{info, Level};

#[tokio::main]
async fn main() {
    // Initialize tracing
    RedactedLoggerBuilder::new(Level::INFO)
        .include_target(true)
        .init()
        .expect("failed to initialize logging");

    // Build our application with a route
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .layer(CorsLayer::permissive());

    // Run it with hyper on localhost:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Persona server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Basic handler that responds with a static string
async fn root() -> &'static str {
    "Persona Server"
}

// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
