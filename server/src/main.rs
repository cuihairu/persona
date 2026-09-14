//! Server binary entry point: logging, bind address resolution and serving.
//!
//! Process startup cannot run under a test harness; this file is excluded
//! from coverage measurement via `--ignore-filename-regex`. Router and
//! handlers live in the library target and are unit-tested there.

use persona_core::RedactedLoggerBuilder;
use persona_server::build_router;
use std::net::SocketAddr;
use tracing::{info, Level};

#[tokio::main]
async fn main() {
    // Initialize tracing
    RedactedLoggerBuilder::new(Level::INFO)
        .include_target(true)
        .init()
        .expect("failed to initialize logging");

    // Configurable bind address (0.0.0.0 for containers, 127.0.0.1 for local dev)
    let host = std::env::var("PERSONA_SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("PERSONA_SERVER_PORT")
        .unwrap_or_else(|_| "3000".into())
        .parse()
        .expect("PERSONA_SERVER_PORT must be a valid port number");

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("invalid bind address");

    info!("Persona server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, build_router()).await.unwrap();
}
