//! Server binary entry point: logging, bind address resolution and serving.
//!
//! Process startup cannot run under a test harness; this file is excluded
//! from coverage measurement via `--ignore-filename-regex`. Router and
//! handlers live in the library target and are unit-tested there.

use persona_core::RedactedLoggerBuilder;
use persona_server::build_router;
use persona_server::metrics::Metrics;
use persona_server::state::{self, AppState};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn, Level};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // Initialize tracing
    RedactedLoggerBuilder::new(Level::INFO)
        .include_target(true)
        .init()
        .expect("failed to initialize logging");

    // 服务器侧事件库（与 core 身份库无关），启动即迁移。
    let pool = state::init_pool_from_env()
        .await
        .expect("failed to open server database");
    state::run_migrations(&pool)
        .await
        .expect("failed to run server migrations");

    // fail-closed：未配置/空串令牌 => /api 整体禁用。
    let auth_token = std::env::var("PERSONA_SERVER_TOKEN").ok();
    if auth_token.as_deref().map(str::is_empty).unwrap_or(true) {
        warn!("PERSONA_SERVER_TOKEN 未设置或为空：/api/v1 已禁用（fail-closed）");
    }

    let app_state = AppState::new(
        pool,
        auth_token,
        Arc::new(Metrics::new(chrono::Utc::now().timestamp())),
    );

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
    axum::serve(listener, build_router(app_state))
        .await
        .unwrap();
}
