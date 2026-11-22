//! Persona relay node entry point: a thin binary over `persona-server` that
//! serves ONLY the sync + pairing surfaces — a dumb encrypted courier for
//! code-paired (zero-account) cross-device sync. The events/backups/auth/
//! accounts surfaces a full `persona-server` exposes are absent by
//! construction (`build_relay_router`), and the relay migrations create only
//! the sync/pairing tables (`run_relay_migrations`).
//!
//! Process startup cannot run under a test harness; this file is excluded
//! from coverage measurement. Router and handlers live in the
//! `persona-server` library target and are unit-tested there.

use persona_core::RedactedLoggerBuilder;
use persona_server::auth::AuthTokens;
use persona_server::build_relay_router;
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

    // 中转侧数据库（独立于 core 身份库），启动即迁移——只建同步/配对
    // 面所需的表，events/backups/auth/accounts 面的表一律不建。
    let db_path =
        std::env::var("PERSONA_SERVER_DB").unwrap_or_else(|_| "./persona-relay.db".into());
    let pool = state::init_pool(&db_path)
        .await
        .expect("failed to open relay database");
    state::run_relay_migrations(&pool)
        .await
        .expect("failed to run relay migrations");

    // fail-closed（与 persona-server 同口径）：多设备令牌优先，legacy
    // 单令牌兼容；都未配置则 /api/v1 整体禁用。relay 上 Bearer 只门禁
    // sync 面（pairing 信箱免认证——配对双方本就没有共享凭证）。
    let auth = match std::env::var("PERSONA_SERVER_TOKENS") {
        Ok(spec) if !spec.is_empty() => Some(
            AuthTokens::parse(&spec)
                .expect("PERSONA_SERVER_TOKENS 格式非法（应为 name:token,name:token）"),
        ),
        _ => match std::env::var("PERSONA_SERVER_TOKEN") {
            Ok(token) if !token.is_empty() => {
                warn!(
                    "PERSONA_SERVER_TOKEN 是 legacy 配置：建议迁移到多设备令牌 PERSONA_SERVER_TOKENS"
                );
                Some(AuthTokens::single(&token))
            }
            _ => {
                warn!(
                    "PERSONA_SERVER_TOKENS / PERSONA_SERVER_TOKEN 均未设置：/api/v1 已禁用（fail-closed）"
                );
                None
            }
        },
    };

    // relay 不带备份/保留设置：备份面与审计面都不在路由里，oplog 保留
    // 默认 0 = 不清理（纯中继语义——清理意味着放弃对离线设备补发历史）。
    let app_state = AppState::new(
        pool,
        auth,
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

    info!("Persona relay listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, build_relay_router(app_state))
        .await
        .unwrap();
}
