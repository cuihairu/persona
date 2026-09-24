//! Server binary entry point: logging, bind address resolution and serving.
//!
//! Process startup cannot run under a test harness; this file is excluded
//! from coverage measurement via `--ignore-filename-regex`. Router and
//! handlers live in the library target and are unit-tested there.

use persona_core::RedactedLoggerBuilder;
use persona_server::auth::AuthTokens;
use persona_server::build_router;
use persona_server::metrics::Metrics;
use persona_server::state::{self, AppState};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
    let db_path =
        std::env::var("PERSONA_SERVER_DB").unwrap_or_else(|_| "./persona-server.db".into());
    let pool = state::init_pool(&db_path)
        .await
        .expect("failed to open server database");
    state::run_migrations(&pool)
        .await
        .expect("failed to run server migrations");

    // fail-closed：多设备令牌优先（PERSONA_SERVER_TOKENS="laptop:tok1,..."），
    // legacy PERSONA_SERVER_TOKEN 兼容为 "default" 设备；都未配置则 /api
    // 整体禁用。TOKENS 配了但格式非法 => 启动即错（不允许半可用状态）。
    let auth = match std::env::var("PERSONA_SERVER_TOKENS") {
        Ok(spec) if !spec.is_empty() => Some(
            AuthTokens::parse(&spec)
                .expect("PERSONA_SERVER_TOKENS 格式非法（应为 name:token,name:token）"),
        ),
        _ => match std::env::var("PERSONA_SERVER_TOKEN") {
            Ok(token) if !token.is_empty() => {
                warn!("PERSONA_SERVER_TOKEN 是 legacy 配置：建议迁移到多设备令牌 PERSONA_SERVER_TOKENS");
                Some(AuthTokens::single(&token))
            }
            _ => {
                warn!("PERSONA_SERVER_TOKENS / PERSONA_SERVER_TOKEN 均未设置：/api/v1 已禁用（fail-closed）");
                None
            }
        },
    };

    // 备份落盘目录：默认 db 同目录 backups/（容器内即 /data/backups）。
    let backup_dir = std::env::var("PERSONA_SERVER_BACKUP_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(&db_path)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default()
                .join("backups")
        });
    std::fs::create_dir_all(&backup_dir).expect("failed to create backup directory");
    let backup_max_versions: usize = std::env::var("PERSONA_SERVER_BACKUP_MAX_VERSIONS")
        .ok()
        .map(|value| {
            value
                .parse()
                .expect("PERSONA_SERVER_BACKUP_MAX_VERSIONS must be a non-negative integer")
        })
        .unwrap_or(0);
    // 保留策略（0 = 不清理 = 默认）：oplog 窗口须 ≥ 最慢设备离线周期
    // （E2EE_SYNC_DESIGN §11-3）；events 窗口按 SIEM 摘取周期定。
    let oplog_retention_days: u32 = std::env::var("PERSONA_SERVER_OPS_RETENTION_DAYS")
        .ok()
        .map(|value| {
            value
                .parse()
                .expect("PERSONA_SERVER_OPS_RETENTION_DAYS must be a non-negative integer")
        })
        .unwrap_or(0);
    let events_retention_days: u32 = std::env::var("PERSONA_SERVER_EVENTS_RETENTION_DAYS")
        .ok()
        .map(|value| {
            value
                .parse()
                .expect("PERSONA_SERVER_EVENTS_RETENTION_DAYS must be a non-negative integer")
        })
        .unwrap_or(0);

    let app_state = AppState::new(
        pool,
        auth,
        Arc::new(Metrics::new(chrono::Utc::now().timestamp())),
    )
    .with_backup_settings(backup_dir, backup_max_versions)
    .with_retention_settings(oplog_retention_days, events_retention_days);

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
