//! 共享应用状态与服务器侧数据库初始化。
//!
//! server 库与 core 的身份库完全独立：这里只跑 `server/migrations`
//! 下的迁移，不复用 `persona_core::storage::Database`（那会带上全套
//! 身份 schema）。

use crate::auth::AuthTokens;
use crate::metrics::Metrics;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 备份上传上限（线上字节 = 落盘字节：备份子路由无解压层）。
pub const MAX_BACKUP_BYTES: usize = 256 * 1024 * 1024;

/// 全局共享状态（Clone；内部全是 Arc/连接池）。
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub metrics: Arc<Metrics>,
    /// `None` => /api 整体禁用（fail-closed：未配置任何设备令牌）。
    pub auth: Option<Arc<AuthTokens>>,
    /// 备份文件落盘目录（POST 写、GET 下载读；`{dir}/{id}.persenc`）。
    pub backup_dir: PathBuf,
    /// 保留版本数上限；0 = 不限（PERSONA_SERVER_BACKUP_MAX_VERSIONS）。
    pub backup_max_versions: usize,
    /// 备份上传字节上限（生产恒 [`MAX_BACKUP_BYTES`]；测试调小以覆盖
    /// 流式中断路径，256 MiB 的真实上限不适合逐测试生成）。
    pub max_backup_bytes: usize,
    /// uptime 起点（单调时钟）。
    pub started_at: Instant,
    /// `process_start_time_seconds` 用（Unix 秒）。
    pub start_time_unix: i64,
}

impl AppState {
    pub fn new(pool: SqlitePool, auth: Option<AuthTokens>, metrics: Arc<Metrics>) -> Self {
        // 空集合与未配置等价：API 禁用，避免"配了但配错成空"形成半开状态。
        let auth = auth.filter(|tokens| !tokens.is_empty()).map(Arc::new);
        let start_time_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            pool,
            metrics,
            auth,
            backup_dir: PathBuf::from("./backups"),
            backup_max_versions: 0,
            max_backup_bytes: MAX_BACKUP_BYTES,
            started_at: Instant::now(),
            start_time_unix,
        }
    }

    /// 覆盖备份落盘目录与保留策略（main 从 env 读入；测试用 tempdir）。
    pub fn with_backup_settings(mut self, dir: PathBuf, max_versions: usize) -> Self {
        self.backup_dir = dir;
        self.backup_max_versions = max_versions;
        self
    }
}

/// 按路径打开连接池：不存在则建库（mode=rwc），WAL + 5s busy_timeout。
pub async fn init_pool(path: &str) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{path}?mode=rwc"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5))
        // server 侧表不建外键（远端事件无本地父实体可引用），关闭以省 PRAGMA 开销
        .foreign_keys(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    Ok(pool)
}

/// 运行 `server/migrations`（sqlx 编译期内嵌，重复执行幂等）。
pub async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn test_pool() -> SqlitePool {
    // sqlx 对 `sqlite::memory:` 自动生成 shared-cache 随机名：
    // 池内多连接共享同一库，且每个 pool 相互独立（天然测试隔离）。
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    run_migrations(&pool).await.unwrap();
    pool
}

#[cfg(test)]
pub(crate) async fn test_state(token: Option<&str>) -> AppState {
    AppState::new(
        test_pool().await,
        token.filter(|t| !t.is_empty()).map(AuthTokens::single),
        Arc::new(Metrics::new(0)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    #[tokio::test]
    async fn empty_token_is_treated_as_disabled() {
        let state = AppState::new(
            test_pool().await,
            Some(AuthTokens::single("")),
            Arc::new(Metrics::new(0)),
        );
        assert!(state.auth.is_none());

        let state = AppState::new(
            test_pool().await,
            Some(AuthTokens::single("token")),
            Arc::new(Metrics::new(0)),
        );
        assert!(state.auth.is_some());
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let pool = test_pool().await;
        run_migrations(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn in_memory_pool_shares_one_database_across_connections() {
        // 回归 sqlx 内存库语义：两个独立连接必须看到同一个库。
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let mut first = pool.acquire().await.unwrap();
        let mut second = pool.acquire().await.unwrap();
        sqlx::query("CREATE TABLE shared_check (x INTEGER)")
            .execute(&mut *first)
            .await
            .unwrap();
        sqlx::query("INSERT INTO shared_check VALUES (42)")
            .execute(&mut *second)
            .await
            .unwrap();
        let value: i64 = sqlx::query_scalar("SELECT x FROM shared_check")
            .fetch_one(&mut *first)
            .await
            .unwrap();
        assert_eq!(value, 42);
    }

    #[tokio::test]
    async fn file_db_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.db");

        let pool = init_pool(path.to_str().unwrap()).await.unwrap();
        run_migrations(&pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (id, action, resource_type, success, metadata, client_timestamp, received_at, received_at_ms) VALUES ('e1', 'login', 'user', 1, '{}', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 1000)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let reopened = init_pool(path.to_str().unwrap()).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&reopened)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let stored: String = sqlx::query("SELECT action FROM audit_events WHERE id = 'e1'")
            .fetch_one(&reopened)
            .await
            .unwrap()
            .try_get("action")
            .unwrap();
        assert_eq!(stored, "login");
    }
}
