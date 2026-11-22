//! 共享应用状态与服务器侧数据库初始化。
//!
//! server 库与 core 的身份库完全独立：这里只跑 `server/migrations`
//! 下的迁移，不复用 `persona_core::storage::Database`（那会带上全套
//! 身份 schema）。

use crate::auth::{AuthTokens, SrpAuthState};
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
    /// SRP 会话/短期令牌状态。与 `auth` 同生命周期（静态令牌未配置 =
    /// 认证体系整体未启用 = SRP 端点同样禁用）。
    pub srp: Option<Arc<SrpAuthState>>,
    /// 账号 WebAuthn 未决挑战（passkey 注册/登录仪式），内存态、TTL 120s。
    /// 无条件构造（不随 `auth` 门禁）：账号注册流本身免 Bearer。
    pub account_webauthn: Arc<crate::api::AccountWebauthnState>,
    /// 备份文件落盘目录（POST 写、GET 下载读；`{dir}/{id}.persenc`）。
    pub backup_dir: PathBuf,
    /// 保留版本数上限；0 = 不限（PERSONA_SERVER_BACKUP_MAX_VERSIONS）。
    pub backup_max_versions: usize,
    /// 备份上传字节上限（生产恒 [`MAX_BACKUP_BYTES`]；测试调小以覆盖
    /// 流式中断路径，256 MiB 的真实上限不适合逐测试生成）。
    pub max_backup_bytes: usize,
    /// sync oplog 保留天数（按 received_at 滚动清理）；0 = 不清理
    /// （PERSONA_SERVER_OPS_RETENTION_DAYS）。默认 0 保持纯中继语义——
    /// 清理意味着放弃向「离线超过窗口」设备补发历史的责任，须显式开启。
    pub oplog_retention_days: u32,
    /// 审计事件副本保留天数（按 received_at_ms 滚动清理）；0 = 不清理
    /// （PERSONA_SERVER_EVENTS_RETENTION_DAYS）。
    pub events_retention_days: u32,
    /// uptime 起点（单调时钟）。
    pub started_at: Instant,
    /// `process_start_time_seconds` 用（Unix 秒）。
    pub start_time_unix: i64,
}

impl AppState {
    pub fn new(pool: SqlitePool, auth: Option<AuthTokens>, metrics: Arc<Metrics>) -> Self {
        // 空集合与未配置等价：API 禁用，避免"配了但配错成空"形成半开状态。
        let auth = auth.filter(|tokens| !tokens.is_empty()).map(Arc::new);
        let srp = auth.as_ref().map(|_| Arc::new(SrpAuthState::new()));
        let start_time_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            pool,
            metrics,
            auth,
            srp,
            account_webauthn: Arc::new(crate::api::AccountWebauthnState::new()),
            backup_dir: PathBuf::from("./backups"),
            backup_max_versions: 0,
            max_backup_bytes: MAX_BACKUP_BYTES,
            oplog_retention_days: 0,
            events_retention_days: 0,
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

    /// 覆盖 oplog/events 保留天数（main 从 env 读入；0 = 不清理）。
    pub fn with_retention_settings(mut self, oplog_days: u32, events_days: u32) -> Self {
        self.oplog_retention_days = oplog_days;
        self.events_retention_days = events_days;
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

/// persona-relay 只建同步/配对面所需的迁移版本号（0004 设备/信封/oplog、
/// 0005 oplog 索引、0006 组纪元、0009 配对信箱、0010 快照、0011 设备备注）。
/// **今后给 sync/pairing 面新增迁移必须同步把版本号补进这里**——
/// [`crate::state::tests::relay_migration_versions_cover_every_sync_pairing_migration`]
/// 守住（按 SQL 内容抓，不靠文件名）。
const RELAY_MIGRATION_VERSIONS: &[i64] = &[4, 5, 6, 9, 10, 11];

/// 运行 relay 子集迁移：只建同步/配对面表，不建 events/backups/auth/
/// accounts 面（persona-relay 是哑中转）。`ignore_missing` 兼容曾被完整
/// persona-server 迁移过的同一 db——那些版本（1/2/3/7/8）已在
/// `_sqlx_migrations` 里但 relay 的集合不认识，不忽略即启动即错。
pub async fn run_relay_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    let all = sqlx::migrate!("./migrations");
    let mut relay = sqlx::migrate::Migrator::with_migrations(
        all.iter()
            .filter(|m| RELAY_MIGRATION_VERSIONS.contains(&m.version))
            .cloned()
            .collect(),
    );
    relay.set_ignore_missing(true);
    relay.run(pool).await?;
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

    async fn table_exists(pool: &SqlitePool, table: &str) -> bool {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap();
        n > 0
    }

    /// relay 迁移子集：同步/配对面表在，events/backups/auth/accounts 面
    /// 表不在；重复执行幂等。
    #[tokio::test]
    async fn relay_migrations_create_only_sync_and_pairing_tables() {
        let dir = tempfile::tempdir().unwrap();
        let pool = init_pool(dir.path().join("relay.db").to_str().unwrap())
            .await
            .unwrap();
        run_relay_migrations(&pool).await.unwrap();

        for table in [
            "sync_devices",
            "sync_group_keys",
            "sync_oplog",
            "sync_group_epoch",
            "sync_snapshots",
            "pairing_sessions",
            "pairing_messages",
        ] {
            assert!(
                table_exists(&pool, table).await,
                "{table} must exist for relay"
            );
        }
        for table in [
            "audit_events",
            "backups",
            "auth_devices",
            "accounts",
            "account_passkeys",
            "account_srp_credentials",
            "account_recovery_codes",
        ] {
            assert!(
                !table_exists(&pool, table).await,
                "{table} must NOT exist for relay"
            );
        }

        // 幂等
        run_relay_migrations(&pool).await.unwrap();
    }

    /// 同一 db 先被完整 persona-server 迁移过（版本 1/2/3/7/8 已记录在
    /// _sqlx_migrations），relay 再跑子集不能报 missing——`ignore_missing`
    /// 的回归锚（换库/降级部署的兼容路径）。
    #[tokio::test]
    async fn relay_migrations_tolerate_a_full_server_db() {
        let dir = tempfile::tempdir().unwrap();
        let pool = init_pool(dir.path().join("mixed.db").to_str().unwrap())
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        run_relay_migrations(&pool).await.unwrap();
    }

    /// 迁移是否**定义**（CREATE/ALTER/DROP/建索引于）一张 relay 面表。
    /// 只认 DDL 主体，不认引用：0007 的 `REFERENCES sync_devices(id)` 是
    /// 账号面外键引用，不是 relay 面表定义——relay 不需要它。
    fn defines_relay_table(sql: &str, table: &str) -> bool {
        sql.contains(&format!("create table if not exists {table}"))
            || sql.contains(&format!("create table {table}"))
            || sql.contains(&format!("alter table {table}"))
            || sql.contains(&format!(" on {table}"))
            || sql.contains(&format!("drop table if exists {table}"))
            || sql.contains(&format!("drop table {table}"))
    }

    /// 守门：今后新增任何**定义** sync/pairing 表的迁移，必须同步补进
    /// [`RELAY_MIGRATION_VERSIONS`]（按 DDL 主体抓，不靠文件名、不认外键
    /// 引用）；反向核对 relay 集合里每个版本都在全量集合中且确实定义
    /// relay 面表（relay 集合过时 = 这里抓）。
    #[test]
    fn relay_migration_versions_cover_every_sync_pairing_migration() {
        let all = sqlx::migrate!("./migrations");
        let surfaces = [
            "sync_devices",
            "sync_group_keys",
            "sync_oplog",
            "sync_group_epoch",
            "sync_snapshots",
            "pairing_sessions",
            "pairing_messages",
        ];
        for migration in all.iter() {
            let sql = migration.sql.as_str().to_lowercase();
            let defines_surface = surfaces
                .iter()
                .any(|table| defines_relay_table(&sql, table));
            let in_relay = RELAY_MIGRATION_VERSIONS.contains(&migration.version);
            if defines_surface {
                assert!(
                    in_relay,
                    "migration {} ({}) defines sync/pairing tables but is not in \
                     RELAY_MIGRATION_VERSIONS — persona-relay would miss this table",
                    migration.version, migration.description
                );
            }
        }
        for version in RELAY_MIGRATION_VERSIONS {
            let migration = all
                .iter()
                .find(|m| m.version == *version)
                .unwrap_or_else(|| panic!("RELAY version {version} no longer exists"));
            let sql = migration.sql.as_str().to_lowercase();
            assert!(
                surfaces
                    .iter()
                    .any(|table| defines_relay_table(&sql, table)),
                "RELAY lists migration {version} ({}) but it defines no relay-surface table \
                 — stale entry",
                migration.description
            );
        }
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
