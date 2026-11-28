//! Shared application state and server-side database initialization.
//!
//! The `server` crate is fully independent of core's identity storage:
//! only the migrations under `server/migrations` are run here; it does not
//! reuse `persona_core::storage::Database` (which would pull in the entire
//! identity schema).

use crate::auth::{AuthTokens, SrpAuthState};
use crate::metrics::Metrics;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Backup upload limit (wire bytes = bytes on disk: the backup sub-routes have no decompression layer).
pub const MAX_BACKUP_BYTES: usize = 256 * 1024 * 1024;

/// Globally shared state (Clone; everything inside is Arc/pools).
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub metrics: Arc<Metrics>,
    /// `None` => the whole /api is disabled (fail-closed: no device tokens configured).
    pub auth: Option<Arc<AuthTokens>>,
    /// SRP session/short-lived token state. Shares `auth`'s lifetime (static
    /// tokens unconfigured = auth subsystem entirely disabled = SRP endpoints disabled too).
    pub srp: Option<Arc<SrpAuthState>>,
    /// Account WebAuthn pending challenges (passkey registration/login ceremonies), in-memory with TTL 120s.
    /// Constructed unconditionally (not gated by `auth`): the account registration flow itself is Bearer-exempt.
    pub account_webauthn: Arc<crate::api::AccountWebauthnState>,
    /// Login awareness (PERSONA-DEVALERT-001): in-memory login ledger +
    /// tiered new-device/unusual-location detection + optional Herald
    /// fan-out. Constructed unconditionally so the ledger works even when
    /// notifications are unconfigured.
    pub login_watch: Arc<crate::login_watch::LoginWatch>,
    /// Directory where backup files are written (POST writes, GET downloads; `{dir}/{id}.persenc`).
    pub backup_dir: PathBuf,
    /// Max number of retained versions; 0 = unlimited (PERSONA_SERVER_BACKUP_MAX_VERSIONS).
    pub backup_max_versions: usize,
    /// Backup upload byte limit (always [`MAX_BACKUP_BYTES`] in production; tests shrink it to cover
    /// the mid-stream abort path — generating 256 MiB per test is not practical).
    pub max_backup_bytes: usize,
    /// sync oplog retention in days (rolling cleanup by received_at); 0 = no cleanup
    /// (PERSONA_SERVER_OPS_RETENTION_DAYS). The default 0 preserves pure relay semantics —
    /// cleanup means giving up on re-sending history to devices "offline beyond the window", so it must be enabled explicitly.
    pub oplog_retention_days: u32,
    /// Audit event copy retention in days (rolling cleanup by received_at_ms); 0 = no cleanup
    /// (PERSONA_SERVER_EVENTS_RETENTION_DAYS).
    pub events_retention_days: u32,
    /// Uptime origin (monotonic clock).
    pub started_at: Instant,
    /// Used for `process_start_time_seconds` (Unix seconds).
    pub start_time_unix: i64,
}

impl AppState {
    pub fn new(pool: SqlitePool, auth: Option<AuthTokens>, metrics: Arc<Metrics>) -> Self {
        // An empty set is equivalent to unconfigured: the API is disabled,
        // avoiding a half-open state from "configured but wrongly set to empty".
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
            login_watch: Arc::new(crate::login_watch::LoginWatch::new(None)),
            backup_dir: PathBuf::from("./backups"),
            backup_max_versions: 0,
            max_backup_bytes: MAX_BACKUP_BYTES,
            oplog_retention_days: 0,
            events_retention_days: 0,
            started_at: Instant::now(),
            start_time_unix,
        }
    }

    /// Overrides the backup directory and retention policy (main reads from env; tests use a tempdir).
    pub fn with_backup_settings(mut self, dir: PathBuf, max_versions: usize) -> Self {
        self.backup_dir = dir;
        self.backup_max_versions = max_versions;
        self
    }

    /// Overrides oplog/events retention in days (main reads from env; 0 = no cleanup).
    pub fn with_retention_settings(mut self, oplog_days: u32, events_days: u32) -> Self {
        self.oplog_retention_days = oplog_days;
        self.events_retention_days = events_days;
        self
    }

    /// Attaches a Herald gateway to the login watch (main reads
    /// PERSONA_HERALD_URL/CHANNELS/API_KEY from env; tests inject fakes via
    /// [`with_login_watch`]).
    pub fn with_herald(
        mut self,
        base_url: &str,
        channels: Vec<String>,
        api_key: Option<String>,
    ) -> Self {
        self.login_watch = Arc::new(crate::login_watch::LoginWatch::new(Some(Arc::new(
            crate::login_watch::HeraldNotifier::new(base_url, channels, api_key),
        ))));
        self
    }

    /// Replaces the whole login watch (test wiring with injected
    /// resolver/clock; prod wiring uses [`with_herald`]).
    pub fn with_login_watch(mut self, watch: Arc<crate::login_watch::LoginWatch>) -> Self {
        self.login_watch = watch;
        self
    }
}

/// Opens a connection pool at the given path: creates the database if missing (mode=rwc), WAL + 5s busy_timeout.
pub async fn init_pool(path: &str) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{path}?mode=rwc"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5))
        // server-side tables define no foreign keys (remote events have no local parent entity to
        // reference); turned off to save the PRAGMA overhead
        .foreign_keys(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    Ok(pool)
}

/// Runs `server/migrations` (embedded by sqlx at compile time; re-running is idempotent).
pub async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Migration versions needed to build only the sync/pairing surfaces that
/// persona-relay requires (0004 devices/envelope/oplog, 0005 oplog indexes,
/// 0006 group epoch, 0009 pairing inbox, 0010 snapshots, 0011 device notes).
/// **Any new migration added to the sync/pairing surfaces must add its version here as well** —
/// [`crate::state::tests::relay_migration_versions_cover_every_sync_pairing_migration`]
/// enforces this (matched by SQL content, not by file name).
const RELAY_MIGRATION_VERSIONS: &[i64] = &[4, 5, 6, 9, 10, 11];

/// Runs the relay subset of migrations: creates only the sync/pairing tables,
/// not the events/backups/auth/accounts surfaces (persona-relay is a dumb relay).
/// `ignore_missing` keeps compatibility with a db previously migrated by full
/// persona-server — those versions (1/2/3/7/8) are already recorded in
/// `_sqlx_migrations` but unknown to relay's set, and startup would fail without ignoring them.
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
    // sqlx auto-generates a shared-cache random name for `sqlite::memory:`:
    // multiple connections in the pool share one database, and each pool is
    // independent (natural test isolation).
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

    /// Relay migration subset: sync/pairing tables exist, events/backups/auth/accounts
    /// tables do not; re-running is idempotent.
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

        // idempotent
        run_relay_migrations(&pool).await.unwrap();
    }

    /// A db previously migrated by full persona-server (versions 1/2/3/7/8 already
    /// recorded in _sqlx_migrations) must not make relay's subset report missing —
    /// regression anchor for `ignore_missing` (compatibility path for database
    /// swaps / downgraded deployments).
    #[tokio::test]
    async fn relay_migrations_tolerate_a_full_server_db() {
        let dir = tempfile::tempdir().unwrap();
        let pool = init_pool(dir.path().join("mixed.db").to_str().unwrap())
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        run_relay_migrations(&pool).await.unwrap();
    }

    /// Whether a migration **defines** (CREATE/ALTER/DROP/indexes) a relay-surface table.
    /// Only DDL bodies count, not references: 0007's `REFERENCES sync_devices(id)` is an
    /// account-surface foreign key reference, not a relay-surface table definition — relay does not need it.
    fn defines_relay_table(sql: &str, table: &str) -> bool {
        sql.contains(&format!("create table if not exists {table}"))
            || sql.contains(&format!("create table {table}"))
            || sql.contains(&format!("alter table {table}"))
            || sql.contains(&format!(" on {table}"))
            || sql.contains(&format!("drop table if exists {table}"))
            || sql.contains(&format!("drop table {table}"))
    }

    /// Gate: any future migration that **defines** a sync/pairing table must also be added to
    /// [`RELAY_MIGRATION_VERSIONS`] (matched by DDL body, not by file name, and ignoring foreign key
    /// references); the reverse check verifies every version in the relay set exists in the full
    /// set and really does define a relay-surface table (a stale relay set is caught here).
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
        // Regression test for sqlx in-memory db semantics: two independent connections must see the same database.
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
