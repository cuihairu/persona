use anyhow::{anyhow, Result};
use clap::Args;
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::config::CliConfig;
use persona_core::context::{
    cwd_hash, suggest, ContextMapFile, ContextSignals, SuggestResult, LEARN_WINDOW_DAYS,
};
use persona_core::storage::{ContextLearnRepository, IdentityRepository, WorkspaceRepository};
use persona_core::{Database, Repository};

/// Suggest the likely identity for the current context (cwd/repo/host).
///
/// Context only suggests, never authorizes: the result is a default
/// candidate — activate it explicitly with `persona switch <name>`.
#[derive(Args)]
pub struct SuggestArgs {
    /// Print machine-readable JSON (signals, candidates, warnings)
    #[arg(long)]
    pub json: bool,

    /// Print only the top candidate's name (empty if none); for shell prompts
    #[arg(long)]
    pub short: bool,
}

pub async fn execute(args: SuggestArgs, config: &CliConfig) -> Result<()> {
    let signals = ContextSignals::collect();
    let paths = MapPaths::current();
    let env_override = std::env::var("PERSONA_CONTEXT_OVERRIDE").ok();
    let result = compute_suggestion(config, &paths, &signals, env_override.as_deref()).await?;
    if args.short {
        // PS1 友好：只打分身名，无候选/仅 active 时不打（提示层静默）。
        if let Some(top) = result.candidates.first() {
            println!("{}", top.identity);
        }
        return Ok(());
    }
    if args.json {
        print_json(&signals, &result)?;
        return Ok(());
    }
    print_human(&signals, &result);
    Ok(())
}

/// 两张映射表的路径（真实执行取环境推导；测试注入 TempDir 路径）。
pub(crate) struct MapPaths {
    pub global: PathBuf,
    pub repo_local: PathBuf,
}

impl MapPaths {
    fn current() -> MapPaths {
        MapPaths {
            global: global_map_path(),
            repo_local: repo_local_map_path(),
        }
    }
}

/// 建议计算：开库（不解锁——名字与 active 指针不是秘密材料，锁着也要能
/// 出建议）取有效分身名与 active，读两张映射表，交给 core 纯决策。
pub(crate) async fn compute_suggestion(
    config: &CliConfig,
    paths: &MapPaths,
    signals: &ContextSignals,
    env_override: Option<&str>,
) -> Result<SuggestResult> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;

    let irepo = IdentityRepository::new(db.clone());
    let valid_names: BTreeSet<String> = irepo
        .find_all()
        .await
        .map_err(|e| anyhow!("Failed to list identities: {}", e))?
        .into_iter()
        .map(|i| i.name)
        .collect();

    let wrepo = WorkspaceRepository::new(db.clone());
    let path_str = config.workspace.path.to_string_lossy().to_string();
    let mut active: Option<String> = None;
    if let Some(ws) = wrepo
        .find_by_path(&path_str)
        .await
        .map_err(|e| anyhow!("Failed to load workspace: {}", e))?
    {
        if let Some(id) = ws.active_identity_id {
            active = irepo
                .find_by_id(&id)
                .await
                .map_err(|e| anyhow!("Failed to fetch identity: {}", e))?
                .map(|i| i.name);
        }
    }

    let repo_local = read_map_or_empty(&paths.repo_local);
    let global = read_map_or_empty(&paths.global);

    // 历史学习（默认关）：开关打开时读同目录 30 天窗口计数，交给
    // core 纯决策出学习候选。读失败按「无学习数据」降级（设计 §10）。
    let learn_counts = match ContextLearnRepository::new(db.clone())
        .learn_enabled()
        .await
    {
        Ok(true) => ContextLearnRepository::new(db.clone())
            .counts_since(
                &cwd_hash(&config.workspace.path),
                chrono::Utc::now() - chrono::Duration::days(LEARN_WINDOW_DAYS),
            )
            .await
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    let mut result = suggest(
        signals,
        Some(&repo_local.0),
        Some(&global.0),
        env_override,
        active.as_deref(),
        &valid_names,
        Some(&learn_counts),
    );
    // 损坏映射层：忽略该层并告警（设计 §10），不崩。
    for (label, bad) in [("repo", &repo_local.1), ("global", &global.1)] {
        if let Some(err) = bad {
            result
                .warnings
                .push(format!("{label} context map ignored: {err}"));
        }
    }
    Ok(result)
}

/// 阶段 3 host 维度建议（`persona ssh run --host`）：以 SSH 目标主机为
/// 唯一信号跑打分，命中时返回一行建议文本供调用方打印。
///
/// 只建议不授权——不改 agent 目标主机文件、不改任何策略评判。
/// `PERSONA_NO_CONTEXT` 非空时整层关闭（与 shell hook 同一口径）；任何
/// 加载失败（开库/读映射/读历史）静默降级为无建议（设计 §10）。
pub(crate) async fn host_suggestion_line(config: &CliConfig, host: &str) -> Option<String> {
    host_suggestion_line_for(config, &MapPaths::current(), host).await
}

/// 同上，映射表路径由调用方注入（`MapPaths::current()` 的环境推导在
/// Windows 上走 known-folder API、不认 HOME 环境变量，测试无法重定向
/// ——与 `compute_suggestion` 同一注入口径）。
pub(crate) async fn host_suggestion_line_for(
    config: &CliConfig,
    paths: &MapPaths,
    host: &str,
) -> Option<String> {
    if std::env::var("PERSONA_NO_CONTEXT")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return None;
    }
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let signals = ContextSignals {
        cwd: PathBuf::new(),
        repo: None,
        host: Some(host.to_string()),
    };
    let env_override = std::env::var("PERSONA_CONTEXT_OVERRIDE").ok();
    let result = compute_suggestion(config, paths, &signals, env_override.as_deref())
        .await
        .ok()?;
    let top = result.candidates.first()?;
    Some(format!(
        "ssh run: context suggests `persona switch {}` (score {:.2}) — context only suggests, never authorizes.",
        top.identity, top.score
    ))
}

/// 全局映射表 `~/.persona/context.toml`（设计 §5）。
pub fn global_map_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".persona")
        .join("context.toml")
}

/// 仓库内映射表 `<cwd>/.persona/context.toml`（设计 §5，明文只含分身名）。
pub fn repo_local_map_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".persona")
        .join("context.toml")
}

/// 读映射文件：(解析结果, 解析失败原因)。文件不存在 = 空表无告警；
/// 损坏 = 空表 + 告警文本（调用方并进 suggest 告警）。
/// pub(crate)：桥协议阶段 4 复用同一读取口径。
pub(crate) fn read_map_or_empty(path: &PathBuf) -> (ContextMapFile, Option<String>) {
    match std::fs::read_to_string(path) {
        Ok(text) => match ContextMapFile::parse(&text) {
            Ok(m) => (m, None),
            Err(e) => (ContextMapFile::default(), Some(e)),
        },
        Err(_) => (ContextMapFile::default(), None),
    }
}

#[derive(Serialize)]
struct ContextJson<'a> {
    cwd: &'a str,
    repo: Option<&'a str>,
    host: Option<&'a str>,
}

#[derive(Serialize)]
struct SuggestOutput<'a> {
    context: ContextJson<'a>,
    active: Option<&'a str>,
    suggestions: &'a [persona_core::context::Suggestion],
    warnings: &'a [String],
}

fn print_json(signals: &ContextSignals, result: &SuggestResult) -> Result<()> {
    let out = SuggestOutput {
        context: ContextJson {
            cwd: &signals.cwd.to_string_lossy(),
            repo: signals.repo.as_deref(),
            host: signals.host.as_deref(),
        },
        active: result.active.as_deref(),
        suggestions: &result.candidates,
        warnings: &result.warnings,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn print_human(signals: &ContextSignals, result: &SuggestResult) {
    for warning in &result.warnings {
        eprintln!("{}", format!("warning: {warning}").yellow());
    }
    println!(
        "Context: cwd={} repo={} host={}",
        signals.cwd.display(),
        signals.repo.as_deref().unwrap_or("-"),
        signals.host.as_deref().unwrap_or("-"),
    );
    if result.candidates.is_empty() {
        match &result.active {
            Some(name) => println!("No context match; active identity stays: {name}"),
            None => println!("No context match; no active identity set"),
        }
        return;
    }
    println!("Suggested identities (top first):");
    for (i, c) in result.candidates.iter().enumerate() {
        println!(
            "  {}. {} (score {:.2}) — {}",
            i + 1,
            c.identity,
            c.score,
            c.reason
        );
    }
    println!();
    println!(
        "Context only suggests, never authorizes. Run `persona switch {}` to activate.",
        result.candidates[0].identity
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use persona_core::models::{Identity as CoreIdentityModel, IdentityType, Workspace};
    use persona_core::storage::WorkspaceRepository;
    use tempfile::TempDir;

    /// 串行化改写 HOME / PERSONA_NO_CONTEXT 的测试。
    static SUGGEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// Migrated database with one identity inserted (name = "OpenSource").
    async fn seeded_db(dir: &TempDir, set_active: bool) -> Database {
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        let identity = repo
            .create(&CoreIdentityModel::new(
                "OpenSource".to_string(),
                IdentityType::Personal,
            ))
            .await
            .unwrap();
        if set_active {
            let wrepo = WorkspaceRepository::new(db.clone());
            let mut ws = Workspace::new(dir.path().to_path_buf(), "test".to_string());
            ws.switch_identity(identity.id);
            wrepo.create(&ws).await.unwrap();
        }
        db
    }

    fn signals_with_repo(repo: Option<&str>) -> ContextSignals {
        ContextSignals {
            cwd: PathBuf::from("/tmp"),
            repo: repo.map(str::to_string),
            host: Some("dev-pc".to_string()),
        }
    }

    fn paths_for(dir: &TempDir) -> MapPaths {
        MapPaths {
            global: dir.path().join("global-context.toml"),
            repo_local: dir.path().join("repo-context.toml"),
        }
    }

    #[tokio::test]
    async fn repo_map_hit_suggests_seeded_identity() {
        let dir = TempDir::new().unwrap();
        seeded_db(&dir, false).await;
        let paths = paths_for(&dir);
        std::fs::write(
            &paths.repo_local,
            "[project.\"github.com/example/repo\"]\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        let result = compute_suggestion(
            &config_for(&dir),
            &paths,
            &signals_with_repo(Some("github.com/example/repo")),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].identity, "OpenSource");
        assert_eq!(
            result.candidates[0].score,
            persona_core::context::PROJECT_WEIGHT
        );
        assert!(result.warnings.is_empty());
    }

    #[tokio::test]
    async fn no_match_falls_back_to_active_identity() {
        let dir = TempDir::new().unwrap();
        seeded_db(&dir, true).await;
        let result = compute_suggestion(
            &config_for(&dir),
            &paths_for(&dir),
            &signals_with_repo(Some("github.com/other/repo")),
            None,
        )
        .await
        .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.active.as_deref(), Some("OpenSource"));
    }

    #[tokio::test]
    async fn invalid_mapping_name_surfaces_warning_through_cli_seam() {
        let dir = TempDir::new().unwrap();
        seeded_db(&dir, false).await;
        let paths = paths_for(&dir);
        std::fs::write(
            &paths.global,
            "[project.\"github.com/example/repo\"]\nidentity = \"Ghost\"\n",
        )
        .unwrap();
        let result = compute_suggestion(
            &config_for(&dir),
            &paths,
            &signals_with_repo(Some("github.com/example/repo")),
            None,
        )
        .await
        .unwrap();
        assert!(result.candidates.is_empty());
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("unknown identity \"Ghost\"")));
    }

    #[test]
    fn map_paths_are_distinct_and_under_persona_dirs() {
        let global = global_map_path();
        assert!(global.to_string_lossy().contains(".persona"));
        assert!(global.ends_with("context.toml"));
        let local = repo_local_map_path();
        assert!(local.ends_with(".persona/context.toml"));
    }

    #[test]
    fn missing_map_file_reads_as_empty_without_warning() {
        let (m, warn) = read_map_or_empty(&PathBuf::from("/nonexistent/persona-ctx/context.toml"));
        assert!(m.is_empty());
        assert!(warn.is_none());
    }

    #[test]
    fn broken_map_file_reads_as_empty_with_warning() {
        let dir = std::env::temp_dir().join(format!("persona-suggest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("context.toml");
        std::fs::write(&path, "[project.\"x\"\nidentity = ").unwrap();
        let (m, warn) = read_map_or_empty(&path);
        assert!(m.is_empty());
        assert!(warn.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 阶段 2 端到端：学习开关打开 + 有记录 → compute_suggestion 产出学习
    /// 候选；开关默认关 → 行为与阶段 1 完全一致（无候选）。
    #[tokio::test]
    async fn learn_records_surface_through_compute_suggestion() {
        use persona_core::context::LEARN_WEIGHT;
        use persona_core::models::{Identity as CoreIdentityModel, IdentityType};
        use persona_core::storage::ContextLearnRepository;

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            IdentityRepository::new(db.clone())
                .create(&CoreIdentityModel::new(
                    "Client-A".to_string(),
                    IdentityType::Personal,
                ))
                .await
                .unwrap();
            let learn = ContextLearnRepository::new(db);
            let hash = cwd_hash(&config.workspace.path);
            for _ in 0..2 {
                learn
                    .record("Client-A", &hash, Some("dev-pc"), chrono::Utc::now())
                    .await
                    .unwrap();
            }
        }

        // 开关未开（默认关）→ 无候选，行为与阶段 1 一致。
        let result = compute_suggestion(
            &config,
            &paths_for(&dir),
            &signals_with_repo(Some("github.com/other/repo")),
            None,
        )
        .await
        .unwrap();
        assert!(
            result.candidates.is_empty(),
            "learn off must change nothing"
        );

        // 打开开关 → 学习候选进位。
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            ContextLearnRepository::new(db)
                .set_learn_enabled(true)
                .await
                .unwrap();
        }
        let result = compute_suggestion(
            &config,
            &paths_for(&dir),
            &signals_with_repo(Some("github.com/other/repo")),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].identity, "Client-A");
        assert_eq!(result.candidates[0].score, LEARN_WEIGHT);
        assert!(result.candidates[0].reason.contains("2 times"));
    }

    // ------------------------------------------------------------------
    // 阶段 3：host 维度建议（`persona ssh run --host`）
    // ------------------------------------------------------------------

    /// 串行化会改写进程环境变量的测试（PERSONA_NO_CONTEXT / PERSONA_CONTEXT_OVERRIDE）。
    fn lock_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            SUGGEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
        )
    }

    /// 捕获一个环境变量并在 drop 时恢复，panic 也生效。
    struct EnvRestore {
        name: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvRestore {
        fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var(name).ok();
            std::env::set_var(name, &value);
            EnvRestore {
                name,
                prev: prev.map(Into::into),
            }
        }

        fn remove(name: &'static str) -> Self {
            let prev = std::env::var(name).ok();
            std::env::remove_var(name);
            EnvRestore {
                name,
                prev: prev.map(Into::into),
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(prev) => std::env::set_var(self.name, prev),
                None => std::env::remove_var(self.name),
            }
        }
    }

    /// 写注入的全局映射表（不走 home 目录推导：Windows 上 dirs 走
    /// known-folder API、不认 HOME/USERPROFILE 环境变量，测试无法重定向）。
    fn write_global_map(dir: &TempDir, body: &str) -> MapPaths {
        let paths = paths_for(dir);
        std::fs::write(&paths.global, body).unwrap();
        paths
    }

    #[tokio::test]
    async fn host_suggestion_line_reports_matching_host() {
        let _lock = lock_env();
        let dir = TempDir::new().unwrap();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let _ovr = EnvRestore::remove("PERSONA_CONTEXT_OVERRIDE");
        seeded_db(&dir, false).await;
        let paths = write_global_map(
            &dir,
            "[host.'^git\\.company\\.com$']\nidentity = \"OpenSource\"\n",
        );

        let line = host_suggestion_line_for(&config_for(&dir), &paths, "git.company.com")
            .await
            .expect("a host hit must produce a line");
        assert!(line.contains("persona switch OpenSource"));
        assert!(line.contains("score"));
        // 建议层永不承诺授权——文案必须把边界说清。
        assert!(line.contains("never authorizes"));
    }

    #[tokio::test]
    async fn host_suggestion_line_ignores_repo_signals_and_project_maps() {
        let _lock = lock_env();
        let dir = TempDir::new().unwrap();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let _ovr = EnvRestore::remove("PERSONA_CONTEXT_OVERRIDE");
        seeded_db(&dir, false).await;

        let config = config_for(&dir);
        let paths = paths_for(&dir);
        // 只有 project 命中：host 维度不得借道 project 权重出题。
        std::fs::write(
            &paths.repo_local,
            "[project.\"github.com/example/repo\"]\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        // host 信号未命中任何映射 → 无建议。
        assert!(host_suggestion_line_for(&config, &paths, "github.com")
            .await
            .is_none());
        // 同一 host 命中 host 模式时，project 映射不参与（只出 host 候选）。
        std::fs::write(
            &paths.global,
            "[host.'github\\.com']\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        let line = host_suggestion_line_for(&config, &paths, "github.com")
            .await
            .unwrap();
        assert!(line.contains("persona switch OpenSource"));
        // 与 project 精确命中的权重不同（0.8 < 1.0），行内含分数 0.80。
        assert!(line.contains("0.80"));
        // repo 维度走 project 权重、host 命中走 HOST_WEIGHT；同分身双命中聚合为一条。
        let with_repo = ContextSignals {
            cwd: PathBuf::new(),
            repo: Some("github.com/example/repo".to_string()),
            host: Some("github.com".to_string()),
        };
        let result = compute_suggestion(&config, &paths, &with_repo, None)
            .await
            .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.candidates[0].score,
            persona_core::context::PROJECT_WEIGHT + persona_core::context::HOST_WEIGHT
        );
    }

    #[tokio::test]
    async fn host_suggestion_line_no_match_returns_none() {
        let _lock = lock_env();
        let dir = TempDir::new().unwrap();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let _ovr = EnvRestore::remove("PERSONA_CONTEXT_OVERRIDE");
        seeded_db(&dir, true).await; // active 已设：仍不得凭 active 出题
        let paths = write_global_map(&dir, "[host.'^github\\.com$']\nidentity = \"OpenSource\"\n");

        assert!(
            host_suggestion_line_for(&config_for(&dir), &paths, "git.company.com")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn host_suggestion_line_no_context_flag_disables_the_layer() {
        let _lock = lock_env();
        let dir = TempDir::new().unwrap();
        let _ovr = EnvRestore::remove("PERSONA_CONTEXT_OVERRIDE");
        seeded_db(&dir, false).await;
        let paths = write_global_map(
            &dir,
            "[host.'git\\.company\\.com']\nidentity = \"OpenSource\"\n",
        );
        let config = config_for(&dir);

        // 未设 → 建议照出。
        let _clear = EnvRestore::remove("PERSONA_NO_CONTEXT");
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_some());
        drop(_clear);
        // 空串 = 与未设同义（shell hook 用 [ -z ] 判定）。
        let _empty = EnvRestore::set("PERSONA_NO_CONTEXT", "");
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_some());
        drop(_empty);
        // 非空 = 整层关闭。
        let _off = EnvRestore::set("PERSONA_NO_CONTEXT", "1");
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn host_suggestion_line_blank_host_returns_none() {
        let _lock = lock_env();
        let dir = TempDir::new().unwrap();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let _ovr = EnvRestore::remove("PERSONA_CONTEXT_OVERRIDE");
        seeded_db(&dir, false).await;
        let paths = write_global_map(&dir, "[host.'']\nidentity = \"OpenSource\"\n");
        let config = config_for(&dir);

        assert!(host_suggestion_line_for(&config, &paths, "   ")
            .await
            .is_none());
        assert!(host_suggestion_line_for(&config, &paths, "")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn host_suggestion_line_degrades_silently_on_bad_inputs() {
        let _lock = lock_env();
        let dir = TempDir::new().unwrap();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let _ovr = EnvRestore::remove("PERSONA_CONTEXT_OVERRIDE");
        seeded_db(&dir, false).await;
        let config = config_for(&dir);
        let paths = paths_for(&dir);

        // 映射文件损坏 → 该层忽略，静默无建议（不崩、不告警外泄）。
        std::fs::write(&paths.global, "[hosts\nbroken").unwrap();
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_none());
        // 映射里写了不存在的分身名 → 无候选。
        std::fs::write(
            &paths.global,
            "[host.'git\\.company\\.com']\nidentity = \"Ghost\"\n",
        )
        .unwrap();
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_none());
        // 无效正则 → 该条目不命中。
        std::fs::write(
            &paths.global,
            "[host.'[unclosed']\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_none());
        // 数据库打不开 → 整条链路降级为无建议，不向调用方上抛。
        std::fs::write(
            &paths.global,
            "[host.'git\\.company\\.com']\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        let mut broken = config_for(&dir);
        broken.workspace.path = dir.path().join("no-such-dir");
        assert!(host_suggestion_line_for(&broken, &paths, "git.company.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn host_suggestion_line_honors_context_override_env() {
        let _lock = lock_env();
        let dir = TempDir::new().unwrap();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        seeded_db(&dir, false).await;
        let paths = paths_for(&dir);
        // 无映射表：覆盖变量单独成候选（与 `persona context suggest` 同一口径）。
        let line = host_suggestion_line_for(&config_for(&dir), &paths, "github.com").await;
        assert!(line.is_none(), "override unset: no candidates without maps");
        let _ovr = EnvRestore::set("PERSONA_CONTEXT_OVERRIDE", "OpenSource");
        let line = host_suggestion_line_for(&config_for(&dir), &paths, "github.com")
            .await
            .expect("override produces a candidate");
        assert!(line.contains("persona switch OpenSource"));
        // 无效分身名 → 与 suggest 命令一致，不成为候选。
        let _bad = EnvRestore::set("PERSONA_CONTEXT_OVERRIDE", "Ghost");
        assert!(
            host_suggestion_line_for(&config_for(&dir), &paths, "github.com")
                .await
                .is_none()
        );
    }
}
