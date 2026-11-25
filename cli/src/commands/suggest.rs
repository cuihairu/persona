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
        // PS1-friendly: only score identity names; print nothing when there are no candidates
        // or only active (the prompt layer stays silent).
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

/// The paths of the two mapping tables (taken from the environment at runtime; tests inject TempDir paths).
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

/// Suggestion computation: open the vault (no unlock — the identity name and the active pointer are
/// not secret material, so suggestions must still work while locked), take the
/// effective identity name and active, read both mapping tables, and hand them
/// to core for a pure decision.
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

    // History learning (off by default): when enabled, read the 30-day window
    // counts from the same directory and hand them to core's pure decision to
    // produce learning candidates. A read failure degrades as "no learning data"
    // (design §10).
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
    // Corrupt mapping layer: ignore it and warn (design §10); do not crash.
    for (label, bad) in [("repo", &repo_local.1), ("global", &global.1)] {
        if let Some(err) = bad {
            result
                .warnings
                .push(format!("{label} context map ignored: {err}"));
        }
    }
    Ok(result)
}

/// Phase 3 host-dimension suggestion (`persona ssh run --host`): score using the
/// SSH target host as the sole signal and, on a hit, return a line of suggestion
/// text for the caller to print.
///
/// Suggest only, never authorize — it does not modify the agent's target host files or any policy judgment.
/// When `PERSONA_NO_CONTEXT` is non-empty the whole layer is off (same policy
/// as the shell hook); any load failure (vault/mappings/history) silently degrades
/// to no suggestion (design §10).
pub(crate) async fn host_suggestion_line(config: &CliConfig, host: &str) -> Option<String> {
    host_suggestion_line_for(config, &MapPaths::current(), host).await
}

/// Same as above, the mapping-table paths are injected by the caller (the
/// environment-based derivation in `MapPaths::current()` goes through the
/// known-folder API on Windows and does not honor the HOME environment
/// variable, so tests cannot redirect it — the same injection entrypoint as
/// `compute_suggestion`).
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

/// The global mapping table `~/.persona/context.toml` (design §5).
pub fn global_map_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".persona")
        .join("context.toml")
}

/// The in-repo mapping table `<cwd>/.persona/context.toml` (design §5; plaintext holds identity names only).
pub fn repo_local_map_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".persona")
        .join("context.toml")
}

/// Reading a mapping file: (parse result, parse failure reason). A missing file = an empty table with no warning;
/// corrupt = an empty table plus warning text (the caller folds it into the suggest warnings).
/// pub(crate): the bridge protocol phase 4 reuses this same reading policy.
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

    /// Serialize tests that rewrite HOME / PERSONA_NO_CONTEXT.
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

    /// Phase 2 end-to-end: learning switch on + records present →
    /// compute_suggestion produces learning candidates; switch off (the default)
    /// → behavior is identical to phase 1 (no candidates).
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

        // Switch off (the default) → no candidates; behavior matches phase 1.
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

        // Switch on → learning candidates carry through.
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
    // Phase 3: host-dimension suggestion (`persona ssh run --host`)
    // ------------------------------------------------------------------

    /// Serialize tests that rewrite process environment variables (PERSONA_NO_CONTEXT / PERSONA_CONTEXT_OVERRIDE).
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

    /// Capture an environment variable and restore it on drop; works even after a panic.
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

    /// Write an injected global mapping table (not the home-directory derivation: on
    /// Windows dirs goes through the known-folder API and does not honor the
    /// HOME/USERPROFILE environment variables, so tests cannot redirect it).
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
        // The suggestion layer never promises authorization — the copy must state the boundary clearly.
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
        // Only a project hit: the host dimension must not borrow project weight to suggest.
        std::fs::write(
            &paths.repo_local,
            "[project.\"github.com/example/repo\"]\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        // The host signal matches no mapping → no suggestion.
        assert!(host_suggestion_line_for(&config, &paths, "github.com")
            .await
            .is_none());
        // When the same host hits the host pattern, the project mapping does not participate (only host candidates are produced).
        std::fs::write(
            &paths.global,
            "[host.'github\\.com']\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        let line = host_suggestion_line_for(&config, &paths, "github.com")
            .await
            .unwrap();
        assert!(line.contains("persona switch OpenSource"));
        // The weight differs from an exact project hit (0.8 < 1.0), so the line carries the score 0.80.
        assert!(line.contains("0.80"));
        // The repo dimension uses the project weight, a host hit uses HOST_WEIGHT; a double hit for the same identity is aggregated into one line.
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
        seeded_db(&dir, true).await; // active is set: it must still not produce suggestions from active
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

        // Not set → suggestions still appear.
        let _clear = EnvRestore::remove("PERSONA_NO_CONTEXT");
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_some());
        drop(_clear);
        // Empty string = same as unset (the shell hook checks with [ -z ]).
        let _empty = EnvRestore::set("PERSONA_NO_CONTEXT", "");
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_some());
        drop(_empty);
        // Non-empty = the whole layer is off.
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

        // Corrupt mapping file → the layer is ignored, silently no suggestions (no crash, no leaked warning).
        std::fs::write(&paths.global, "[hosts\nbroken").unwrap();
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_none());
        // The mapping names an identity that does not exist → no candidates.
        std::fs::write(
            &paths.global,
            "[host.'git\\.company\\.com']\nidentity = \"Ghost\"\n",
        )
        .unwrap();
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_none());
        // Invalid regex → that entry does not match.
        std::fs::write(
            &paths.global,
            "[host.'[unclosed']\nidentity = \"OpenSource\"\n",
        )
        .unwrap();
        assert!(host_suggestion_line_for(&config, &paths, "git.company.com")
            .await
            .is_none());
        // The database cannot be opened → the whole chain degrades to no suggestions; the error is not propagated to the caller.
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
        // No mapping tables: the override variable becomes the sole candidate (same policy as `persona context suggest`).
        let line = host_suggestion_line_for(&config_for(&dir), &paths, "github.com").await;
        assert!(line.is_none(), "override unset: no candidates without maps");
        let _ovr = EnvRestore::set("PERSONA_CONTEXT_OVERRIDE", "OpenSource");
        let line = host_suggestion_line_for(&config_for(&dir), &paths, "github.com")
            .await
            .expect("override produces a candidate");
        assert!(line.contains("persona switch OpenSource"));
        // Invalid identity name → consistent with the suggest command; it does not become a candidate.
        let _bad = EnvRestore::set("PERSONA_CONTEXT_OVERRIDE", "Ghost");
        assert!(
            host_suggestion_line_for(&config_for(&dir), &paths, "github.com")
                .await
                .is_none()
        );
    }

    // ------------------------------------------------------------------
    // execute() end-to-end: the real MapPaths::current()/ContextSignals::collect()
    // derivation runs, HOME is redirected to an empty TempDir (Unix only: on
    // Windows dirs goes through the known-folder API and does not honor
    // HOME, so it cannot be redirected — see the write_global_map note).
    // ------------------------------------------------------------------

    /// HOME redirected to an empty directory: the global table reads empty and the in-repo table does not exist.
    /// The guard drops first (restoring HOME), then the directory is removed; the drop order is the reverse of the declaration order, so it is safe.
    #[cfg(unix)]
    fn home_redirect() -> (TempDir, EnvRestore) {
        let dir = TempDir::new().unwrap();
        let guard = EnvRestore::set("HOME", dir.path());
        (dir, guard)
    }

    /// Compute once in the same terms as execute to lock in the environmental precondition (the redirect really took effect).
    #[cfg(unix)]
    async fn current_suggestion(config: &CliConfig, override_name: Option<&str>) -> SuggestResult {
        compute_suggestion(
            config,
            &MapPaths::current(),
            &ContextSignals::collect(),
            override_name,
        )
        .await
        .unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_prints_suggestion_in_human_json_and_short_modes() {
        let _lock = lock_env();
        let (_home, _home_guard) = home_redirect();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let dir = TempDir::new().unwrap();
        seeded_db(&dir, false).await;
        let config = config_for(&dir);
        let _ovr = EnvRestore::set("PERSONA_CONTEXT_OVERRIDE", "OpenSource");

        // Precondition locked in: after the redirect both mapping tables are empty and the only candidate comes from the override variable.
        let result = current_suggestion(&config, Some("OpenSource")).await;
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].identity, "OpenSource");
        assert_eq!(result.candidates[0].reason, "env PERSONA_CONTEXT_OVERRIDE");

        execute(
            SuggestArgs {
                json: false,
                short: false,
            },
            &config,
        )
        .await
        .unwrap();
        execute(
            SuggestArgs {
                json: true,
                short: false,
            },
            &config,
        )
        .await
        .unwrap();
        execute(
            SuggestArgs {
                json: false,
                short: true,
            },
            &config,
        )
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_human_output_reports_fallback_without_candidates() {
        let _lock = lock_env();
        let (_home, _home_guard) = home_redirect();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let _ovr = EnvRestore::remove("PERSONA_CONTEXT_OVERRIDE");

        // active is set: when there are no candidates, prompt to keep active.
        let dir = TempDir::new().unwrap();
        seeded_db(&dir, true).await;
        let config = config_for(&dir);
        let result = current_suggestion(&config, None).await;
        assert!(result.candidates.is_empty());
        assert_eq!(result.active.as_deref(), Some("OpenSource"));
        execute(
            SuggestArgs {
                json: false,
                short: false,
            },
            &config,
        )
        .await
        .unwrap();

        // active is missing too: prompt that it is not set.
        let bare = TempDir::new().unwrap();
        seeded_db(&bare, false).await;
        let config = config_for(&bare);
        let result = current_suggestion(&config, None).await;
        assert!(result.candidates.is_empty());
        assert_eq!(result.active, None);
        execute(
            SuggestArgs {
                json: false,
                short: false,
            },
            &config,
        )
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_warns_on_invalid_override_before_fallback_line() {
        let _lock = lock_env();
        let (_home, _home_guard) = home_redirect();
        let _no_ctx = EnvRestore::remove("PERSONA_NO_CONTEXT");
        let dir = TempDir::new().unwrap();
        seeded_db(&dir, false).await;
        let config = config_for(&dir);
        let _bad = EnvRestore::set("PERSONA_CONTEXT_OVERRIDE", "Ghost");

        let result = current_suggestion(&config, Some("Ghost")).await;
        assert!(result.candidates.is_empty());
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("PERSONA_CONTEXT_OVERRIDE=Ghost")));

        execute(
            SuggestArgs {
                json: false,
                short: false,
            },
            &config,
        )
        .await
        .unwrap();
    }
}
