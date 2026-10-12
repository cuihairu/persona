use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::path::{Path, PathBuf};

use persona_core::context::{ContextMapFile, IdentityEntry};

/// Manage context-to-identity mappings (docs/CONTEXT_AWARE_DESIGN.md, stage 1).
///
/// Mappings live in `~/.persona/context.toml` (global) and optionally
/// `<repo>/.persona/context.toml` (repo-local, higher in the override
/// chain). They only shape `persona suggest` output — a mapping never
/// authorizes anything by itself.
#[derive(Args)]
pub struct ContextArgs {
    #[command(subcommand)]
    command: ContextCommand,
}

#[derive(Subcommand)]
enum ContextCommand {
    /// Add or update a mapping (default: project mapping; --host for a host regex)
    Map {
        /// Project mapping key (`host/owner/repo`) or host regex with --host
        pattern: String,
        /// Identity name this pattern suggests
        #[arg(long)]
        identity: String,
        /// Treat the pattern as a hostname regex instead of a repo id
        #[arg(long)]
        host: bool,
        /// Write the repo-local map (<cwd>/.persona/context.toml) instead of the global one
        #[arg(long)]
        repo: bool,
    },
    /// Show where a pattern maps (repo-local map first, then global)
    Get { pattern: String },
    /// Remove a mapping (from the repo-local map with --repo, else the global one)
    Unmap {
        pattern: String,
        #[arg(long)]
        repo: bool,
    },
    /// Show mapping files, their entries and the current override env var
    Status,
}

pub async fn execute(args: ContextArgs) -> Result<()> {
    let global = global_map_path();
    let repo_local = repo_local_map_path();
    match args.command {
        ContextCommand::Map {
            pattern,
            identity,
            host,
            repo,
        } => map_mapping(&pattern, &identity, host, repo, &global, &repo_local),
        ContextCommand::Get { pattern } => get_mapping(&pattern, &global, &repo_local),
        ContextCommand::Unmap { pattern, repo } => {
            unmap_mapping(&pattern, repo, &global, &repo_local)
        }
        ContextCommand::Status => status(&global, &repo_local),
    }
}

fn global_map_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".persona")
        .join("context.toml")
}

fn repo_local_map_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".persona")
        .join("context.toml")
}

/// 读目标映射文件；存在但损坏时拒绝写入（宁可让用户先修表，不静默覆盖）。
fn load_or_fail(path: &Path) -> Result<ContextMapFile> {
    match std::fs::read_to_string(path) {
        Ok(text) => ContextMapFile::parse(&text).map_err(|e| {
            anyhow!(
                "{} is corrupt, fix or remove it first: {}",
                path.display(),
                e
            )
        }),
        Err(_) => Ok(ContextMapFile::default()),
    }
}

fn write_map(path: &Path, map: &ContextMapFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("Failed to create {}: {}", parent.display(), e))?;
    }
    std::fs::write(path, map.to_toml().map_err(|e| anyhow!("{e}"))?)
        .map_err(|e| anyhow!("Failed to write {}: {}", path.display(), e))
}

fn describe(kind: bool) -> &'static str {
    if kind {
        "host"
    } else {
        "project"
    }
}

fn map_mapping(
    pattern: &str,
    identity: &str,
    host: bool,
    repo_local: bool,
    global: &Path,
    repo: &Path,
) -> Result<()> {
    let path = if repo_local { repo } else { global };
    let mut map = load_or_fail(path)?;
    let entry = IdentityEntry {
        identity: identity.to_string(),
    };
    if host {
        map.hosts.insert(pattern.to_string(), entry);
    } else {
        map.projects.insert(pattern.to_string(), entry);
    }
    write_map(path, &map)?;
    println!(
        "Mapped {} \"{}\" -> \"{}\" in {}",
        describe(host),
        pattern,
        identity,
        path.display()
    );
    Ok(())
}

/// 在 (仓库内, 全局) 两个文件里按 project → host 顺序查一个模式。
fn find_in<'a>(
    pattern: &str,
    map: &'a ContextMapFile,
) -> Option<(&'static str, &'a IdentityEntry)> {
    map.projects
        .get(pattern)
        .map(|e| ("project", e))
        .or_else(|| map.hosts.get(pattern).map(|e| ("host", e)))
}

fn get_mapping(pattern: &str, global: &Path, repo: &Path) -> Result<()> {
    let local = load_or_fail(repo)?;
    if let Some((kind, entry)) = find_in(pattern, &local) {
        println!(
            "{kind} \"{pattern}\" -> \"{}\" (repo-local {})",
            entry.identity,
            repo.display()
        );
        return Ok(());
    }
    let global_map = load_or_fail(global)?;
    if let Some((kind, entry)) = find_in(pattern, &global_map) {
        println!(
            "{kind} \"{pattern}\" -> \"{}\" (global {})",
            entry.identity,
            global.display()
        );
        return Ok(());
    }
    println!("No mapping for \"{pattern}\"");
    Ok(())
}

fn unmap_mapping(pattern: &str, repo_local: bool, global: &Path, repo: &Path) -> Result<()> {
    let path = if repo_local { repo } else { global };
    let mut map = load_or_fail(path)?;
    // 两类键都要尝试移除（同一 pattern 可能同时挂在 project 与 host 下）。
    let removed_project = map.projects.remove(pattern).is_some();
    let removed_host = map.hosts.remove(pattern).is_some();
    if !removed_project && !removed_host {
        println!("No mapping for \"{pattern}\" in {}", path.display());
        return Ok(());
    }
    write_map(path, &map)?;
    println!("Removed \"{pattern}\" from {}", path.display());
    Ok(())
}

fn print_file_section(label: &str, path: &Path) -> Result<Option<ContextMapFile>> {
    match std::fs::read_to_string(path) {
        Ok(text) => match ContextMapFile::parse(&text) {
            Ok(map) => {
                println!(
                    "{label}: {} ({} project, {} host)",
                    path.display(),
                    map.projects.len(),
                    map.hosts.len()
                );
                for (pattern, entry) in &map.projects {
                    println!("  project \"{pattern}\" -> \"{}\"", entry.identity);
                }
                for (pattern, entry) in &map.hosts {
                    println!("  host \"{pattern}\" -> \"{}\"", entry.identity);
                }
                Ok(Some(map))
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    format!(
                        "warning: {label} map at {} is corrupt and ignored: {e}",
                        path.display()
                    )
                    .yellow()
                );
                Ok(None)
            }
        },
        Err(_) => {
            println!("{label}: {} (not created yet)", path.display());
            Ok(None)
        }
    }
}

fn status(global: &Path, repo: &Path) -> Result<()> {
    print_file_section("Global map", global)?;
    print_file_section("Repo-local map", repo)?;
    match std::env::var("PERSONA_CONTEXT_OVERRIDE") {
        Ok(name) if !name.trim().is_empty() => {
            println!("Env override: PERSONA_CONTEXT_OVERRIDE={}", name.trim());
        }
        _ => println!("Env override: PERSONA_CONTEXT_OVERRIDE not set"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn temp_paths(tag: &str) -> (PathBuf, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("persona-ctx-cli-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        (base.join("global.toml"), base.join("repo.toml"))
    }

    fn cleanup(file: &Path) {
        // 传入的是 base 目录内的文件路径，删的是其所在临时目录
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    #[test]
    fn map_upsert_then_unmap_roundtrip() {
        let (global, _repo) = temp_paths("upsert");
        map_mapping(
            "github.com/a/b",
            "Work",
            false,
            false,
            &global,
            Path::new("/nonexistent"),
        )
        .unwrap();
        let text = std::fs::read_to_string(&global).unwrap();
        let parsed = ContextMapFile::parse(&text).unwrap();
        assert_eq!(
            parsed.projects.get("github.com/a/b").unwrap().identity,
            "Work"
        );
        // upsert 同键覆盖
        map_mapping(
            "github.com/a/b",
            "Ops",
            true,
            false,
            &global,
            Path::new("/nonexistent"),
        )
        .unwrap();
        let parsed = ContextMapFile::parse(&std::fs::read_to_string(&global).unwrap()).unwrap();
        assert_eq!(parsed.hosts.get("github.com/a/b").unwrap().identity, "Ops");
        // 同 pattern 跨 kind 共存是设计行为；unmap 才两类一起清
        assert_eq!(
            parsed.projects.get("github.com/a/b").unwrap().identity,
            "Work"
        );
        unmap_mapping("github.com/a/b", false, &global, Path::new("/nonexistent")).unwrap();
        let parsed = ContextMapFile::parse(&std::fs::read_to_string(&global).unwrap()).unwrap();
        assert!(parsed.hosts.is_empty() && parsed.projects.is_empty());
        cleanup(&global);
    }

    #[test]
    fn map_refuses_to_overwrite_corrupt_file() {
        let dir =
            std::env::temp_dir().join(format!("persona-ctx-cli-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let global = dir.join("context.toml");
        std::fs::write(&global, "[project.\"x\"\nidentity = ").unwrap();
        let err = map_mapping(
            "github.com/a/b",
            "Work",
            false,
            false,
            &global,
            Path::new("/nonexistent"),
        )
        .expect_err("corrupt file must refuse");
        assert!(err.to_string().contains("corrupt"));
        // 原文件未被覆盖
        assert_eq!(
            std::fs::read_to_string(&global).unwrap(),
            "[project.\"x\"\nidentity = "
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn get_prefers_repo_local_then_global() {
        let (global, repo) = temp_paths("get");
        map_mapping("github.com/a/b", "Global", false, false, &global, &repo).unwrap();
        map_mapping("github.com/a/b", "Local", false, true, &global, &repo).unwrap();
        // get 是打印型命令，这里只验证它不报错且两个文件都在位
        get_mapping("github.com/a/b", &global, &repo).unwrap();
        let local = ContextMapFile::parse(&std::fs::read_to_string(&repo).unwrap()).unwrap();
        assert_eq!(
            local.projects.get("github.com/a/b").unwrap().identity,
            "Local"
        );
        cleanup(&repo);
    }

    #[test]
    fn unmap_missing_pattern_is_reported_not_error() {
        let (global, _repo) = temp_paths("unmap-missing");
        unmap_mapping("nope", false, &global, Path::new("/nonexistent")).unwrap();
        assert!(!global.exists());
    }

    #[test]
    fn find_in_checks_projects_then_hosts() {
        let mut map = ContextMapFile::default();
        map.hosts.insert(
            "p".to_string(),
            IdentityEntry {
                identity: "H".to_string(),
            },
        );
        map.projects.insert(
            "q".to_string(),
            IdentityEntry {
                identity: "P".to_string(),
            },
        );
        assert_eq!(find_in("p", &map).unwrap().0, "host");
        assert_eq!(find_in("q", &map).unwrap().0, "project");
        assert!(find_in("z", &map).is_none());
        let _: BTreeMap<String, IdentityEntry> = BTreeMap::new();
    }
}
