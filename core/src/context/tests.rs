use super::*;

use std::collections::BTreeSet;
use std::path::PathBuf;

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn signals(repo: Option<&str>, host: Option<&str>) -> ContextSignals {
    ContextSignals {
        cwd: PathBuf::from("/tmp"),
        repo: repo.map(str::to_string),
        host: host.map(str::to_string),
    }
}

fn map_toml(text: &str) -> ContextMapFile {
    ContextMapFile::parse(text).expect("valid map")
}

// ---- URL 归一化 ----

#[test]
fn normalizes_scp_style_remote() {
    assert_eq!(
        normalize_remote_url("git@github.com:cuihairu/persona.git"),
        Some("github.com/cuihairu/persona".to_string())
    );
}

#[test]
fn normalizes_https_remote() {
    assert_eq!(
        normalize_remote_url("https://github.com/cuihairu/persona.git"),
        Some("github.com/cuihairu/persona".to_string())
    );
}

#[test]
fn normalizes_ssh_url_with_port_and_userinfo() {
    assert_eq!(
        normalize_remote_url("ssh://git@github.com:22/cuihairu/persona.git"),
        Some("github.com/cuihairu/persona".to_string())
    );
}

#[test]
fn normalizes_https_with_token_userinfo() {
    assert_eq!(
        normalize_remote_url("https://user:token@github.com/org/repo"),
        Some("github.com/org/repo".to_string())
    );
}

#[test]
fn local_path_remotes_have_no_forge_identity() {
    assert_eq!(normalize_remote_url("/srv/git/repo.git"), None);
    assert_eq!(normalize_remote_url("C:\\repos\\repo"), None);
    assert_eq!(normalize_remote_url("../other/repo"), None);
    assert_eq!(normalize_remote_url(""), None);
}

// ---- .git/config 解析 ----

#[test]
fn parses_origin_url_from_git_config() {
    let config = "[core]\n\trepositoryformatversion = 0\n\
                  [remote \"origin\"]\n\turl = git@github.com:org/repo.git\n\
                  \tfetch = +refs/heads/*:refs/remotes/origin/*\n";
    assert_eq!(
        parse_origin_url(config),
        Some("github.com/org/repo".to_string())
    );
}

#[test]
fn parses_origin_url_with_crlf_and_other_remotes() {
    let config = "[remote \"upstream\"]\r\n\turl = https://gitlab.com/x/y.git\r\n\
                  [remote \"origin\"]\r\n\turl = git@github.com:org/repo.git\r\n";
    assert_eq!(
        parse_origin_url(config),
        Some("github.com/org/repo".to_string())
    );
}

#[test]
fn pushurl_only_origin_yields_none() {
    let config = "[remote \"origin\"]\n\tpushurl = git@github.com:org/repo.git\n";
    assert_eq!(parse_origin_url(config), None);
}

#[test]
fn url_outside_origin_section_is_ignored() {
    let config = "[remote \"upstream\"]\n\turl = https://gitlab.com/x/y.git\n";
    assert_eq!(parse_origin_url(config), None);
}

// ---- repo 发现 ----

#[test]
fn discovers_repo_by_walking_up_parents() {
    let root = std::env::temp_dir().join(format!("persona-ctx-{}", std::process::id()));
    let deep = root.join("a/b/c");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(
        root.join(".git/config"),
        "[remote \"origin\"]\n\turl = git@github.com:org/deep.git\n",
    )
    .unwrap();
    assert_eq!(
        discover_git_repo(&deep),
        Some("github.com/org/deep".to_string())
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn discovers_repo_through_worktree_pointer_file() {
    let root = std::env::temp_dir().join(format!("persona-ctx-wt-{}", std::process::id()));
    let wt = root.join("wt");
    std::fs::create_dir_all(&wt).unwrap();
    std::fs::create_dir_all(root.join("main/.git")).unwrap();
    std::fs::write(
        root.join("main/.git/config"),
        "[remote \"origin\"]\n\turl = https://github.com/org/main.git\n",
    )
    .unwrap();
    std::fs::write(wt.join(".git"), "gitdir: ../main/.git\n").unwrap();
    assert_eq!(
        discover_git_repo(&wt),
        Some("github.com/org/main".to_string())
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn no_git_dir_yields_none() {
    let dir = std::env::temp_dir();
    assert_eq!(discover_git_repo(&dir), None);
}

// ---- 映射表解析 ----

#[test]
fn parses_context_map_toml() {
    let m = map_toml(
        "[project.\"github.com/cuihairu/persona\"]\nidentity = \"OpenSource\"\n\n\
         [host.\".*-server$\"]\nidentity = \"Ops\"\n",
    );
    assert_eq!(
        m.projects
            .get("github.com/cuihairu/persona")
            .unwrap()
            .identity,
        "OpenSource"
    );
    assert_eq!(m.hosts.get(".*-server$").unwrap().identity, "Ops");
}

#[test]
fn parses_empty_map() {
    assert!(ContextMapFile::parse("").unwrap().is_empty());
    assert!(ContextMapFile::parse("# comment only\n")
        .unwrap()
        .is_empty());
}

#[test]
fn broken_map_reports_error() {
    assert!(ContextMapFile::parse("[project.\"x\"]\nidentity = 123\n").is_err());
}

#[test]
fn map_roundtrips_through_toml() {
    let m = map_toml("[project.\"github.com/a/b\"]\nidentity = \"Work\"\n");
    let text = m.to_toml().unwrap();
    assert_eq!(ContextMapFile::parse(&text).unwrap(), m);
}

// ---- 建议决策 ----

#[test]
fn project_mapping_hit_scores_full() {
    let maps = map_toml("[project.\"github.com/cuihairu/persona\"]\nidentity = \"OpenSource\"\n");
    let r = suggest(
        &signals(Some("github.com/cuihairu/persona"), Some("dev-pc")),
        None,
        Some(&maps),
        None,
        Some("Default"),
        &names(&["OpenSource", "Default"]),
        None,
    );
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates[0].identity, "OpenSource");
    assert_eq!(r.candidates[0].score, PROJECT_WEIGHT);
    assert_eq!(r.candidates[0].reason, "repo github.com/cuihairu/persona");
    assert!(r.warnings.is_empty());
}

#[test]
fn host_regex_mapping_hit() {
    let maps = map_toml("[host.\".*-server$\"]\nidentity = \"Ops\"\n");
    let r = suggest(
        &signals(None, Some("web-01-server")),
        None,
        Some(&maps),
        None,
        None,
        &names(&["Ops"]),
        None,
    );
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates[0].identity, "Ops");
    assert_eq!(r.candidates[0].score, HOST_WEIGHT);
}

#[test]
fn no_mapping_match_falls_back_to_active() {
    let r = suggest(
        &signals(Some("github.com/a/b"), Some("dev-pc")),
        None,
        None,
        None,
        Some("Default"),
        &names(&["Default"]),
        None,
    );
    assert!(r.candidates.is_empty());
    assert_eq!(r.active.as_deref(), Some("Default"));
}

#[test]
fn repo_local_mapping_shadows_global_same_pattern() {
    let global = map_toml("[project.\"github.com/a/b\"]\nidentity = \"Global\"\n");
    let local = map_toml("[project.\"github.com/a/b\"]\nidentity = \"Local\"\n");
    let r = suggest(
        &signals(Some("github.com/a/b"), None),
        Some(&local),
        Some(&global),
        None,
        None,
        &names(&["Global", "Local"]),
        None,
    );
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates[0].identity, "Local");
}

#[test]
fn local_map_only_shadows_matching_pattern() {
    let global = map_toml("[project.\"github.com/other/x\"]\nidentity = \"Global\"\n");
    let local = map_toml("[project.\"github.com/a/b\"]\nidentity = \"Local\"\n");
    let r = suggest(
        &signals(Some("github.com/a/b"), None),
        Some(&local),
        Some(&global),
        None,
        None,
        &names(&["Global", "Local"]),
        None,
    );
    assert_eq!(r.candidates[0].identity, "Local");
    let r2 = suggest(
        &signals(Some("github.com/other/x"), None),
        Some(&local),
        Some(&global),
        None,
        None,
        &names(&["Global", "Local"]),
        None,
    );
    assert_eq!(r2.candidates[0].identity, "Global");
}

#[test]
fn multiple_signals_same_identity_sum_scores() {
    let maps = map_toml(
        "[project.\"github.com/a/b\"]\nidentity = \"Work\"\n\n\
         [host.\"^dev-pc$\"]\nidentity = \"Work\"\n",
    );
    let r = suggest(
        &signals(Some("github.com/a/b"), Some("dev-pc")),
        None,
        Some(&maps),
        None,
        None,
        &names(&["Work"]),
        None,
    );
    assert_eq!(r.candidates.len(), 1);
    assert!((r.candidates[0].score - (PROJECT_WEIGHT + HOST_WEIGHT)).abs() < 1e-9);
}

#[test]
fn tie_break_prefers_active_then_name_order() {
    // 同模式重复键在 TOML 层会报重复键；用两个同权重不同模式制造平局。
    let maps =
        map_toml("[host.\"^h$\"]\nidentity = \"Beta\"\n\n[host.\"^h.*$\"]\nidentity = \"Alpha\"\n");
    let r = suggest(
        &signals(None, Some("h")),
        None,
        Some(&maps),
        None,
        Some("Alpha"),
        &names(&["Alpha", "Beta"]),
        None,
    );
    assert_eq!(r.candidates.len(), 2);
    assert_eq!(r.candidates[0].identity, "Alpha"); // 平局 active 优先
    let r2 = suggest(
        &signals(None, Some("h")),
        None,
        Some(&maps),
        None,
        Some("Zeta"),
        &names(&["Alpha", "Beta", "Zeta"]),
        None,
    );
    assert_eq!(r2.candidates[0].identity, "Alpha"); // 无 active 命中 → 名字升序
}

#[test]
fn env_override_is_top_of_chain() {
    let maps = map_toml("[project.\"github.com/a/b\"]\nidentity = \"Mapped\"\n");
    let r = suggest(
        &signals(Some("github.com/a/b"), None),
        None,
        Some(&maps),
        Some("Forced"),
        Some("Default"),
        &names(&["Forced", "Mapped", "Default"]),
        None,
    );
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates[0].identity, "Forced");
    assert_eq!(r.candidates[0].reason, "env PERSONA_CONTEXT_OVERRIDE");
}

#[test]
fn invalid_env_override_falls_through_with_warning() {
    let maps = map_toml("[project.\"github.com/a/b\"]\nidentity = \"Mapped\"\n");
    let r = suggest(
        &signals(Some("github.com/a/b"), None),
        None,
        Some(&maps),
        Some("Ghost"),
        Some("Default"),
        &names(&["Mapped", "Default"]),
        None,
    );
    assert_eq!(r.candidates[0].identity, "Mapped");
    assert!(r.warnings.iter().any(|w| w.contains("Ghost")));
}

#[test]
fn unknown_mapping_identity_is_skipped_with_warning() {
    let maps = map_toml("[project.\"github.com/a/b\"]\nidentity = \"Ghost\"\n");
    let r = suggest(
        &signals(Some("github.com/a/b"), None),
        None,
        Some(&maps),
        None,
        Some("Default"),
        &names(&["Default"]),
        None,
    );
    assert!(r.candidates.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("Ghost")));
}

#[test]
fn forged_signals_only_shape_suggestion_never_authorize() {
    // 设计铁律：建议不授权——伪造信号只改变候选，纯函数无授权副作用。
    // 同一映射下，攻击者改 PERSONA_HOST 只能让「建议」指向别的分身，
    // 不会改变任何策略结果（这里以纯函数输出断言其唯一效果）。
    let maps = map_toml("[host.\"^evil$\"]\nidentity = \"Ops\"\n");
    let legit = suggest(
        &signals(None, Some("dev-pc")),
        None,
        Some(&maps),
        None,
        Some("Default"),
        &names(&["Ops", "Default"]),
        None,
    );
    let forged = suggest(
        &signals(None, Some("evil")),
        None,
        Some(&maps),
        None,
        Some("Default"),
        &names(&["Ops", "Default"]),
        None,
    );
    assert!(legit.candidates.is_empty());
    assert_eq!(legit.active.as_deref(), Some("Default"));
    assert_eq!(forged.candidates[0].identity, "Ops");
    // 两种情况下 active 指针都不变——建议函数没有写路径。
    assert_eq!(legit.active, forged.active);
}

#[test]
fn invalid_host_regex_is_ignored_not_fatal() {
    let maps = map_toml("[host.\"(\"]\nidentity = \"Ops\"\n");
    let r = suggest(
        &signals(None, Some("dev-pc")),
        None,
        Some(&maps),
        None,
        Some("Default"),
        &names(&["Ops", "Default"]),
        None,
    );
    assert!(r.candidates.is_empty());
}

#[test]
fn empty_identity_name_in_mapping_warns() {
    let maps = map_toml("[project.\"github.com/a/b\"]\nidentity = \"\"\n");
    let r = suggest(
        &signals(Some("github.com/a/b"), None),
        None,
        Some(&maps),
        None,
        Some("Default"),
        &names(&["Default"]),
        None,
    );
    assert!(r.candidates.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("empty identity")));
}

#[test]
fn no_mappings_matches_today_behavior() {
    // 验收「无映射时输出=active」：candidates 空 + active 原样带回。
    let r = suggest(
        &signals(Some("github.com/a/b"), Some("dev-pc")),
        None,
        None,
        None,
        Some("Solo"),
        &names(&["Solo"]),
        None,
    );
    assert!(r.candidates.is_empty());
    assert!(r.warnings.is_empty());
    assert_eq!(r.active.as_deref(), Some("Solo"));
}

// ---- 历史学习（阶段 2，设计 §4.1） ----

#[test]
fn learn_counts_produce_low_weight_candidate() {
    let counts = vec![("Client-A".to_string(), 41), ("Other".to_string(), 2)];
    let r = suggest(
        &signals(Some("github.com/client-a/repo"), Some("dev-pc")),
        None,
        None,
        None,
        Some("Default"),
        &names(&["Client-A", "Other", "Default"]),
        Some(&counts),
    );
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates[0].identity, "Client-A");
    assert_eq!(r.candidates[0].score, LEARN_WEIGHT);
    assert!(r.candidates[0].reason.contains("41 times"));
}

#[test]
fn learn_single_count_reason_reads_naturally() {
    let counts = vec![("Solo".to_string(), 1)];
    let r = suggest(
        &signals(None, None),
        None,
        None,
        None,
        None,
        &names(&["Solo"]),
        Some(&counts),
    );
    assert_eq!(r.candidates[0].reason, "used recently in this directory");
}

#[test]
fn learn_ranks_below_any_mapping_hit() {
    let maps = map_toml("[host.\"^dev-pc$\"]\nidentity = \"Mapped\"\n");
    let counts = vec![("Learned".to_string(), 99)];
    let r = suggest(
        &signals(None, Some("dev-pc")),
        None,
        Some(&maps),
        None,
        None,
        &names(&["Mapped", "Learned"]),
        Some(&counts),
    );
    assert_eq!(r.candidates[0].identity, "Mapped");
    assert_eq!(r.candidates[0].score, HOST_WEIGHT);
    assert_eq!(r.candidates[1].identity, "Learned");
}

#[test]
fn learn_and_mapping_same_identity_accumulate() {
    let maps = map_toml("[host.\"^dev-pc$\"]\nidentity = \"Both\"\n");
    let counts = vec![("Both".to_string(), 7)];
    let r = suggest(
        &signals(None, Some("dev-pc")),
        None,
        Some(&maps),
        None,
        None,
        &names(&["Both"]),
        Some(&counts),
    );
    assert_eq!(r.candidates.len(), 1);
    assert!((r.candidates[0].score - (HOST_WEIGHT + LEARN_WEIGHT)).abs() < 1e-9);
    assert!(r.candidates[0].reason.contains("host matches"));
    assert!(r.candidates[0].reason.contains("7 times"));
}

#[test]
fn learn_takes_first_of_prec_sorted_counts() {
    // 仓库层按 (次数降序, 名字升序) 传参；首名即学习候选——这里锁定
    // 纯函数「取首个」的契约，平局规则归仓库层。
    let counts = vec![
        ("Tied-B".to_string(), 5),
        ("Tied-A".to_string(), 5),
        ("Low".to_string(), 2),
    ];
    let r = suggest(
        &signals(None, None),
        None,
        None,
        None,
        None,
        &names(&["Tied-A", "Tied-B", "Low"]),
        Some(&counts),
    );
    assert_eq!(r.candidates[0].identity, "Tied-B");
}

#[test]
fn learn_unknown_identity_is_skipped_with_warning() {
    let counts = vec![("Ghost".to_string(), 3)];
    let r = suggest(
        &signals(None, None),
        None,
        None,
        None,
        Some("Default"),
        &names(&["Default"]),
        Some(&counts),
    );
    assert!(r.candidates.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("Ghost")));
}

#[test]
fn learn_counts_none_or_empty_changes_nothing() {
    let empty: Vec<(String, u64)> = Vec::new();
    for learn in [None, Some(empty.as_slice())] {
        let r = suggest(
            &signals(None, Some("dev-pc")),
            None,
            None,
            None,
            Some("Default"),
            &names(&["Default"]),
            learn,
        );
        assert!(r.candidates.is_empty());
        assert!(r.warnings.is_empty());
    }
}

#[test]
fn learn_below_threshold_lone_zero_count_is_ignored() {
    let counts = vec![("Ghost".to_string(), 0)];
    let r = suggest(
        &signals(None, None),
        None,
        None,
        None,
        Some("Default"),
        &names(&["Default", "Ghost"]),
        Some(&counts),
    );
    assert!(r.candidates.is_empty());
}

#[test]
fn cwd_hash_is_stable_hex_and_path_sensitive() {
    use std::path::Path;
    let a = cwd_hash(Path::new("/home/user/workspaces/persona"));
    let b = cwd_hash(Path::new("/home/user/workspaces/persona"));
    let c = cwd_hash(Path::new("/home/user/workspaces/other"));
    assert_eq!(a, b, "same path must hash equal");
    assert_ne!(a, c);
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
}
