//! Context-aware identity suggestion（设计 docs/CONTEXT_AWARE_DESIGN.md 阶段 1）。
//!
//! 铁律（与 concepts/context.md 一致）：**Context 只建议，不授权**。建议结果
//! 永远不会绕过策略放行动作；未被确认的建议不改变 `active_identity_id`，
//! 只改变「默认候选」。打分是确定性纯函数（无随机/ML），决策在 core、
//! 客户端只采集信号。
//!
//! 信号（v1）：`cwd`（上溯 `.git` 读 `remote origin` → forge 归一化）、
//! `host`（`PERSONA_HOST` 覆盖 / gethostname）。映射表 `~/.persona/context.toml`
//! （全局）+ `$repo/.persona/context.toml`（仓库内，链上位高）；覆盖链
//! （高优先在上）：`PERSONA_CONTEXT_OVERRIDE` > 仓库内映射 > 全局映射 >
//! active identity。隐私：信号全部本地计算，永不外发；审计只记用户确认
//! （复用 switch 审计），不记信号本身。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 候选入选阈值：score < MIN_SUGGEST 不进候选（设计 §4）。
pub const MIN_SUGGEST: f64 = 0.6;
/// 项目映射命中权重（设计示例：score 1.0）。
pub const PROJECT_WEIGHT: f64 = 1.0;
/// 主机正则命中权重（低于项目命中，高于阈值）。
pub const HOST_WEIGHT: f64 = 0.8;

/// 客户端采集的上下文信号（设计 §3 v1 行）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContextSignals {
    /// 终端当前目录。
    pub cwd: PathBuf,
    /// 上溯 `.git` 读 remote origin 归一化出的 forge 身份
    /// （`github.com/owner/repo`）；无 Git 信号为 None。
    pub repo: Option<String>,
    /// 主机名（`PERSONA_HOST` 覆盖 / gethostname）；不可得为 None。
    pub host: Option<String>,
}

impl ContextSignals {
    /// 从进程环境采集信号（CLI 直用；测试请构造字面量，决策函数不依赖环境）。
    pub fn collect() -> ContextSignals {
        let cwd = std::env::current_dir().unwrap_or_default();
        let repo = discover_git_repo(&cwd);
        ContextSignals {
            cwd,
            repo,
            host: current_host(),
        }
    }
}

/// 当前主机名：`PERSONA_HOST` 覆盖优先（空值视为未设），否则 gethostname。
pub fn current_host() -> Option<String> {
    if let Ok(host) = std::env::var("PERSONA_HOST") {
        let host = host.trim().to_string();
        if !host.is_empty() {
            return Some(host);
        }
    }
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
}

/// 从 `start` 逐级上溯找 `.git`（目录或 worktree/submodule 指针文件），
/// 读 `[remote "origin"] url` 并归一化为 forge 身份。取不到（离线/损坏/
/// 非 Git 目录/本地路径 remote）返回 None，其余信号照常（设计 §10 降级）。
pub fn discover_git_repo(start: &Path) -> Option<String> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let dot_git = d.join(".git");
        if dot_git.is_dir() {
            return read_origin_remote(&dot_git);
        }
        if dot_git.is_file() {
            // worktree / submodule：`.git` 是 `gitdir: <path>` 指针
            if let Ok(text) = std::fs::read_to_string(&dot_git) {
                if let Some(line) = text.lines().find_map(|l| l.strip_prefix("gitdir:")) {
                    let p = PathBuf::from(line.trim());
                    let p = if p.is_absolute() { p } else { d.join(p) };
                    return read_origin_remote(&p);
                }
            }
            return None;
        }
        dir = d.parent();
    }
    None
}

/// 读 git 目录下的 `config`，取 origin 的 url 归一化。
fn read_origin_remote(git_dir: &Path) -> Option<String> {
    let config = std::fs::read_to_string(git_dir.join("config")).ok()?;
    parse_origin_url(&config)
}

/// 从 `.git/config` 文本解析 `[remote "origin"] url`（INI 子集：节头 +
/// `key = value` 行；容忍 CRLF 与缩进）。只有 pushurl 时返回 None。
pub fn parse_origin_url(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_origin = line.starts_with("[remote \"origin\"]");
            continue;
        }
        if !in_origin {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("url")
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix('='))
        {
            return normalize_remote_url(rest.trim());
        }
    }
    None
}

/// 把 remote url 归一化为 `host/owner/repo` 形式（设计 §4 的映射键）。
/// 支持 scp 语法（`git@host:path`）、ssh/https/http/git URL（含端口与
/// userinfo）；本地路径 remote（绝对路径/盘符）无 forge 身份，返回 None。
pub fn normalize_remote_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let bytes = url.as_bytes();
    let is_drive_letter = bytes.len() > 1 && bytes[1] == b':';
    let (host, path) = if let Some(rest) = url
        .strip_prefix("ssh://")
        .or_else(|| url.strip_prefix("git://"))
        .or_else(|| url.strip_prefix("https://"))
        .or_else(|| url.strip_prefix("http://"))
    {
        // rest = [user[:pass]@]host[:port]/path
        let rest = match rest.find('@') {
            Some(at) if rest.find('/').is_none_or(|s| at < s) => &rest[at + 1..],
            _ => rest,
        };
        let slash = rest.find('/')?;
        let host = &rest[..slash];
        let host = host.split(':').next().unwrap_or(host); // 去 :port
        (host.to_string(), rest[slash + 1..].to_string())
    } else if !url.starts_with('/') && !is_drive_letter {
        // scp 语法 [user@]host:path
        let colon = url.find(':')?;
        let mut host = url[..colon].to_string();
        if let Some(at) = host.rfind('@') {
            host = host[at + 1..].to_string();
        }
        (host, url[colon + 1..].to_string())
    } else {
        return None; // 本地路径 remote
    };
    if host.is_empty() {
        return None;
    }
    let path = path.trim().trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    Some(format!("{host}/{path}"))
}

/// 映射条目：模式 → 分身名。仓库内映射只允许明文引用分身名，
/// 不涉及密钥材料（设计 §5）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityEntry {
    pub identity: String,
}

/// `context.toml` 文件模型。TOML 形态：
///
/// ```toml
/// `[project."github.com/cuihairu/persona"]`
/// identity = "OpenSource"
///
/// [host ".*-server$"]
/// identity = "Ops"
/// ```
///
/// BTreeMap 保证文件重写输出顺序稳定；键为模式原文（引号内，含 `.`/`/`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextMapFile {
    #[serde(
        default,
        rename = "project",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub projects: BTreeMap<String, IdentityEntry>,
    #[serde(default, rename = "host", skip_serializing_if = "BTreeMap::is_empty")]
    pub hosts: BTreeMap<String, IdentityEntry>,
}

impl ContextMapFile {
    pub fn parse(text: &str) -> Result<ContextMapFile, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// 空表（无任何条目）。
    pub fn is_empty(&self) -> bool {
        self.projects.is_empty() && self.hosts.is_empty()
    }
}

/// 一条建议：分身名、得分与命中原因（人类可读，进 CLI 输出）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suggestion {
    pub identity: String,
    pub score: f64,
    pub reason: String,
}

/// 建议结果：阈值过滤后的候选（已排序）+ 告警（跳过的无效项）+
/// 当前 active（供无候选时兜底——行为与今日完全一致，设计 §4/§7）。
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SuggestResult {
    pub candidates: Vec<Suggestion>,
    pub warnings: Vec<String>,
    pub active: Option<String>,
}

/// 纯决策函数（设计 §4 算法 v1）：
///
/// - `PERSONA_CONTEXT_OVERRIDE` 命中有效分身 → 它就是唯一候选；
/// - 项目映射精确匹配归一化 repo；主机映射逐条正则匹配 host；
/// - 同一信号仓库内映射遮蔽全局映射同键条目；多信号命中同一分身则
///   得分累加、原因合并；
/// - 名字不在 `valid_names` 的候选跳过并告警（与 switch 同源校验）；
/// - 排序：得分降序 → 平局 active 优先 → 分身名升序；
/// - score < `MIN_SUGGEST` 不入选；全空则 `candidates` 为空、调用方
///   兜底显示 `active`。
pub fn suggest(
    signals: &ContextSignals,
    repo_local: Option<&ContextMapFile>,
    global: Option<&ContextMapFile>,
    env_override: Option<&str>,
    active: Option<&str>,
    valid_names: &BTreeSet<String>,
) -> SuggestResult {
    let mut warnings: Vec<String> = Vec::new();
    let mut result = SuggestResult {
        active: active.map(str::to_string),
        ..SuggestResult::default()
    };

    // 覆盖链顶端：环境变量覆盖（仅是「建议层」覆盖，不扩大任何授权）。
    if let Some(name) = env_override.map(str::trim).filter(|n| !n.is_empty()) {
        if valid_names.contains(name) {
            result.candidates.push(Suggestion {
                identity: name.to_string(),
                score: 1.0,
                reason: "env PERSONA_CONTEXT_OVERRIDE".to_string(),
            });
            return result;
        }
        warnings.push(format!(
            "PERSONA_CONTEXT_OVERRIDE={name} is not a valid identity name; ignored"
        ));
    }

    let empty = ContextMapFile::default();
    let local = repo_local.unwrap_or(&empty);
    let global = global.unwrap_or(&empty);

    // 项目映射：精确匹配归一化 repo；仓库内遮蔽全局同键。
    if let Some(repo) = &signals.repo {
        let entry = local
            .projects
            .get(repo)
            .or_else(|| global.projects.get(repo));
        if let Some(entry) = entry {
            push_candidate(
                &mut result,
                &entry.identity,
                PROJECT_WEIGHT,
                format!("repo {repo}"),
                valid_names,
                &mut warnings,
            );
        }
    }

    // 主机映射：两侧全部模式求值（同模式仓库内遮蔽全局）。
    if let Some(host) = &signals.host {
        let mut patterns: BTreeMap<&str, (&IdentityEntry, &str)> = BTreeMap::new();
        for (pattern, entry) in &global.hosts {
            patterns.insert(pattern.as_str(), (entry, "global"));
        }
        for (pattern, entry) in &local.hosts {
            patterns.insert(pattern.as_str(), (entry, "repo"));
        }
        for (pattern, (entry, source)) in &patterns {
            // 无效正则按「该条目不命中」处理（设计 §10：损坏层忽略），不致命。
            let matched = regex::Regex::new(pattern)
                .ok()
                .is_some_and(|re| re.is_match(host));
            if matched {
                push_candidate(
                    &mut result,
                    &entry.identity,
                    HOST_WEIGHT,
                    format!("host matches {pattern} ({source})"),
                    valid_names,
                    &mut warnings,
                );
            }
        }
    }

    // 阈值过滤 + 排序（得分降序 → active 优先 → 名字升序）。
    result.warnings = warnings;
    result.candidates.retain(|c| c.score >= MIN_SUGGEST);
    result.candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let a_active = active == Some(a.identity.as_str());
                let b_active = active == Some(b.identity.as_str());
                b_active.cmp(&a_active)
            })
            .then_with(|| a.identity.cmp(&b.identity))
    });
    result
}

/// 聚合一条命中：无效名跳过告警；同分身重复命中得分累加、原因合并。
fn push_candidate(
    result: &mut SuggestResult,
    identity: &str,
    weight: f64,
    reason: String,
    valid_names: &BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    if identity.trim().is_empty() {
        warnings.push("mapping has empty identity name; ignored".to_string());
        return;
    }
    if !valid_names.contains(identity) {
        warnings.push(format!(
            "mapping references unknown identity \"{identity}\"; skipped"
        ));
        return;
    }
    if let Some(existing) = result
        .candidates
        .iter_mut()
        .find(|c| c.identity == identity)
    {
        existing.score += weight;
        if !existing.reason.contains(&reason) {
            existing.reason.push_str("; ");
            existing.reason.push_str(&reason);
        }
    } else {
        result.candidates.push(Suggestion {
            identity: identity.to_string(),
            score: weight,
            reason,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let maps =
            map_toml("[project.\"github.com/cuihairu/persona\"]\nidentity = \"OpenSource\"\n");
        let r = suggest(
            &signals(Some("github.com/cuihairu/persona"), Some("dev-pc")),
            None,
            Some(&maps),
            None,
            Some("Default"),
            &names(&["OpenSource", "Default"]),
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
        );
        assert_eq!(r.candidates[0].identity, "Local");
        let r2 = suggest(
            &signals(Some("github.com/other/x"), None),
            Some(&local),
            Some(&global),
            None,
            None,
            &names(&["Global", "Local"]),
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
        );
        assert_eq!(r.candidates.len(), 1);
        assert!((r.candidates[0].score - (PROJECT_WEIGHT + HOST_WEIGHT)).abs() < 1e-9);
    }

    #[test]
    fn tie_break_prefers_active_then_name_order() {
        // 同模式重复键在 TOML 层会报重复键；用两个同权重不同模式制造平局。
        let maps = map_toml(
            "[host.\"^h$\"]\nidentity = \"Beta\"\n\n[host.\"^h.*$\"]\nidentity = \"Alpha\"\n",
        );
        let r = suggest(
            &signals(None, Some("h")),
            None,
            Some(&maps),
            None,
            Some("Alpha"),
            &names(&["Alpha", "Beta"]),
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
        );
        let forged = suggest(
            &signals(None, Some("evil")),
            None,
            Some(&maps),
            None,
            Some("Default"),
            &names(&["Ops", "Default"]),
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
        );
        assert!(r.candidates.is_empty());
        assert!(r.warnings.is_empty());
        assert_eq!(r.active.as_deref(), Some("Solo"));
    }
}
