use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use super::map::{ContextMapFile, IdentityEntry};
use super::signals::ContextSignals;
use super::{HOST_WEIGHT, LEARN_WEIGHT, MIN_SUGGEST, PROJECT_WEIGHT};

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

/// 目录哈希：学习记录只存 cwd 的 SHA-256，不存路径原文（设计 §4.1）。
pub fn cwd_hash(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
}

/// 纯决策函数（设计 §4 算法 v1 + §4.1 学习层）：
///
/// - `PERSONA_CONTEXT_OVERRIDE` 命中有效分身 → 它就是唯一候选；
/// - 项目映射精确匹配归一化 repo；主机映射逐条正则匹配 host；
/// - 同一信号仓库内映射遮蔽全局映射同键条目；多信号命中同一分身则
///   得分累加、原因合并；
/// - `learn_counts`（同目录 30 天窗口计数，次数降序/名字升序）给出
///   历史学习候选，权重 [`LEARN_WEIGHT`]，排在任何映射命中之下
///   （覆盖链：override > 仓库内映射 > 全局映射 > 历史学习 > active）；
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
    learn_counts: Option<&[(String, u64)]>,
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

    // 历史学习：同目录计数之首出一个学习候选（计数已由仓库层按
    // 次数降序/名字升序排好，取首个即确定性）。
    if let Some(counts) = learn_counts {
        if let Some((identity, count)) = counts.first() {
            if *count > 0 {
                let reason = if *count == 1 {
                    "used recently in this directory".to_string()
                } else {
                    format!("used {count} times recently in this directory")
                };
                push_candidate(
                    &mut result,
                    identity,
                    LEARN_WEIGHT,
                    reason,
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
