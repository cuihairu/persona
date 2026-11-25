use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use super::map::{ContextMapFile, IdentityEntry};
use super::signals::ContextSignals;
use super::{HOST_WEIGHT, LEARN_WEIGHT, MIN_SUGGEST, PROJECT_WEIGHT};

/// A single suggestion: identity name, score, and the reason it matched
/// (human-readable, shown in CLI output).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suggestion {
    pub identity: String,
    pub score: f64,
    pub reason: String,
}

/// Suggestion result: threshold-filtered candidates (already sorted) +
/// warnings (skipped invalid entries) + the currently active identity
/// (fallback for when there are no candidates — behavior is exactly the
/// same as today, design §4/§7).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SuggestResult {
    pub candidates: Vec<Suggestion>,
    pub warnings: Vec<String>,
    pub active: Option<String>,
}

/// Directory hash: learning records store only the SHA-256 of the cwd,
/// never the raw path (design §4.1).
pub fn cwd_hash(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
}

/// Pure decision function (design §4 algorithm v1 + §4.1 learning layer):
///
/// - `PERSONA_CONTEXT_OVERRIDE` matching a valid identity → it is the
///   only candidate;
/// - project mappings match the normalized repo exactly; host mappings
///   regex-match the host pattern by pattern;
/// - for the same signal, a repo-local mapping shadows the global
///   mapping entry with the same key; when several signals hit the same
///   identity, scores accumulate and reasons are merged;
/// - `learn_counts` (counted over a 30-day window for the same
///   directory, count descending / name ascending) yields a historical
///   learning candidate with weight [`LEARN_WEIGHT`], ranked below any
///   mapping hit (override chain: override > repo-local mapping > global
///   mapping > historical learning > active);
/// - candidates whose name is not in `valid_names` are skipped with a
///   warning (same validation as switch);
/// - sorting: score descending → ties prefer active → identity name
///   ascending;
/// - score < `MIN_SUGGEST` is not selected; if everything is empty then
///   `candidates` is empty and the caller falls back to showing `active`.
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

    // Top of the override chain: the environment variable override (a
    // "suggestion layer" override only, it grants no additional authority).
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

    // Project mappings: exact match on the normalized repo; repo-local
    // shadows global entries with the same key.
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

    // Host mappings: evaluate every pattern on both sides (repo-local
    // shadows global for the same pattern).
    if let Some(host) = &signals.host {
        let mut patterns: BTreeMap<&str, (&IdentityEntry, &str)> = BTreeMap::new();
        for (pattern, entry) in &global.hosts {
            patterns.insert(pattern.as_str(), (entry, "global"));
        }
        for (pattern, entry) in &local.hosts {
            patterns.insert(pattern.as_str(), (entry, "repo"));
        }
        for (pattern, (entry, source)) in &patterns {
            // An invalid regex is treated as "this entry does not match" (design
            // §10: corrupted layers are ignored), not fatal.
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

    // Historical learning: emit one learning candidate from the top of the
    // same-directory counts (already sorted by the repo layer, count
    // descending / name ascending, so taking the first is deterministic).
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

    // Threshold filtering + sorting (score descending → active preferred →
    // name ascending).
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

/// Aggregate one hit: invalid names are skipped with a warning; repeat
/// hits on the same identity accumulate score and merge reasons.
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
