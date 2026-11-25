//! Context-aware identity suggestion (design phase 1 in
//! docs/CONTEXT_AWARE_DESIGN.md).
//!
//! Iron rule (consistent with concepts/context.md): **context only
//! suggests, it never authorizes**. Suggestion results never bypass
//! policy to approve actions; an unconfirmed suggestion does not change
//! `active_identity_id`, only the "default candidate". Scoring is a
//! deterministic pure function (no randomness/ML); decisions live in
//! core, clients only collect signals.
//!
//! Signals (v1): `cwd` (walk up to `.git`, read `remote origin` →
//! normalize into a forge identity), `host` (`PERSONA_HOST` override /
//! gethostname). Mapping tables: `~/.persona/context.toml` (global) +
//! `$repo/.persona/context.toml` (repo-local, higher on the chain);
//! override chain (highest priority on top): `PERSONA_CONTEXT_OVERRIDE`
//! > repo-local mappings > global mappings > active identity. Privacy:
//! signals are computed entirely locally and never sent out; the audit
//! log records only user confirmation (reusing the switch audit), never
//! the signals themselves.

mod git;
mod map;
mod signals;
mod suggest;
#[cfg(test)]
mod tests;

pub use git::{discover_git_repo, normalize_remote_url, parse_origin_url};
pub use map::{ContextMapFile, IdentityEntry};
pub use signals::{current_host, ContextSignals};
pub use suggest::{cwd_hash, suggest, SuggestResult, Suggestion};

/// Candidate selection threshold: score < MIN_SUGGEST does not become a
/// candidate (design §4).
pub const MIN_SUGGEST: f64 = 0.6;
/// Weight for a project-mapping hit (design example: score 1.0).
pub const PROJECT_WEIGHT: f64 = 1.0;
/// Weight for a host-regex hit (below a project hit, above the threshold).
pub const HOST_WEIGHT: f64 = 0.8;
/// Weight for a historical learning candidate (design §4.1 example:
/// score 0.7, below any mapping hit).
pub const LEARN_WEIGHT: f64 = 0.7;
/// Learning count window (design example: "last 30 days"): records
/// outside the window are not counted.
pub const LEARN_WINDOW_DAYS: i64 = 30;
