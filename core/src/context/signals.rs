use std::path::PathBuf;

use super::git::discover_git_repo;

/// Context signals collected on the client side (design §3, v1 line).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContextSignals {
    /// The terminal's current directory.
    pub cwd: PathBuf,
    /// Forge identity normalized from the remote origin found by walking
    /// up to `.git` (`github.com/owner/repo`); None when there is no Git
    /// signal.
    pub repo: Option<String>,
    /// Hostname (`PERSONA_HOST` override / gethostname); None when
    /// unavailable.
    pub host: Option<String>,
}

impl ContextSignals {
    /// Collect signals from the process environment (used directly by the
    /// CLI; tests should construct literals instead — the decision
    /// function does not depend on the environment).
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

/// Current hostname: `PERSONA_HOST` override takes precedence (an empty
/// value counts as unset), otherwise gethostname.
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
