//! ~/.ssh/config integration for "route SSH through the persona agent".
//!
//! How it works: OpenSSH 8.3+'s `IdentityAgent` directive lets you specify an
//! agent socket per host, equivalent to exporting `SSH_AUTH_SOCK` for a single
//! host. The desktop shell pins the agent to listen on a stable path (see
//! [`agent_stable_socket`]), and this module writes that path into a
//! `# persona managed begin/end` anchor comment block in `~/.ssh/config` —
//! only the inside of the block is touched, nothing else of the user's config
//! is ever modified; disabling removes the block wholesale.
//!
//! Scope: OpenSSH takes, in file order, "the first value matching that host",
//! and config lines appended at EOF land inside the user's **last
//! Host/Match block** scope (if the user's config ends with `Host github.com`,
//! no other host can reach the persona agent at all). Hence the block contains
//! a `Host *` line: the global match at EOF applies to every host, while a
//! host-level `IdentityAgent` written earlier in the file stays preferred under
//! first-wins semantics.

use std::path::Path;

use serde::Serialize;

mod config_block;
mod config_scan;
#[cfg(test)]
mod tests;

pub use config_block::{
    agent_stable_socket, has_manual_persona_entry, identity_agent_value,
    managed_block_identity_agent, remove_managed_block, ssh_config_path, upsert_managed_block,
    write_config_atomic,
};
pub use config_scan::probe_ssh_version;
use config_scan::{collect_agent_entries, socket_probe};

/// The anchor comments: the only marker for block recognition; changing them
/// would break the disable path for older configs
pub const BLOCK_BEGIN: &str = "# persona managed begin";
pub const BLOCK_END: &str = "# persona managed end";

/// The three integration states are rendered by the frontend from the
/// `enabled`/`anomaly` combination
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshIntegrationStatus {
    /// The anchor block exists and its IdentityAgent points at the current stable socket
    pub enabled: bool,
    /// The anchor block exists but points elsewhere (an old path / hand-edited)
    /// — re-enabling fixes it
    pub anomaly: Option<String>,
    /// A persona IdentityAgent hand-written outside the anchor block (surfaced,
    /// but never touched automatically)
    pub manual_entry: bool,
    pub config_path: String,
    /// The agent's stable socket (the value written / the comparison baseline)
    pub socket_path: String,
    /// The anchor block's current IdentityAgent value (None when not enabled)
    pub identity_agent: Option<String>,
    /// OpenSSH < 8.3 has no IdentityAgent support (left unset when version
    /// probing fails)
    pub ssh_version: Option<String>,
    /// The config file exists on disk (its absence is not an error: the first
    /// enable creates it)
    pub config_exists: bool,
    /// Why the read failed (permissions/IO) — displayed honestly, never
    /// swallowed silently (the enable path refuses to write based on this)
    pub read_error: Option<String>,
}

/// One agent-related config line (its true origin after Include expansion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigEntry {
    /// Source file (the main config before Include expansion, or an included file)
    pub file: String,
    /// Line number, 1-based
    pub line: usize,
    /// Enclosing scope: empty string = top level (applies to all hosts);
    /// otherwise the verbatim Host/Match line
    pub scope: String,
    /// Keyword (case preserved as written; comparisons use lowercase)
    pub keyword: String,
    /// Value (quotes stripped)
    pub value: String,
}

/// Analysis of the agent-related surface of `~/.ssh/config` (with Include
/// expansion). Read-only; any failure lands in a field and is shown as-is,
/// so the frontend never has to guess.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigAgentAnalysis {
    pub config_path: String,
    pub config_exists: bool,
    pub readable: bool,
    /// Why the read failed (permissions/IO, e.g. the config is a directory or
    /// not readable)
    pub read_error: Option<String>,
    /// Non-fatal parse warnings (Include missing file / cycle / too deep /
    /// glob with no match)
    pub warnings: Vec<String>,
    /// Agent-related entries (with Include expansion; entries inside the persona
    /// anchor block are excluded — the block's state is examined separately)
    pub entries: Vec<SshConfigEntry>,
    /// The ForwardAgent entries (on/off values verbatim, each with its scope)
    pub forward_agent_entries: Vec<SshConfigEntry>,
    /// The effective IdentityAgent: a top-level approximation of ssh's
    /// "first matching value" semantics — the first top-level (no Host/Match
    /// qualifier) entry wins; when no user global entry exists, the persona
    /// anchor block value is used (`Host *` applies to all connections, and the
    /// block at EOF is overridden by earlier entries); when neither exists,
    /// None (the result differs per host, so no guess is made).
    pub identity_agent_effective: Option<String>,
    /// The environment's SSH_AUTH_SOCK (None when unset)
    pub ssh_auth_sock: Option<String>,
    /// The socket ssh will actually use: effective IdentityAgent first,
    /// then the environment
    pub effective_socket: Option<String>,
    /// Unix socket reachability probe of effective_socket
    /// (None = platform unsupported / no socket)
    pub socket_alive: Option<bool>,
    /// Whether some process is listening on the persona agent's stable socket
    /// (= the agent is running)
    pub persona_socket_alive: bool,
}

/// Read the config (with Include expansion) and analyze its agent-related
/// surface. Any failure lands in a field; never panics, never swallows
/// silently.
pub fn analyze_config(config_path: &Path, ssh_auth_sock: Option<String>) -> SshConfigAgentAnalysis {
    let exists = config_path.exists();
    let mut read_error = None;
    let mut warnings = Vec::new();
    let mut entries = Vec::new();
    // The anchor block value participates in the effective-value decision: the
    // block is appended at EOF, so a user's earlier global entry overrides it
    // under "first occurrence wins"; with no user global entry, the block value
    // is what ssh actually uses
    let mut managed_block_value = None;
    if exists {
        match std::fs::read_to_string(config_path) {
            Ok(content) => {
                managed_block_value = managed_block_identity_agent(&content);
                // The persona anchor block's line-number span within the main
                // file (entries inside the block are excluded)
                let skip_span = {
                    let lines: Vec<&str> = content.lines().collect();
                    let begin = lines.iter().position(|l| l.trim() == BLOCK_BEGIN);
                    let end = lines.iter().position(|l| l.trim() == BLOCK_END);
                    begin.zip(end).filter(|(b, e)| e >= b)
                };
                let mut visited = std::collections::HashSet::new();
                collect_agent_entries(
                    config_path,
                    0,
                    true,
                    skip_span,
                    &mut visited,
                    &mut warnings,
                    &mut entries,
                );
            }
            Err(e) => read_error = Some(e.to_string()),
        }
    }

    // A top-level approximation of ssh's "first matching value" semantics:
    // the first top-level (global scope) IdentityAgent; when only host-level
    // entries exist, no guess is made (the result differs per host), and the
    // anchor block value is used instead (`Host *` applies to all connections).
    let identity_agent_effective = entries
        .iter()
        .find(|e| e.keyword.eq_ignore_ascii_case("identityagent") && e.scope.is_empty())
        .map(|e| e.value.clone())
        .or(managed_block_value);
    let forward_agent_entries = entries
        .iter()
        .filter(|e| e.keyword.eq_ignore_ascii_case("forwardagent"))
        .cloned()
        .collect();
    let effective_socket = identity_agent_effective
        .clone()
        .or_else(|| ssh_auth_sock.clone());
    let socket_alive = effective_socket
        .as_deref()
        .map(|s| socket_probe(Path::new(s)));
    let persona_socket_alive = socket_probe(&agent_stable_socket());

    SshConfigAgentAnalysis {
        config_path: config_path.display().to_string(),
        config_exists: exists,
        readable: read_error.is_none(),
        read_error,
        warnings,
        entries,
        forward_agent_entries,
        identity_agent_effective,
        ssh_auth_sock,
        effective_socket,
        socket_alive,
        persona_socket_alive,
    }
}
