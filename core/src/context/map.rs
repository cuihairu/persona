use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A mapping entry: pattern → identity name. Repo-local mappings may
/// only reference identity names in plaintext; no secret material is
/// involved (design §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityEntry {
    pub identity: String,
}

/// File model for `context.toml`. TOML shape:
///
/// ```toml
/// `[project."github.com/cuihairu/persona"]`
/// identity = "OpenSource"
///
/// [host ".*-server$"]
/// identity = "Ops"
/// ```
///
/// BTreeMap keeps the file-rewrite output order stable; keys are the raw
/// pattern text (as written inside quotes, including `.` and `/`).
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

    /// Empty table (no entries at all).
    pub fn is_empty(&self) -> bool {
        self.projects.is_empty() && self.hosts.is_empty()
    }
}
