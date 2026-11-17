use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
