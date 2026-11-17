use std::path::PathBuf;

use super::git::discover_git_repo;

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
