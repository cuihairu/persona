use std::path::{Path, PathBuf};

use super::{BLOCK_BEGIN, BLOCK_END};

/// agent 稳定 socket 路径：desktop 壳启动 agent 前经
/// `PERSONA_AGENT_SOCKET_PATH` 注入 daemon，此函数返回同一路径供写入与比对。
pub fn agent_stable_socket() -> PathBuf {
    #[cfg(unix)]
    {
        // XDG_RUNTIME_DIR 是用户级 runtime 目录（/run/user/<uid>，重启清空，
        // 不会积累 stale socket）；缺失（某些 macOS/精简环境）退回 ~/.persona/run
        if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
            if !dir.is_empty() {
                let p = PathBuf::from(dir).join("persona").join("ssh-agent.sock");
                if std::fs::create_dir_all(p.parent().unwrap_or(Path::new("/"))).is_ok() {
                    return p;
                }
            }
        }
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".persona")
            .join("run")
            .join("ssh-agent.sock")
    }

    #[cfg(windows)]
    {
        // 命名管道稳定名；AgentListener::bind 取 file_name 造 \\.\pipe\{name}
        PathBuf::from("persona-ssh-agent")
    }
}

/// 写进 IdentityAgent 的值：unix 是绝对路径；windows 是完整管道路径。
pub fn identity_agent_value() -> String {
    #[cfg(unix)]
    {
        agent_stable_socket().display().to_string()
    }

    #[cfg(windows)]
    {
        format!(r"\\.\pipe\{}", agent_stable_socket().display())
    }
}

pub fn ssh_config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ssh")
        .join("config")
}

/// 抽出锚点块的 IdentityAgent 值；块损坏（有 begin 无 end）返回 None。
/// 多个值时取第一个（OpenSSH 语义也是先用）。
pub fn managed_block_identity_agent(config: &str) -> Option<String> {
    let begin = config.lines().position(|l| l.trim() == BLOCK_BEGIN)?;
    let end = config.lines().position(|l| l.trim() == BLOCK_END)?;
    if end < begin {
        return None;
    }
    config
        .lines()
        .skip(begin + 1)
        .take(end - begin - 1)
        .find_map(|l| {
            let t = l.trim();
            t.starts_with("IdentityAgent")
                .then(|| t.strip_prefix("IdentityAgent").map(str::trim))
                .flatten()
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        })
}

/// 锚点块之外是否存在指向 persona 的 IdentityAgent（用户手写的）
pub fn has_manual_persona_entry(config: &str) -> bool {
    let mut inside = false;
    config.lines().any(|l| {
        let t = l.trim();
        if t == BLOCK_BEGIN {
            inside = true;
            return false;
        }
        if t == BLOCK_END {
            inside = false;
            return false;
        }
        !inside && t.starts_with("IdentityAgent") && t.contains("persona")
    })
}

/// 幂等替换锚点块内容（保留块外一切）。无块则 append（前置空行分隔）；
/// 损坏块（begin 无 end）按删到 EOF 收敛。
pub fn upsert_managed_block(config: &str, identity_agent_value: &str) -> String {
    let block =
        format!("{BLOCK_BEGIN}\nHost *\nIdentityAgent {identity_agent_value}\n{BLOCK_END}\n");

    match (
        config.lines().position(|l| l.trim() == BLOCK_BEGIN),
        config.lines().position(|l| l.trim() == BLOCK_END),
    ) {
        (Some(begin), Some(end)) if end >= begin => rebuild(config, begin, end, &block),
        // 损坏块（begin 无 end，或 end 错位在 begin 前）：自 begin 删到 EOF
        // 收敛（head 里可能的孤儿 end 行一并滤除），再 append 完整块。
        (Some(begin), _) => {
            let head: String = config
                .lines()
                .take(begin)
                .filter(|l| l.trim() != BLOCK_END)
                .collect::<Vec<&str>>()
                .join("\n");
            let mut s = head.trim_end().to_string();
            if !s.is_empty() {
                s.push_str("\n\n");
            }
            s.push_str(&block);
            s
        }
        _ => {
            let mut s = String::from(config.trim_end());
            if !s.is_empty() {
                s.push_str("\n\n");
            }
            s.push_str(&block);
            s
        }
    }
}

/// 行级重建：[0, begin) + block + (end, len)
fn rebuild(config: &str, begin: usize, end: usize, block: &str) -> String {
    let mut out = String::new();
    for (i, line) in config.lines().enumerate() {
        if i < begin {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(block);
    for (i, line) in config.lines().enumerate() {
        if i > end {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 移除锚点块（含块后紧邻空行）；损坏块（begin 无 end/错位）删 begin 到 EOF。
pub fn remove_managed_block(config: &str) -> String {
    let Some(begin) = config.lines().position(|l| l.trim() == BLOCK_BEGIN) else {
        return config.to_string();
    };
    // 完好块保留 end 之后内容；end 缺失或错位在 begin 前一律删到 EOF
    let end = config
        .lines()
        .position(|l| l.trim() == BLOCK_END)
        .filter(|&e| e > begin);

    let mut out = String::new();
    for (i, line) in config.lines().enumerate() {
        if i < begin {
            out.push_str(line);
            out.push('\n');
        }
    }
    if let Some(end) = end {
        let mut skip_blank = true;
        for (i, line) in config.lines().enumerate() {
            if i > end {
                if skip_blank && line.trim().is_empty() {
                    continue;
                }
                skip_blank = false;
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    let trimmed = out.trim_end();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

/// 原子写 config：tmp + rename，保留原权限；无原文件时 0600（私网凭据配置）。
pub fn write_config_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let mode = std::fs::metadata(path).ok().map(|m| m.permissions());
    let tmp = path.with_extension("persona-tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    if let Some(m) = mode {
        let _ = std::fs::set_permissions(&tmp, m);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::rename(&tmp, path)
}
