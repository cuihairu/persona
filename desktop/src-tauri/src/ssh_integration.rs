//! 「SSH 走 persona agent」的 ~/.ssh/config 集成。
//!
//! 原理：OpenSSH 8.3+ 的 `IdentityAgent` 指令可为 host 指定 agent socket，
//! 等效于对单个 host 导出的 `SSH_AUTH_SOCK`。桌面壳把 agent 固定监听在
//! 稳定路径（见 [`agent_stable_socket`]），本模块把该路径写进 `~/.ssh/config`
//! 的 `# persona managed begin/end` 锚点注释块——只动块内，用户其余配置
//! 一律不碰；停用即整块移除。

use std::path::{Path, PathBuf};

use serde::Serialize;

/// 锚点注释：块识别的唯一标记，改动会破坏老配置的停用路径
pub const BLOCK_BEGIN: &str = "# persona managed begin";
pub const BLOCK_END: &str = "# persona managed end";

/// 集成状态三态由前端按 `enabled`/`anomaly` 组合渲染
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshIntegrationStatus {
    /// 锚点块存在且 IdentityAgent 指向当前稳定 socket
    pub enabled: bool,
    /// 锚点块存在但指向别处（旧路径/手改过）——重新启用即可修复
    pub anomaly: Option<String>,
    /// 锚点块外用户手写的 persona IdentityAgent（提示但不自动动它）
    pub manual_entry: bool,
    pub config_path: String,
    /// agent 稳定 socket（写入值/比对基准）
    pub socket_path: String,
    /// 锚点块当前的 IdentityAgent 值（未启用时 None）
    pub identity_agent: Option<String>,
    /// OpenSSH < 8.3 不支持 IdentityAgent（version 探测失败时不填）
    pub ssh_version: Option<String>,
}

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
    let block = format!("{BLOCK_BEGIN}\nIdentityAgent {identity_agent_value}\n{BLOCK_END}\n");

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

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "/run/user/1000/persona/ssh-agent.sock";

    #[test]
    fn upsert_appends_when_absent_and_is_idempotent() {
        let cfg = "Host github.com\n  User git\n";
        let a = upsert_managed_block(cfg, AGENT);
        assert!(a.contains(BLOCK_BEGIN));
        assert!(a.contains(&format!("IdentityAgent {AGENT}")));
        assert!(a.contains("Host github.com"));
        // 再跑一遍：块不重复、内容一致
        let b = upsert_managed_block(&a, AGENT);
        assert_eq!(a, b);
        assert_eq!(b.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn upsert_updates_existing_block_only() {
        let with_block = format!(
            "Host a\n  IdentityAgent /old/path\n\n{BLOCK_BEGIN}\nIdentityAgent /old/persona\n{BLOCK_END}\n\nHost b\n  User git\n"
        );
        let updated = upsert_managed_block(&with_block, AGENT);
        assert!(updated.contains(&format!("IdentityAgent {AGENT}")));
        assert!(!updated.contains("/old/persona"));
        // 用户块外的 IdentityAgent 原样保留
        assert!(updated.contains("IdentityAgent /old/path"));
        assert!(updated.contains("Host b"));
    }

    #[test]
    fn remove_strips_block_and_blank_run_but_keeps_user_config() {
        let with_block = format!(
            "Host a\n  User git\n\n{BLOCK_BEGIN}\nIdentityAgent {AGENT}\n{BLOCK_END}\n\nHost b\n  User git\n"
        );
        let cleaned = remove_managed_block(&with_block);
        assert!(!cleaned.contains(BLOCK_BEGIN));
        assert!(!cleaned.contains("IdentityAgent"));
        assert!(cleaned.contains("Host a"));
        assert!(cleaned.contains("Host b"));
        // 幂等
        assert_eq!(remove_managed_block(&cleaned), cleaned);
    }

    #[test]
    fn damaged_block_begin_without_end_is_replaced_not_duplicated() {
        let damaged = format!("Host a\n\n{BLOCK_BEGIN}\nIdentityAgent /stale\n");
        let fixed = upsert_managed_block(&damaged, AGENT);
        assert_eq!(fixed.matches(BLOCK_BEGIN).count(), 1);
        assert!(fixed.contains(&format!("IdentityAgent {AGENT}")));
        assert!(!fixed.contains("/stale"));
        // remove 同样收敛损坏块
        assert!(!remove_managed_block(&fixed).contains(BLOCK_BEGIN));
        let damaged2 = format!("Host a\n\n{BLOCK_BEGIN}\nIdentityAgent /stale\n");
        let cleaned = remove_managed_block(&damaged2);
        assert!(!cleaned.contains("/stale"));
        assert!(cleaned.contains("Host a"));
    }

    #[test]
    fn managed_block_identity_agent_reads_value() {
        let cfg = format!("x\n{BLOCK_BEGIN}\nIdentityAgent {AGENT}\n{BLOCK_END}\n");
        assert_eq!(managed_block_identity_agent(&cfg).as_deref(), Some(AGENT));
        assert_eq!(managed_block_identity_agent("no block"), None);
        // 有 begin 无 end = 损坏
        assert_eq!(
            managed_block_identity_agent(&format!("{BLOCK_BEGIN}\nIdentityAgent p\n")),
            None
        );
    }

    #[test]
    fn manual_entry_detection_ignores_managed_block() {
        let cfg = format!(
            "{BLOCK_BEGIN}\nIdentityAgent {AGENT}\n{BLOCK_END}\nHost a\n  IdentityAgent /home/me/persona-sock\n"
        );
        assert!(has_manual_persona_entry(&cfg));
        let only_managed = format!("{BLOCK_BEGIN}\nIdentityAgent {AGENT}\n{BLOCK_END}\n");
        assert!(!has_manual_persona_entry(&only_managed));
        // 大小写不敏感的 persona 线索
        let other = "Host a\n  IdentityAgent /other\n";
        assert!(!has_manual_persona_entry(other));
    }

    /// 硬验收：OpenSSH 真实解析锚点块（注释行不得干扰 IdentityAgent）。
    /// `ssh -G -F <file> <host>` 输出归一化配置；无 ssh（精简 CI 容器）则跳过。
    #[cfg(unix)]
    #[test]
    fn ssh_g_resolves_identity_agent_from_managed_block() {
        let Some(ssh) = which_ssh() else {
            eprintln!("ssh not on PATH; skipping OpenSSH round-trip");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        let cfg = format!(
            "Host example.test\n  User git\n\n{}\n",
            upsert_managed_block("", AGENT)
        );
        std::fs::write(&config_path, &cfg).unwrap();

        let out = std::process::Command::new(ssh)
            .args(["-G", "-F"])
            .arg(&config_path)
            .arg("example.test")
            .output()
            .expect("ssh -G runs");
        assert!(out.status.success(), "ssh -G failed: {out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.starts_with("identityagent "))
            .unwrap_or_else(|| panic!("identityagent missing in ssh -G output:\n{stdout}"));
        assert_eq!(line, format!("identityagent {AGENT}"));
        // 用户配置照常生效
        assert!(stdout.lines().any(|l| l == "user git"));
    }

    #[cfg(unix)]
    fn which_ssh() -> Option<std::path::PathBuf> {
        for dir in std::env::var("PATH").ok()?.split(':') {
            let p = Path::new(dir).join("ssh");
            if p.is_file() {
                return Some(p);
            }
        }
        None
    }
}
