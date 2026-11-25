use std::path::{Path, PathBuf};

use super::{BLOCK_BEGIN, BLOCK_END};

/// The agent's stable socket path: the desktop shell injects it into the daemon
/// via `PERSONA_AGENT_SOCKET_PATH` before starting the agent, and this function
/// returns the same path for writing and comparison.
pub fn agent_stable_socket() -> PathBuf {
    #[cfg(unix)]
    {
        // XDG_RUNTIME_DIR is the user-level runtime directory (/run/user/<uid>,
        // cleared on reboot so stale sockets do not accumulate); when missing
        // (some macOS / minimal environments) fall back to ~/.persona/run
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
        // Stable named-pipe name; AgentListener::bind takes the file_name to build \\.\pipe\{name}
        PathBuf::from("persona-ssh-agent")
    }
}

/// The value written into IdentityAgent: on unix an absolute path; on windows
/// the full pipe path.
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

/// Extract the IdentityAgent value from the anchor block; a corrupted block
/// (begin without end) returns None.
/// When multiple values exist, take the first (OpenSSH also applies the first).
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

/// Whether an IdentityAgent pointing at persona exists outside the anchor block
/// (hand-written by the user)
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

/// Idempotently replace the anchor block's contents (preserving everything
/// outside the block). With no block, append (separated by a leading blank
/// line); a corrupted block (begin without end) converges by deleting to EOF.
pub fn upsert_managed_block(config: &str, identity_agent_value: &str) -> String {
    let block =
        format!("{BLOCK_BEGIN}\nHost *\nIdentityAgent {identity_agent_value}\n{BLOCK_END}\n");

    match (
        config.lines().position(|l| l.trim() == BLOCK_BEGIN),
        config.lines().position(|l| l.trim() == BLOCK_END),
    ) {
        (Some(begin), Some(end)) if end >= begin => rebuild(config, begin, end, &block),
        // Corrupted block (begin without end, or an end misplaced before begin):
        // converge by deleting from begin to EOF (any orphan end lines in the
        // head are filtered out too), then append the complete block.
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

/// Line-level rebuild: [0, begin) + block + (end, len)
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

/// Remove the anchor block (including a blank line immediately after it); a
/// corrupted block (begin without end / misplaced) is deleted from begin to EOF.
pub fn remove_managed_block(config: &str) -> String {
    let Some(begin) = config.lines().position(|l| l.trim() == BLOCK_BEGIN) else {
        return config.to_string();
    };
    // An intact block keeps content after end; a missing end or one misplaced
    // before begin always deletes to EOF
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

/// Write the config atomically: tmp + rename, preserving the original
/// permissions; 0600 when there is no original file (private-network credential
/// config).
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
