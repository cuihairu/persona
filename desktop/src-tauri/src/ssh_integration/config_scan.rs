// ---------------------------------------------------------------------------
// config 解析与 agent 面分析（Include 展开、作用域追踪、socket 探测）
//
// 只读：识别 agent 相关配置（IdentityAgent/ForwardAgent/AddKeysToAgent/
// ProxyAgent——最后一个非 OpenSSH 标准键，出现即在列表里如实展示）在哪些
// 文件哪些行哪些 Host/Match 作用域里；结合环境 SSH_AUTH_SOCK 与 Unix
// socket 连通探测给出「agent 是否开启/配置在哪/socket 路径」。任何失败
// 都进 read_error / warnings 字段如实显示，不让前端猜。
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};

use super::SshConfigEntry;

/// 分析关注的 agent 相关关键字（小写比对）。
const AGENT_KEYWORDS: [&str; 4] = [
    "identityagent",
    "forwardagent",
    "addkeystoagent",
    "proxyagent",
];
const INCLUDE_MAX_DEPTH: usize = 5;

/// 解析单行 → (keyword, value)。`Key Value` 与 `Key=Value` 两形态；
/// 注释/空行 → None。值去成对引号（不成对原样保留）。
pub(super) fn parse_ssh_line(line: &str) -> Option<(String, String)> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let (keyword, value) = match t.split_once('=') {
        // `Key=Value`：= 前不得有空白（`Host a = b` 之类按空白拆）
        Some((k, v)) if !k.trim().is_empty() && !k.contains(char::is_whitespace) => (k, v),
        _ => t.split_once(char::is_whitespace)?,
    };
    let value = value.trim();
    // `Key = value` 形态：空白拆分后值以 = 开头（ssh_config 允许 = 作分隔符）
    let value = value.strip_prefix('=').map(str::trim).unwrap_or(value);
    let value = match value.strip_prefix('"') {
        Some(rest) if rest.ends_with('"') => &rest[..rest.len() - 1],
        _ => value,
    };
    Some((keyword.trim().to_string(), value.to_string()))
}

/// 值拆 token：空白分隔，双引号内保留空白（OpenSSH Include 语义）。
fn split_tokens(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in value.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// 段内 glob 匹配（`*` 任意串、`?` 单字符；经典回溯）。
pub(super) fn glob_match(pat: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let (mut star_p, mut star_n) = (None::<usize>, 0usize);
    while n < name.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star_p = Some(p);
            star_n = n;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_n += 1;
            n = star_n;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// 展开含 `*`/`?` 的路径（逐段走文件系统；字面段直接拼）。返回现存文件。
fn expand_glob(pattern: &Path) -> Vec<PathBuf> {
    let mut current: Vec<PathBuf> = vec![PathBuf::new()];
    for comp in pattern.components() {
        let comp_str = comp.as_os_str().to_string_lossy();
        let mut next = Vec::new();
        for base in &current {
            if !comp_str.contains('*') && !comp_str.contains('?') {
                next.push(base.join(comp.as_os_str()));
            } else {
                let dir = if base.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    base.as_path()
                };
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        if glob_match(comp_str.as_bytes(), name.to_string_lossy().as_bytes()) {
                            next.push(base.join(name));
                        }
                    }
                }
            }
        }
        current = next;
    }
    current.into_iter().filter(|p| p.is_file()).collect()
}

/// Include token → 实际路径候选：`~` 展开；相对路径相对 `~/.ssh`
/// （OpenSSH 语义）；支持 glob。无匹配给警告。
fn expand_include_token(token: &str, warnings: &mut Vec<String>) -> Vec<PathBuf> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            warnings.push(format!("Include 无法解析（无 HOME）：{token}"));
            return Vec::new();
        }
    };
    let pattern = if let Some(rest) = token.strip_prefix("~/") {
        home.join(rest)
    } else if token.starts_with('/') {
        PathBuf::from(token)
    } else {
        home.join(".ssh").join(token)
    };
    let matched = expand_glob(&pattern);
    if matched.is_empty() {
        warnings.push(format!("Include 无匹配文件：{token}"));
    }
    matched
}

/// 深度优先展开 Include 并收集 agent 相关条目。`skip_span` 只对主 config
/// 生效（persona 锚点块行号区间——块状态单独看，不混进用户条目列表）。
pub(super) fn collect_agent_entries(
    path: &Path,
    depth: usize,
    is_root: bool,
    skip_span: Option<(usize, usize)>,
    visited: &mut std::collections::HashSet<PathBuf>,
    warnings: &mut Vec<String>,
    out: &mut Vec<SshConfigEntry>,
) {
    if depth > INCLUDE_MAX_DEPTH {
        warnings.push(format!(
            "Include 嵌套超过 {INCLUDE_MAX_DEPTH} 层，停止展开：{}",
            path.display()
        ));
        return;
    }
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical) {
        warnings.push(format!("Include 循环引用，停止展开：{}", path.display()));
        return;
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warnings.push(format!("无法读取 {}: {e}", path.display()));
            return;
        }
    };
    let file_display = path.display().to_string();
    let mut scope = String::new();
    for (idx, line) in content.lines().enumerate() {
        if is_root {
            if let Some((begin, end)) = skip_span {
                if idx >= begin && idx <= end {
                    continue;
                }
            }
        }
        let Some((keyword, value)) = parse_ssh_line(line) else {
            continue;
        };
        match keyword.to_ascii_lowercase().as_str() {
            "host" | "match" => scope = format!("{keyword} {value}"),
            "include" => {
                for token in split_tokens(&value) {
                    for included in expand_include_token(&token, warnings) {
                        collect_agent_entries(
                            &included,
                            depth + 1,
                            false,
                            None,
                            visited,
                            warnings,
                            out,
                        );
                    }
                }
            }
            k if AGENT_KEYWORDS.contains(&k) => out.push(SshConfigEntry {
                file: file_display.clone(),
                line: idx + 1,
                scope: scope.clone(),
                keyword,
                value,
            }),
            _ => {}
        }
    }
}

/// Unix socket 连通探测：能连上 = 有进程在听。Windows 走命名管道打开。
#[cfg(unix)]
pub(super) fn socket_probe(path: &Path) -> bool {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(path).is_ok()
}

#[cfg(windows)]
pub(super) fn socket_probe(path: &Path) -> bool {
    let s = path.display().to_string();
    let target = if s.starts_with(r"\\.\pipe\") {
        s
    } else {
        format!(r"\\.\pipe\{s}")
    };
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(target)
        .is_ok()
}

/// 从 `ssh -V` stderr 提取（展示标签, 主/次版本）。样本：
/// `OpenSSH_10.2p1 Ubuntu-…` / `OpenSSH_9.6p1, OpenSSL …` / `OpenSSH_8.3`。
pub(super) fn parse_ssh_version(stderr: &str) -> Option<(String, (u32, u32))> {
    let rest = stderr.split("OpenSSH_").nth(1)?;
    let token = rest.split(|c: char| c.is_whitespace() || c == ',').next()?;
    if token.is_empty() {
        return None;
    }
    let mut nums = token
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let major = nums.next()?.parse().ok()?;
    let minor = nums.next().unwrap_or("0").parse().ok()?;
    Some((format!("OpenSSH_{token}"), (major, minor)))
}

/// `ssh -V` 探测（版本号走 stderr，ssh 的约定）。未装 OpenSSH / 解析
/// 失败 → None，前端如实显示「未探测到」，不猜。
pub fn probe_ssh_version() -> Option<String> {
    let out = std::process::Command::new("ssh").arg("-V").output().ok()?;
    let text = String::from_utf8_lossy(&out.stderr);
    parse_ssh_version(&text).map(|(label, _)| label)
}
