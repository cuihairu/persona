//! 「SSH 走 persona agent」的 ~/.ssh/config 集成。
//!
//! 原理：OpenSSH 8.3+ 的 `IdentityAgent` 指令可为 host 指定 agent socket，
//! 等效于对单个 host 导出的 `SSH_AUTH_SOCK`。桌面壳把 agent 固定监听在
//! 稳定路径（见 [`agent_stable_socket`]），本模块把该路径写进 `~/.ssh/config`
//! 的 `# persona managed begin/end` 锚点注释块——只动块内，用户其余配置
//! 一律不碰；停用即整块移除。
//!
//! 作用域：OpenSSH 按文件顺序取「首个匹配该 host 的值」，而追加到 EOF 的
//! 配置行会落入用户**最后一个 Host/Match 块**的作用域（若用户 config 以
//! `Host github.com` 结尾，其他 host 根本拿不到 persona agent）。因此块内
//! 带一行 `Host *`：EOF 处的全域匹配对所有 host 生效，且用户写在文件更前
//! 面的 host 级 `IdentityAgent` 按 first-wins 语义原样优先。

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
    /// config 文件在盘上（不存在不算错误：首次启用会创建）
    pub config_exists: bool,
    /// 读失败原因（权限/IO）——如实显示，绝不静默吞（启用路径据此拒绝写）
    pub read_error: Option<String>,
}

/// 一条 agent 相关配置行（Include 展开后的真实来源）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigEntry {
    /// 来源文件（Include 展开前的主 config 或被 Include 的文件）
    pub file: String,
    /// 1 起的行号
    pub line: usize,
    /// 所处作用域：空串 = 顶层（对所有 host 生效）；否则 Host/Match 行原文
    pub scope: String,
    /// 关键字（原样大小写，比较时用小写）
    pub keyword: String,
    /// 值（去引号）
    pub value: String,
}

/// `~/.ssh/config`（含 Include 展开）的 agent 相关面分析。
/// 只读；任何失败都落到字段里如实显示，不让前端猜。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigAgentAnalysis {
    pub config_path: String,
    pub config_exists: bool,
    pub readable: bool,
    /// 读失败原因（权限/IO，如 config 是目录/权限不足）
    pub read_error: Option<String>,
    /// 非致命解析警告（Include 缺文件/循环/超深度/glob 无匹配）
    pub warnings: Vec<String>,
    /// agent 相关条目（含 Include 展开；persona 锚点块内不计——块状态单独看）
    pub entries: Vec<SshConfigEntry>,
    /// ForwardAgent 条目集合（on/off 值原样，作用域各自标明）
    pub forward_agent_entries: Vec<SshConfigEntry>,
    /// 生效 IdentityAgent：ssh 语义「首个匹配值」的顶层级近似——第一个
    /// 顶层（无 Host/Match 限定）条目优先；无用户全局条目时取 persona
    /// 锚点块值（Host * 对所有连接生效，块在 EOF 被更早条目压过）；两者
    /// 皆无时 None（对不同 host 结果不同，不妄断）。
    pub identity_agent_effective: Option<String>,
    /// 环境 SSH_AUTH_SOCK（无则 None）
    pub ssh_auth_sock: Option<String>,
    /// ssh 实际会用到的 socket：effective IdentityAgent 优先，其次环境
    pub effective_socket: Option<String>,
    /// effective_socket 的 Unix socket 连通探测（None = 平台不支持/无 socket）
    pub socket_alive: Option<bool>,
    /// persona agent 稳定 socket 是否有进程在听（= agent 运行中）
    pub persona_socket_alive: bool,
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

// ---------------------------------------------------------------------------
// config 解析与 agent 面分析（Include 展开、作用域追踪、socket 探测）
//
// 只读：识别 agent 相关配置（IdentityAgent/ForwardAgent/AddKeysToAgent/
// ProxyAgent——最后一个非 OpenSSH 标准键，出现即在列表里如实展示）在哪些
// 文件哪些行哪些 Host/Match 作用域里；结合环境 SSH_AUTH_SOCK 与 Unix
// socket 连通探测给出「agent 是否开启/配置在哪/socket 路径」。任何失败
// 都进 read_error / warnings 字段如实显示，不让前端猜。
// ---------------------------------------------------------------------------

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
fn parse_ssh_line(line: &str) -> Option<(String, String)> {
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
fn glob_match(pat: &[u8], name: &[u8]) -> bool {
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
fn collect_agent_entries(
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
fn socket_probe(path: &Path) -> bool {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(path).is_ok()
}

#[cfg(windows)]
fn socket_probe(path: &Path) -> bool {
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
fn parse_ssh_version(stderr: &str) -> Option<(String, (u32, u32))> {
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

/// 读 config（含 Include 展开）并分析 agent 相关面。任何失败落字段，
/// 绝不 panic、绝不静默吞。
pub fn analyze_config(config_path: &Path, ssh_auth_sock: Option<String>) -> SshConfigAgentAnalysis {
    let exists = config_path.exists();
    let mut read_error = None;
    let mut warnings = Vec::new();
    let mut entries = Vec::new();
    // 锚点块值参与生效判定：块追加在文件 EOF，用户更早的全局条目按
    // 「先出现先生效」压过它；没有用户全局条目时块值就是 ssh 实际用的值
    let mut managed_block_value = None;
    if exists {
        match std::fs::read_to_string(config_path) {
            Ok(content) => {
                managed_block_value = managed_block_identity_agent(&content);
                // 主文件里 persona 锚点块的行号区间（块内条目不计）
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

    // ssh 语义「首个匹配值」的顶层级近似：第一个顶层（全局作用域）
    // IdentityAgent；只有 host 级条目时不妄断（不同 host 结果不同），
    // 此时退锚点块值（Host * 对所有连接生效）。
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

    #[test]
    fn upsert_block_carries_host_star_so_eof_append_reaches_all_hosts() {
        // 用户 config 以具体 Host 块结尾：EOF 追加若无 Host * 会落入该块
        // 作用域，其他 host 静默拿不到 persona agent（走查实证的缺口）
        let cfg =
            "Host github.com\n  User git\n\nHost bastion.example.com\n  ProxyJump github.com\n";
        let out = upsert_managed_block(cfg, AGENT);
        let begin = out.find(BLOCK_BEGIN).unwrap();
        let end = out.find(BLOCK_END).unwrap();
        let block = &out[begin..end];
        let star = block.find("Host *").expect("块内应有 Host * 作用域行");
        let agent = block.find("IdentityAgent").expect("块内应有 IdentityAgent");
        assert!(star < agent, "Host * 必须排在 IdentityAgent 之前才生效");
        // 幂等：再跑一遍不重复
        assert_eq!(upsert_managed_block(&out, AGENT), out);
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

        let out = std::process::Command::new(&ssh)
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

        // 块外无关 host 同样解析到（Host * 作用域；块落在 Host example.test
        // 之后但不得被其作用域吞掉）
        let out2 = std::process::Command::new(&ssh)
            .args(["-G", "-F"])
            .arg(&config_path)
            .arg("unrelated.test")
            .output()
            .expect("ssh -G runs");
        assert!(out2.status.success(), "ssh -G failed: {out2:?}");
        let stdout2 = String::from_utf8_lossy(&out2.stdout);
        let line2 = stdout2
            .lines()
            .find(|l| l.starts_with("identityagent "))
            .unwrap_or_else(|| panic!("identityagent missing for unrelated host:\n{stdout2}"));
        assert_eq!(line2, format!("identityagent {AGENT}"));
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

    #[test]
    fn parse_ssh_line_handles_both_forms_and_comments() {
        assert_eq!(
            parse_ssh_line("  IdentityAgent /run/x  "),
            Some(("IdentityAgent".into(), "/run/x".into()))
        );
        assert_eq!(
            parse_ssh_line("forwardagent=/run/y"),
            Some(("forwardagent".into(), "/run/y".into()))
        );
        // `Key = value`（= 作分隔符）与成对引号值
        assert_eq!(
            parse_ssh_line("ForwardAgent = yes"),
            Some(("ForwardAgent".into(), "yes".into()))
        );
        assert_eq!(
            parse_ssh_line("ProxyAgent \"a b/c\""),
            Some(("ProxyAgent".into(), "a b/c".into()))
        );
        // 不成对引号原样保留
        assert_eq!(
            parse_ssh_line("IdentityAgent \"a b"),
            Some(("IdentityAgent".into(), "\"a b".into()))
        );
        assert_eq!(parse_ssh_line("# comment"), None);
        assert_eq!(parse_ssh_line("   "), None);
    }

    #[test]
    fn glob_match_segment_semantics() {
        assert!(glob_match(b"*", b"anything.conf"));
        assert!(glob_match(b"conf.d*", b"conf.d"));
        assert!(glob_match(b"*.conf", b"a.conf"));
        assert!(!glob_match(b"*.conf", b"a.conf.bak"));
        assert!(glob_match(b"file?", b"file1"));
        assert!(!glob_match(b"file?", b"file12"));
        assert!(glob_match(b"a*b*c", b"aXbYc"));
        assert!(!glob_match(b"a?c", b"ac"));
    }

    #[test]
    fn analyze_collects_agent_entries_across_scopes_and_includes() {
        let dir = tempfile::tempdir().unwrap();
        let inc_dir = dir.path().join("conf.d");
        std::fs::create_dir(&inc_dir).unwrap();
        std::fs::write(inc_dir.join("extra.conf"), "AddKeysToAgent yes\n").unwrap();
        let config_path = dir.path().join("config");
        // OpenSSH 语义：相对 Include 相对 ~/.ssh 解析，这里用绝对路径指向 tempdir；
        // 全局 IdentityAgent 必须在任何 Host/Match 之前（作用域持续到下一个块头）
        std::fs::write(
            &config_path,
            format!(
                "IdentityAgent /global/sock\nHost github.com\n  User git\n  ForwardAgent no\n\n\
                 Match host *.corp\n  IdentityAgent /match/sock\n\n\
                 Include {}\n",
                inc_dir.join("*.conf").display()
            ),
        )
        .unwrap();

        let a = analyze_config(&config_path, Some("/env/sock".into()));
        assert!(a.readable);
        assert!(a.read_error.is_none());
        assert!(a.warnings.is_empty(), "warnings: {:?}", a.warnings);
        // 作用域归属与行号（1 起）
        assert_eq!(a.forward_agent_entries.len(), 1);
        assert_eq!(a.forward_agent_entries[0].scope, "Host github.com");
        assert_eq!(a.forward_agent_entries[0].line, 4);
        // 顶层级首个 IdentityAgent 生效，环境变量被压后
        assert_eq!(a.identity_agent_effective.as_deref(), Some("/global/sock"));
        assert_eq!(a.effective_socket.as_deref(), Some("/global/sock"));
        // Include 展开进条目（file 指向被包含文件）
        let add = a
            .entries
            .iter()
            .find(|e| e.keyword == "AddKeysToAgent")
            .expect("Include 内条目应被收集");
        assert!(
            add.file.ends_with("conf.d/extra.conf"),
            "file: {}",
            add.file
        );
        assert_eq!(add.value, "yes");
        // Match 作用域条目如实展示，但不妄断生效值
        let m = a
            .entries
            .iter()
            .find(|e| e.keyword == "IdentityAgent" && e.scope.starts_with("Match"))
            .expect("Match 块条目应被收集");
        assert_eq!(m.value, "/match/sock");
        // 目标 socket 不存在 → 探测 false（不是 None 的「未知」）
        assert_eq!(a.socket_alive, Some(false));
        assert_eq!(a.ssh_auth_sock.as_deref(), Some("/env/sock"));
    }

    #[test]
    fn analyze_excludes_persona_managed_block_entries() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(
            &config_path,
            format!(
                "{BLOCK_BEGIN}\nHost *\n  IdentityAgent {AGENT}\n{BLOCK_END}\nHost a\n  ForwardAgent yes\n"
            ),
        )
        .unwrap();
        let a = analyze_config(&config_path, None);
        // 条目列表不含锚点块（那是 persona 自己写的，不是用户配置）
        assert!(a.entries.iter().all(|e| e.keyword != "IdentityAgent"));
        assert_eq!(a.forward_agent_entries.len(), 1);
        // 但生效判定包含块值：无用户全局条目时 ssh 实际用的就是块
        assert_eq!(a.identity_agent_effective.as_deref(), Some(AGENT));
        assert_eq!(a.effective_socket.as_deref(), Some(AGENT));
        // AGENT 路径在测试环境不存在 → 探测 false（不是 None 的「未知」）
        assert_eq!(a.socket_alive, Some(false));
    }

    #[test]
    fn user_global_identity_agent_beats_managed_block_first_wins() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        // 用户全局条目在前，块在 EOF：ssh first-wins 语义下用户条目生效
        std::fs::write(
            &config_path,
            format!(
                "IdentityAgent /user/global.sock\n\n{BLOCK_BEGIN}\nHost *\n  IdentityAgent {AGENT}\n{BLOCK_END}\n"
            ),
        )
        .unwrap();
        let a = analyze_config(&config_path, None);
        assert_eq!(
            a.identity_agent_effective.as_deref(),
            Some("/user/global.sock")
        );
        assert_eq!(a.effective_socket.as_deref(), Some("/user/global.sock"));
    }

    #[test]
    fn analyze_warns_on_missing_and_circular_includes() {
        let dir = tempfile::tempdir().unwrap();
        let a_path = dir.path().join("a.conf");
        let b_path = dir.path().join("b.conf");
        let root = dir.path().join("root.conf");
        // root → a →（缺失 glob + 指回 root 的环）；root → b（正常条目）
        std::fs::write(
            &a_path,
            format!("Include missing-glob-*.conf\nInclude {}\n", root.display()),
        )
        .unwrap();
        std::fs::write(&b_path, "AddKeysToAgent yes\n").unwrap();
        std::fs::write(
            &root,
            format!(
                "Include {}\nInclude {}\n",
                a_path.display(),
                b_path.display()
            ),
        )
        .unwrap();

        let a = analyze_config(&root, None);
        assert!(a.warnings.iter().any(|w| w.contains("无匹配文件")));
        assert!(a.warnings.iter().any(|w| w.contains("循环引用")));
        // 环不挡正常收集：b.conf 的条目照进列表
        assert_eq!(a.entries.len(), 1);
        assert_eq!(a.entries[0].keyword, "AddKeysToAgent");
    }

    #[test]
    fn analyze_missing_config_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope");
        let a = analyze_config(&p, Some("/env".into()));
        assert!(!a.config_exists);
        assert!(a.read_error.is_none());
        assert!(a.entries.is_empty());
        // 生效 socket 退回环境变量
        assert_eq!(a.effective_socket.as_deref(), Some("/env"));
    }

    #[test]
    fn parse_ssh_version_extracts_label_and_numbers() {
        assert_eq!(
            parse_ssh_version("OpenSSH_10.2p1 Ubuntu-3ubuntu1, OpenSSL 3.0.13"),
            Some(("OpenSSH_10.2p1".into(), (10, 2)))
        );
        assert_eq!(
            parse_ssh_version("OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024"),
            Some(("OpenSSH_9.6p1".into(), (9, 6)))
        );
        // 无 p 后缀
        assert_eq!(
            parse_ssh_version("OpenSSH_8.3\n"),
            Some(("OpenSSH_8.3".into(), (8, 3)))
        );
        // 不是 OpenSSH（如 Windows 的 Win32-OpenSSH 也会带 OpenSSH_，但
        // 完全无关的输出应回 None）
        assert_eq!(
            parse_ssh_version("usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy]"),
            None
        );
        assert_eq!(parse_ssh_version(""), None);
    }

    #[test]
    fn analyze_reports_unreadable_config_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        // 路径是目录：确定性的读失败（不依赖 chmod，CI root 也能跑）
        let as_dir = dir.path().join("config");
        std::fs::create_dir(&as_dir).unwrap();
        let a = analyze_config(&as_dir, None);
        assert!(a.config_exists);
        assert!(!a.readable);
        assert!(a.read_error.is_some());
        assert!(a.entries.is_empty());
    }
}
