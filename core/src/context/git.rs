use std::path::{Path, PathBuf};

/// 从 `start` 逐级上溯找 `.git`（目录或 worktree/submodule 指针文件），
/// 读 `[remote "origin"] url` 并归一化为 forge 身份。取不到（离线/损坏/
/// 非 Git 目录/本地路径 remote）返回 None，其余信号照常（设计 §10 降级）。
pub fn discover_git_repo(start: &Path) -> Option<String> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let dot_git = d.join(".git");
        if dot_git.is_dir() {
            return read_origin_remote(&dot_git);
        }
        if dot_git.is_file() {
            // worktree / submodule：`.git` 是 `gitdir: <path>` 指针
            if let Ok(text) = std::fs::read_to_string(&dot_git) {
                if let Some(line) = text.lines().find_map(|l| l.strip_prefix("gitdir:")) {
                    let p = PathBuf::from(line.trim());
                    let p = if p.is_absolute() { p } else { d.join(p) };
                    return read_origin_remote(&p);
                }
            }
            return None;
        }
        dir = d.parent();
    }
    None
}

/// 读 git 目录下的 `config`，取 origin 的 url 归一化。
fn read_origin_remote(git_dir: &Path) -> Option<String> {
    let config = std::fs::read_to_string(git_dir.join("config")).ok()?;
    parse_origin_url(&config)
}

/// 从 `.git/config` 文本解析 `[remote "origin"] url`（INI 子集：节头 +
/// `key = value` 行；容忍 CRLF 与缩进）。只有 pushurl 时返回 None。
pub fn parse_origin_url(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_origin = line.starts_with("[remote \"origin\"]");
            continue;
        }
        if !in_origin {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("url")
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix('='))
        {
            return normalize_remote_url(rest.trim());
        }
    }
    None
}

/// 把 remote url 归一化为 `host/owner/repo` 形式（设计 §4 的映射键）。
/// 支持 scp 语法（`git@host:path`）、ssh/https/http/git URL（含端口与
/// userinfo）；本地路径 remote（绝对路径/盘符）无 forge 身份，返回 None。
pub fn normalize_remote_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let bytes = url.as_bytes();
    let is_drive_letter = bytes.len() > 1 && bytes[1] == b':';
    let (host, path) = if let Some(rest) = url
        .strip_prefix("ssh://")
        .or_else(|| url.strip_prefix("git://"))
        .or_else(|| url.strip_prefix("https://"))
        .or_else(|| url.strip_prefix("http://"))
    {
        // rest = [user[:pass]@]host[:port]/path
        let rest = match rest.find('@') {
            Some(at) if rest.find('/').is_none_or(|s| at < s) => &rest[at + 1..],
            _ => rest,
        };
        let slash = rest.find('/')?;
        let host = &rest[..slash];
        let host = host.split(':').next().unwrap_or(host); // 去 :port
        (host.to_string(), rest[slash + 1..].to_string())
    } else if !url.starts_with('/') && !is_drive_letter {
        // scp 语法 [user@]host:path
        let colon = url.find(':')?;
        let mut host = url[..colon].to_string();
        if let Some(at) = host.rfind('@') {
            host = host[at + 1..].to_string();
        }
        (host, url[colon + 1..].to_string())
    } else {
        return None; // 本地路径 remote
    };
    if host.is_empty() {
        return None;
    }
    let path = path.trim().trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    Some(format!("{host}/{path}"))
}
