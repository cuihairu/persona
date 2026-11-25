use std::path::{Path, PathBuf};

/// Walk up from `start` looking for `.git` (a directory or a
/// worktree/submodule pointer file), read `[remote "origin"] url` and
/// normalize it into a forge identity. Returns None when nothing can be
/// obtained (offline/corrupted/not a Git directory/local-path remote);
/// the other signals proceed as usual (design §10 degradation).
pub fn discover_git_repo(start: &Path) -> Option<String> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let dot_git = d.join(".git");
        if dot_git.is_dir() {
            return read_origin_remote(&dot_git);
        }
        if dot_git.is_file() {
            // worktree / submodule: `.git` is a `gitdir: <path>` pointer
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

/// Read the `config` under the git directory and normalize origin's url.
fn read_origin_remote(git_dir: &Path) -> Option<String> {
    let config = std::fs::read_to_string(git_dir.join("config")).ok()?;
    parse_origin_url(&config)
}

/// Parse `[remote "origin"] url` out of `.git/config` text (an INI
/// subset: section headers + `key = value` lines; tolerates CRLF and
/// indentation). Returns None when there is only a pushurl.
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

/// Normalize a remote url into `host/owner/repo` form (the mapping key
/// in design §4). Supports scp syntax (`git@host:path`) and
/// ssh/https/http/git URLs (including ports and userinfo); local-path
/// remotes (absolute path / drive letter) carry no forge identity and
/// return None.
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
        let host = host.split(':').next().unwrap_or(host); // drop :port
        (host.to_string(), rest[slash + 1..].to_string())
    } else if !url.starts_with('/') && !is_drive_letter {
        // scp syntax [user@]host:path
        let colon = url.find(':')?;
        let mut host = url[..colon].to_string();
        if let Some(at) = host.rfind('@') {
            host = host[at + 1..].to_string();
        }
        (host, url[colon + 1..].to_string())
    } else {
        return None; // local-path remote
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
