use super::*;

pub(super) fn current_target_host() -> Option<String> {
    fn parse_connection_var(var: &str) -> Option<String> {
        std::env::var(var)
            .ok()
            .and_then(|value| value.split_whitespace().next().map(|s| s.to_string()))
    }

    fn parse_host_from_command(command: &str) -> Option<String> {
        let mut fallback = None;
        for raw_token in command.split_whitespace() {
            let token = raw_token.trim_matches(|c| c == '"' || c == '\'');
            if token.is_empty()
                || token.starts_with('-')
                || token.eq_ignore_ascii_case("ssh")
                || token.eq_ignore_ascii_case("ssh.exe")
                || token.starts_with('$')
            {
                continue;
            }

            let candidate = if let Some(idx) = token.rfind('@') {
                token[idx + 1..].to_string()
            } else if token.contains('/') || token.contains('=') {
                continue;
            } else {
                token.to_string()
            };

            let is_hostname = candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
            if !is_hostname {
                continue;
            }
            if candidate.contains('.') || candidate.contains(':') {
                return Some(candidate);
            }
            if fallback.is_none() {
                fallback = Some(candidate);
            }
        }
        fallback
    }

    if let Ok(value) = std::env::var("PERSONA_AGENT_TARGET_HOST") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    for var in ["PERSONA_AGENT_TARGET_HOST_HINT", "PERSONA_AGENT_SSH_DEST"] {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    for var in ["SSH_CONNECTION", "SSH_CLIENT"] {
        if let Some(host) = parse_connection_var(var) {
            if !host.is_empty() {
                return Some(host);
            }
        }
    }

    for var in [
        "PERSONA_AGENT_SSH_COMMAND",
        "SSH_ORIGINAL_COMMAND",
        "GIT_SSH_COMMAND",
    ] {
        if let Ok(cmd) = std::env::var(var) {
            if let Some(host) = parse_host_from_command(&cmd) {
                return Some(host);
            }
        }
    }

    None
}

pub(crate) fn is_host_in_known_hosts(host: &str) -> bool {
    let custom = std::env::var("PERSONA_KNOWN_HOSTS_FILE").ok();
    let paths = custom
        .into_iter()
        .map(PathBuf::from)
        .chain(dirs::home_dir().map(|p| p.join(".ssh").join("known_hosts")));
    for path in paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                if let Some(first) = line.split_whitespace().next() {
                    if first.split(',').any(|entry| entry == host) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub(super) fn resolve_persona_db_path() -> PathBuf {
    std::env::var("PERSONA_DB_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
                .join("identities.db")
        })
}

pub(super) fn detect_platform() -> Option<BiometricPlatform> {
    #[cfg(target_os = "macos")]
    {
        // Try to detect Touch ID vs Face ID
        // In a real implementation, you'd check hardware capabilities
        Some(BiometricPlatform::TouchId)
    }

    #[cfg(target_os = "windows")]
    {
        Some(BiometricPlatform::WindowsHello)
    }

    #[cfg(target_os = "linux")]
    {
        Some(BiometricPlatform::LinuxSecretService)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}
