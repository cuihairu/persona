use super::*;

// Host detection fallbacks / db path / parsing edges
// ------------------------------------------------------------------

#[test]
fn current_target_host_command_and_connection_fallbacks() {
    let _guard = env_lock();
    for var in [
        "PERSONA_AGENT_TARGET_HOST",
        "PERSONA_AGENT_TARGET_HOST_HINT",
        "PERSONA_AGENT_SSH_DEST",
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "PERSONA_AGENT_SSH_COMMAND",
        "SSH_ORIGINAL_COMMAND",
        "GIT_SSH_COMMAND",
    ] {
        std::env::remove_var(var);
    }

    // SSH_CLIENT second-priority connection var.
    std::env::set_var("SSH_CLIENT", "10.0.0.9 2222 10.0.0.1 22");
    assert_eq!(current_target_host().as_deref(), Some("10.0.0.9"));
    std::env::remove_var("SSH_CLIENT");

    // PERSONA_AGENT_SSH_COMMAND parsed for a bare (dotless) hostname.
    std::env::set_var("PERSONA_AGENT_SSH_COMMAND", "ssh admin@intranet");
    assert_eq!(current_target_host().as_deref(), Some("intranet"));
    std::env::remove_var("PERSONA_AGENT_SSH_COMMAND");

    // SSH_ORIGINAL_COMMAND wins over GIT_SSH_COMMAND and filters flags/paths.
    std::env::set_var(
        "SSH_ORIGINAL_COMMAND",
        "ssh -p 2222 deploy@host.example.com",
    );
    std::env::set_var("GIT_SSH_COMMAND", "ssh git@other.example.com");
    assert_eq!(current_target_host().as_deref(), Some("host.example.com"));
    std::env::remove_var("SSH_ORIGINAL_COMMAND");
    std::env::remove_var("GIT_SSH_COMMAND");

    // Only path-like / flag tokens -> None.
    std::env::set_var("GIT_SSH_COMMAND", "ssh /usr/bin/git-cleanup");
    assert_eq!(current_target_host(), None);
    std::env::remove_var("GIT_SSH_COMMAND");

    // A quoted $variable is filtered; nothing else qualifies -> None.
    std::env::set_var("PERSONA_AGENT_SSH_COMMAND", "ssh \"$TARGET\"");
    assert_eq!(current_target_host(), None);
    std::env::remove_var("PERSONA_AGENT_SSH_COMMAND");
}

#[test]
fn resolve_persona_db_path_prefers_env_override() {
    let _guard = env_lock();

    let dir = tempfile::tempdir().unwrap();
    let custom = dir.path().join("custom.db");
    std::env::set_var("PERSONA_DB_PATH", &custom);
    assert_eq!(resolve_persona_db_path(), custom);

    std::env::remove_var("PERSONA_DB_PATH");
    let fallback = resolve_persona_db_path();
    assert!(fallback.ends_with(".persona/identities.db"));
}

#[test]
fn parse_public_line_to_blob_rejects_malformed_lines() {
    assert_eq!(parse_public_line_to_blob(""), None);
    assert_eq!(parse_public_line_to_blob("ssh-ed25519 !!!not-b64!!!"), None);
    assert_eq!(parse_public_line_to_blob("garbage"), None);
}

#[test]
fn current_target_host_skips_invalid_tokens_and_blank_hints() {
    let _guard = env_lock();
    for var in [
        "PERSONA_AGENT_TARGET_HOST",
        "PERSONA_AGENT_TARGET_HOST_HINT",
        "PERSONA_AGENT_SSH_DEST",
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "PERSONA_AGENT_SSH_COMMAND",
        "SSH_ORIGINAL_COMMAND",
        "GIT_SSH_COMMAND",
    ] {
        std::env::remove_var(var);
    }

    // A token that is not a hostname (illegal characters) is skipped and
    // no fallback host remains.
    std::env::set_var("GIT_SSH_COMMAND", "ssh user@bad!host.example");
    assert_eq!(current_target_host(), None);
    std::env::remove_var("GIT_SSH_COMMAND");

    // Blank hint/dest values are skipped and SSH_CONNECTION wins.
    std::env::set_var("PERSONA_AGENT_TARGET_HOST_HINT", "   ");
    std::env::set_var("PERSONA_AGENT_SSH_DEST", "");
    std::env::set_var("SSH_CONNECTION", "9.9.9.9 1 2");
    assert_eq!(current_target_host().as_deref(), Some("9.9.9.9"));
}
