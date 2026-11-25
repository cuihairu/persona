use super::config_scan::{glob_match, parse_ssh_line, parse_ssh_version};
use super::*;

const AGENT: &str = "/run/user/1000/persona/ssh-agent.sock";

#[test]
fn upsert_appends_when_absent_and_is_idempotent() {
    let cfg = "Host github.com\n  User git\n";
    let a = upsert_managed_block(cfg, AGENT);
    assert!(a.contains(BLOCK_BEGIN));
    assert!(a.contains(&format!("IdentityAgent {AGENT}")));
    assert!(a.contains("Host github.com"));
    // Run it again: no duplicate block, identical content
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
    // The IdentityAgent outside the managed block is preserved as-is
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
    // Idempotent
    assert_eq!(remove_managed_block(&cleaned), cleaned);
}

#[test]
fn write_then_reread_round_trip_keeps_enabled_truthful() {
    // Real-file round trip: one-click enable (upsert + atomic write) -> re-read using the same
    // path ssh_agent_integration_status uses -> the enabled criterion must be true; one-click
    // disable (remove the whole block + atomic write) -> re-reading must be false. The frontend
    // always goes through this re-read point after enable/disable, so this pins the
    // "write -> read" consistency.
    let dir = std::env::temp_dir().join(format!("persona-ssh-int-{}", std::process::id()));
    let path = dir.join(".ssh").join("config");
    let config = "Host github.com\n  User git\n";

    // Enable path
    write_config_atomic(&path, &upsert_managed_block(config, AGENT)).expect("write enabled config");
    let (reread, read_error) = match std::fs::read_to_string(&path) {
        Ok(c) => (c, None),
        Err(e) => (String::new(), Some(e.to_string())),
    };
    assert_eq!(read_error, None);
    assert_eq!(
        managed_block_identity_agent(&reread).as_deref(),
        Some(AGENT),
        "enabled 判据（锚点块 == agent socket）在回读后必须为真"
    );

    // Disable path
    write_config_atomic(&path, &remove_managed_block(&reread)).expect("write disabled config");
    let reread = std::fs::read_to_string(&path).expect("reread disabled config");
    assert_eq!(managed_block_identity_agent(&reread), None);
    // The user config survives both round trips untouched
    assert!(reread.contains("Host github.com"));
    assert!(reread.contains("  User git"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn damaged_block_begin_without_end_is_replaced_not_duplicated() {
    let damaged = format!("Host a\n\n{BLOCK_BEGIN}\nIdentityAgent /stale\n");
    let fixed = upsert_managed_block(&damaged, AGENT);
    assert_eq!(fixed.matches(BLOCK_BEGIN).count(), 1);
    assert!(fixed.contains(&format!("IdentityAgent {AGENT}")));
    assert!(!fixed.contains("/stale"));
    // remove likewise converges the damaged block
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
    // A begin without an end = damaged
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
    // Case-insensitive persona hint
    let other = "Host a\n  IdentityAgent /other\n";
    assert!(!has_manual_persona_entry(other));
}

#[test]
fn upsert_block_carries_host_star_so_eof_append_reaches_all_hosts() {
    // A user config ending in a specific Host block: an EOF append without Host * would land in
    // that block's scope, and other hosts would silently get no persona agent (a gap proven by
    // the real ssh -G run)
    let cfg = "Host github.com\n  User git\n\nHost bastion.example.com\n  ProxyJump github.com\n";
    let out = upsert_managed_block(cfg, AGENT);
    let begin = out.find(BLOCK_BEGIN).unwrap();
    let end = out.find(BLOCK_END).unwrap();
    let block = &out[begin..end];
    let star = block.find("Host *").expect("块内应有 Host * 作用域行");
    let agent = block.find("IdentityAgent").expect("块内应有 IdentityAgent");
    assert!(star < agent, "Host * 必须排在 IdentityAgent 之前才生效");
    // Idempotent: a second run adds nothing
    assert_eq!(upsert_managed_block(&out, AGENT), out);
}

/// Hard acceptance: real OpenSSH parsing of the anchor block (comment lines must not interfere
/// with IdentityAgent). `ssh -G -F <file> <host>` prints the normalized configuration; skipped
/// when ssh is unavailable (slim CI container).
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
    // The user config still takes effect as usual
    assert!(stdout.lines().any(|l| l == "user git"));

    // An unrelated host outside the block also resolves to it (Host * scope; the block comes
    // after Host example.test but must not be swallowed by that block's scope)
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
    // `Key = value` (using = as the separator) and paired quoted values
    assert_eq!(
        parse_ssh_line("ForwardAgent = yes"),
        Some(("ForwardAgent".into(), "yes".into()))
    );
    assert_eq!(
        parse_ssh_line("ProxyAgent \"a b/c\""),
        Some(("ProxyAgent".into(), "a b/c".into()))
    );
    // Unpaired quotes are kept verbatim
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
    // OpenSSH semantics: a relative Include resolves against ~/.ssh, so an absolute path pointing
    // into the tempdir is used here; a global IdentityAgent must precede any Host/Match (its
    // scope extends until the next block header)
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
    // Scope attribution and line numbers (1-based)
    assert_eq!(a.forward_agent_entries.len(), 1);
    assert_eq!(a.forward_agent_entries[0].scope, "Host github.com");
    assert_eq!(a.forward_agent_entries[0].line, 4);
    // The first top-level IdentityAgent wins, and the env var ranks below it
    assert_eq!(a.identity_agent_effective.as_deref(), Some("/global/sock"));
    assert_eq!(a.effective_socket.as_deref(), Some("/global/sock"));
    // Include expands into entries (file points at the included file)
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
    // Match-scope entries are shown as they are, without presuming they take effect
    let m = a
        .entries
        .iter()
        .find(|e| e.keyword == "IdentityAgent" && e.scope.starts_with("Match"))
        .expect("Match 块条目应被收集");
    assert_eq!(m.value, "/match/sock");
    // Target socket doesn't exist -> probe is false (not None's "unknown")
    assert_eq!(a.socket_alive, Some(false));
    assert_eq!(a.ssh_auth_sock.as_deref(), Some("/env/sock"));
}

#[test]
fn analyze_excludes_persona_managed_block_entries() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    // A nonexistent path fabricated inside the test rather than a real, well-known socket: the
    // probe assertions must not depend on whether the machine happens to have one live agent
    // (parallel tests / a real local instance would both match).
    let agent = dir.path().join("absent-agent.sock");
    let agent = agent.to_string_lossy().to_string();
    std::fs::write(
            &config_path,
            format!(
                "{BLOCK_BEGIN}\nHost *\n  IdentityAgent {agent}\n{BLOCK_END}\nHost a\n  ForwardAgent yes\n"
            ),
        )
        .unwrap();
    let a = analyze_config(&config_path, None);
    // The entry list excludes the anchor block (persona wrote that itself, it isn't user config)
    assert!(a.entries.iter().all(|e| e.keyword != "IdentityAgent"));
    assert_eq!(a.forward_agent_entries.len(), 1);
    // But the effective-value judgement does include the block's value: with no user global
    // entry, that is what ssh actually uses
    assert_eq!(a.identity_agent_effective.as_deref(), Some(agent.as_str()));
    assert_eq!(a.effective_socket.as_deref(), Some(agent.as_str()));
    // The path doesn't exist -> probe is false (not None's "unknown")
    assert_eq!(a.socket_alive, Some(false));
}

#[test]
fn user_global_identity_agent_beats_managed_block_first_wins() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    // The user's global entry comes first and the block is at EOF: under ssh's first-wins
    // semantics the user entry takes effect
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
    // root -> a -> (missing glob + a cycle back to root); root -> b (a normal entry)
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
    // The cycle doesn't block ordinary collection: b.conf's entry still lands in the list
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
    // The effective socket falls back to the environment variable
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
    // No p suffix
    assert_eq!(
        parse_ssh_version("OpenSSH_8.3\n"),
        Some(("OpenSSH_8.3".into(), (8, 3)))
    );
    // Not OpenSSH (Windows' Win32-OpenSSH also carries OpenSSH_, but wholly unrelated output
    // should return None)
    assert_eq!(
        parse_ssh_version("usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy]"),
        None
    );
    assert_eq!(parse_ssh_version(""), None);
}

#[test]
fn analyze_reports_unreadable_config_instead_of_panicking() {
    let dir = tempfile::tempdir().unwrap();
    // The path is a directory: a deterministic read failure (doesn't rely on chmod, so it runs
    // even as root in CI)
    let as_dir = dir.path().join("config");
    std::fs::create_dir(&as_dir).unwrap();
    let a = analyze_config(&as_dir, None);
    assert!(a.config_exists);
    assert!(!a.readable);
    assert!(a.read_error.is_some());
    assert!(a.entries.is_empty());
}
