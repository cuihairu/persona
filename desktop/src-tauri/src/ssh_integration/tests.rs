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
fn write_then_reread_round_trip_keeps_enabled_truthful() {
    // 真实文件往返：一键启用（upsert + 原子写）→ 按
    // ssh_agent_integration_status 的同一种读法回读 → enabled 判据必须为真；
    // 一键停用（整块移除 + 原子写）→ 回读必须为假。前端启用/停用后
    // 一律走这个回读点，所以这里钉住「写→读」的一致性。
    let dir = std::env::temp_dir().join(format!("persona-ssh-int-{}", std::process::id()));
    let path = dir.join(".ssh").join("config");
    let config = "Host github.com\n  User git\n";

    // 启用链路
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

    // 停用链路
    write_config_atomic(&path, &remove_managed_block(&reread)).expect("write disabled config");
    let reread = std::fs::read_to_string(&path).expect("reread disabled config");
    assert_eq!(managed_block_identity_agent(&reread), None);
    // 用户配置在两次往返中保持原样
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
    let cfg = "Host github.com\n  User git\n\nHost bastion.example.com\n  ProxyJump github.com\n";
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
    // 用测试内自造的不存在路径而非真实稳定 socket：探测断言不能依赖
    // 机器上是否恰有一个活 agent（并行测试/本机真实实例都会命中）。
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
    // 条目列表不含锚点块（那是 persona 自己写的，不是用户配置）
    assert!(a.entries.iter().all(|e| e.keyword != "IdentityAgent"));
    assert_eq!(a.forward_agent_entries.len(), 1);
    // 但生效判定包含块值：无用户全局条目时 ssh 实际用的就是块
    assert_eq!(a.identity_agent_effective.as_deref(), Some(agent.as_str()));
    assert_eq!(a.effective_socket.as_deref(), Some(agent.as_str()));
    // 路径不存在 → 探测 false（不是 None 的「未知」）
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
