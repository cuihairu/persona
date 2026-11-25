//! End-to-end walkthrough of the SSH agent integration (the evidence chain the
//! user walkthrough requires): isolated temp HOME (the real ~/.ssh/config is
//! never touched) -> drive the real command layer enable/disable -> real
//! OpenSSH `ssh -G` verifies identityagent resolves to the persona stable
//! socket -> after disabling, the rest of the user's config is restored
//! byte for byte.
//!
//! Separate test process: HOME/XDG_RUNTIME_DIR only affect this process (each
//! file under tests/ is its own binary), so the lib unit tests stay clean.
//! Environments without an ssh binary, or with OpenSSH < 8.3 (no IdentityAgent
//! support), are skipped automatically.
#![cfg(unix)]

use std::process::Command;

const SEED_CONFIG: &str = "\
# Personal SSH config (用户自己的配置，走查要求证明它不被触碰)
Host github.com
  User git
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes

Host bastion.example.com
  ProxyJump github.com
  ServerAliveInterval 60
";

/// Parse the OpenSSH major/minor version from `ssh -V` (stderr); IdentityAgent needs 8.3+.
fn openssh_version() -> Option<(u32, u32)> {
    let out = Command::new("ssh").arg("-V").output().ok()?;
    let text = String::from_utf8_lossy(&out.stderr);
    let rest = text.split("OpenSSH_").nth(1)?;
    let mut nums = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let major = nums.next()?.parse().ok()?;
    let minor = nums.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

/// Run `ssh -G <host>` and return stdout. Note: OpenSSH locates ~/.ssh/config
/// via the passwd home rather than the $HOME environment variable, so -F must
/// point explicitly at the config under test; HOME/XDG_RUNTIME_DIR are only
/// for the command layer's dirs probing.
fn ssh_g(host: &str, config: &std::path::Path) -> String {
    let out = Command::new("ssh")
        .args([
            "-F",
            config.to_str().expect("非 UTF-8 config 路径"),
            "-G",
            host,
        ])
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .expect("ssh -G spawn");
    assert!(out.status.success(), "ssh -G failed: {}", out.status);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn identityagent_line(g_output: &str) -> &str {
    g_output
        .lines()
        .find(|l| l.trim_start().starts_with("identityagent"))
        .unwrap_or("<identityagent 行缺失>")
}

#[test]
fn ssh_agent_integration_walkthrough_enable_ssh_g_disable_restores_user_config() {
    let Some((major, minor)) = openssh_version() else {
        eprintln!("WALKTHROUGH SKIP: 无 ssh 二进制");
        return;
    };
    if (major, minor) < (8, 3) {
        eprintln!("WALKTHROUGH SKIP: OpenSSH {major}.{minor} < 8.3，IdentityAgent 不支持");
        return;
    }

    let home = tempfile::tempdir().expect("temp home");
    let runtime = tempfile::tempdir().expect("temp XDG_RUNTIME_DIR");

    // Process-level HOME/XDG_RUNTIME_DIR: ssh_config_path()/agent_stable_socket()
    // both read them from env, and only this test process is affected (separate binary)
    std::env::set_var("HOME", home.path());
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());

    // 0700/0600: ssh warns about, and may even ignore, a config with permissions that are too loose
    let ssh_dir = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config_path = ssh_dir.join("config");
    std::fs::write(&config_path, SEED_CONFIG).unwrap();

    let socket = persona_desktop::ssh_integration::agent_stable_socket();
    let socket_str = socket.display().to_string();
    println!("WALKTHROUGH socket = {socket_str}");

    // -- Baseline: not enabled, ssh -G does not resolve to the persona socket --
    let baseline = ssh_g("github.com", &config_path);
    println!(
        "WALKTHROUGH baseline identityagent: {}",
        identityagent_line(&baseline)
    );
    assert!(
        !baseline.contains(&socket_str),
        "基线不应已指向 persona socket"
    );

    // -- Analysis baseline: no agent entry -> effective value unknown, status light = not enabled --
    let baseline_analysis = persona_desktop::commands::ssh_agent_config_analysis()
        .data
        .expect("config analysis 返回");
    println!(
        "WALKTHROUGH baseline analysis: effective={:?} sock_env={:?} alive={:?} persona_alive={}",
        baseline_analysis.identity_agent_effective,
        baseline_analysis.ssh_auth_sock,
        baseline_analysis.socket_alive,
        baseline_analysis.persona_socket_alive,
    );
    assert!(baseline_analysis.config_exists);
    assert!(baseline_analysis.readable);
    assert!(baseline_analysis.read_error.is_none());
    assert!(baseline_analysis.entries.is_empty());
    assert_eq!(baseline_analysis.identity_agent_effective, None);

    // -- Enable (real command layer: anchor block written idempotently) --
    let enabled = persona_desktop::commands::ssh_agent_integration_enable()
        .expect("enable command")
        .data
        .expect("enable 返回 status");
    println!(
        "WALKTHROUGH enable → enabled={} identity_agent={:?}",
        enabled.enabled, enabled.identity_agent
    );
    assert!(enabled.enabled);
    assert_eq!(enabled.identity_agent.as_deref(), Some(socket_str.as_str()));

    let on_disk = std::fs::read_to_string(&config_path).unwrap();
    assert!(on_disk.contains(persona_desktop::ssh_integration::BLOCK_BEGIN));
    assert!(on_disk.contains(&format!("IdentityAgent {socket_str}")));
    // The rest of the user's config is preserved verbatim
    assert!(on_disk.contains("IdentitiesOnly yes"));
    assert!(on_disk.contains("ProxyJump github.com"));
    println!("WALKTHROUGH config after enable:\n{on_disk}");

    // -- Core: real OpenSSH resolves this host's identityagent to the persona stable socket --
    let resolved = ssh_g("github.com", &config_path);
    println!("WALKTHROUGH full ssh -G stdout:\n{resolved}");
    let line = identityagent_line(&resolved);
    println!("WALKTHROUGH after-enable identityagent: {line}");
    assert_eq!(
        line.trim(),
        format!("identityagent {socket_str}"),
        "ssh -G 应解析到 persona 稳定 socket"
    );

    // -- Analysis flips (on): effective value = anchor block value, status light = enabled --
    let on_analysis = persona_desktop::commands::ssh_agent_config_analysis()
        .data
        .expect("config analysis 返回");
    println!(
        "WALKTHROUGH after-enable analysis: effective={:?} alive={:?} persona_alive={}",
        on_analysis.identity_agent_effective,
        on_analysis.socket_alive,
        on_analysis.persona_socket_alive,
    );
    assert_eq!(
        on_analysis.identity_agent_effective.as_deref(),
        Some(socket_str.as_str())
    );
    // Anchor block entries do not leak into the user's entry list (the seed config has none)
    assert!(on_analysis.entries.is_empty());
    // The temp XDG_RUNTIME_DIR has no agent process -> the light honestly shows not running / no listener
    assert!(!on_analysis.persona_socket_alive);
    assert_eq!(on_analysis.socket_alive, Some(false));

    // -- Disable (the anchor block is removed in one piece) --
    let disabled = persona_desktop::commands::ssh_agent_integration_disable()
        .expect("disable command")
        .data
        .expect("disable 返回 status");
    assert!(!disabled.enabled);
    assert_eq!(disabled.identity_agent, None);

    // The user's config is restored byte for byte (hard evidence that disabling only touches the anchor block)
    let restored = std::fs::read_to_string(&config_path).unwrap();
    assert_eq!(restored, SEED_CONFIG, "停用后用户配置应逐字节还原");

    let after = ssh_g("github.com", &config_path);
    println!(
        "WALKTHROUGH after-disable identityagent: {}",
        identityagent_line(&after)
    );
    assert!(
        !after.contains(&socket_str),
        "停用后不应再解析到 persona socket"
    );

    // -- Analysis flips back (off): the block is gone, effective value returns to unknown --
    let off_analysis = persona_desktop::commands::ssh_agent_config_analysis()
        .data
        .expect("config analysis 返回");
    assert_eq!(off_analysis.identity_agent_effective, None);
    assert!(off_analysis.entries.is_empty());
    println!(
        "WALKTHROUGH after-disable analysis: effective={:?} ✓ 状态灯翻回未启用",
        off_analysis.identity_agent_effective
    );
}
