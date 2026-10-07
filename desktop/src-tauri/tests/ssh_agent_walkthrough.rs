//! SSH agent 集成端到端走查（用户走查要求的证据链）：
//! 临时 HOME 隔离（不碰真实 ~/.ssh/config）→ 驱动真实命令层
//! enable/disable → 真 OpenSSH `ssh -G` 验证 identityagent 解析指向
//! persona 稳定 socket → 停用后用户其余配置逐字节还原。
//!
//! 独立测试进程：HOME/XDG_RUNTIME_DIR 只影响本进程（tests/ 目录每个
//! 文件是独立二进制），与 lib 单测互不污染。无 ssh 二进制或
//! OpenSSH < 8.3（IdentityAgent 不支持）的环境自动跳过。
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

/// `ssh -V`（stderr）解析 OpenSSH 主/次版本；IdentityAgent 需 8.3+。
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

/// 跑 `ssh -G <host>`，返回 stdout。注意：OpenSSH 定位 ~/.ssh/config 走
/// passwd home 而非 $HOME 环境变量，必须用 -F 显式指向被测 config；
/// HOME/XDG_RUNTIME_DIR 仅供命令层的 dirs 探测。
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

    // 进程级 HOME/XDG_RUNTIME_DIR：ssh_config_path()/agent_stable_socket()
    // 都从 env 读取，且只影响本测试进程（独立二进制）
    std::env::set_var("HOME", home.path());
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());

    // 0700/0600：ssh 对过松权限的 config 会告警甚至忽略
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

    // ── 基线：未启用，ssh -G 不解析到 persona socket ──
    let baseline = ssh_g("github.com", &config_path);
    println!(
        "WALKTHROUGH baseline identityagent: {}",
        identityagent_line(&baseline)
    );
    assert!(
        !baseline.contains(&socket_str),
        "基线不应已指向 persona socket"
    );

    // ── 启用（真实命令层：锚点块幂等写入）──
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
    // 用户其余配置原样保留
    assert!(on_disk.contains("IdentitiesOnly yes"));
    assert!(on_disk.contains("ProxyJump github.com"));
    println!("WALKTHROUGH config after enable:\n{on_disk}");

    // ── 核心：真 OpenSSH 把该 host 的 identityagent 解析到 persona 稳定 socket ──
    let resolved = ssh_g("github.com", &config_path);
    println!("WALKTHROUGH full ssh -G stdout:\n{resolved}");
    let line = identityagent_line(&resolved);
    println!("WALKTHROUGH after-enable identityagent: {line}");
    assert_eq!(
        line.trim(),
        format!("identityagent {socket_str}"),
        "ssh -G 应解析到 persona 稳定 socket"
    );

    // ── 停用（锚点块整块移除）──
    let disabled = persona_desktop::commands::ssh_agent_integration_disable()
        .expect("disable command")
        .data
        .expect("disable 返回 status");
    assert!(!disabled.enabled);
    assert_eq!(disabled.identity_agent, None);

    // 用户配置逐字节还原（停用只动锚点块的硬证据）
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
}
