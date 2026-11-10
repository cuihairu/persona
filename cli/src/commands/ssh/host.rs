use super::agent::agent_state_dir;
use super::signing::audit_ssh_event;
use super::*;

pub(crate) async fn run_with_host(
    host: &str,
    command: Vec<String>,
    config: &crate::config::CliConfig,
) -> Result<()> {
    use tokio::process::Command;
    if command.is_empty() {
        anyhow::bail!("Provide a command after --");
    }
    // 阶段 3 host 维度建议：只建议，不授权——不改 agent 目标主机文件、
    // 不改任何策略评判；读失败在 suggest 层静默降级。
    if let Some(line) = crate::commands::suggest::host_suggestion_line(config, host).await {
        eprintln!("{line}");
    }
    // Write host to state file
    let state_dir = agent_state_dir();
    std::fs::create_dir_all(&state_dir).ok();
    let host_file = state_dir.join("agent-target-host");
    std::fs::write(&host_file, host).context("Failed to write agent target host")?;
    // Spawn command
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    if let Some(sock) = current_or_stored_agent_socket(&state_dir) {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let status = cmd.status().await.context("Failed to run command")?;
    // Cleanup
    let _ = std::fs::remove_file(&host_file);
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("Command exited with status {}", status)
    }
}

pub(crate) fn current_or_stored_agent_socket(state_dir: &Path) -> Option<String> {
    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        let trimmed = sock.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let sock_file = state_dir.join("ssh-agent.sock");
    let sock = std::fs::read_to_string(sock_file).ok()?;
    let trimmed = sock.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// 供远端脚本/argv 组装用的 ssh 二进制（测试与非常规安装可覆盖）。
fn ssh_binary() -> String {
    std::env::var("PERSONA_SSH_BINARY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ssh".to_string())
}

/// POSIX sh 单引号转义（authorized_keys 内容只出现 base64 与算法名，
/// 但远端路径是调用方给的，一律按不可信处理）。
pub(crate) fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// bare 公钥行（去注释/选项）：与写入远端 authorized_keys 的形态一致，
/// 也让 remove 的整行匹配只认我们的写法、不误删其他工具的行。
pub(crate) fn bare_public_line(line: &str) -> String {
    let mut tokens = line.split_whitespace();
    let algo = tokens.next().unwrap_or_default();
    let blob = tokens.next().unwrap_or_default();
    if algo.is_empty() || blob.is_empty() {
        line.trim().to_string()
    } else {
        format!("{algo} {blob}")
    }
}

/// 生成远端 `sh -c` 脚本（POSIX sh）。`path_expr` 已带引用：默认
/// `"$HOME/.ssh/authorized_keys"`（远端展开），自定义路径走单引号字面量。
/// - add：幂等（`grep -qxF` 去重后 `printf >>`，不覆盖已有行）；整行
///   单引号引用——公钥行内含空格，不引号会被 shell 拆词
/// - remove：只有第 2 字段（key blob）等于我们的行才会删——awk 重写到
///   `cat` 回原文件保 inode/权限，不误伤其他工具管理的行；blob 内嵌
///   awk 双引号程序体，只放行 base64 字符集
/// - list：原样 `cat` 远端文件（不含即空）
pub(crate) fn authorized_keys_plan(action: &str, path_expr: &str, key: &str) -> Result<String> {
    match action {
        "list" => Ok(format!("if test -f {path_expr}; then cat {path_expr}; fi")),
        "remove" => {
            if !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
            {
                anyhow::bail!(
                    "Unexpected characters in the key blob; refusing to build the remote script"
                );
            }
            Ok(format!(
                "if test -f {path_expr}; then awk '$2 != \"{key}\"' {path_expr} > \
                 {path_expr}.persona-tmp && cat {path_expr}.persona-tmp > {path_expr} && \
                 rm -f {path_expr}.persona-tmp; fi"
            ))
        }
        _ => {
            let quoted = sh_quote(key);
            Ok(format!(
                "mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\" && touch {path_expr} && \
                 chmod 600 {path_expr} && if grep -qxF {quoted} {path_expr}; then :; else \
                 printf '%s\\n' {quoted} >> {path_expr}; fi"
            ))
        }
    }
}

/// 跑一次 ssh（captured stdout/stderr），期间挂 agent-target-host——
/// 与 `ssh run` 同一策略口径（known_hosts/确认/限速由 agent 的 host
/// 策略管）。会话结束无论成败都清 host 文件。
async fn ssh_capture(host: &str, program: &str, args: &[String]) -> Result<std::process::Output> {
    use tokio::process::Command;
    let state_dir = agent_state_dir();
    std::fs::create_dir_all(&state_dir).ok();
    let host_file = state_dir.join("agent-target-host");
    std::fs::write(&host_file, host).context("Failed to write agent target host")?;
    let outcome = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .context("Failed to run ssh");
    let _ = std::fs::remove_file(&host_file);
    outcome
}

/// authorized_keys 分发：密钥由 vault 出（私钥不出库），传输/认证交给
/// 用户自己的 `ssh` 二进制（与 `ssh run` 同一信任模型——本仓不做 SSH
/// 客户端协议实现，这是设计边界不是缺失）。
pub(crate) async fn authorize(
    identity_name: &str,
    host: &str,
    opts: AuthorizeOptions,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;
    let all = service.get_credentials_for_identity(&identity.id).await?;
    let mut keys: Vec<(String, Uuid)> = Vec::new();
    for cred in all {
        if !matches!(cred.credential_type, CredentialType::SshKey) {
            continue;
        }
        if let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&cred.id).await? {
            keys.push((ssh.public_key, cred.id));
        }
    }
    if keys.is_empty() {
        anyhow::bail!(
            "Identity '{}' has no SSH keys; run `persona ssh generate` first",
            identity.name
        );
    }
    let (public_line, cred_id) = match opts.id {
        Some(wanted) => keys
            .into_iter()
            .find(|(_, cred_id)| *cred_id == wanted)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Credential {wanted} is not an SSH key of identity '{}'",
                    identity.name
                )
            })?,
        None if keys.len() == 1 => keys.remove(0),
        None => anyhow::bail!(
            "{} SSH keys for identity '{}'; pick one with --id",
            keys.len(),
            identity.name
        ),
    };
    let line = bare_public_line(&public_line);
    let blob = match line.split_whitespace().nth(1) {
        Some(blob) if line.split_whitespace().count() == 2 => blob,
        _ => anyhow::bail!("Vault key {} has an unexpected public key format", cred_id),
    };
    let path_expr = match opts.remote_path.as_deref() {
        Some(path) => sh_quote(path),
        None => "\"$HOME/.ssh/authorized_keys\"".to_string(),
    };
    let action = if opts.list {
        "list"
    } else if opts.remove {
        "remove"
    } else {
        "add"
    };
    // remove 的匹配键是 blob（第 2 字段），add/list 用整行
    let key = if action == "remove" {
        blob
    } else {
        line.as_str()
    };
    let script = authorized_keys_plan(action, &path_expr, key)?;

    let mut argv = vec![ssh_binary()];
    if let Some(port) = opts.port {
        argv.push("-p".to_string());
        argv.push(port.to_string());
    }
    argv.push(host.to_string());
    argv.push(script);
    if opts.dry_run {
        let display: Vec<String> = argv
            .iter()
            .map(|piece| {
                if piece.chars().any(char::is_whitespace) {
                    format!("{piece:?}")
                } else {
                    piece.clone()
                }
            })
            .collect();
        println!("{}", display.join(" "));
        return Ok(());
    }

    let output = ssh_capture(host, &argv[0], &argv[1..]).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "ssh exited with {}: {}",
            output
                .status
                .code()
                .map(|c| format!("status {c}"))
                .unwrap_or_else(|| "failure".to_string()),
            stderr.trim()
        );
    }
    if action == "list" {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            println!(
                "{} No matching authorized_keys lines on {}.",
                "none".yellow(),
                host
            );
        } else {
            print!("{stdout}");
        }
    } else {
        println!(
            "{} {} → {} (credential {})",
            "✓".green(),
            action,
            host,
            cred_id
        );
    }
    // 审计口径：动作 + 目标主机 + 凭据/身份（best-effort）
    audit_ssh_event(
        &config.get_database_path(),
        "ssh_authorize",
        Some(identity.id),
        Some(cred_id),
        &[
            ("host", host.to_string()),
            ("action", action.to_string()),
            ("ok", output.status.success().to_string()),
        ],
    )
    .await;
    Ok(())
}
