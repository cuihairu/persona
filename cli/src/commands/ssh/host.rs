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
    // Phase 3 host-dimension suggestion: advisory only, never authorization —
    // it leaves the agent target host file and every policy verdict alone;
    // read failures degrade silently in the suggest layer.
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

/// ssh binary used to assemble remote scripts/argv (overridable by tests and
/// nonstandard installs).
fn ssh_binary() -> String {
    std::env::var("PERSONA_SSH_BINARY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ssh".to_string())
}

/// POSIX sh single-quote escaping (authorized_keys content only ever holds
/// base64 and algorithm names, but the remote path is caller-supplied and is
/// always treated as untrusted).
pub(crate) fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Bare public key line (comments/options stripped): matches the form written
/// to the remote authorized_keys, and keeps remove's whole-line matching
/// limited to our own lines so other tools' entries are not deleted.
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

/// Build the remote `sh -c` script (POSIX sh). `path_expr` is already quoted:
/// the default is `"$HOME/.ssh/authorized_keys"` (expanded remotely), custom
/// paths use a single-quoted literal.
/// - add: idempotent (dedupe with `grep -qxF` then `printf >>`, never
///   overwriting existing lines); the whole line is single-quoted — a public
///   key line contains spaces and would be word-split without quoting
/// - remove: only lines whose 2nd field (key blob) equals ours are dropped —
///   awk rewrites into a temp file and `cat`s it back into the original to
///   preserve the inode/permissions, so lines managed by other tools stay
///   intact; the blob is embedded in the awk program body wrapped in double
///   quotes and only the base64 character set is allowed
/// - list: `cat` the remote file as-is (empty if it does not exist)
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

/// Run ssh once (captured stdout/stderr) with the agent-target-host file set
/// for the duration — same policy treatment as `ssh run` (known_hosts,
/// confirmation, and rate limits are governed by the agent's host policy).
/// The host file is cleared on session end whether the run succeeded or not.
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

/// authorized_keys distribution: keys come out of the vault (the private key
/// never leaves it), while transport/authentication is handed to the user's
/// own `ssh` binary (same trust model as `ssh run` — this repo does not
/// implement the SSH client protocol; that is a design boundary, not a gap).
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
    // remove matches on the blob (2nd field); add/list match the whole line
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
    // Audit fields: action + target host + credential/identity (best-effort)
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
