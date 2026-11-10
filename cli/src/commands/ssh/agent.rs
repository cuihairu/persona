use super::*;

/// 的代理可能报一个超大长度导致无界内存分配，先查再分配。
const MAX_AGENT_RESP_LEN: usize = 16 * 1024 * 1024;

/// 等待 daemon 打出 SSH_AUTH_SOCK= 的上限。正常在 spawn 后毫秒级完成；
/// 超窗仍无 socket 行按「daemon 挂起」处理（kill + 报错），绝不让 CLI
/// 永久阻塞——无上限时 daemon 沉默（如 socket 绑定卡住）会拖死调用方。
const AGENT_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 以 `deadline` 为上限等待 future，超时折算成 `TimedOut` 的 io::Error。
pub(crate) async fn with_startup_deadline<T>(
    deadline: std::time::Duration,
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    match tokio::time::timeout(deadline, fut).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "persona-ssh-agent did not report SSH_AUTH_SOCK in time",
        )),
    }
}

pub(crate) async fn start_agent(
    config: &crate::config::CliConfig,
    print_export: bool,
    ui: &dyn crate::utils::prompt::PromptUi,
    identity: Option<&str>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;
    println!("{}", "Starting persona-ssh-agent...".cyan().bold());
    let db_path = config.get_database_path();
    let agent_bin = resolve_agent_binary()?;
    let state_dir = agent_state_dir();
    std::fs::create_dir_all(&state_dir).context("Failed to create agent state directory")?;
    let socket_path = state_dir.join("agent.socket");
    let mut cmd = Command::new(&agent_bin);
    cmd.env("PERSONA_DB_PATH", db_path.to_string_lossy().to_string());
    cmd.env("PERSONA_AGENT_SOCKET_PATH", &socket_path);
    // if vault encrypted, prompt for master password and pass via env
    let service = ensure_service(config, ui).await?; // ensure migrations; may prompt
                                                     // If ensure_service prompted, service is unlocked; but agent needs password via env for future reloads
                                                     // Here we conservatively ask user again (not stored from ensure_service)
                                                     // 身份过滤器：名字在这里先验存在（未知名早失败），agent 侧
                                                     // 按 PERSONA_AGENT_IDENTITY fail-closed 只加载该分身的密钥。
    if let Some(name) = identity {
        let resolved = resolve_identity(&service, name).await?;
        cmd.env("PERSONA_AGENT_IDENTITY", resolved.name);
    }
    let pass = if config.ui.interactive {
        ui.password(
            "Enter master password for agent (leave empty if not set)",
            true,
            None,
        )?
    } else {
        std::env::var("PERSONA_MASTER_PASSWORD").unwrap_or_default()
    };
    if !pass.is_empty() {
        cmd.env("PERSONA_MASTER_PASSWORD", pass);
    }
    // forward stdout to capture SSH_AUTH_SOCK
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context("Failed to start persona-ssh-agent")?;
    let stdout = child.stdout.take().context("No stdout from agent")?;
    let mut reader = BufReader::new(stdout).lines();
    let sock_line = match with_startup_deadline(AGENT_STARTUP_TIMEOUT, async {
        let mut sock_line = None;
        for _ in 0..8 {
            let Some(line) = reader.next_line().await? else {
                break;
            };
            if line.starts_with("SSH_AUTH_SOCK=") {
                sock_line = Some(line);
                break;
            }
            println!("{}", line);
        }
        Ok(sock_line)
    })
    .await
    {
        Ok(sock_line) => sock_line,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            // `Child::kill().await` reaps the child, and reaping a Windows
            // process that still has pending I/O never completes — awaiting it
            // here would trade the daemon's silence for a fresh permanent hang
            // in the CLI, i.e. exactly the failure the deadline exists to stop.
            // Signal without reaping (`start_kill` returns immediately) and let
            // the caller see the timeout; the agent's own pid file is what
            // `stop-agent` uses for cleanup.
            let _ = child.start_kill();
            anyhow::bail!(
                "persona-ssh-agent did not report SSH_AUTH_SOCK within {}s (is it stuck binding its socket?)",
                AGENT_STARTUP_TIMEOUT.as_secs()
            );
        }
        Err(err) => return Err(err.into()),
    };
    if let Some(sock) = sock_line {
        let sock_value = sock
            .split_once('=')
            .map(|(_, value)| value.trim())
            .unwrap_or("");
        println!("{} {}", "Agent socket:".yellow(), sock_value.cyan());
        if print_export {
            println!();
            println!("{}", "Run the following in your shell:".dimmed());
            print_sock_export(sock_value);
        }
        // The daemon prints the socket line before loading keys, so it can
        // still die right after (e.g. a stale binary rejected by a newer db
        // migration). Poll briefly: a dead daemon must surface as an error,
        // not as the success message printed above.
        ensure_agent_alive(&mut child).await?;
    } else {
        // The child closed stdout without a socket line.
        ensure_agent_alive(&mut child).await?;
        println!(
            "{}",
            "Could not detect SSH_AUTH_SOCK from agent output.".yellow()
        );
    }

    Ok(())
}

/// Poll the freshly spawned agent briefly: a daemon that already exited
/// (stale binary, db migration failure, broken vault) must surface as an
/// error instead of a reported-successful start. `try_wait` can transiently
/// report None for a child that already exited but is not reaped yet, hence
/// the bounded loop rather than a single check.
async fn ensure_agent_alive(child: &mut tokio::process::Child) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let mut status = None;
    for _ in 0..20 {
        match child.try_wait()? {
            Some(exit) => {
                status = Some(exit);
                break;
            }
            None => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    let Some(status) = status else {
        return Ok(());
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr_output = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut stderr_output).await;
    }
    let stderr_output = stderr_output.trim();
    if stderr_output.is_empty() {
        anyhow::bail!("persona-ssh-agent exited early with status {}", status);
    }
    anyhow::bail!(
        "persona-ssh-agent exited early with status {}: {}",
        status,
        stderr_output
    );
}

pub(crate) fn resolve_agent_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("PERSONA_SSH_AGENT_BIN") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Ok(candidate);
        }
        anyhow::bail!(
            "PERSONA_SSH_AGENT_BIN is set but does not point to a file: {}",
            candidate.display()
        );
    }

    let binary_name = agent_binary_name();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(resolved) = find_agent_binary_near(&current_exe, binary_name) {
            return Ok(resolved);
        }
    }

    Ok(PathBuf::from(binary_name))
}

pub(crate) fn agent_state_dir() -> PathBuf {
    std::env::var("PERSONA_AGENT_STATE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
        })
}

pub(crate) fn find_agent_binary_near(current_exe: &Path, binary_name: &str) -> Option<PathBuf> {
    let current_dir = current_exe.parent()?;
    let candidates = [
        current_dir.join(binary_name),
        current_dir.join("deps").join(binary_name),
        current_dir.parent().map(|dir| dir.join(binary_name))?,
        current_dir
            .parent()
            .map(|dir| dir.join("deps").join(binary_name))?,
    ];

    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[cfg(unix)]
pub(crate) fn agent_binary_name() -> &'static str {
    "persona-ssh-agent"
}

#[cfg(windows)]
pub(crate) fn agent_binary_name() -> &'static str {
    "persona-ssh-agent.exe"
}

fn print_sock_export(sock_value: &str) {
    for line in format_sock_export_lines(sock_value) {
        println!("{line}");
    }
}

pub(crate) fn format_sock_export_lines(sock_value: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec![format!("  export SSH_AUTH_SOCK={}", sock_value)]
    }
    #[cfg(windows)]
    {
        vec![
            "  # PowerShell".to_string(),
            format!("  $env:SSH_AUTH_SOCK = '{}'", sock_value),
            "  # cmd.exe".to_string(),
            format!("  set SSH_AUTH_SOCK={}", sock_value),
        ]
    }
}

pub(crate) async fn agent_status(_config: &crate::config::CliConfig) -> Result<()> {
    let state_dir = agent_state_dir();
    let sock_file = state_dir.join("ssh-agent.sock");
    let pid_file = state_dir.join("ssh-agent.pid");
    let mut running = false;
    if sock_file.exists() {
        let sock = std::fs::read_to_string(&sock_file).unwrap_or_default();
        println!("{} {}", "Socket:".yellow(), sock.trim().cyan());
        running = true;
    }
    if pid_file.exists() {
        let pid = std::fs::read_to_string(&pid_file).unwrap_or_default();
        println!("{} {}", "PID:".yellow(), pid.trim().cyan());
        running = true;
    }
    // Query the key count from the same agent the Socket line describes —
    // the state file's socket. SSH_AUTH_SOCK is only a fallback for when no
    // state file exists yet: in a desktop session it usually points at the
    // system ssh-agent, and key counts from that mixed two agents into one
    // status report.
    let query_target = if sock_file.exists() {
        std::fs::read_to_string(&sock_file)
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        std::env::var("SSH_AUTH_SOCK").unwrap_or_default()
    };
    if !query_target.is_empty() {
        if let Ok(count) = query_agent_identities(&query_target).await {
            println!("{} {}", "Agent keys:".yellow(), count.to_string().cyan());
        }
    }
    if !running {
        println!("{}", "persona-ssh-agent is not running.".yellow());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn query_agent_identities(sock_path: &str) -> Result<usize> {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("Failed to connect to agent at {}", sock_path))?;
    // Build request: len(4) + type(1)=11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11u8;
    stream.write_all(&pkt).await?;
    // Read response len
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    if resp_len > MAX_AGENT_RESP_LEN {
        anyhow::bail!("Agent response length {} exceeds limit", resp_len);
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    if resp.is_empty() || resp[0] != 12 {
        anyhow::bail!("Unexpected agent response");
    }
    // parse count
    if resp.len() < 5 {
        anyhow::bail!("Malformed agent response");
    }
    let count = BigEndian::read_u32(&resp[1..5]) as usize;
    Ok(count)
}

#[cfg(windows)]
pub(crate) async fn query_agent_identities(sock_path: &str) -> Result<usize> {
    use byteorder::{BigEndian, ByteOrder};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pipe_name = if sock_path.starts_with(r"\\.\pipe\") {
        sock_path.to_string()
    } else {
        format!(r"\\.\pipe\{}", sock_path)
    };

    let mut stream = open_named_pipe_with_retry(&pipe_name, 10, Duration::from_millis(50))
        .await
        .with_context(|| format!("Failed to connect to agent at {}", pipe_name))?;

    // Build request: len(4) + type(1)=11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11u8;
    stream.write_all(&pkt).await?;

    // Read response len
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    if resp_len > MAX_AGENT_RESP_LEN {
        anyhow::bail!("Agent response length {} exceeds limit", resp_len);
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    if resp.is_empty() || resp[0] != 12 {
        anyhow::bail!("Unexpected agent response");
    }
    // parse count
    if resp.len() < 5 {
        anyhow::bail!("Malformed agent response");
    }
    let count = BigEndian::read_u32(&resp[1..5]) as usize;
    Ok(count)
}

#[cfg(windows)]
pub(crate) async fn open_named_pipe_with_retry(
    pipe_name: &str,
    attempts: usize,
    delay: std::time::Duration,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..attempts {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(err) => {
                let retryable = matches!(err.raw_os_error(), Some(231)) // ERROR_PIPE_BUSY
                    || err.kind() == std::io::ErrorKind::NotFound;
                last_err = Some(err);
                if !retryable {
                    break;
                }
            }
        }
        tokio::time::sleep(delay).await;
    }

    Err(anyhow::anyhow!(
        "Failed to open named pipe {}: {}",
        pipe_name,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

pub(crate) fn stop_agent() -> Result<()> {
    let state_dir = agent_state_dir();
    let pid_file = state_dir.join("ssh-agent.pid");
    if !pid_file.exists() {
        println!("{}", "No agent PID file found.".yellow());
        return Ok(());
    }
    let pid_str = std::fs::read_to_string(&pid_file).unwrap_or_default();
    let pid = pid_str.trim();
    if pid.is_empty() {
        println!("{}", "Empty PID file.".yellow());
        return Ok(());
    }
    match stop_agent_pid(pid)? {
        StopOutcome::Stopped => {
            println!("{} Stopped persona-ssh-agent (pid {})", "✓".green(), pid);
            // Cleanup sock/pid files
            let _ = std::fs::remove_file(pid_file);
            let sock_file = state_dir.join("ssh-agent.sock");
            let _ = std::fs::remove_file(sock_file);
        }
        // 进程已不在（陈旧 pidfile）：清掉文件，按"无需再停"处理。
        StopOutcome::AlreadyGone => {
            println!(
                "{}",
                format!("PID {pid} is not running (stale pidfile); removing.").yellow()
            );
            let _ = std::fs::remove_file(pid_file);
            let sock_file = state_dir.join("ssh-agent.sock");
            let _ = std::fs::remove_file(sock_file);
        }
        // PID 被别的进程复用（不是 agent）：拒绝杀，绝不误伤。
        StopOutcome::Refused => {
            println!(
                "{}",
                format!("PID {pid} is not persona-ssh-agent; refusing to kill.").red()
            );
        }
    }
    Ok(())
}

/// stop_agent 的三态结果：杀成功 / 进程早已不在（陈旧 pidfile）/ 拒绝杀。
#[derive(PartialEq, Debug)]
pub(crate) enum StopOutcome {
    Stopped,
    AlreadyGone,
    Refused,
}

/// 读 /proc/<pid>/cmdline 判断该 PID 是否为 persona-ssh-agent。
///
/// `None` = 进程不存在；`Some(true)` = 是我们；`Some(false)` = 别的进程。
/// 用来防"陈旧 pidfile + PID 被复用"时误杀无辜进程。
#[cfg(unix)]
pub(crate) fn is_persona_agent_process(pid: &str) -> Option<bool> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let text = String::from_utf8_lossy(&cmdline);
    let is_agent = text
        .split('\0')
        .any(|arg| arg.contains("persona-ssh-agent"));
    Some(is_agent)
}

#[cfg(unix)]
pub(crate) fn stop_agent_pid(pid: &str) -> Result<StopOutcome> {
    let Ok(numeric) = pid.parse::<i32>() else {
        // 非数字 pidfile 是损坏状态而非进程：按陈旧清理，不误判为"拒绝杀"。
        return Ok(StopOutcome::AlreadyGone);
    };
    match is_persona_agent_process(pid) {
        None => Ok(StopOutcome::AlreadyGone),
        Some(false) => Ok(StopOutcome::Refused),
        Some(true) => {
            // 直接用 libc::kill 发 SIGTERM：fork 外部 `kill` 在内存吃紧时可能
            // 因 fork 失败返回 Err，被误报为 Refused 而留下 pidfile；直接
            // 系统调用无此窗口。EPERM 等仍按 Refused 处理（与旧语义一致）。
            let rc = unsafe { libc::kill(numeric, libc::SIGTERM) };
            Ok(if rc == 0 {
                StopOutcome::Stopped
            } else {
                StopOutcome::Refused
            })
        }
    }
}

#[cfg(windows)]
pub(crate) fn stop_agent_pid(pid: &str) -> Result<StopOutcome> {
    use std::process::Command;

    // Windows 没有 /proc：用 tasklist 探测进程是否还在（输出含 PID 数字即
    // 存活，判定不受系统语言影响）；不在则按陈旧 pidfile 处理，与 Unix
    // 侧语义对齐，也让 AlreadyGone 分支在 Windows 上可达。
    let listed = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output();
    let alive = matches!(&listed, Ok(o) if String::from_utf8_lossy(&o.stdout).contains(pid));
    if !alive {
        return Ok(StopOutcome::AlreadyGone);
    }

    let status = Command::new("taskkill").args(["/PID", pid, "/T"]).status();
    if matches!(status, Ok(s) if s.success()) {
        return Ok(StopOutcome::Stopped);
    }

    let status_force = Command::new("taskkill")
        .args(["/PID", pid, "/T", "/F"])
        .status();
    Ok(if matches!(status_force, Ok(s) if s.success()) {
        StopOutcome::Stopped
    } else {
        StopOutcome::Refused
    })
}
