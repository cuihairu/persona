use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use anyhow::{bail, Context, Result};

use super::open_unlocked;
use super::refs::{parse_env_assignments, resolve_ref};

// -----------------------------------------------------------------------
// run（shell plugins 通用机制：env 注入 + 前台转发）
// -----------------------------------------------------------------------

/// spawn 子进程：继承父环境 + 注入解析后的变量；stdio 全透传。
/// 独立成函数便于测试退出码分支（不经过 execute 的 exit 短路）。
pub(crate) async fn spawn_with_env(
    assignments: &[(String, String)],
    command: &[std::ffi::OsString],
) -> Result<std::process::ExitStatus> {
    let (program, rest) = command
        .split_first()
        .with_context(|| "run requires a command after `--`")?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(rest);
    for (name, value) in assignments {
        cmd.env(name, value);
    }
    cmd.status()
        .await
        .with_context(|| format!("failed to spawn {}", program.to_string_lossy()))
}

pub(super) async fn run_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    env_specs: &[String],
    command: &[std::ffi::OsString],
) -> Result<()> {
    if command.is_empty() {
        bail!("run requires a command after `--`");
    }
    let parsed = parse_env_assignments(env_specs)?;
    let service = open_unlocked(config, ui).await?;
    // 先全部解析再 spawn：引用有错就不该启动半环境子进程
    let mut assignments = Vec::with_capacity(parsed.len());
    for (name, secret_ref) in &parsed {
        let value = resolve_ref(&service, secret_ref)
            .await
            .with_context(|| format!("failed to resolve {secret_ref}"))?;
        assignments.push((name.clone(), value));
    }
    let status = spawn_with_env(&assignments, command).await?;
    if status.success() {
        return Ok(());
    }
    // 转发子进程退出码（测试只走 spawn_with_env，不进这条 exit 短路）
    std::process::exit(status.code().unwrap_or(1));
}
