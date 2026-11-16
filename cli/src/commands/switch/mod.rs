use crate::config::CliConfig;
use crate::utils::prompt::TerminalUi;
use anyhow::Result;
use clap::Args;
use flow::{execute_with, execute_with_reason};
use persona_core::context::ContextSignals;

#[derive(Args)]
pub struct SwitchArgs {
    /// Identity name to switch to
    name: Option<String>,

    /// Force switch without confirmation
    #[arg(short, long)]
    force: bool,

    /// Show interactive selection menu
    #[arg(short, long)]
    interactive: bool,

    /// Switch to previous identity
    #[arg(short, long)]
    previous: bool,
}

pub async fn execute(args: SwitchArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

/// `persona use <name>` — one-click confirm of a suggestion. Identical
/// semantics to `persona switch` (same audit trail); when the target matches
/// the current top suggestion, the audit entry carries the suggestion reason.
pub async fn execute_use(args: SwitchArgs, config: &CliConfig) -> Result<()> {
    let top = suggest_reason_for(config).await;
    execute_with_reason(args, config, &TerminalUi, top).await
}

/// 当前建议首位（分身名, reason）；无候选/开库失败返回 None（建议层永不致命）。
async fn suggest_reason_for(config: &CliConfig) -> Option<(String, String)> {
    let signals = ContextSignals::collect();
    let paths = crate::commands::suggest::MapPaths {
        global: crate::commands::suggest::global_map_path(),
        repo_local: crate::commands::suggest::repo_local_map_path(),
    };
    let env_override = std::env::var("PERSONA_CONTEXT_OVERRIDE").ok();
    let result = crate::commands::suggest::compute_suggestion(
        config,
        &paths,
        &signals,
        env_override.as_deref(),
    )
    .await
    .ok()?;
    let top = result.candidates.first()?;
    Some((top.identity.clone(), top.reason.clone()))
}
mod flow;
mod identity;
mod perform;

pub(crate) use perform::perform_switch;

#[cfg(test)]
mod tests;
