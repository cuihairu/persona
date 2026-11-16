//! 编辑流程编排：存在性检查 → 加载 → 编辑 → 校验 → 确认 → 保存。

use anyhow::Result;
use colored::*;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};

use super::display::{show_changes_summary, show_current_values};
use super::fields::{edit_from_args, edit_interactive, edit_single_field};
use super::persist::{identity_exists, load_identity, save_identity, validate_identity};
use super::EditArgs;

pub async fn execute(args: EditArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: EditArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!(
        "✏️ Editing identity '{}'...",
        args.name.bright_cyan().bold()
    );
    println!();

    // Check if identity exists
    if !identity_exists(&args.name, config, ui).await? {
        anyhow::bail!("Identity '{}' not found", args.name);
    }

    // Load current identity data
    let mut identity = load_identity(&args.name, config, ui).await?;

    // Show current values
    show_current_values(&identity)?;

    // Perform editing based on mode
    if args.interactive {
        edit_interactive(&mut identity, ui)?;
    } else if let Some(field) = args.field {
        edit_single_field(&mut identity, &field, args.value, ui)?;
    } else {
        edit_from_args(&mut identity, &args)?;
    }

    // Validate changes
    validate_identity(&identity)?;

    // Show changes summary
    show_changes_summary(&identity)?;

    // Confirm changes
    if !ui.confirm("Save changes?", true)? {
        println!("{}", "Changes discarded.".yellow());
        return Ok(());
    }

    // Save changes
    save_identity(&identity, config, ui).await?;

    println!();
    println!(
        "{} Identity '{}' updated successfully!",
        "✓".green().bold(),
        identity.name.bright_green().bold()
    );

    Ok(())
}
