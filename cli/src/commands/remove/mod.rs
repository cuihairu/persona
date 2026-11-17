use anyhow::Result;
use clap::Args;
use colored::*;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};

mod backup;
mod checks;
mod post;
mod removal;
mod summary;
#[cfg(test)]
mod tests;

use backup::create_backup;
use checks::{identity_exists, is_active_identity};
use post::show_post_removal_info;
use removal::perform_removal;
use summary::show_removal_summary;

#[derive(Args)]
pub struct RemoveArgs {
    /// Identity name to remove
    name: String,

    /// Force removal without confirmation
    #[arg(short, long)]
    force: bool,

    /// Create backup before removal
    #[arg(short, long)]
    backup: bool,

    /// Remove all associated data
    #[arg(long)]
    purge: bool,
}

pub async fn execute(args: RemoveArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: RemoveArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!(
        "🗑️ Removing identity '{}'...",
        args.name.bright_red().bold()
    );
    println!();

    // Check if identity exists
    if !identity_exists(&args.name, config, ui).await? {
        anyhow::bail!("Identity '{}' not found", args.name);
    }

    // Check if it's the active identity
    if is_active_identity(&args.name, config).await? {
        println!(
            "{} Identity '{}' is currently active",
            "⚠️".yellow(),
            args.name.yellow()
        );

        if !args.force
            && !ui.confirm(
                "Do you want to continue removing the active identity?",
                false,
            )?
        {
            println!("{}", "Removal cancelled.".yellow());
            return Ok(());
        }
    }

    // Show identity summary before removal
    show_removal_summary(&args.name, config, ui).await?;

    // Confirmation
    if !args.force {
        println!();
        println!("{}", "⚠️  This action cannot be undone!".red().bold());

        let confirmation_text = format!("remove {}", args.name);
        let user_input = ui.input(
            &format!("Type '{}' to confirm removal", confirmation_text),
            None,
            true,
        )?;

        if user_input != confirmation_text {
            println!(
                "{}",
                "Removal cancelled - confirmation text didn't match.".yellow()
            );
            return Ok(());
        }
    }

    // Create backup if requested
    if args.backup {
        create_backup(&args.name, config, ui).await?;
    }

    // Perform removal
    perform_removal(&args.name, args.purge, config, ui).await?;

    println!();
    println!(
        "{} Identity '{}' removed successfully",
        "✓".green().bold(),
        args.name.bright_green()
    );

    // Show next steps
    show_post_removal_info(config, ui).await?;

    Ok(())
}
