use super::identity::{
    get_current_identity, get_previous_identity, select_identity_interactive,
    verify_identity_exists,
};
use super::perform::{perform_switch, show_identity_summary};
use super::SwitchArgs;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use anyhow::Context;
use anyhow::Result;
use colored::*;

pub(crate) async fn execute_with(
    args: SwitchArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    execute_with_reason(args, config, ui, None).await
}

/// `suggestion` = (top candidate name, reason); `perform_switch` attaches the
/// reason to the audit entry when the switch targets exactly that candidate.
pub(crate) async fn execute_with_reason(
    args: SwitchArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
    suggestion: Option<(String, String)>,
) -> Result<()> {
    println!("{}", "🔄 Switching identity...".cyan().bold());
    println!();

    let target_identity = if args.previous {
        get_previous_identity(config).await?
    } else if args.interactive || args.name.is_none() {
        select_identity_interactive(config, ui).await?
    } else {
        args.name.context("Identity name is required")?
    };

    // Get current active identity
    let current_identity = get_current_identity(config).await?;

    // Check if already active
    if let Some(ref current) = current_identity {
        if current == &target_identity {
            println!(
                "{} Identity '{}' is already active",
                "ℹ️".blue(),
                target_identity.bright_blue().bold()
            );
            return Ok(());
        }
    }

    // Verify target identity exists
    verify_identity_exists(&target_identity, config, ui).await?;

    // Show confirmation if not forced
    if !args.force {
        let confirmation_message = if let Some(current) = &current_identity {
            format!(
                "Switch from '{}' to '{}'?",
                current.yellow(),
                target_identity.green()
            )
        } else {
            format!("Switch to '{}'?", target_identity.green())
        };

        if !ui.confirm(&confirmation_message, true)? {
            println!("{}", "Switch cancelled.".yellow());
            return Ok(());
        }
    }

    // Perform the switch
    perform_switch(
        &target_identity,
        current_identity.as_deref(),
        config,
        ui,
        suggestion.as_ref(),
    )
    .await?;

    println!();
    println!(
        "{} Successfully switched to identity '{}'",
        "✓".green().bold(),
        target_identity.bright_green().bold()
    );

    // Show identity summary
    show_identity_summary(&target_identity, config, ui).await?;

    Ok(())
}
