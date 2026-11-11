use anyhow::{anyhow, Context, Result};
use colored::*;
use std::path::{Path, PathBuf};

use crate::config::CliConfig;
use crate::utils::file_crypto::encrypt_file_inplace;
use crate::utils::progress::create_progress_bar;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::Database;
use persona_core::Repository;

mod args;
mod formats;
mod output;
mod plan;

pub use args::ExportArgs;

use formats::perform_export;
use output::show_export_info;
use plan::{
    determine_output_path, get_all_identity_names, select_identities_interactive,
    show_export_summary, validate_identity_names,
};

pub async fn execute(args: ExportArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ExportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    println!("{}", "📤 Exporting identities...".cyan().bold());
    println!();

    // Determine which identities to export
    let identity_names = if args.interactive {
        select_identities_interactive(config, ui).await?
    } else if args.names.is_empty() {
        get_all_identity_names(config, ui).await?
    } else {
        validate_identity_names(&args.names, config, ui).await?;
        args.names.clone()
    };

    if identity_names.is_empty() {
        println!("{}", "No identities to export.".yellow());
        return Ok(());
    }

    // Determine output file
    let output_path = determine_output_path(&args, &identity_names)?;

    // Show export summary
    show_export_summary(&identity_names, &output_path, &args)?;

    // 统一授权入口（架构校正批1）：Export 恒判 InteractionRequired——
    // 策略允许导出但必须调用边显式确认，以下确认框即履约（提示文案/
    // 默认值不变）。Denied 在本地会话上不可达（见 authz 模块），保留
    // 防御臂以对齐统一裁决词汇。
    let export_decision = persona_core::authz::authorize(
        &persona_core::authz::AuthzPrincipal::LocalSession,
        &persona_core::authz::AuthzResource::Vault,
        persona_core::authz::AuthzAction::Export,
        &persona_core::authz::AuthzContext::LOCAL,
    );
    if let persona_core::authz::AuthzDecision::Denied { reason } = export_decision {
        return Err(anyhow!("Export denied: {}", reason));
    }

    // Confirm export
    if !ui.confirm("Proceed with export?", true)? {
        println!("{}", "Export cancelled.".yellow());
        return Ok(());
    }

    // Warn about sensitive data
    if args.include_sensitive {
        println!();
        println!(
            "{}",
            "⚠️  Warning: Export will include sensitive data!"
                .red()
                .bold()
        );
        // 敏感载荷：同一裁决点再次要求交互履约（更严提示，默认否）。
        let sensitive_decision = persona_core::authz::authorize(
            &persona_core::authz::AuthzPrincipal::LocalSession,
            &persona_core::authz::AuthzResource::Vault,
            persona_core::authz::AuthzAction::Export,
            &persona_core::authz::AuthzContext::LOCAL,
        );
        if let persona_core::authz::AuthzDecision::Denied { reason } = sensitive_decision {
            return Err(anyhow!("Export denied: {}", reason));
        }
        if !ui.confirm("Are you sure you want to include sensitive data?", false)? {
            println!("{}", "Export cancelled.".yellow());
            return Ok(());
        }
    }

    // Perform export
    perform_export(&identity_names, &output_path, &args, config, ui).await?;

    println!();
    println!("{} Export completed successfully!", "✓".green().bold());
    println!(
        "  Output file: {}",
        output_path.display().to_string().cyan()
    );

    // Show file info
    show_export_info(&output_path)?;

    Ok(())
}

#[cfg(test)]
mod tests;
