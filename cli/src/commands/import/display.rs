//! Result display: the import summary preview and the conflict report output (pure printing, no decisions).

use anyhow::Result;
use colored::*;

use super::{ImportArgs, ImportConflict, ImportData};

pub(super) fn show_import_summary(import_data: &ImportData, args: &ImportArgs) -> Result<()> {
    println!("{}", "Import Summary:".yellow().bold());
    println!("  File: {}", args.file.display().to_string().cyan());
    println!("  Format version: {}", import_data.version.cyan());
    println!("  Created: {}", import_data.created.dimmed());
    println!(
        "  Identities: {}",
        import_data.identities.len().to_string().cyan()
    );
    println!("  Import mode: {}", args.mode.cyan());

    if args.dry_run {
        println!("  Mode: {}", "Dry run".yellow());
    }

    if args.backup {
        println!("  Backup: {}", "Yes".green());
    }

    println!();

    // Show identity preview
    if !import_data.identities.is_empty() {
        println!("{}", "Identities to import:".dimmed());
        for (i, identity) in import_data.identities.iter().enumerate().take(5) {
            println!(
                "  {}. {} ({})",
                i + 1,
                identity.name.cyan(),
                identity.identity_type.dimmed()
            );
        }

        if import_data.identities.len() > 5 {
            println!(
                "  ... and {} more",
                (import_data.identities.len() - 5).to_string().dimmed()
            );
        }
        println!();
    }

    Ok(())
}

pub(super) fn handle_import_conflicts(
    conflicts: &[ImportConflict],
    args: &ImportArgs,
) -> Result<()> {
    println!("{} Import conflicts detected:", "⚠️".yellow().bold());
    println!();

    for conflict in conflicts {
        println!("  Identity: {}", conflict.name.cyan());
        println!("  Conflict: {}", conflict.conflict_type.red());
        println!("  Existing: {}", conflict.existing_data.dimmed());
        println!("  New: {}", conflict.new_data.dimmed());
        println!();
    }

    match args.mode.as_str() {
        "merge" => {
            println!(
                "{} Mode: Merge - New data will be merged with existing",
                "ℹ️".blue()
            );
        }
        "replace" => {
            println!(
                "{} Mode: Replace - Existing data will be overwritten",
                "⚠️".yellow()
            );
        }
        "skip" => {
            println!(
                "{} Mode: Skip - Conflicting identities will be skipped",
                "ℹ️".blue()
            );
        }
        _ => {
            anyhow::bail!("Invalid import mode: {}", args.mode);
        }
    }

    Ok(())
}
