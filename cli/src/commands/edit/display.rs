//! 展示：编辑前的现值清单与保存前的变更摘要（纯打印，不做决策）。

use anyhow::Result;
use colored::*;

use super::Identity;

pub(super) fn show_current_values(identity: &Identity) -> Result<()> {
    println!("{}", "Current values:".yellow().bold());
    println!("  {}: {}", "Name".dimmed(), identity.name.cyan());
    println!("  {}: {}", "Type".dimmed(), identity.identity_type.cyan());
    println!("  {}: {}", "Description".dimmed(), identity.description);

    if let Some(ref email) = identity.email {
        println!("  {}: {}", "Email".dimmed(), email.cyan());
    }

    if let Some(ref phone) = identity.phone {
        println!("  {}: {}", "Phone".dimmed(), phone.cyan());
    }

    if !identity.tags.is_empty() {
        println!(
            "  {}: {}",
            "Tags".dimmed(),
            identity.tags.join(", ").dimmed()
        );
    }

    if !identity.attributes.is_empty() {
        println!(
            "  {}: {} custom attributes",
            "Attributes".dimmed(),
            identity.attributes.len()
        );
    }

    println!();
    Ok(())
}

pub(super) fn show_changes_summary(identity: &Identity) -> Result<()> {
    println!();
    println!("{}", "Changes summary:".yellow().bold());
    println!("  Identity will be updated with new values");
    println!("  Modified timestamp: {}", identity.modified.dimmed());

    Ok(())
}
