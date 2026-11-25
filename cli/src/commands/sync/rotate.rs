//! Group-key rotation and conflict resolution (`persona sync rotate` / `persona sync conflicts`).
//!
//! Mirrors desktop `sync_rotate` (sync.rs:823), `sync_conflicts_list` (864), and
//! `sync_conflict_resolve` (889). The only difference is error presentation: the desktop
//! uses `ApiResponse::error_with_code` to translate the concurrent-rotation 409 into a
//! frontend-recognizable code, while the CLI reports straight to the terminal (the Display
//! of `PersonaError::ConcurrentConflict` already carries the code).

use anyhow::{anyhow, Result};
use colored::Colorize;
use uuid::Uuid;

use super::devices::admin_api_for;
use super::session;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;

/// Rotate the group key: re-enqueue all group credentials under the new group key and push (same semantics as the desktop).
pub(crate) async fn rotate(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let (sess, service) = session::open_sync_session(config, ui).await?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| anyhow!("locked: master key unavailable: {e}"))?;
    let admin = admin_api_for(config).await?;
    let report = sess
        .rotate_group_key(master, &admin)
        .await
        .map_err(|e| anyhow!("sync_rotate_failed: {e}"))?;

    println!("{}", "🔄 Group key rotated".cyan().bold());
    println!("  rewrapped:  {}", report.rewrapped);
    println!("  pushed:     {}", report.pushed);
    if report.skipped > 0 {
        println!(
            "  {}  {} credentials were skipped (legacy or undecryptable) — they stay",
            "⚠️".yellow(),
            report.skipped
        );
    }
    Ok(())
}

/// The conflict-resolution list (read-only, no state change): every pending entry plus
/// primary/replica snapshots. master is not decrypted — `list_conflicts` decrypts with the
/// group key (obtained by unwrapping the envelope at session assembly).
pub(crate) async fn list_conflicts(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let (sess, _service) = session::open_sync_session(config, ui).await?;
    let entries = sess
        .list_conflicts()
        .await
        .map_err(|e| anyhow!("sync_conflicts_failed: {e}"))?;
    if entries.is_empty() {
        println!("{}", "✓ No pending sync conflicts".green().bold());
        return Ok(());
    }
    println!(
        "{}  {}",
        "⚠️".yellow().bold(),
        format!("{} pending sync conflicts", entries.len()).yellow()
    );
    for entry in &entries {
        println!("  {}", format!("item {}", entry.item_id).cyan());
        print_version("primary", &entry.primary);
        for copy in &entry.copies {
            print_version("copy", copy);
        }
        println!();
    }
    println!(
        "{}",
        "Resolve with: persona sync conflicts resolve <item_id> --adopt <op_id>".bright_black()
    );
    Ok(())
}

/// Resolve: adopt one replica (write the primary vault first, then enqueue with the new lamport; the remaining versions are evicted from the view).
pub(crate) async fn resolve_conflict(
    config: &CliConfig,
    item_id: &str,
    adopt_op_id: &str,
    ui: &dyn PromptUi,
) -> Result<()> {
    // UUID parsing happens before session assembly (cheap errors first, no unlock needed)
    let item = Uuid::parse_str(item_id.trim()).map_err(|_| anyhow!("Malformed item id"))?;
    let adopt =
        Uuid::parse_str(adopt_op_id.trim()).map_err(|_| anyhow!("Malformed conflict op id"))?;
    let (sess, service) = session::open_sync_session(config, ui).await?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| anyhow!("locked: master key unavailable: {e}"))?;
    sess.resolve_conflict(master, item, adopt)
        .await
        .map_err(|e| anyhow!("sync_resolve_failed: {e}"))?;
    println!("{}  {}", "✓ Conflict resolved".green().bold(), item);
    Ok(())
}

/// Print one conflict version (with the entry name attached when a snapshot is available, so the user can tell which copy is the real one).
fn print_version(role: &str, version: &persona_core::sync::resolve::ConflictVersion) {
    let title = version
        .snapshot
        .as_ref()
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "(tombstone)".to_string());
    println!(
        "    {:<7} op {}  lamport {}  \"{}\"",
        role, version.op_id, version.lamport, title
    );
}
