//! 组密钥轮换与冲突裁决（`persona sync rotate` / `persona sync conflicts`）。
//!
//! 镜像 desktop `sync_rotate`（sync.rs:823）、`sync_conflicts_list`（864）、
//! `sync_conflict_resolve`（889）。差异只在错误呈现：桌面用
//! `ApiResponse::error_with_code` 把并发轮换 409 翻成前端可识别码，CLI 直接
//! 报错给终端（`PersonaError::ConcurrentConflict` 的 Display 已带码）。

use anyhow::{anyhow, Result};
use colored::Colorize;
use uuid::Uuid;

use super::devices::admin_api_for;
use super::session;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;

/// 轮换组密钥：全组凭据以新组密钥重新入账并推送（桌面同语义）。
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

/// 冲突裁决列表（只读，不改状态）：全部待裁决条目 + 主位/副本快照。
/// 不解密 master——`list_conflicts` 的解密走组密钥（会话装配时拆信封得）。
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

/// 裁决：采纳一个副本（先写主库再以新 lamport 入账，其余版本淘汰出视图）。
pub(crate) async fn resolve_conflict(
    config: &CliConfig,
    item_id: &str,
    adopt_op_id: &str,
    ui: &dyn PromptUi,
) -> Result<()> {
    // UUID 解析在会话装配之前（便宜的错误先报，免解锁）
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

/// 打印一个冲突版本（快照可用时附条目名，便于用户认哪份是真）。
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
