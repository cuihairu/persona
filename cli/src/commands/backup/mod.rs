//! `persona backup …`：整库加密备份的推送/列举/拉取/恢复/删除。
//!
//! 与事件上报共用 `PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN`（env-only、
//! 都非空才启用，敏感值不落盘）。备份体 = VACUUM INTO 快照 → gzip →
//! PERSENC1（`persona_core::backup`），服务器只见密文。
//!
//! push 不要求解锁主密码（物理快照是文件级操作）；restore 换库前先
//! 留 `.bak`。附件 blob 不在 v1 备份内（恢复后元数据在、文件体缺失）。

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use env::{client_from_env, resolve_passphrase};
use persona_core::backup::{create_backup_bytes, restore_backup_bytes};
use persona_core::Database;
use std::path::PathBuf;

mod env;

#[cfg(test)]
mod tests;

#[derive(Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    command: BackupCommand,
}

#[derive(Subcommand)]
enum BackupCommand {
    /// Snapshot the vault, encrypt it, and push to the server (no master-password unlock needed)
    Push {
        /// Read the backup passphrase from this env var (CI/automation; must be set and non-empty)
        #[arg(long)]
        passphrase_env: Option<String>,
    },
    /// List server-side backup versions (newest first)
    List {
        /// Page size (server default 20, cap 100)
        #[arg(long, default_value_t = 20)]
        limit: u32,
        /// Cursor returned by the previous page
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Download a backup ciphertext to a file (no decryption, no vault swap)
    Pull {
        /// Backup version id
        id: String,
        /// Output path
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Restore: download (or --file local ciphertext), verify, keep a .bak, swap the vault
    Restore {
        /// Server backup version id to restore (mutually exclusive with --file)
        id: Option<String>,
        /// Local ciphertext file (mutually exclusive with id; offline restore path)
        #[arg(long)]
        file: Option<PathBuf>,
        /// Read the backup passphrase from this env var
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Skip the confirmation prompt (dangerous: overwrites the current vault)
        #[arg(short, long)]
        yes: bool,
    },
    /// Delete a server-side backup version
    Delete {
        /// Backup version id
        id: String,
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

pub async fn execute(args: BackupArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: BackupArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        BackupCommand::Push { passphrase_env } => {
            // 物理快照无需主密钥；唯一前置是库文件存在
            let db_path = config.get_database_path();
            if !db_path.exists() {
                bail!(
                    "no vault database at {} — run `persona migrate` first",
                    db_path.display()
                );
            }
            let passphrase = resolve_passphrase(passphrase_env.as_deref(), "backup", ui, true)?;
            let client = client_from_env()?;
            let db = Database::from_file(&db_path).await?;
            println!("{}", "📤 Creating encrypted snapshot...".cyan().bold());
            let blob = create_backup_bytes(db.pool(), &passphrase, None).await?;
            let result = client.push(&blob.bytes).await?;
            println!(
                "{}",
                format!(
                    "✅ {} backup {} ({} bytes, sha256 {}…)",
                    if result.deduplicated {
                        "Unchanged"
                    } else {
                        "Pushed"
                    },
                    result.id,
                    result.size_bytes,
                    &result.sha256[..12.min(result.sha256.len())],
                )
                .green()
            );
            println!(
                "   device: {}, created at: {}",
                result.device_name, result.created_at
            );
            Ok(())
        }
        BackupCommand::List { limit, cursor } => {
            let client = client_from_env()?;
            let page = client.list(limit, cursor.as_deref()).await?;
            if page.backups.is_empty() {
                println!("{}", "No backups on the server yet.".yellow());
                return Ok(());
            }
            for backup in &page.backups {
                println!(
                    "  {}  {}  {:>10} bytes  {}  {}",
                    backup.id,
                    backup.device_name,
                    backup.size_bytes,
                    &backup.sha256[..12.min(backup.sha256.len())],
                    backup.created_at
                );
            }
            if let Some(next) = page.next_cursor {
                println!(
                    "{}",
                    format!("-- next page: --cursor {next}").bright_black()
                );
            }
            Ok(())
        }
        BackupCommand::Pull { id, out } => {
            let client = client_from_env()?;
            let downloaded = client.download(&id).await?;
            std::fs::write(&out, &downloaded.bytes)
                .with_context(|| format!("failed to write {}", out.display()))?;
            println!(
                "{}",
                format!(
                    "✅ Pulled {} → {} ({}, sha256 verified)",
                    id,
                    out.display(),
                    downloaded.bytes.len()
                )
                .green()
            );
            Ok(())
        }
        BackupCommand::Restore {
            id,
            file,
            passphrase_env,
            yes,
        } => {
            let (ciphertext, source_label) = match (id, file) {
                (Some(id), None) => {
                    let client = client_from_env()?;
                    println!("{}", "⬇️  Downloading backup...".cyan().bold());
                    (client.download(&id).await?.bytes, format!("server:{id}"))
                }
                (None, Some(path)) => (
                    std::fs::read(&path)
                        .with_context(|| format!("failed to read {}", path.display()))?,
                    path.display().to_string(),
                ),
                (Some(_), Some(_)) => bail!("pass either a backup id or --file, not both"),
                (None, None) => bail!("pass a backup id or --file"),
            };
            let passphrase = {
                // 确认在前、口令在后：用户取消就不该被问口令
                let db_path_probe = config.get_database_path();
                if !yes {
                    let target = if db_path_probe.exists() {
                        format!("replace {} (a .bak copy is kept)", db_path_probe.display())
                    } else {
                        format!("create {}", db_path_probe.display())
                    };
                    if !ui.confirm(
                        &format!("Restore backup from {source_label} and {target}?"),
                        false,
                    )? {
                        println!("{}", "Restore cancelled.".yellow());
                        return Ok(());
                    }
                }
                resolve_passphrase(passphrase_env.as_deref(), "backup", ui, false)?
            };
            let db_path = config.get_database_path();

            // 解密复验到同目录临时文件，成功后才动现有库
            let mut staged = db_path.clone();
            staged.set_extension("restore.tmp");
            restore_backup_bytes(&ciphertext, &passphrase, &staged)
                .context("restore failed; the current vault was not touched")?;
            if db_path.exists() {
                let mut backup_path = db_path.clone();
                backup_path.set_extension("bak");
                std::fs::copy(&db_path, &backup_path)
                    .with_context(|| format!("failed to back up {} first", db_path.display()))?;
            }
            std::fs::rename(&staged, &db_path).with_context(|| {
                format!("failed to move the restored file to {}", db_path.display())
            })?;
            println!(
                "{}",
                format!(
                    "✅ Restored vault from {source_label} → {}",
                    db_path.display()
                )
                .green()
            );
            let backup_path = db_path.with_extension("bak");
            if backup_path.exists() {
                println!(
                    "{}",
                    format!("   previous vault kept at {}", backup_path.display()).bright_black()
                );
            }
            println!(
                "{}",
                "   attachments are NOT part of the backup (metadata only)".yellow()
            );
            Ok(())
        }
        BackupCommand::Delete { id, yes } => {
            if !yes && !ui.confirm(&format!("Delete backup {id} from the server?"), false)? {
                println!("{}", "Delete cancelled.".yellow());
                return Ok(());
            }
            let client = client_from_env()?;
            client.delete(&id).await?;
            println!("{}", format!("🗑️  Deleted backup {id}.").green());
            Ok(())
        }
    }
}
