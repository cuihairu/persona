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
use persona_core::backup::{create_backup_bytes, restore_backup_bytes, BackupClient};
use persona_core::Database;
use std::path::PathBuf;

#[derive(Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    command: BackupCommand,
}

#[derive(Subcommand)]
enum BackupCommand {
    /// 快照当前库 → 加密 → 推送到服务器（无需解锁主密码）
    Push {
        /// 从指定环境变量读备份口令（CI/自动化；变量必须已设且非空）
        #[arg(long)]
        passphrase_env: Option<String>,
    },
    /// 列出服务器上的备份版本（新→旧）
    List {
        /// 每页条数（服务器默认 20、上限 100）
        #[arg(long, default_value_t = 20)]
        limit: u32,
        /// 上一页返回的游标
        #[arg(long)]
        cursor: Option<String>,
    },
    /// 下载备份密文到文件（不解密、不换库）
    Pull {
        /// 备份版本 id
        id: String,
        /// 输出路径
        #[arg(short, long)]
        out: PathBuf,
    },
    /// 恢复：下载（或 --file 本地密文）→ 解密复验 → 留 .bak → 换库
    Restore {
        /// 要恢复的服务器备份版本 id（与 --file 二选一）
        id: Option<String>,
        /// 本地密文文件（与 id 二选一；离线恢复路径）
        #[arg(long)]
        file: Option<PathBuf>,
        /// 从指定环境变量读备份口令
        #[arg(long)]
        passphrase_env: Option<String>,
        /// 跳过确认提示（危险：直接覆盖当前库）
        #[arg(short, long)]
        yes: bool,
    },
    /// 删除服务器上的备份版本
    Delete {
        /// 备份版本 id
        id: String,
        /// 跳过确认提示
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

/// `PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` 都非空才构造客户端
/// （fail-closed，与事件上报同一惯例；缺一只直接报错——备份命令没有
/// "静默跳过"的合理降级）。
fn client_from_env() -> Result<BackupClient> {
    let url = non_blank_env("PERSONA_SERVER_URL");
    let token = non_blank_env("PERSONA_SERVER_TOKEN");
    match (url, token) {
        (Some(url), Some(token)) => BackupClient::new(&url, token),
        _ => bail!("PERSONA_SERVER_URL and PERSONA_SERVER_TOKEN must both be set"),
    }
}

fn non_blank_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// 备份口令解析：`--passphrase-env VAR`（必须已设且非空——显式指定
/// 变量名后变量缺失是配置错误，不静默回退）→ `PERSONA_PAYLOAD_PASSPHRASE`
/// → 交互提示。push 带确认（新口令要录两遍），restore 不带（口令是既有的）。
fn resolve_passphrase(
    env_var: Option<&str>,
    kind: &str,
    ui: &dyn PromptUi,
    confirm: bool,
) -> Result<String> {
    if let Some(var) = env_var {
        return std::env::var(var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("--passphrase-env {var} is not set (or blank)"));
    }
    if let Ok(value) = std::env::var("PERSONA_PAYLOAD_PASSPHRASE") {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    let confirmation = confirm.then_some(("Confirm passphrase", "Passphrases do not match"));
    ui.password(&format!("Enter {kind} passphrase"), false, confirmation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{Identity, IdentityType};
    use persona_core::storage::repository::{IdentityRepository, Repository};
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn config_for(dir: &tempfile::TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// 建一个带单个 identity 的库并返回 (库, identity id)。
    async fn seeded_db(path: &std::path::Path) -> Database {
        let db = Database::from_file(path).await.unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.create(&Identity::new("Seed".to_owned(), IdentityType::Personal))
            .await
            .unwrap();
        db
    }

    async fn identity_count(path: &std::path::Path) -> usize {
        let db = Database::from_file(path).await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.find_all().await.unwrap().len()
    }

    #[test]
    fn resolve_passphrase_prefers_explicit_env_var() {
        let _guard = env_guard();
        std::env::set_var("PERSONA_BACKUP_TEST_PW", "from-var");
        // 不预载答案：若实现误走 prompt，ScriptedUi 直接 panic（更强的保护）
        let ui = ScriptedUi::new();
        let got = resolve_passphrase(Some("PERSONA_BACKUP_TEST_PW"), "backup", &ui, true).unwrap();
        assert_eq!(got, "from-var");
        assert!(ui.exhausted(), "explicit var must skip the prompt");

        // 显式指定的变量缺失/空白是配置错误，不静默回退
        std::env::set_var("PERSONA_BACKUP_TEST_PW", "  ");
        let err =
            resolve_passphrase(Some("PERSONA_BACKUP_TEST_PW"), "backup", &ui, true).unwrap_err();
        assert!(err.to_string().contains("--passphrase-env"));
        std::env::remove_var("PERSONA_BACKUP_TEST_PW");
    }

    #[test]
    fn resolve_passphrase_falls_back_to_payload_env_then_prompt() {
        let _guard = env_guard();
        std::env::set_var("PERSONA_PAYLOAD_PASSPHRASE", "payload-pw");
        let ui = ScriptedUi::new();
        let got = resolve_passphrase(None, "backup", &ui, true).unwrap();
        assert_eq!(got, "payload-pw");
        assert!(ui.exhausted());
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let ui = ScriptedUi::new().password("typed-pw");
        let got = resolve_passphrase(None, "backup", &ui, false).unwrap();
        assert_eq!(got, "typed-pw");
        assert!(ui.exhausted());
    }

    #[test]
    fn client_from_env_fails_closed_without_both_vars() {
        let _guard = env_guard();
        std::env::set_var("PERSONA_SERVER_URL", "http://127.0.0.1:9");
        std::env::remove_var("PERSONA_SERVER_TOKEN");
        let err = match client_from_env() {
            Ok(_) => panic!("client must not be constructed without both env vars"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("must both be set"));
        std::env::remove_var("PERSONA_SERVER_URL");
    }

    #[tokio::test]
    async fn push_requires_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let args = BackupArgs {
            command: BackupCommand::Push {
                passphrase_env: Some("PERSONA_BACKUP_TEST_PW".to_string()),
            },
        };
        std::env::set_var("PERSONA_BACKUP_TEST_PW", "pw");
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("persona migrate"));
        std::env::remove_var("PERSONA_BACKUP_TEST_PW");
    }

    #[tokio::test]
    async fn restore_from_file_swaps_vault_and_keeps_bak() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db_path = config.get_database_path();

        // 库 v1（1 个 identity）→ 备份；随后库继续长到 2 个
        let db = seeded_db(&db_path).await;
        let blob = create_backup_bytes(db.pool(), "backup-pass", None)
            .await
            .unwrap();
        let ciphertext_path = dir.path().join("vault.persenc");
        std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.create(&Identity::new(
            "After Backup".to_owned(),
            IdentityType::Personal,
        ))
        .await
        .unwrap();
        db.close().await;
        assert_eq!(identity_count(&db_path).await, 2);

        // 恢复：确认 yes + 口令（restore 无确认式双录）
        let ui = ScriptedUi::new().confirm(true).password("backup-pass");
        let args = BackupArgs {
            command: BackupCommand::Restore {
                id: None,
                file: Some(ciphertext_path.clone()),
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());

        // 库回到备份时刻（1 个），.bak 保留覆盖前的状态（2 个）
        let mut bak = db_path.clone();
        bak.set_extension("bak");
        assert_eq!(identity_count(&db_path).await, 1, "restored vault");
        assert_eq!(identity_count(&bak).await, 2, "pre-restore copy");
        let mut staged = db_path.clone();
        staged.set_extension("restore.tmp");
        assert!(!staged.exists(), "staging file must be renamed away");
    }

    #[tokio::test]
    async fn restore_rejects_wrong_passphrase_and_leaves_vault_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db_path = config.get_database_path();
        let db = seeded_db(&db_path).await;
        let blob = create_backup_bytes(db.pool(), "right-pass", None)
            .await
            .unwrap();
        let ciphertext_path = dir.path().join("vault.persenc");
        std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
        db.close().await;

        let ui = ScriptedUi::new().confirm(true).password("wrong-pass");
        let args = BackupArgs {
            command: BackupCommand::Restore {
                id: None,
                file: Some(ciphertext_path),
                passphrase_env: None,
                yes: true,
            },
        };
        let err = execute_with(args, &config, &ui).await.unwrap_err();
        assert!(
            err.to_string().contains("not touched"),
            "unexpected error: {err}"
        );
        assert_eq!(identity_count(&db_path).await, 1, "vault unchanged");
        let mut bak = db_path.clone();
        bak.set_extension("bak");
        assert!(!bak.exists(), "no .bak on failed restore");
    }

    #[tokio::test]
    async fn restore_requires_confirmation_when_not_forced() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db_path = config.get_database_path();
        let db = seeded_db(&db_path).await;
        let blob = create_backup_bytes(db.pool(), "backup-pass", None)
            .await
            .unwrap();
        let ciphertext_path = dir.path().join("vault.persenc");
        std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
        db.close().await;

        // confirm(false) → 取消；口令提示不应到达（确认在前）
        let ui = ScriptedUi::new().confirm(false);
        let args = BackupArgs {
            command: BackupCommand::Restore {
                id: None,
                file: Some(ciphertext_path),
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());
        assert_eq!(
            identity_count(&db_path).await,
            1,
            "cancelled restore is a no-op"
        );
        let mut bak = db_path.clone();
        bak.set_extension("bak");
        assert!(!bak.exists());
    }
}
