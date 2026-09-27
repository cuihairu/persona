//! `persona travel …`：旅行模式（把被标记身份整包移出本设备/原样恢复）。
//!
//! 语义与门禁都在 core（见 `persona_core::travel`）；本模块只做编排：
//! 状态展示与 mark/unmark 不需要解密主密钥（status 无门禁、mark 走
//! switch.rs 的解锁分叉），enter/exit 需要完整解锁（`init_service`，
//! 同时带起附件存储）。travel 口令与主密码相互独立，三级解析照抄
//! backup.rs：`--passphrase-env` → `PERSONA_PAYLOAD_PASSPHRASE` → 提示。

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::models::{AuditAction, AuditLog, ResourceType};
use persona_core::storage::{AuditLogRepository, IdentityRepository, Repository};
use persona_core::Database;
use persona_core::PersonaService;

#[derive(Args)]
pub struct TravelArgs {
    #[command(subcommand)]
    command: TravelCommand,
}

#[derive(Subcommand)]
enum TravelCommand {
    /// 显示旅行模式状态（旗标/sidecar/一致性）与被标记身份
    Status,
    /// 标记身份：进入旅行模式时随之移出本设备
    Mark {
        /// 身份名
        name: String,
    },
    /// 取消标记（身份留在本设备）
    Unmark {
        /// 身份名
        name: String,
    },
    /// 进入旅行模式：被标记身份打包加密进 sidecar 并从主库删除
    Enter {
        /// 从指定环境变量读 travel 口令（必须已设且非空）
        #[arg(long)]
        passphrase_env: Option<String>,
        /// 跳过确认提示（危险：被标记身份将立即从本机移除）
        #[arg(short, long)]
        yes: bool,
    },
    /// 退出旅行模式：输 travel 口令把数据原样恢复回主库
    Exit {
        /// 从指定环境变量读 travel 口令
        #[arg(long)]
        passphrase_env: Option<String>,
    },
}

pub async fn execute(args: TravelArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: TravelArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        TravelCommand::Status => show_status(config).await,
        TravelCommand::Mark { name } => set_marked(config, ui, &name, true).await,
        TravelCommand::Unmark { name } => set_marked(config, ui, &name, false).await,
        TravelCommand::Enter {
            passphrase_env,
            yes,
        } => enter(config, ui, passphrase_env.as_deref(), yes).await,
        TravelCommand::Exit { passphrase_env } => exit(config, ui, passphrase_env.as_deref()).await,
    }
}

/// 打开库 + 迁移 + 构造未解锁 service（status 只读旗标，无需主密码）。
async fn open_service(config: &CliConfig) -> Result<(Database, PersonaService)> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    Ok((db, service))
}

/// 被标记身份清单。sqlx 在 cli 只是 dev-dependency（生产代码走 repository
/// 层），这里开一条只读连接列出全部身份再过滤。
async fn marked_names(config: &CliConfig) -> Result<Vec<String>> {
    let db = Database::from_file(config.get_database_path())
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    let mut names: Vec<String> = IdentityRepository::new(db)
        .find_all()
        .await
        .map_err(|e| anyhow!("Failed to list identities: {}", e))?
        .into_iter()
        .filter(|identity| identity.travel_marked)
        .map(|identity| identity.name)
        .collect();
    names.sort();
    Ok(names)
}

async fn show_status(config: &CliConfig) -> Result<()> {
    let db_path = config.get_database_path();
    let (_db, service) = open_service(config).await?;
    let status = service
        .travel_status(&db_path)
        .await
        .into_anyhow()
        .context("failed to read travel status")?;

    println!("{}", "✈️  Travel mode".cyan().bold());
    if status.active {
        if status.inconsistent {
            println!(
                "{}",
                "⚠️  INCONSISTENT: travel mode is active but the sidecar file is \
                 missing — the data only lived in that file and is LOST."
                    .red()
                    .bold()
            );
            println!(
                "   expected sidecar: {}",
                persona_core::travel::sidecar_path(&db_path).display()
            );
        } else {
            match &status.entered_at {
                Some(at) => println!("{}", format!("State: ACTIVE (since {at})").green().bold()),
                None => println!("{}", "State: ACTIVE".green().bold()),
            }
            println!(
                "   marked identities are sealed in {}",
                persona_core::travel::sidecar_path(&db_path).display()
            );
        }
    } else {
        println!("State: inactive");
        let sidecar = persona_core::travel::sidecar_path(&db_path);
        if status.sidecar_exists {
            println!(
                "{}",
                format!(
                    "⚠️  Leftover sidecar found at {} — remove it manually or run \
                     `persona travel exit` to restore",
                    sidecar.display()
                )
                .yellow()
            );
        }
    }

    let marked = marked_names(config).await?;
    if marked.is_empty() {
        println!("Marked for travel: (none)");
        println!(
            "{}",
            "Use `persona travel mark <name>` to mark an identity.".bright_black()
        );
    } else {
        println!("Marked for travel: {}", marked.join(", "));
    }
    Ok(())
}

/// mark/unmark：switch.rs 的解锁分叉——有用户则解锁走 service（自带审计），
/// 未初始化库直连 repo 并手工补审计（身份列存在但主密码体系未建）。
async fn set_marked(config: &CliConfig, ui: &dyn PromptUi, name: &str, marked: bool) -> Result<()> {
    let (db, mut service) = open_service(config).await?;

    if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = crate::commands::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Failed to authenticate user: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => bail!("Authentication failed: {:?}", other),
        }
        let identity = service
            .get_identity_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to load identity: {}", e))?
            .with_context(|| format!("Identity '{name}' not found"))?;
        service
            .set_travel_marked(&identity.id, marked)
            .await
            .into_anyhow()
            .context("failed to update travel mark")?;
    } else {
        let repo = IdentityRepository::new(db.clone());
        let mut identity = repo
            .find_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to load identity: {}", e))?
            .with_context(|| format!("Identity '{name}' not found"))?;
        identity.travel_marked = marked;
        repo.update(&identity)
            .await
            .map_err(|e| anyhow!("Failed to update identity: {}", e))?;
        let log = AuditLog::new(AuditAction::TravelMarkChanged, ResourceType::Identity, true)
            .with_identity_id(Some(identity.id));
        AuditLogRepository::new(db.clone())
            .create(&log)
            .await
            .map_err(|e| anyhow!("Failed to write audit log: {}", e))?;
        crate::commands::service::emit_audit(&log);
    }

    println!(
        "{}",
        format!(
            "✓ Identity '{name}' {} for travel",
            if marked { "marked" } else { "unmarked" }
        )
        .green()
    );
    Ok(())
}

async fn enter(
    config: &CliConfig,
    ui: &dyn PromptUi,
    passphrase_env: Option<&str>,
    yes: bool,
) -> Result<()> {
    let db_path = config.get_database_path();
    let service = crate::commands::service::init_service(config, ui).await?;

    let marked = marked_names(config).await?;
    if marked.is_empty() {
        bail!("no identities are marked for travel — use `persona travel mark <name>` first");
    }

    // 确认在前、口令在后：用户取消就不该被问口令
    if !yes {
        let listing = marked.join(", ");
        if !ui.confirm(
            &format!(
                "Move {len} marked identit{} ({listing}) off this device? \
                 They will only be recoverable with the travel passphrase.",
                if marked.len() == 1 { "y" } else { "ies" },
                len = marked.len(),
            ),
            false,
        )? {
            println!("{}", "Enter travel mode cancelled.".yellow());
            return Ok(());
        }
    }
    let passphrase = resolve_passphrase(passphrase_env, ui, true)?;

    println!("{}", "📦 Packing marked identities...".cyan().bold());
    let counts = service
        .enter_travel_mode(&db_path, &passphrase)
        .await
        .into_anyhow()?;
    println!(
        "{}",
        format!(
            "✅ Travel mode active — {} identit{}, {} credential{}, {} attachment file{}, \
             {} passkey{}, {} wallet{} and {} history rows moved to {}",
            counts.identities,
            if counts.identities == 1 { "y" } else { "ies" },
            counts.credentials,
            if counts.credentials == 1 { "" } else { "s" },
            counts.files,
            if counts.files == 1 { "" } else { "s" },
            counts.passkeys,
            if counts.passkeys == 1 { "" } else { "s" },
            counts.wallets,
            if counts.wallets == 1 { "" } else { "s" },
            counts.history_rows,
            persona_core::travel::sidecar_path(&db_path).display(),
        )
        .green()
    );
    println!(
        "{}",
        "   The travel passphrase is the ONLY way to restore this data — \
         there is no master-password fallback."
            .yellow()
    );
    Ok(())
}

async fn exit(config: &CliConfig, ui: &dyn PromptUi, passphrase_env: Option<&str>) -> Result<()> {
    let db_path = config.get_database_path();
    let service = crate::commands::service::init_service(config, ui).await?;

    if !persona_core::travel::sidecar_path(&db_path).exists() {
        bail!(
            "no travel sidecar at {} — travel mode was never entered here (or the file was removed)",
            persona_core::travel::sidecar_path(&db_path).display()
        );
    }

    // 口令本身就是确认：单录
    let passphrase = resolve_passphrase(passphrase_env, ui, false)?;

    println!("{}", "📥 Restoring marked identities...".cyan().bold());
    let counts = service
        .exit_travel_mode(&db_path, &passphrase)
        .await
        .into_anyhow()?;
    println!(
        "{}",
        format!(
            "✅ Travel mode exited — {} identit{}, {} credential{}, {} attachment file{}, \
             {} passkey{}, {} wallet{} and {} history rows restored",
            counts.identities,
            if counts.identities == 1 { "y" } else { "ies" },
            counts.credentials,
            if counts.credentials == 1 { "" } else { "s" },
            counts.files,
            if counts.files == 1 { "" } else { "s" },
            counts.passkeys,
            if counts.passkeys == 1 { "" } else { "s" },
            counts.wallets,
            if counts.wallets == 1 { "" } else { "s" },
            counts.history_rows,
        )
        .green()
    );
    Ok(())
}

/// travel 口令三级解析（照抄 backup.rs）：显式 env 变量 →
/// `PERSONA_PAYLOAD_PASSPHRASE` → 交互提示。enter 带确认（新口令双录，
/// 由终端层执行），exit 不带（口令是既有的）。
fn resolve_passphrase(env_var: Option<&str>, ui: &dyn PromptUi, confirm: bool) -> Result<String> {
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
    ui.password("Enter travel passphrase", false, confirmation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{Identity, IdentityType, Workspace};
    use persona_core::storage::WorkspaceRepository;

    /// 进程 env 是单槽：凡 set/remove `PERSONA_*` 的测试都必须与读它的
    /// 测试（prompt_master_password env 优先）串行。统一拿 bridge 测试的
    /// 全局锁（switch/ssh/backup 同款，poisoned 恢复防级联）。
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::commands::bridge::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// env 变量 RAII 守卫：panic unwind 也保证清掉。之前靠测试尾部显式
    /// remove_var，一次 panic 就把 PERSONA_MASTER_PASSWORD 泄漏给同进程
    /// 其它测试（switch/ssh 的 ScriptedUi 队列被 env 抢答而错位失败）。
    struct EnvVar(&'static str);

    impl EnvVar {
        fn set(name: &'static str, value: &str) -> Self {
            std::env::set_var(name, value);
            Self(name)
        }

        /// 确保变量不存在（清掉进程里可能的残留），退出时无需恢复。
        fn remove(name: &'static str) -> Self {
            std::env::remove_var(name);
            Self(name)
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    fn config_for(dir: &tempfile::TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// 建一个带 master 用户的库（含一个 identity），返回 (dir, config)。
    ///
    /// 照 `persona init` 的完整流程补 workspace 行——core 的 travel
    /// settings 读写要求 workspaces 首行存在。
    async fn seeded_workspace() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        WorkspaceRepository::new(db.clone())
            .create(&Workspace::new(
                dir.path().to_path_buf(),
                "test".to_string(),
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let identity = service
            .create_identity("work".to_string(), IdentityType::Work)
            .await
            .unwrap();
        assert!(!identity.travel_marked);
        (dir, config)
    }

    /// 行存在看 travel_marked；enter 之后行被移出库，None 同样视为
    /// 未标记（这正是"被标记身份已不在本机"要断言的状态）。
    async fn identity_marked(config: &CliConfig, name: &str) -> bool {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.find_by_name(name)
            .await
            .unwrap()
            .map(|identity| identity.travel_marked)
            .unwrap_or(false)
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_then_unmark_persists_and_audits() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let ui = ScriptedUi::new();
        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());
        assert!(identity_marked(&config, "work").await);

        let audits: i64 = {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            sqlx::query_scalar(
                "SELECT COUNT(1) FROM audit_logs WHERE action = 'travel_mark_changed'",
            )
            .fetch_one(db.pool())
            .await
            .unwrap()
        };
        assert_eq!(audits, 1, "mark flip is audited");

        let args = TravelArgs {
            command: TravelCommand::Unmark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(!identity_marked(&config, "work").await);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_unknown_identity_fails() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;
        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "ghost".to_string(),
            },
        };
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn enter_requires_confirmation_then_moves_data_to_sidecar() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _pp = EnvVar::remove("PERSONA_PAYLOAD_PASSPHRASE");
        let (_dir, config) = seeded_workspace().await;

        // 先标记
        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();

        // 无标记即 enter：拒绝
        // （work 已标记，这里验证的是确认取消路径）
        let ui = ScriptedUi::new().confirm(false);
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(
            ui.exhausted(),
            "cancel must not reach the passphrase prompt"
        );
        assert!(!persona_core::travel::sidecar_path(&config.get_database_path()).exists());

        // 确认 + 口令（双录由 dialoguer 在 TerminalUi 内部完成，ScriptedUi
        // 的 password 忽略 confirmation 参数、只消费一个答案）
        let ui = ScriptedUi::new().confirm(true).password("travel-secret");
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());

        // 行消失 + sidecar 落盘 + 旗标开
        assert!(!identity_marked(&config, "work").await, "row must be gone");
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM identities")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "marked identity removed from the vault");
        let sealed = std::fs::read(persona_core::travel::sidecar_path(
            &config.get_database_path(),
        ))
        .unwrap();
        assert!(persona_core::backup::file_crypto::is_persona_encrypted(
            &sealed
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn exit_wrong_passphrase_keeps_sidecar_then_right_one_restores() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _tp = EnvVar::set("PERSONA_TRAVEL_TEST_PW", "travel-secret");
        let (_dir, config) = seeded_workspace().await;
        let db_path = config.get_database_path();

        let args = TravelArgs {
            command: TravelCommand::Mark {
                name: "work".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
                yes: true,
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();

        // 错口令：sidecar 保留、数据仍缺失
        let ui = ScriptedUi::new().password("wrong");
        let args = TravelArgs {
            command: TravelCommand::Exit {
                passphrase_env: None,
            },
        };
        let err = execute_with(args, &config, &ui).await.unwrap_err();
        assert!(err.to_string().contains("passphrase is wrong"), "{err}");
        assert!(persona_core::travel::sidecar_path(&db_path).exists());

        // 对口令：恢复 + sidecar 删除
        let ui = ScriptedUi::new().password("travel-secret");
        let args = TravelArgs {
            command: TravelCommand::Exit {
                passphrase_env: None,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());
        assert!(!persona_core::travel::sidecar_path(&db_path).exists());
        let db = Database::from_file(&db_path).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM identities")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1, "identity restored");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn enter_reports_missing_passphrase_env() {
        let _guard = env_guard();
        let _tp = EnvVar::remove("PERSONA_TRAVEL_TEST_PW");
        // 显式指定的 env 缺失是配置错误，不静默回退
        let ui = ScriptedUi::new();
        let err = super::resolve_passphrase(Some("PERSONA_TRAVEL_TEST_PW"), &ui, true).unwrap_err();
        assert!(err.to_string().contains("--passphrase-env"), "{err}");
        assert!(ui.exhausted(), "env path must not touch the prompt");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn enter_without_marked_identities_is_rejected() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _tp = EnvVar::set("PERSONA_TRAVEL_TEST_PW", "pw");
        let (_dir, config) = seeded_workspace().await;
        let args = TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
                yes: true,
            },
        };
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no identities are marked"),
            "{err}"
        );
    }

    /// 未初始化主密码体系的库：直建 workspace + identity，不走
    /// `initialize_user` → `has_users()` 为 false，mark 走 repo 直连分叉。
    async fn seeded_workspace_without_users() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        WorkspaceRepository::new(db.clone())
            .create(&Workspace::new(
                dir.path().to_path_buf(),
                "test".to_string(),
            ))
            .await
            .unwrap();
        IdentityRepository::new(db.clone())
            .create(&Identity::new("anon".to_owned(), IdentityType::Personal))
            .await
            .unwrap();
        db.close().await;
        (dir, config)
    }

    fn status_args() -> TravelArgs {
        TravelArgs {
            command: TravelCommand::Status,
        }
    }

    fn mark_args(name: &str) -> TravelArgs {
        TravelArgs {
            command: TravelCommand::Mark {
                name: name.to_string(),
            },
        }
    }

    /// 走 env 口令 + 跳过确认的 enter（要求测试已设 `PERSONA_TRAVEL_TEST_PW`）。
    fn enter_args() -> TravelArgs {
        TravelArgs {
            command: TravelCommand::Enter {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
                yes: true,
            },
        }
    }

    /// 未建主密码体系时 mark 也要能标（首次使用前就可能想标记），且必须补
    /// 审计——这是 set_marked 里与 service 分叉平行的手工路径。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_on_an_uninitialized_vault_updates_the_row_and_audits() {
        let _guard = env_guard();
        // 不设 PERSONA_MASTER_PASSWORD：若实现误走解锁分叉，无 env 无提示
        // 队列的 ScriptedUi 会直接 panic（比断言更早暴露错误分叉）。
        let (_dir, config) = seeded_workspace_without_users().await;

        execute_with(mark_args("anon"), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(identity_marked(&config, "anon").await);

        let audit_count = || async {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(1) FROM audit_logs WHERE action = 'travel_mark_changed'",
            )
            .fetch_one(db.pool())
            .await
            .unwrap();
            db.close().await;
            count
        };
        assert_eq!(audit_count().await, 1, "repo 分叉也要补审计");

        let args = TravelArgs {
            command: TravelCommand::Unmark {
                name: "anon".to_string(),
            },
        };
        execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(!identity_marked(&config, "anon").await);
        assert_eq!(audit_count().await, 2, "mark 与 unmark 各补一条审计");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mark_with_a_wrong_master_password_is_rejected() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "not-the-pin");
        let (_dir, config) = seeded_workspace().await;
        let err = execute_with(mark_args("work"), &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Authentication failed"), "{err}");
        assert!(
            !identity_marked(&config, "work").await,
            "认证失败不得改旗标"
        );
    }

    /// status 的四种世界状态（inactive / 残留 sidecar / ACTIVE / 旗标在而
    /// 容器没了）各走一遍渲染；分支条件用 core 的 travel_status 钉死，
    /// stdout 不进断言（单元测试捕不到，行为由状态断言背书）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn status_walks_inactive_leftover_active_and_inconsistent_states() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let _tp = EnvVar::set("PERSONA_TRAVEL_TEST_PW", "travel-secret");
        let (_dir, config) = seeded_workspace().await;
        let db_path = config.get_database_path();
        let sidecar = persona_core::travel::sidecar_path(&db_path);

        async fn flags(config: &CliConfig) -> persona_core::travel::TravelStatus {
            // PersonaService 没有 Debug：init_service 失败时手动 panic 带出错误
            let service =
                match crate::commands::service::init_service(config, &ScriptedUi::new()).await {
                    Ok(service) => service,
                    Err(err) => panic!("init_service failed: {err}"),
                };
            service
                .travel_status(&config.get_database_path())
                .await
                .into_anyhow()
                .unwrap()
        }

        // ① inactive、无 sidecar、无标记
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert!(!flags(&config).await.active);

        // ② inactive 但残留 sidecar（手造一个）：警告分支
        std::fs::write(&sidecar, b"leftover").unwrap();
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let status = flags(&config).await;
        assert!(!status.active && status.sidecar_exists);

        // ③ 标记两个身份（marked_names 必须排序输出）
        let service =
            match crate::commands::service::init_service(&config, &ScriptedUi::new()).await {
                Ok(service) => service,
                Err(err) => panic!("init_service failed: {err}"),
            };
        service
            .create_identity("alpha".to_string(), IdentityType::Work)
            .await
            .unwrap();
        execute_with(mark_args("work"), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(mark_args("alpha"), &config, &ScriptedUi::new())
            .await
            .unwrap();
        // 挂着标记时的 status（清单有内容、随包提示两个分支都走到）
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert_eq!(
            marked_names(&config).await.unwrap(),
            vec!["alpha".to_string(), "work".to_string()],
            "标记清单必须排序"
        );

        // ④ 残留 sidecar 挡路时 enter 必须拒绝：那是上一包的容器，覆盖=丢数据
        let err = execute_with(enter_args(), &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("travel sidecar already exists"),
            "unexpected: {err}"
        );

        // ⑤ 清掉残留 → enter → ACTIVE
        std::fs::remove_file(&sidecar).unwrap();
        execute_with(enter_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let status = flags(&config).await;
        assert!(status.active && !status.inconsistent);
        assert!(status.entered_at.is_some(), "enter 要记录进入时刻");
        assert!(
            marked_names(&config).await.unwrap().is_empty(),
            "行已随包移走"
        );

        // ⑥ 手删 sidecar：旗标仍在而容器没了 → inconsistent（数据已丢，
        // 必须诚实呈现而不是假装可恢复）
        std::fs::remove_file(&sidecar).unwrap();
        execute_with(status_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let status = flags(&config).await;
        assert!(status.active && status.inconsistent);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn exit_without_a_sidecar_names_where_it_should_be() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;
        let args = TravelArgs {
            command: TravelCommand::Exit {
                passphrase_env: Some("PERSONA_TRAVEL_TEST_PW".to_string()),
            },
        };
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no travel sidecar"), "{err}");
    }

    /// `PERSONA_PAYLOAD_PASSPHRASE` 命中即返回、不碰提示；空白视同未设。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn travel_passphrase_falls_back_to_payload_env() {
        let _guard = env_guard();
        let _pp = EnvVar::set("PERSONA_PAYLOAD_PASSPHRASE", "payload-pw");
        let ui = ScriptedUi::new();
        assert_eq!(resolve_passphrase(None, &ui, false).unwrap(), "payload-pw");
        assert!(ui.exhausted(), "payload env 命中就别碰提示");

        let _blank = EnvVar::set("PERSONA_PAYLOAD_PASSPHRASE", "   ");
        let ui = ScriptedUi::new().password("typed-after-blank");
        assert_eq!(
            resolve_passphrase(None, &ui, false).unwrap(),
            "typed-after-blank"
        );
        assert!(ui.exhausted());
    }
}
