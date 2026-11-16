//! `persona secrets …`：本地 Secrets 自动化（gap #28 余项三件套）。
//!
//! 复用 Connect 的解锁/审计路径（`PersonaService` 直读，解密自动记
//! `CredentialDecrypted` 审计），提供三种消费形态：
//!
//! - `resolve`：引用 → 明文（脚本基元，一行一值）
//! - `run`：`--env NAME=REF` 注入子进程环境后执行（shell plugins 通用机制）
//! - `k8s`：渲染 K8s `Secret` 清单（YAML，`data` 走 base64）到 stdout
//! - `external`：Terraform `external` provider 协议助手（stdin JSON 查询 →
//!   stdout JSON 明文；native gRPC provider 需 Go SDK，刻意不做）
//!
//! 引用语法统一为 `IDENTITY/ITEM/FIELD`：identity 按名称、item 按凭据名
//! 精确匹配；`name`/`username`/`url`/`notes` 取元数据（不解密），其余字段
//! 解密后按类型词汇表取值；`secret` 是各类型主秘密的别名。可选字段未设置
//! 即报错（不静默给空串）。

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::storage::Database;
use persona_core::PersonaService;

use refs::{resolve_ref, SecretRef};
use render::{render_external, render_k8s};
use run::run_command;

mod fields;
mod refs;
mod render;
mod run;

#[cfg(test)]
mod tests;

#[derive(Args)]
pub struct SecretsArgs {
    #[command(subcommand)]
    command: SecretsCommand,
}

#[derive(Subcommand)]
enum SecretsCommand {
    /// 解析引用并打印明文（一行一值；顺序与参数一致）
    Resolve {
        /// 引用列表（IDENTITY/ITEM/FIELD）
        #[arg(required = true)]
        refs: Vec<String>,
    },
    /// 注入环境变量后执行命令（明文只进子进程环境，不进 shell 历史）
    Run {
        /// NAME=REF 注入项（可多次）
        #[arg(long = "env")]
        env: Vec<String>,
        /// `--` 之后的命令与参数
        #[arg(last = true, required = true)]
        command: Vec<std::ffi::OsString>,
    },
    /// 渲染 Kubernetes Secret 清单（YAML 到 stdout，供 kubectl apply）
    K8s {
        /// Secret 名称
        #[arg(long)]
        name: String,
        /// 命名空间（缺省不写该字段，跟随 kubectl 上下文）
        #[arg(long)]
        namespace: Option<String>,
        /// KEY=REF 键值来源（可多次；至少一项）
        #[arg(long = "key")]
        keys: Vec<String>,
        /// 附加 label（可多次，KEY=VALUE）
        #[arg(long)]
        labels: Vec<String>,
        /// 附加 annotation（可多次，KEY=VALUE）
        #[arg(long = "annotation")]
        annotations: Vec<String>,
    },
    /// Terraform external provider 协议助手：stdin 收 {"NAME":"REF"} 查询，
    /// stdout 回 {"NAME":"明文"}（错误走 stderr + 非零退出）
    External,
}

pub async fn execute(args: SecretsArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: SecretsArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        SecretsCommand::Resolve { refs } => {
            let service = open_unlocked(config, ui).await?;
            let parsed = refs
                .iter()
                .map(|raw| SecretRef::parse(raw))
                .collect::<Result<Vec<_>>>()?;
            for secret_ref in &parsed {
                println!(
                    "{}",
                    resolve_ref(&service, secret_ref)
                        .await
                        .with_context(|| format!("failed to resolve {secret_ref}"))?
                );
            }
            Ok(())
        }
        SecretsCommand::Run { env, command } => run_command(config, ui, &env, &command).await,
        SecretsCommand::K8s {
            name,
            namespace,
            keys,
            labels,
            annotations,
        } => {
            render_k8s(
                config,
                ui,
                &name,
                namespace.as_deref(),
                &keys,
                &labels,
                &annotations,
            )
            .await
        }
        SecretsCommand::External => render_external(config, ui).await,
    }
}

// -----------------------------------------------------------------------
// 解锁（与 connect.rs 同一条链：惯例 PERSONA_MASTER_PASSWORD env 优先）
// -----------------------------------------------------------------------

async fn open_unlocked(config: &CliConfig, ui: &dyn PromptUi) -> Result<PersonaService> {
    let db = Database::from_file(config.get_database_path())
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db)
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    if !service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        bail!("Workspace not initialized. Run `persona init` first");
    }

    let password = crate::commands::service::prompt_master_password(ui)?;
    match service
        .authenticate_user(&password)
        .await
        .map_err(|e| anyhow!("Failed to authenticate user: {}", e))?
    {
        persona_core::auth::authentication::AuthResult::Success => Ok(service),
        other => bail!("Authentication failed: {:?}", other),
    }
}
