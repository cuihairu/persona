//! `persona secrets …`: local Secrets automation (the remaining gap #28 trio).
//!
//! Reuses Connect's unlock/audit path (reads directly via `PersonaService`;
//! decryption automatically records a `CredentialDecrypted` audit) and offers these
//! consumption forms:
//!
//! - `resolve`: reference → plaintext (a script primitive, one value per line)
//! - `run`: inject `--env NAME=REF` into the child environment, then execute (the
//!   generic shell plugins mechanism)
//! - `k8s`: render a K8s `Secret` manifest (YAML, `data` base64-encoded) to stdout
//! - `external`: the Terraform `external` provider protocol helper (stdin JSON query →
//!   stdout JSON plaintext; a native gRPC provider would need the Go SDK, deliberately not done)
//!
//! The reference syntax is uniformly `IDENTITY/ITEM/FIELD`: identity matched by name
//! and item matched exactly by credential name; `name`/`username`/`url`/`notes` come
//! from metadata (no decryption), other fields are decrypted and looked up via the type
//! vocabulary; `secret` aliases each type's primary secret. An unset optional field
//! errors out (no silent empty string).

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
    /// Resolve references and print plaintext (one value per line; order matches the arguments)
    Resolve {
        /// The list of references (IDENTITY/ITEM/FIELD)
        #[arg(required = true)]
        refs: Vec<String>,
    },
    /// Execute a command with injected environment variables (plaintext only enters the child environment, never the shell history)
    Run {
        /// NAME=REF injection items (repeatable)
        #[arg(long = "env")]
        env: Vec<String>,
        /// The command and arguments after `--`
        #[arg(last = true, required = true)]
        command: Vec<std::ffi::OsString>,
    },
    /// Render a Kubernetes Secret manifest (YAML to stdout, for kubectl apply)
    K8s {
        /// The Secret name
        #[arg(long)]
        name: String,
        /// The namespace (omitted by default, following the kubectl context)
        #[arg(long)]
        namespace: Option<String>,
        /// KEY=REF value sources (repeatable; at least one)
        #[arg(long = "key")]
        keys: Vec<String>,
        /// Extra labels (repeatable, KEY=VALUE)
        #[arg(long)]
        labels: Vec<String>,
        /// Extra annotations (repeatable, KEY=VALUE)
        #[arg(long = "annotation")]
        annotations: Vec<String>,
    },
    /// Terraform external provider protocol helper: accepts a {"NAME":"REF"} query on
    /// stdin and answers {"NAME":"<plaintext>"} on stdout (errors go to stderr + non-zero exit)
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
// Unlock (the same chain as connect.rs: by convention the PERSONA_MASTER_PASSWORD env takes priority)
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
