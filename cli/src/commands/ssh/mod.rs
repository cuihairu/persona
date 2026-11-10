use crate::utils::core_ext::CoreResultExt;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    models::{CredentialData, CredentialType, Identity as CoreIdentity, SecurityLevel, SshKeyData},
    Database, PersonaService,
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// 读 agent socket 响应的长度上限（与 ssh-agent 侧 BUG-1 同法）：恶意/损坏
mod agent;
mod args;
mod host;
mod keys;
mod signing;

pub use args::{SshArgs, SshSubcommand};

use agent::{agent_status, start_agent, stop_agent};
use host::{authorize, run_with_host};
use keys::{
    export_pubkey, generate_key, import_file, import_seed, list_all_keys, list_keys, remove_key,
};
use signing::gpg_sign;

/// authorized_keys 分发的参数集（避免 handler 摊成十几个位置参数）。
struct AuthorizeOptions {
    id: Option<Uuid>,
    remove: bool,
    list: bool,
    dry_run: bool,
    port: Option<u16>,
    remote_path: Option<String>,
}

pub async fn execute(args: SshArgs, config: &crate::config::CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: SshArgs,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    match args.command {
        SshSubcommand::Generate {
            identity,
            name,
            key_type,
            comment,
            favorite,
        } => generate_key(&identity, name, &key_type, comment, favorite, config, ui).await,
        SshSubcommand::List { identity } => list_keys(&identity, config, ui).await,
        SshSubcommand::Remove { id, yes } => remove_key(id, yes, config, ui).await,
        SshSubcommand::Status => agent_status(config).await,
        SshSubcommand::AddToAgent {
            identity,
            print_export,
        } => start_agent(config, print_export, ui, identity.as_deref()).await,
        SshSubcommand::AgentStatus => agent_status(config).await,
        SshSubcommand::StartAgent { print_export } => {
            start_agent(config, print_export, ui, None).await
        }
        SshSubcommand::ListAll => list_all_keys(config, ui).await,
        SshSubcommand::Import {
            identity,
            name,
            seed_base64,
            seed_hex,
        } => import_seed(&identity, name, seed_base64, seed_hex, config, ui).await,
        SshSubcommand::ImportFile {
            identity,
            file,
            name,
            passphrase,
        } => import_file(&identity, &file, name, passphrase, config, ui).await,
        SshSubcommand::ExportPub { id } => export_pubkey(id, config, ui).await,
        SshSubcommand::StopAgent => stop_agent(),
        SshSubcommand::Run { host, command } => run_with_host(&host, command, config).await,
        SshSubcommand::GpgSign {
            mode,
            namespace,
            key,
            file,
            output,
        } => gpg_sign(&mode, &namespace, key, &file, output, config, ui).await,
        SshSubcommand::Authorize {
            identity,
            host,
            id,
            remove,
            list,
            dry_run,
            port,
            remote_path,
        } => {
            authorize(
                &identity,
                &host,
                AuthorizeOptions {
                    id,
                    remove,
                    list,
                    dry_run,
                    port,
                    remote_path,
                },
                config,
                ui,
            )
            .await
        }
    }
}

pub(crate) async fn ensure_service(
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<PersonaService> {
    let db_path = config.get_database_path();
    let db: persona_core::Database = Database::from_file::<std::path::PathBuf>(db_path.to_owned())
        .await
        .into_anyhow()
        .context("Failed to open database")?;
    db.migrate().await.context("Failed to run migrations")?;
    let mut service = crate::commands::service::new_service(db)
        .await
        .context("Failed to create PersonaService")?;
    if service.has_users().await? {
        let password = if config.ui.interactive {
            crate::commands::service::prompt_master_password(ui)?
        } else {
            std::env::var("PERSONA_MASTER_PASSWORD")
                .context("Master password required but PERSONA_MASTER_PASSWORD not set")?
        };
        match service.authenticate_user(&password).await? {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }
    Ok(service)
}

async fn resolve_identity(service: &PersonaService, name: &str) -> Result<CoreIdentity> {
    service
        .get_identity_by_name(name)
        .await?
        .with_context(|| format!("Identity '{}' not found", name))
}

#[cfg(test)]
mod tests;
