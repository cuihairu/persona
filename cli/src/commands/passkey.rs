use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use std::path::PathBuf;
use tabled::{settings::Style, Table, Tabled};
use uuid::Uuid;

use persona_core::{
    crypto::{local_client_data, CLIENT_DATA_TYPE_CREATE},
    PersonaService,
};

#[derive(Args)]
pub struct PasskeyArgs {
    #[command(subcommand)]
    pub command: PasskeyCommand,
}

#[derive(Subcommand)]
pub enum PasskeyCommand {
    /// Create a new passkey for an identity
    Create {
        /// Identity name to attach the passkey to
        #[arg(long, short)]
        identity: String,

        /// Relying party ID (e.g. example.com)
        #[arg(long, short)]
        rp: String,

        /// RP name shown to the user (defaults to the rp id)
        #[arg(long)]
        rp_name: Option<String>,

        /// Origin the ceremony runs on (defaults to https://<rp>)
        #[arg(long)]
        origin: Option<String>,

        /// Account username (usually an e-mail address)
        #[arg(long, short)]
        user: Option<String>,

        /// Human-friendly display name (defaults to the rp name)
        #[arg(long)]
        display: Option<String>,

        /// Require user verification on this credential
        #[arg(long, default_value_t = true)]
        uv: bool,

        /// clientDataJSON file carrying a live RP challenge (optional;
        /// without it a local challenge is generated)
        #[arg(long)]
        client_data: Option<PathBuf>,
    },
    /// List passkeys, optionally for a single identity
    List {
        /// Identity name (omit to list across identities)
        #[arg(long, short)]
        identity: Option<String>,
    },
    /// Show the details of one passkey
    Show {
        /// Passkey ID
        id: Uuid,
    },
    /// Remove a passkey
    Remove {
        /// Passkey ID
        id: Uuid,
    },
    /// Sign a test assertion and verify it against the stored public key
    SelfTest {
        /// Passkey ID
        id: Uuid,
    },
}

pub async fn handle_passkey(args: PasskeyArgs, config: &CliConfig) -> Result<()> {
    let service = init_service(config).await?;

    match args.command {
        PasskeyCommand::Create {
            identity,
            rp,
            rp_name,
            origin,
            user,
            display,
            uv,
            client_data,
        } => {
            let identity = service
                .get_identity_by_name(&identity)
                .await
                .into_anyhow()?
                .with_context(|| format!("Identity '{}' not found", identity))?;

            let origin = origin.unwrap_or_else(|| format!("https://{}", rp));
            let client_data_json = match client_data {
                Some(path) => std::fs::read(&path)
                    .with_context(|| format!("Failed to read {}", path.display()))?,
                None => local_client_data(CLIENT_DATA_TYPE_CREATE, &origin)?,
            };

            let passkey = service
                .create_passkey(
                    identity.id,
                    rp.clone(),
                    &origin,
                    &client_data_json,
                    None,
                    user,
                    display.or(rp_name),
                    uv,
                )
                .await
                .into_anyhow()?;

            println!("{}", "✓ Passkey created".green().bold());
            println!("  ID: {}", passkey.id.to_string().cyan());
            println!("  RP: {}", passkey.rp_id);
            if let Some(name) = &passkey.rp_name {
                println!("  RP name: {}", name);
            }
            if let Some(name) = &passkey.user_name {
                println!("  User: {}", name);
            }
            println!(
                "  Credential ID: {}",
                hex::encode(&passkey.credential_id).dimmed()
            );
            println!(
                "  User verification: {}",
                if passkey.uv_initialized {
                    "required"
                } else {
                    "not required"
                }
            );
        }

        PasskeyCommand::List { identity } => {
            let passkeys = match identity {
                Some(name) => {
                    let identity = service
                        .get_identity_by_name(&name)
                        .await
                        .into_anyhow()?
                        .with_context(|| format!("Identity '{}' not found", name))?;
                    service.list_passkeys(&identity.id).await.into_anyhow()?
                }
                None => {
                    let mut all = Vec::new();
                    for identity in service.get_identities().await.into_anyhow()? {
                        all.extend(service.list_passkeys(&identity.id).await.into_anyhow()?);
                    }
                    all
                }
            };

            if passkeys.is_empty() {
                println!("{}", "No passkeys found.".yellow());
                return Ok(());
            }

            let rows: Vec<PasskeyTable> = passkeys
                .iter()
                .map(|p| PasskeyTable {
                    id: p.id.to_string().chars().take(8).collect(),
                    rp: p.rp_id.clone(),
                    user: p.user_name.clone().unwrap_or_default(),
                    uv: if p.uv_initialized { "✓" } else { "✗" }.to_string(),
                    export: if p.export_allowed { "✓" } else { "✗" }.to_string(),
                    created: p.created_at.format("%Y-%m-%d").to_string(),
                })
                .collect();
            let table = Table::new(&rows).with(Style::modern()).to_string();
            println!("{}", table);
            println!("{}", format!("{} passkey(s)", rows.len()).dimmed());
        }

        PasskeyCommand::Show { id } => {
            let passkey = service
                .get_passkey(&id)
                .await
                .into_anyhow()?
                .with_context(|| format!("Passkey '{}' not found", id))?;

            println!("{}", format!("🔑 Passkey: {}", passkey.rp_id).cyan().bold());
            println!("  ID: {}", passkey.id);
            if let Some(name) = &passkey.rp_name {
                println!("  RP name: {}", name);
            }
            if let Some(name) = &passkey.user_name {
                println!("  User: {}", name);
            }
            if let Some(name) = &passkey.user_display_name {
                println!("  Display name: {}", name);
            }
            println!(
                "  Credential ID: {}",
                hex::encode(&passkey.credential_id).dimmed()
            );
            println!(
                "  User handle: {}",
                hex::encode(&passkey.user_handle).dimmed()
            );
            println!("  Algorithm: ES256 ({})", passkey.alg);
            println!(
                "  User verification: {}",
                if passkey.uv_initialized {
                    "required"
                } else {
                    "not required"
                }
            );
            println!(
                "  Export allowed: {}",
                if passkey.export_allowed { "yes" } else { "no" }
            );
            println!(
                "  Created: {}",
                passkey.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            if let Some(used) = passkey.last_used_at {
                println!("  Last used: {}", used.format("%Y-%m-%d %H:%M:%S UTC"));
            }
            if !passkey.tags.is_empty() {
                println!("  Tags: {}", passkey.tags.join(", "));
            }
        }

        PasskeyCommand::Remove { id } => {
            let deleted = service.delete_passkey(&id).await.into_anyhow()?;
            if deleted {
                println!("{}", "✓ Passkey removed".green().bold());
            } else {
                bail!("Passkey '{}' not found", id);
            }
        }

        PasskeyCommand::SelfTest { id } => {
            service
                .passkey_self_test(&id)
                .await
                .into_anyhow()
                .context("Self-test FAILED: assertion could not be verified")?;
            println!("{}", "✓ Self-test passed".green().bold());
            println!("  Assertion signed with the stored key and verified");
            println!("  against its public key (same check an RP runs).");
        }
    }

    Ok(())
}

#[derive(Tabled)]
struct PasskeyTable {
    id: String,
    rp: String,
    user: String,
    uv: String,
    export: String,
    created: String,
}

/// Open the workspace database, run migrations and unlock with the master
/// password — the same flow `credential` commands use.
async fn init_service(config: &CliConfig) -> Result<PersonaService> {
    let db_path = config.get_database_path();
    let db = persona_core::Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to connect to database: {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;
    let mut service = PersonaService::new(db)
        .await
        .into_anyhow()
        .context("Failed to create PersonaService")?;

    if service
        .has_users()
        .await
        .into_anyhow()
        .context("Failed to check users")?
    {
        let password = dialoguer::Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service
            .authenticate_user(&password)
            .await
            .into_anyhow()
            .context("Failed to authenticate user")?
        {
            persona_core::auth::authentication::AuthResult::Success => Ok(service),
            other => bail!("Authentication failed: {:?}", other),
        }
    } else {
        bail!("Workspace not initialized. Run `persona init` first");
    }
}
