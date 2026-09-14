use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use std::path::PathBuf;
use tabled::{settings::Style, Table, Tabled};
use uuid::Uuid;

use persona_core::crypto::{local_client_data, CLIENT_DATA_TYPE_CREATE};

use super::service::init_service;

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
    handle_passkey_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn handle_passkey_with(
    args: PasskeyArgs,
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = init_service(config, ui).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use persona_core::{Database, PersonaService};
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the bridge and service tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK.lock().unwrap(),
            ENV_LOCK.lock().unwrap(),
        )
    }

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// Caller must already hold `lock_process_env()`.
    async fn seeded_config(dir: &TempDir) -> CliConfig {
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let config = config_for(dir);
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            db.migrate().await.unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        service
            .create_identity_full(persona_core::Identity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        config
    }

    fn create_args(identity: &str, rp: &str) -> PasskeyArgs {
        PasskeyArgs {
            command: PasskeyCommand::Create {
                identity: identity.to_string(),
                rp: rp.to_string(),
                rp_name: Some("Example".to_string()),
                origin: None,
                user: Some("alice@example.com".to_string()),
                display: None,
                uv: true,
                client_data: None,
            },
        }
    }

    #[tokio::test]
    async fn passkey_create_list_show_selftest_remove_round_trip() {
        let _guard = lock_process_env();
        let dir = TempDir::new().unwrap();
        let config = seeded_config(&dir).await;

        // Unknown identity fails during create.
        let err = handle_passkey(create_args("ghost", "example.com"), &config)
            .await
            .expect_err("unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));

        handle_passkey(create_args("alice", "example.com"), &config)
            .await
            .expect("create works");

        // List for identity and globally.
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::List {
                    identity: Some("alice".to_string()),
                },
            },
            &config,
        )
        .await
        .expect("list for identity works");
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::List { identity: None },
            },
            &config,
        )
        .await
        .expect("global list works");

        // Fetch the created passkey through the service for id-based commands.
        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let alice = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let keys = service.list_passkeys(&alice.id).await.unwrap();
        assert_eq!(keys.len(), 1);
        let id = keys[0].id;
        drop(service);

        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::Show { id },
            },
            &config,
        )
        .await
        .expect("show works");
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::SelfTest { id },
            },
            &config,
        )
        .await
        .expect("self-test verifies the stored key");

        // Unknown ids fail for Show/Remove/SelfTest.
        let ghost = uuid::Uuid::new_v4();
        let err = handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::Show { id: ghost },
            },
            &config,
        )
        .await
        .expect_err("unknown show must fail");
        assert!(err.to_string().contains("not found"));
        let err = handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::Remove { id: ghost },
            },
            &config,
        )
        .await
        .expect_err("unknown remove must fail");
        assert!(err.to_string().contains("not found"));
        let err = handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::SelfTest { id: ghost },
            },
            &config,
        )
        .await
        .expect_err("unknown self-test must fail");
        assert!(err.to_string().contains("Self-test FAILED"));

        // Empty list for an identity without passkeys.
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::List {
                    identity: Some("bob".to_string()),
                },
            },
            &config,
        )
        .await
        .expect_err("unknown identity list fails");

        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::Remove { id },
            },
            &config,
        )
        .await
        .expect("remove works");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn passkey_show_renders_full_metadata_and_client_data_file() {
        let _guard = lock_process_env();
        let dir = TempDir::new().unwrap();
        let config = seeded_config(&dir).await;

        // A clientDataJSON supplied from a file takes precedence over the
        // locally generated challenge, and `uv: false` stores a credential
        // that does not require user verification.
        let cd_path = dir.path().join("client-data.json");
        std::fs::write(
            &cd_path,
            local_client_data(CLIENT_DATA_TYPE_CREATE, "https://vault.example.com").unwrap(),
        )
        .unwrap();
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::Create {
                    identity: "alice".to_string(),
                    rp: "vault.example.com".to_string(),
                    rp_name: None,
                    origin: Some("https://vault.example.com".to_string()),
                    user: Some("alice@example.com".to_string()),
                    display: Some("Alice's laptop".to_string()),
                    uv: false,
                    client_data: Some(cd_path),
                },
            },
            &config,
        )
        .await
        .expect("create from client-data file with uv disabled works");

        // The summary table renders the ✗ marks for uv and export.
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::List {
                    identity: Some("alice".to_string()),
                },
            },
            &config,
        )
        .await
        .expect("list renders unchecked marks");

        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let alice = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let id = service.list_passkeys(&alice.id).await.unwrap()[0].id;
        drop(service);

        // Self-test stamps last_used_at; the follow-up Show renders it.
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::SelfTest { id },
            },
            &config,
        )
        .await
        .expect("self-test works");

        // Enrich mutable metadata through the repository so Show renders the
        // optional RP-name and tags lines too.
        let db = Database::from_file(config.get_database_path()).await.unwrap();
        let repo = persona_core::storage::PasskeyRepository::new(std::sync::Arc::new(db));
        let mut item = repo.find_by_id(&id).await.unwrap().unwrap();
        item.rp_name = Some("Vault Corp".to_string());
        item.tags = vec!["work".to_string(), "primary".to_string()];
        repo.update(&item).await.unwrap();

        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::Show { id },
            },
            &config,
        )
        .await
        .expect("show renders names, usage and tags");

        // An identity without passkeys reports the empty state.
        {
            let service = init_service(&config, &crate::utils::prompt::TerminalUi)
                .await
                .unwrap();
            service
                .create_identity_full(persona_core::Identity::new(
                    "bob".to_string(),
                    persona_core::models::IdentityType::Personal,
                ))
                .await
                .unwrap();
        }
        handle_passkey(
            PasskeyArgs {
                command: PasskeyCommand::List {
                    identity: Some("bob".to_string()),
                },
            },
            &config,
        )
        .await
        .expect("empty list reports no passkeys");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }
}
