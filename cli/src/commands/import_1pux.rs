//! `persona import-1pux` — migrate from a 1Password `.1pux` export.
//!
//! The heavy lifting lives in core (`persona_core::import_1pux`): parsing
//! the ZIP container and mapping items onto persona structures as a pure
//! plan. This command prints that plan (identities, credentials by type,
//! skipped items with reasons), then applies it after an explicit
//! confirmation. `--dry-run` stops after the preview and never opens the
//! workspace. Attachments (`files/`) are never imported.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use uuid::Uuid;

use crate::commands::service::init_service;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::import_1pux::{parse_1pux, plan_import, ImportPlan, PlannedCredential};
use persona_core::models::{Identity, IdentityType};
use persona_core::PersonaService;

#[derive(Args)]
pub struct Import1PuxArgs {
    /// Path to the 1Password export file (.1pux)
    pub file: PathBuf,

    /// Show what would be imported without touching the vault
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn execute(args: Import1PuxArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: Import1PuxArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let bytes = std::fs::read(&args.file)
        .with_context(|| format!("Failed to read {}", args.file.display()))?;
    let export = parse_1pux(&bytes)?;
    let plan = plan_import(&export);

    print_plan(&plan);

    if args.dry_run {
        println!("Dry run: nothing was imported.");
        return Ok(());
    }

    let confirmed = ui.confirm(
        &format!(
            "Import {} credential(s) into {} vault/identity container(s)?",
            plan.credentials.len(),
            plan.identities.len()
        ),
        false,
    )?;
    if !confirmed {
        println!("Import cancelled.");
        return Ok(());
    }

    let service = init_service(config, ui).await?;
    let summary = apply_plan(&service, &plan).await?;
    println!(
        "Done: {} credential(s) imported ({} identit(y/ies) created, {} reused).",
        summary.imported, summary.identities_created, summary.identities_reused
    );
    Ok(())
}

struct ApplySummary {
    imported: usize,
    identities_created: usize,
    identities_reused: usize,
}

/// Apply a confirmed plan: create/reuse identities, then credentials.
///
/// Same-name identities are reused (reported, never duplicated); the whole
/// run aborts on the first failure so a partial import can simply be re-run.
async fn apply_plan(service: &PersonaService, plan: &ImportPlan) -> Result<ApplySummary> {
    let mut vault_to_identity: HashMap<String, Uuid> = HashMap::new();
    let mut identities_created = 0;
    let mut identities_reused = 0;

    for planned in &plan.identities {
        let identity = match service.get_identity_by_name(&planned.name).await? {
            Some(existing) => {
                println!(
                    "Reusing existing identity '{}' for 1Password vault {}",
                    planned.name, planned.vault_uuid
                );
                identities_reused += 1;
                existing
            }
            None => {
                let mut identity = Identity::new(
                    planned.name.clone(),
                    IdentityType::Custom("1Password".to_string()),
                );
                identity.description = Some(planned.description.clone());
                identities_created += 1;
                service
                    .create_identity_full(identity)
                    .await
                    .with_context(|| format!("Failed to create identity '{}'", planned.name))?
            }
        };
        vault_to_identity.insert(planned.vault_uuid.clone(), identity.id);
    }

    let mut imported = 0;
    for planned in &plan.credentials {
        let identity_id = vault_to_identity
            .get(&planned.vault_uuid)
            .with_context(|| format!("No identity mapped for vault {}", planned.vault_uuid))?;
        import_credential(service, *identity_id, planned).await?;
        imported += 1;
    }

    Ok(ApplySummary {
        imported,
        identities_created,
        identities_reused,
    })
}

async fn import_credential(
    service: &PersonaService,
    identity_id: Uuid,
    planned: &PlannedCredential,
) -> Result<()> {
    // create_credential only fills the encrypted payload; presentation
    // fields are patched on and persisted with update_credential (same
    // pattern as the desktop create flows).
    let mut credential = service
        .create_credential(
            identity_id,
            planned.name.clone(),
            planned.credential_type.clone(),
            planned.security_level.clone(),
            &planned.credential_data,
        )
        .await
        .with_context(|| format!("Failed to create credential '{}'", planned.name))?;

    credential.url = planned.url.clone();
    credential.username = planned.username.clone();
    credential.notes = planned.notes.clone();
    credential.tags = planned.tags.clone();
    credential.metadata = planned.metadata.clone();
    credential.is_favorite = planned.is_favorite;

    service
        .update_credential(&credential)
        .await
        .with_context(|| format!("Failed to finalize credential '{}'", planned.name))?;
    Ok(())
}

fn print_plan(plan: &ImportPlan) {
    println!("1PUX import plan");
    println!("  Identities (one per 1Password vault):");
    if plan.identities.is_empty() {
        println!("    (none)");
    }
    for identity in &plan.identities {
        println!("    - {} [{}]", identity.name, identity.description);
    }

    if plan.credentials.is_empty() {
        println!("  Credentials: none");
    } else {
        println!("  Credentials: {}", plan.credentials.len());
        let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
        for credential in &plan.credentials {
            *by_type
                .entry(credential.credential_type.to_string())
                .or_default() += 1;
        }
        for (kind, count) in &by_type {
            println!("    {kind}: {count}");
        }
    }

    if plan.skipped.is_empty() {
        println!("  Skipped: none");
    } else {
        println!("  Skipped ({} item(s)):", plan.skipped.len());
        for skipped in &plan.skipped {
            println!(
                "    [{}] {} ({}) — {}",
                skipped.vault_name, skipped.title, skipped.category, skipped.reason
            );
        }
    }
    println!("  Note: attachments (files/) are not imported in this release.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::credential::{CredentialData, CredentialType};
    use persona_core::{Database, IdentityRepository, PersonaService, Repository};
    use std::io::Write;
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the other env-gated command tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        fn lock_or_recover(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
            lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }
        (
            lock_or_recover(&crate::commands::bridge::tests::ENV_LOCK),
            lock_or_recover(&ENV_LOCK),
        )
    }

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// Build a minimal .1pux ZIP in-memory fixture: one vault with a Login
    /// (password + TOTP), an archived item and an unmapped category.
    fn sample_1pux() -> Vec<u8> {
        let data = serde_json::json!({
            "accounts": [{
                "attrs": { "uuid": "acc-1", "name": "Account" },
                "vaults": [{
                    "attrs": { "uuid": "vault-1", "name": "Personal" },
                    "items": [
                        {
                            "uuid": "item-1", "categoryUuid": "001", "favIndex": 1,
                            "overview": {
                                "title": "Example",
                                "urls": [
                                    { "href": "https://example.com" },
                                    { "href": "https://example.com/login" }
                                ],
                                "tags": ["web"]
                            },
                            "details": {
                                "loginFields": [
                                    { "type": "T", "designation": "username", "value": "alice@example.com" },
                                    { "type": "P", "designation": "password", "value": "hunter2" }
                                ],
                                "notesPlain": "note",
                                "sections": [{
                                    "fields": [{
                                        "id": "ONE_TIME_PASSWORD",
                                        "value": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
                                    }]
                                }]
                            }
                        },
                        {
                            "uuid": "item-2", "categoryUuid": "001", "state": "ARCHIVED",
                            "overview": { "title": "Old" }, "details": {}
                        },
                        {
                            "uuid": "item-3", "categoryUuid": "002",
                            "overview": { "title": "Card" }, "details": {}
                        }
                    ]
                }]
            }]
        })
        .to_string();

        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("export.attributes", options).unwrap();
        writer
            .write_all(br#"{"version": 3, "description": "test"}"#)
            .unwrap();
        writer.start_file("export.data", options).unwrap();
        writer.write_all(data.as_bytes()).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn write_sample(dir: &TempDir) -> PathBuf {
        let path = dir.path().join("export.1pux");
        std::fs::write(&path, sample_1pux()).unwrap();
        path
    }

    async fn initialized_service(config: &CliConfig) {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    fn args(file: &Path, dry_run: bool) -> Import1PuxArgs {
        Import1PuxArgs {
            file: file.to_path_buf(),
            dry_run,
        }
    }

    #[tokio::test]
    async fn dry_run_prints_plan_without_touching_the_workspace() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_sample(&dir);

        execute_with(args(&path, true), &config, &ScriptedUi::new())
            .await
            .unwrap();

        // The dry-run path never opens the workspace: no database is created.
        assert!(
            !config.get_database_path().exists(),
            "dry run must not create a workspace database"
        );
    }

    #[tokio::test]
    async fn declined_confirmation_leaves_the_vault_empty() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_sample(&dir);
        initialized_service(&config).await;
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        execute_with(
            args(&path, false),
            &config,
            &ScriptedUi::new().confirm(false),
        )
        .await
        .unwrap();

        // The service is left locked after the command; the identity repo
        // works directly on the database.
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let identities = IdentityRepository::new(db).find_all().await.unwrap();
        assert!(identities.is_empty(), "declined import must not persist");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn import_persists_credentials_and_decrypts_to_original_secrets() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_sample(&dir);
        initialized_service(&config).await;
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        execute_with(
            args(&path, false),
            &config,
            &ScriptedUi::new().confirm(true),
        )
        .await
        .unwrap();

        let mut service = {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            PersonaService::new(db).await.unwrap()
        };
        service.authenticate_user("master-pin").await.unwrap();

        let identities = service.get_identities().await.unwrap();
        assert_eq!(identities.len(), 1, "one vault → one identity");
        assert_eq!(identities[0].name, "Personal");
        assert!(identities[0]
            .description
            .as_deref()
            .unwrap()
            .contains("vault-1"));

        let credentials = service
            .get_credentials_for_identity(&identities[0].id)
            .await
            .unwrap();
        assert_eq!(
            credentials.len(),
            2,
            "login + split TOTP; archived/card skipped"
        );

        let login = credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::Password)
            .expect("login credential");
        assert_eq!(login.name, "Example");
        assert_eq!(login.url.as_deref(), Some("https://example.com"));
        assert_eq!(login.username.as_deref(), Some("alice@example.com"));
        assert_eq!(login.notes.as_deref(), Some("note"));
        assert!(login.is_favorite);
        assert_eq!(
            login.metadata.get("alt_urls").map(String::as_str),
            Some("https://example.com/login")
        );
        match service
            .get_credential_data(&login.id)
            .await
            .unwrap()
            .unwrap()
        {
            CredentialData::Password(p) => assert_eq!(p.password, "hunter2"),
            other => panic!("unexpected data: {other:?}"),
        }

        let totp = credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("totp credential");
        assert_eq!(totp.name, "Example (TOTP)");
        match service
            .get_credential_data(&totp.id)
            .await
            .unwrap()
            .unwrap()
        {
            CredentialData::TwoFactor(t) => {
                assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
                assert_eq!(t.issuer, "Example");
            }
            other => panic!("unexpected data: {other:?}"),
        }

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn same_name_identity_is_reused_not_duplicated() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_sample(&dir);
        initialized_service(&config).await;
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        // Pre-create an identity named exactly like the 1Password vault.
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            service.authenticate_user("master-pin").await.unwrap();
            service
                .create_identity(
                    "Personal".to_string(),
                    persona_core::models::IdentityType::Personal,
                )
                .await
                .unwrap();
        }

        execute_with(
            args(&path, false),
            &config,
            &ScriptedUi::new().confirm(true),
        )
        .await
        .unwrap();

        let mut service = {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            PersonaService::new(db).await.unwrap()
        };
        service.authenticate_user("master-pin").await.unwrap();
        let identities = service.get_identities().await.unwrap();
        assert_eq!(identities.len(), 1, "existing identity reused");
        // Imported credentials land on the pre-existing identity.
        let credentials = service
            .get_credentials_for_identity(&identities[0].id)
            .await
            .unwrap();
        assert_eq!(credentials.len(), 2);

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn missing_file_reports_a_read_error() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let err = execute_with(
            args(&dir.path().join("ghost.1pux"), false),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("missing file must fail");
        assert!(err.to_string().contains("Failed to read"));
    }
}
