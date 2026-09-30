//! `persona import-generic` — migrate from generic password-manager exports
//! (CSV or Bitwarden plaintext JSON).
//!
//! Covers the common export shapes: Bitwarden/Chrome/Firefox/1Password/
//! KeePass CSV (columns are sniffed, not positional) and Bitwarden JSON.
//! The whole file lands in a single identity named after the file stem;
//! folders become tags. Same parse → plan → preview → confirm → apply flow
//! as `import-1pux`; `--dry-run` never opens the workspace.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use std::collections::BTreeMap;

use crate::commands::import_common::apply_plan;
use crate::commands::service::init_service;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use persona_core::import_generic::{parse_generic, plan_generic_import, GenericExportFormat};
use persona_core::ImportPlan;

#[derive(Args)]
pub struct ImportGenericArgs {
    /// Path to the exported file (CSV or Bitwarden JSON)
    pub file: PathBuf,

    /// Show what would be imported without touching the vault
    #[arg(long)]
    pub dry_run: bool,

    /// Force a format instead of sniffing: "csv" or "bitwarden-json"
    #[arg(long)]
    pub format: Option<String>,
}

pub async fn execute(args: ImportGenericArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ImportGenericArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let bytes = std::fs::read(&args.file)
        .with_context(|| format!("Failed to read {}", args.file.display()))?;
    let format = match args.format.as_deref() {
        None => None,
        Some("csv") => Some(GenericExportFormat::Csv),
        Some("bitwarden-json") => Some(GenericExportFormat::BitwardenJson),
        Some(other) => bail!(
            "Unknown format '{}' (expected \"csv\" or \"bitwarden-json\")",
            other
        ),
    };
    let export = parse_generic(&bytes, format)?;

    let identity_name = file_stem(&args.file);
    let source_label = args
        .file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| args.file.display().to_string());
    let plan = plan_generic_import(&export, &identity_name, &source_label);

    print_plan(&export, &plan);

    if args.dry_run {
        println!("Dry run: nothing was imported.");
        return Ok(());
    }

    let confirmed = ui.confirm(
        &format!(
            "Import {} credential(s) into identity '{}'?",
            plan.credentials.len(),
            identity_name
        ),
        false,
    )?;
    if !confirmed {
        println!("Import cancelled.");
        return Ok(());
    }

    let identity_kind = match export {
        persona_core::import_generic::GenericExport::Csv(_) => "CSV",
        persona_core::import_generic::GenericExport::BitwardenJson(_) => "Bitwarden",
    };
    let service = init_service(config, ui).await?;
    let summary = apply_plan(&service, &plan, identity_kind, "generic import").await?;
    println!(
        "Done: {} credential(s) imported ({} identit(y/ies) created, {} reused).",
        summary.imported, summary.identities_created, summary.identities_reused
    );
    Ok(())
}

fn file_stem(path: &std::path::Path) -> String {
    path.file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "imported".to_string())
}

fn format_label(format: &GenericExportFormat) -> &'static str {
    match format {
        GenericExportFormat::Csv => "CSV",
        GenericExportFormat::BitwardenJson => "Bitwarden JSON",
    }
}

fn print_plan(export: &persona_core::import_generic::GenericExport, plan: &ImportPlan) {
    let detected = match export {
        persona_core::import_generic::GenericExport::Csv(_) => GenericExportFormat::Csv,
        persona_core::import_generic::GenericExport::BitwardenJson(_) => {
            GenericExportFormat::BitwardenJson
        }
    };
    println!("Generic import plan ({})", format_label(&detected));
    if let persona_core::import_generic::GenericExport::Csv(csv) = export {
        println!("  Columns: {}", csv.headers.join(", "));
    }

    println!("  Identity (one per file):");
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
    println!("  Note: folders/groups become tags; everything lands in a single identity.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::credential::{CredentialData, CredentialType};
    use persona_core::{Database, IdentityRepository, Repository};
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

    /// Bitwarden plaintext JSON: a login with two URIs, TOTP, folder and
    /// favorite, plus a card that CSV cannot carry (skipped with a hint).
    fn sample_bitwarden_json() -> String {
        serde_json::json!({
            "folders": [
                { "id": "f-1", "name": "Work" }
            ],
            "items": [
                {
                    "id": "i-1",
                    "organizationId": null,
                    "folderId": "f-1",
                    "type": 1,
                    "name": "Example",
                    "notes": "note",
                    "favorite": true,
                    "login": {
                        "username": "alice@example.com",
                        "password": "hunter2",
                        "totp": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                        "uris": [
                            { "uri": "https://example.com", "match": null },
                            { "uri": "https://example.com/login", "match": null }
                        ]
                    }
                },
                {
                    "id": "i-2",
                    "folderId": null,
                    "type": 3,
                    "name": "Bank card",
                    "card": { "brand": "Visa", "cardholderName": "Alice" }
                }
            ]
        })
        .to_string()
    }

    fn write_bitwarden_json(dir: &TempDir) -> PathBuf {
        let path = dir.path().join("bitwarden_export.json");
        std::fs::write(&path, sample_bitwarden_json()).unwrap();
        path
    }

    fn write_csv(dir: &TempDir) -> PathBuf {
        let path = dir.path().join("keepass_export.csv");
        std::fs::write(
            &path,
            "Title,Username,Password,URL,Notes,TOTP,Group\n\
             Site A,bob,hunter3,https://a.example.com,c1,,Personal\n\
             Site B,carol,hunter4,https://b.example.com,c2,JBSWY3DPEHPK3PXP,\n",
        )
        .unwrap();
        path
    }

    async fn initialized_service(config: &CliConfig) {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    fn args(file: &Path, dry_run: bool) -> ImportGenericArgs {
        ImportGenericArgs {
            file: file.to_path_buf(),
            dry_run,
            format: None,
        }
    }

    #[tokio::test]
    async fn dry_run_prints_plan_without_touching_the_workspace() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_bitwarden_json(&dir);

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
        let path = write_bitwarden_json(&dir);
        initialized_service(&config).await;
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        execute_with(
            args(&path, false),
            &config,
            &ScriptedUi::new().confirm(false),
        )
        .await
        .unwrap();

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let identities = IdentityRepository::new(db).find_all().await.unwrap();
        assert!(identities.is_empty(), "declined import must not persist");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn bitwarden_json_import_persists_and_decrypts_to_original_secrets() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_bitwarden_json(&dir);
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
            crate::commands::service::new_service(db).await.unwrap()
        };
        service.authenticate_user("master-pin").await.unwrap();

        let identities = service.get_identities().await.unwrap();
        assert_eq!(identities.len(), 1, "one file → one identity");
        assert_eq!(identities[0].name, "bitwarden_export", "file stem");

        let credentials = service
            .get_credentials_for_identity(&identities[0].id)
            .await
            .unwrap();
        assert_eq!(
            credentials.len(),
            3,
            "login + split TOTP + card (JSON export carries card fields)"
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
        assert_eq!(login.tags, vec!["Work".to_string()], "folder → tag");
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

        let card = credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::BankCard)
            .expect("card credential");
        match service
            .get_credential_data(&card.id)
            .await
            .unwrap()
            .unwrap()
        {
            CredentialData::BankCard(c) => assert_eq!(c.card_type, "Visa"),
            other => panic!("unexpected data: {other:?}"),
        }

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn csv_import_persists_passwords_and_folder_tags() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_csv(&dir);
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
            crate::commands::service::new_service(db).await.unwrap()
        };
        service.authenticate_user("master-pin").await.unwrap();

        let identities = service.get_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].name, "keepass_export", "file stem");

        let credentials = service
            .get_credentials_for_identity(&identities[0].id)
            .await
            .unwrap();
        assert_eq!(
            credentials.len(),
            3,
            "two logins + one split TOTP from the bare secret"
        );

        let site_a = credentials.iter().find(|c| c.name == "Site A").unwrap();
        assert_eq!(site_a.tags, vec!["Personal".to_string()]);
        match service
            .get_credential_data(&site_a.id)
            .await
            .unwrap()
            .unwrap()
        {
            CredentialData::Password(p) => assert_eq!(p.password, "hunter3"),
            other => panic!("unexpected data: {other:?}"),
        }

        let site_b_totp = credentials
            .iter()
            .find(|c| c.name == "Site B (TOTP)")
            .expect("bare TOTP split into its own credential");
        match service
            .get_credential_data(&site_b_totp.id)
            .await
            .unwrap()
            .unwrap()
        {
            CredentialData::TwoFactor(t) => {
                assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP")
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
        let path = write_csv(&dir);
        initialized_service(&config).await;
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        // Pre-create an identity named exactly like the file stem.
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.authenticate_user("master-pin").await.unwrap();
            service
                .create_identity(
                    "keepass_export".to_string(),
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
            crate::commands::service::new_service(db).await.unwrap()
        };
        service.authenticate_user("master-pin").await.unwrap();
        let identities = service.get_identities().await.unwrap();
        assert_eq!(identities.len(), 1, "existing identity reused");
        let credentials = service
            .get_credentials_for_identity(&identities[0].id)
            .await
            .unwrap();
        assert_eq!(credentials.len(), 3);

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn missing_file_reports_a_read_error() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let err = execute_with(
            args(&dir.path().join("ghost.csv"), false),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("missing file must fail");
        assert!(err.to_string().contains("Failed to read"));
    }

    #[tokio::test]
    async fn encrypted_bitwarden_export_is_rejected() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = dir.path().join("locked.json");
        std::fs::write(&path, r#"{"encrypted":true,"folders":[],"items":[]}"#).unwrap();

        let err = execute_with(args(&path, false), &config, &ScriptedUi::new())
            .await
            .expect_err("password-protected export must be rejected");
        assert!(
            err.to_string().contains("encrypted"),
            "error should point at the password-protected export: {err}"
        );
    }

    #[tokio::test]
    async fn unknown_format_flag_is_rejected() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = write_csv(&dir);
        let err = execute_with(
            ImportGenericArgs {
                file: path,
                dry_run: false,
                format: Some("keepassx".to_string()),
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("unknown --format value must fail");
        assert!(err.to_string().contains("Unknown format"));
    }

    #[tokio::test]
    async fn explicit_format_flag_overrides_sniffing() {
        // A CSV whose first cell looks like JSON would be sniffed as JSON;
        // --format csv forces the CSV parser regardless.
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let path = dir.path().join("tricky.csv");
        std::fs::write(&path, "{weird},username,password\nx,alice,hunter5\n").unwrap();

        execute_with(
            ImportGenericArgs {
                file: path.clone(),
                dry_run: true,
                format: Some("csv".to_string()),
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("forced csv format must parse");

        // And the same content without the flag fails as (malformed) JSON.
        execute_with(args(&path, true), &config, &ScriptedUi::new())
            .await
            .expect_err("sniffing should treat it as JSON");
    }
}
