use super::output::compress_file;
use super::*;

pub(crate) async fn perform_export(
    identity_names: &[String],
    output_path: &Path,
    args: &ExportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let pb = create_progress_bar(identity_names.len() as u64, "Exporting identities");

    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    // Export based on format
    match args.format.as_str() {
        "json" => export_json(identity_names, output_path, args, config, ui, &pb).await?,
        "yaml" => export_yaml(identity_names, output_path, args, config, ui, &pb).await?,
        "csv" => export_csv(identity_names, output_path, args, config, ui, &pb).await?,
        _ => anyhow::bail!("Unsupported export format: {}", args.format),
    }

    pb.finish_with_message("Export completed");

    // Apply compression if requested
    if args.compression > 0 {
        compress_file(output_path, args.compression)?;
    }

    // Apply encryption if requested
    if args.encrypt {
        let passphrase = super::super::service::prompt_payload_passphrase("export", ui)?;
        encrypt_file_inplace(output_path, &passphrase, None)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn export_json(
    identity_names: &[String],
    output_path: &Path,
    args: &ExportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    // Open service (may require unlock)
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    let unlocked = if service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        let password = super::super::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => true,
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    } else {
        // No users: the service is never unlocked; read via repository.
        false
    };

    let mut export_data = serde_json::json!({
        "export_info": {
            "version": "1.0",
            "created": chrono::Utc::now().to_rfc3339(),
            "identities_count": identity_names.len(),
            "include_sensitive": args.include_sensitive
        },
        "identities": []
    });

    for (i, name) in identity_names.iter().enumerate() {
        // Load identity detail
        let identity = if unlocked {
            service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        } else {
            persona_core::storage::IdentityRepository::new(db.clone())
                .find_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        }
        .with_context(|| format!("Identity '{}' not found", name))?;

        // Collect credentials metadata and optionally data
        let mut credentials_json = Vec::new();
        // Collect passkeys (metadata; private key only when allowed)
        let mut passkeys_json = Vec::new();
        if unlocked {
            let creds = service
                .get_credentials_for_identity(&identity.id)
                .await
                .unwrap_or_default();
            for cred in creds {
                let mut entry = serde_json::json!({
                    "id": cred.id.to_string(),
                    "name": cred.name,
                    "type": cred.credential_type.to_string(),
                    "security_level": cred.security_level.to_string(),
                    "url": cred.url,
                    "username": cred.username,
                    "notes": cred.notes,
                    "tags": cred.tags,
                    "metadata": cred.metadata,
                    "created": cred.created_at.to_rfc3339(),
                    "updated": cred.updated_at.to_rfc3339(),
                    "last_accessed": cred.last_accessed.map(|d| d.to_rfc3339()),
                    "is_active": cred.is_active,
                    "is_favorite": cred.is_favorite,
                });
                if args.include_sensitive {
                    if let Some(data) = service
                        .get_credential_data(&cred.id)
                        .await
                        .map_err(|e| anyhow!("Failed to load credential data: {}", e))?
                    {
                        let json_data = serde_json::to_value(&data)
                            .unwrap_or(serde_json::json!({"raw": "unserializable"}));
                        entry
                            .as_object_mut()
                            .unwrap()
                            .insert("data".to_string(), json_data);
                    }
                } else {
                    // include encrypted bytes hex to allow offline re-import if needed
                    entry.as_object_mut().unwrap().insert(
                        "encrypted_data".to_string(),
                        serde_json::json!(hex::encode(&cred.encrypted_data)),
                    );
                }
                credentials_json.push(entry);
            }

            // Collect passkeys (metadata; private key only when allowed)
            let passkeys = service
                .list_passkeys(&identity.id)
                .await
                .unwrap_or_default();
            for pk in passkeys {
                let mut entry = serde_json::json!({
                    "id": pk.id.to_string(),
                    "rp_id": pk.rp_id,
                    "rp_name": pk.rp_name,
                    "user_handle": hex::encode(&pk.user_handle),
                    "user_name": pk.user_name,
                    "user_display_name": pk.user_display_name,
                    "credential_id": hex::encode(&pk.credential_id),
                    "public_key_cose": hex::encode(&pk.public_key_cose),
                    "alg": pk.alg,
                    "uv_initialized": pk.uv_initialized,
                    "export_allowed": pk.export_allowed,
                    "created": pk.created_at.to_rfc3339(),
                    "last_used": pk.last_used_at.map(|d| d.to_rfc3339()),
                    "tags": pk.tags,
                });
                if args.include_sensitive {
                    if !pk.export_allowed {
                        eprintln!(
                            "⚠️  Passkey {} for {} is marked non-exportable; skipping private key",
                            pk.id, pk.rp_id
                        );
                    } else if let Ok(scalar) = service.export_passkey_private_key(&pk.id).await {
                        entry.as_object_mut().unwrap().insert(
                            "private_key".to_string(),
                            serde_json::json!(hex::encode(&scalar)),
                        );
                    } else {
                        eprintln!(
                            "⚠️  Could not export private key of passkey {} ({})",
                            pk.id, pk.rp_id
                        );
                    }
                }
                passkeys_json.push(entry);
            }
        }

        let identity_data = serde_json::json!({
            "id": identity.id.to_string(),
            "name": identity.name,
            "type": identity.identity_type.to_string(),
            "description": identity.description,
            "email": identity.email,
            "phone": identity.phone,
            "tags": identity.tags,
            "attributes": identity.attributes,
            "active": identity.is_active,
            "created": identity.created_at.to_rfc3339(),
            "modified": identity.updated_at.to_rfc3339(),
            "credentials": credentials_json,
            "passkeys": passkeys_json,
        });

        export_data["identities"]
            .as_array_mut()
            .unwrap()
            .push(identity_data);
        pb.set_position(i as u64 + 1);
    }

    let json_content = serde_json::to_string_pretty(&export_data)?;
    std::fs::write(output_path, json_content).context("Failed to write JSON export file")?;

    Ok(())
}

async fn export_yaml(
    identity_names: &[String],
    output_path: &Path,
    args: &ExportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    // First export as JSON, then convert to YAML
    let temp_json = output_path.with_extension("temp.json");
    export_json(identity_names, &temp_json, args, config, ui, pb).await?;

    let json_content = std::fs::read_to_string(&temp_json)?;
    let json_value: serde_json::Value = serde_json::from_str(&json_content)?;
    let yaml_content = serde_yaml::to_string(&json_value)?;

    std::fs::write(output_path, yaml_content).context("Failed to write YAML export file")?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_json);

    Ok(())
}

async fn export_csv(
    identity_names: &[String],
    output_path: &Path,
    _args: &ExportArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("Failed to create service: {}", e))?;
    let has_users = service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?;
    if has_users {
        let password = super::super::service::prompt_master_password(ui)?;
        match service
            .authenticate_user(&password)
            .await
            .map_err(|e| anyhow!("Auth failed: {}", e))?
        {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }
    let mut csv_content = String::new();
    csv_content.push_str("Name,Type,Description,Email,Created,Modified\n");

    for (i, name) in identity_names.iter().enumerate() {
        let identity = (if has_users {
            service
                .get_identity_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        } else {
            persona_core::storage::IdentityRepository::new(db.clone())
                .find_by_name(name)
                .await
                .map_err(|e| anyhow!("Failed to load identity '{}': {}", name, e))?
        })
        .with_context(|| format!("Identity '{}' not found", name))?;
        csv_content.push_str(&format!(
            "{},{},{},{},{},{}\n",
            identity.name,
            identity.identity_type,
            identity.description.unwrap_or_default().replace(',', " "),
            identity.email.unwrap_or_default(),
            identity.created_at.format("%Y-%m-%d %H:%M:%S"),
            identity.updated_at.format("%Y-%m-%d %H:%M:%S")
        ));

        pb.set_position(i as u64 + 1);
    }

    std::fs::write(output_path, csv_content).context("Failed to write CSV export file")?;

    Ok(())
}
