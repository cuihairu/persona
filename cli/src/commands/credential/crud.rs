use super::*;

#[derive(Tabled)]
struct CredentialRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    credential_type: String,
    #[tabled(rename = "Identity")]
    identity: String,
    #[tabled(rename = "Username")]
    username: String,
    #[tabled(rename = "Favorite")]
    favorite: String,
}

pub(crate) async fn add_credential(
    config: &CliConfig,
    ui: &dyn PromptUi,
    args: AddArgs,
) -> Result<()> {
    let AddArgs {
        identity: identity_name,
        name,
        credential_type,
        security_level,
        username,
        url,
        prompt_secret,
        secret,
        note,
        first_name,
        last_name,
        email,
        phone,
        birthday,
        address,
        id_number,
        passport_number,
        driver_license,
        tax_id,
        organization,
        job_title,
        license_key,
        version,
        publisher,
        purchase_date,
        order_number,
        support_email,
        download_url,
        seats,
        valid_until,
        favorite,
    } = args;

    println!("{}", "➕ Adding credential...".cyan());
    let mut service = init_service(config, ui).await?;
    let identity = resolve_identity(&mut service, &identity_name).await?;

    // note / identity / software-license 不走 secret 路径（各自必填字段）；
    // api-key 走 secret 路径但 data 变体必须是 ApiKey（见该臂注释）；
    // 其余单秘密类型（password 等）落 `_` 兜底。
    let credential_data = match credential_type {
        // Secure Note：正文走 --note（或可见提示输入），密码路径不适用。
        CredentialTypeOption::Note => {
            if secret.is_some() || prompt_secret {
                bail!("Note content is provided via --note; --secret/--prompt-secret do not apply");
            }
            let note_text = match note {
                Some(text) if !text.trim().is_empty() => text,
                _ => ui.input("Note content", None, false)?,
            };
            CredentialData::SecureNote(SecureNoteData {
                note: note_text.clone(),
            })
        }
        // Identity：姓名必填（缺省提示），其余可选字段只在提供时入库。
        CredentialTypeOption::Identity => {
            if secret.is_some() || prompt_secret {
                bail!("Identity fields do not use --secret/--prompt-secret");
            }
            let first = match first_name {
                Some(v) if !v.trim().is_empty() => v,
                _ => ui.input("First name", None, false)?,
            };
            let last = match last_name {
                Some(v) if !v.trim().is_empty() => v,
                _ => ui.input("Last name", None, false)?,
            };
            CredentialData::Identity(IdentityData {
                first_name: first,
                last_name: last,
                username: username.clone(),
                email,
                phone,
                birthday,
                address,
                id_number,
                passport_number,
                driver_license,
                tax_id,
                organization,
                job_title,
            })
        }
        // Software License：license key 必填（缺省提示），元数据可选。
        CredentialTypeOption::SoftwareLicense => {
            if secret.is_some() || prompt_secret {
                bail!("License key is provided via --license-key; --secret/--prompt-secret do not apply");
            }
            let key = match license_key {
                Some(v) if !v.trim().is_empty() => v,
                _ => ui.input("License key", None, false)?,
            };
            CredentialData::SoftwareLicense(SoftwareLicenseData {
                license_key: key,
                version,
                publisher,
                purchase_date,
                order_number,
                support_email,
                download_url,
                seats,
                valid_until,
            })
        }
        // API key：与 password 同为「单秘密」取值路径，但 data 变体必须是
        // ApiKey——曾走 `_` 兜底被建成 Password 变体（type=ApiKey +
        // data=Password），`secrets resolve IDENTITY/ITEM/api_key` 直接报
        // "unknown field"，按变体消费的下游（cockpit 等）同样失效。
        CredentialTypeOption::ApiKey => {
            let secret_value = if prompt_secret {
                super::super::service::prompt_credential_secret(ui)?
            } else if let Some(raw) = secret {
                raw
            } else {
                ui.input("API key (leave blank to skip)", None, true)?
            };
            CredentialData::ApiKey(ApiKeyData {
                api_key: secret_value,
                api_secret: None,
                token: None,
                permissions: Vec::new(),
                expires_at: None,
            })
        }
        _ => {
            let secret_value = if prompt_secret {
                super::super::service::prompt_credential_secret(ui)?
            } else if let Some(raw) = secret {
                raw
            } else {
                ui.input("Secret / password (leave blank to skip)", None, true)?
            };

            CredentialData::Password(PasswordCredentialData {
                password: secret_value.clone(),
                email: None,
                security_questions: Vec::new(),
            })
        }
    };

    let mut created = service
        .create_credential(
            identity.id,
            name.clone(),
            credential_type.into(),
            security_level.into(),
            &credential_data,
        )
        .await
        .into_anyhow()
        .context("Failed to create credential")?;

    created.username = username.clone();
    created.url = url.clone();
    created.is_favorite = favorite;
    service
        .update_credential(&created)
        .await
        .into_anyhow()
        .context("Failed to update credential metadata")?;

    println!(
        "{} Created credential '{}' for identity '{}'",
        "✓".green(),
        name.bright_green(),
        identity.name.bright_cyan()
    );

    Ok(())
}

pub(crate) async fn list_credentials(
    config: &CliConfig,
    ui: &dyn PromptUi,
    identity_name: Option<String>,
    credential_type: Option<String>,
    favorite_only: bool,
    format: String,
) -> Result<()> {
    let mut service = init_service(config, ui).await?;
    let credentials = if let Some(identity_name) = identity_name {
        let identity = resolve_identity(&mut service, &identity_name).await?;
        service
            .get_credentials_for_identity(&identity.id)
            .await
            .into_anyhow()
            .context("Failed to fetch credentials")?
    } else {
        service
            .search_credentials("")
            .await
            .into_anyhow()
            .context("Failed to fetch credentials")?
    };

    let filtered: Vec<Credential> = credentials
        .into_iter()
        .filter(|cred| {
            if favorite_only && !cred.is_favorite {
                return false;
            }
            if let Some(ref t) = credential_type {
                return cred.credential_type.to_string().eq_ignore_ascii_case(t);
            }
            true
        })
        .collect();

    if filtered.is_empty() {
        println!(
            "{}",
            "No credentials found with the given filters.".yellow()
        );
        return Ok(());
    }

    match format.as_str() {
        "table" => {
            let rows: Vec<CredentialRow> = filtered
                .iter()
                .map(|cred| CredentialRow {
                    id: cred.id.to_string(),
                    name: cred.name.clone(),
                    credential_type: cred.credential_type.to_string(),
                    identity: cred.identity_id.to_string(),
                    username: cred.username.clone().unwrap_or_default(),
                    favorite: if cred.is_favorite { "★" } else { "" }.into(),
                })
                .collect();
            println!("{}", Table::new(rows));
        }
        "json" => {
            println!("{}", serde_json::to_string_pretty(&filtered)?);
        }
        "yaml" => {
            println!("{}", serde_yaml::to_string(&filtered)?);
        }
        other => anyhow::bail!("Unsupported format: {}", other),
    }

    Ok(())
}

pub(crate) async fn show_credential(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    reveal: bool,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let credential = service
        .get_credential(&id)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Credential {} not found", id))?;
    println!("{} {}", "Credential:".bold(), credential.name.cyan());
    println!("  ID: {}", credential.id);
    println!("  Type: {}", credential.credential_type);
    println!("  Identity ID: {}", credential.identity_id);
    if let Some(username) = &credential.username {
        println!("  Username: {}", username);
    }
    if let Some(url) = &credential.url {
        println!("  URL: {}", url);
    }
    println!(
        "  Favorite: {}",
        if credential.is_favorite { "yes" } else { "no" }
    );
    println!("  Security level: {}", credential.security_level);

    if reveal {
        let confirm = ui.confirm("Reveal secret value? (visible on screen)", false)?;
        if confirm {
            if let Some(data) = service.get_credential_data(&id).await.into_anyhow()? {
                match data {
                    CredentialData::Password(password) => {
                        println!("  Password: {}", password.password.blue());
                    }
                    CredentialData::ApiKey(api) => {
                        println!("  API Key: {}", api.api_key.blue());
                    }
                    CredentialData::SshKey(ssh) => {
                        println!("  Private Key: {}", ssh.private_key);
                    }
                    CredentialData::SecureNote(note) => {
                        println!("  --- note ---");
                        println!("{}", note.note.blue());
                        println!("  ------------");
                    }
                    CredentialData::Identity(id) => {
                        println!("  Name: {} {}", id.first_name, id.last_name);
                        if let Some(v) = &id.email {
                            println!("  Email: {}", v);
                        }
                        if let Some(v) = &id.phone {
                            println!("  Phone: {}", v);
                        }
                        if let Some(v) = &id.address {
                            println!("  Address: {}", v.replace('\n', ", "));
                        }
                        if let Some(v) = &id.id_number {
                            println!("  ID number: {}", v.blue());
                        }
                        if let Some(v) = &id.passport_number {
                            println!("  Passport: {}", v.blue());
                        }
                        if let Some(v) = &id.driver_license {
                            println!("  Driver license: {}", v.blue());
                        }
                        if let Some(v) = &id.tax_id {
                            println!("  Tax ID: {}", v.blue());
                        }
                    }
                    CredentialData::SoftwareLicense(lic) => {
                        println!("  License key: {}", lic.license_key.blue());
                        if let Some(v) = &lic.version {
                            println!("  Version: {}", v);
                        }
                        if let Some(v) = &lic.publisher {
                            println!("  Publisher: {}", v);
                        }
                        if let Some(v) = &lic.purchase_date {
                            println!("  Purchased: {}", v);
                        }
                        if let Some(v) = &lic.valid_until {
                            println!("  Valid until: {}", v);
                        }
                        if let Some(v) = lic.seats {
                            println!("  Seats: {}", v);
                        }
                        if let Some(v) = &lic.download_url {
                            println!("  Download: {}", v);
                        }
                    }
                    other => {
                        println!("  Data: {:?}", other);
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn remove_credential(
    config: &CliConfig,
    ui: &dyn PromptUi,
    id: Uuid,
    yes: bool,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    if !yes {
        let confirm = ui.confirm(&format!("Remove credential {}?", id), false)?;
        if !confirm {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }
    }
    let deleted = service.delete_credential(&id).await.into_anyhow()?;
    if deleted {
        println!("{} Removed credential {}", "✓".green(), id);
    } else {
        println!("{} Credential {} not found", "⚠".yellow(), id);
    }
    Ok(())
}
