use super::*;

pub(crate) async fn generate_key(
    identity_name: &str,
    label: Option<String>,
    key_type: &str,
    comment: Option<String>,
    favorite: bool,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let key_type = key_type.to_lowercase();
    let comment = comment.unwrap_or_default();
    println!(
        "{}",
        format!("🔑 Generating {key_type} SSH keypair...")
            .cyan()
            .bold()
    );

    // 生成先行：未知类型在解锁 workspace 之前就报错。ed25519 走库内
    // 既有约定（BASE64 seed），rsa/ecdsa 走 ssh_generate（明文 PEM，
    // 封存由 per-item key 负责）——与导入通道的双格式约定一致。
    let (ssh_data, public_line, fingerprint) = if key_type == "ed25519" {
        use ed25519_dalek::SigningKey;
        use rand::Rng;

        let mut rng = rand::rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pub_bytes = signing_key.verifying_key().to_bytes(); // 32-byte public

        // Encode to OpenSSH public line: base64 of [len:"ssh-ed25519"][b"ssh-ed25519"][len:pub][pub]
        let openssh_pub = encode_ssh_ed25519_public(
            &pub_bytes,
            (!comment.is_empty()).then_some(comment.as_str()),
        );
        let fingerprint = ssh_key::PublicKey::from_openssh(&openssh_pub)
            .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string())
            .unwrap_or_default();
        let data = SshKeyData {
            private_key: BASE64.encode(signing_key.to_bytes()), // 32-byte seed
            public_key: openssh_pub.clone(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        };
        (data, openssh_pub, fingerprint)
    } else {
        let generated =
            persona_core::crypto::ssh_generate::generate_ssh_keypair(&key_type, &comment)?;
        let data = SshKeyData {
            private_key: generated.private_key_pem,
            public_key: generated.public_key.clone(),
            key_type: generated.key_type,
            passphrase: None,
        };
        (data, generated.public_key, generated.fingerprint)
    };

    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    // 条目名回退与 import 通道一致：--name > comment > 既有兜底
    let name = label
        .or_else(|| (!comment.is_empty()).then(|| comment.clone()))
        .unwrap_or_else(|| format!("SSH Key ({})", identity.name));

    let mut cred = service
        .create_credential(
            identity.id,
            name.clone(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(ssh_data),
        )
        .await?;

    println!("{} Created SSH key credential:", "✓".green().bold());
    println!("  Name: {}", name.cyan());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Type: {}", key_type.cyan());
    if !fingerprint.is_empty() {
        println!("  Fingerprint: {}", fingerprint.yellow());
    }
    println!("  Public: {}", public_line);
    println!("  ID: {}", cred.id);
    if favorite {
        cred.is_favorite = true;
        service.update_credential(&cred).await?;
        println!("  Favorite: {}", "yes".green());
    }
    Ok(())
}

pub(crate) async fn list_keys(
    identity_name: &str,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;
    let creds = service.get_credentials_for_identity(&identity.id).await?;
    let mut count = 0usize;
    for cred in creds {
        if matches!(cred.credential_type, CredentialType::SshKey) {
            count += 1;
            println!("{} {}", "#".dimmed(), count);
            println!("  ID: {}", cred.id);
            println!("  Name: {}", cred.name.cyan());
            println!("  Created: {}", cred.created_at.format("%Y-%m-%d %H:%M:%S"));
            println!(
                "  Favorite: {}",
                if cred.is_favorite {
                    "yes".green()
                } else {
                    "no".dimmed()
                }
            );
        }
    }
    if count == 0 {
        println!("{}", "No SSH keys for this identity.".yellow());
    }
    Ok(())
}

pub(crate) async fn list_all_keys(
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    let identities = service.get_identities().await?;
    let mut count = 0usize;

    for identity in identities {
        let creds = service.get_credentials_for_identity(&identity.id).await?;
        for cred in creds {
            if matches!(cred.credential_type, CredentialType::SshKey) {
                count += 1;
                println!("{} {}", "#".dimmed(), count);
                println!("  ID: {}", cred.id);
                println!("  Name: {}", cred.name.cyan());
                println!("  Identity: {}", identity.name.cyan());
                println!("  Created: {}", cred.created_at.format("%Y-%m-%d %H:%M:%S"));
                println!(
                    "  Favorite: {}",
                    if cred.is_favorite {
                        "yes".green()
                    } else {
                        "no".dimmed()
                    }
                );
            }
        }
    }

    if count == 0 {
        println!("{}", "No SSH keys found.".yellow());
    }

    Ok(())
}

pub(crate) async fn remove_key(
    id: Uuid,
    yes: bool,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    if !yes && !ui.confirm(&format!("Remove SSH key credential {}?", id), false)? {
        println!("{}", "Cancelled.".yellow());
        return Ok(());
    }
    let _ = service.delete_credential(&id).await?;
    println!("{} Removed credential {}", "✓".green(), id);
    Ok(())
}

pub(crate) fn encode_ssh_ed25519_public(pubkey: &[u8; 32], comment: Option<&str>) -> String {
    // helper to build SSH public key format
    use byteorder::{BigEndian, WriteBytesExt};
    let mut buf: Vec<u8> = Vec::new();
    let algo = b"ssh-ed25519";
    buf.write_u32::<BigEndian>(algo.len() as u32).unwrap();
    buf.extend_from_slice(algo);
    buf.write_u32::<BigEndian>(pubkey.len() as u32).unwrap();
    buf.extend_from_slice(pubkey);
    let b64 = BASE64.encode(&buf);
    match comment {
        Some(c) if !c.is_empty() => format!("ssh-ed25519 {} {}", b64, c),
        _ => format!("ssh-ed25519 {}", b64),
    }
}

pub(crate) async fn import_seed(
    identity_name: &str,
    label: Option<String>,
    seed_b64: Option<String>,
    seed_hex: Option<String>,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    println!("{}", "🔑 Importing SSH seed...".cyan().bold());
    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    let seed = if let Some(b64) = seed_b64 {
        BASE64.decode(&b64).context("Invalid base64 seed")?
    } else if let Some(hexs) = seed_hex {
        let cleaned = hexs.trim();
        hex::decode(cleaned).context("Invalid hex seed")?
    } else {
        anyhow::bail!("Provide --seed-base64 or --seed-hex");
    };
    if seed.len() != 32 {
        anyhow::bail!("Seed must be 32 bytes for ed25519");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed[..32]);
    // Derive public key
    use ed25519_dalek::{SigningKey, VerifyingKey};
    let signing = SigningKey::from_bytes(&arr);
    let verifying: VerifyingKey = signing.verifying_key();
    let pub_bytes = verifying.to_bytes();
    let public_openssh = encode_ssh_ed25519_public(&pub_bytes, None);
    let name = label.unwrap_or_else(|| "SSH Key (imported)".to_string());
    let ssh_data = SshKeyData {
        private_key: BASE64.encode(arr),
        public_key: public_openssh.clone(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    };
    let cred = service
        .create_credential(
            identity.id,
            name.clone(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(ssh_data),
        )
        .await?;
    println!("{} Imported SSH key:", "✓".green().bold());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Name: {}", name.cyan());
    println!("  Public: {}", public_openssh);
    println!("  ID: {}", cred.id);
    Ok(())
}

/// 导入私钥文件（`persona ssh import-file --identity … --file ~/.ssh/id_ed25519`）。
/// 格式自动识别（OpenSSH 容器 / PKCS#8 / PKCS#1 / SEC1，见 core 的
/// ssh_import）；入库口径：私钥存解锁后的 OpenSSH PEM（per-item key
/// 封存在 vault 层），公钥行/类型/指纹解析自同一把钥。
pub(crate) async fn import_file(
    identity_name: &str,
    file_path: &str,
    label: Option<String>,
    passphrase: Option<String>,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    println!("{}", "🔑 Importing private key file...".cyan().bold());
    let pem = std::fs::read_to_string(file_path)
        .with_context(|| format!("Cannot read key file {file_path}"))?;

    // 先按给定口令解析；密钥受保护但没给口令时交互补问一次
    let imported = match persona_core::crypto::ssh_import::import_private_key_file(
        &pem,
        passphrase.as_deref(),
    ) {
        Ok(imported) => imported,
        Err(err) if err.to_string().contains("passphrase required") => {
            let pass = ui
                .password("Key passphrase", false, None)
                .context("Passphrase required to unlock this SSH key")?;
            persona_core::crypto::ssh_import::import_private_key_file(&pem, Some(&pass))?
        }
        Err(err) => return Err(err.into()),
    };

    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    // 条目名回退：--name > 钥匙 comment > 文件名 > 兜底
    let file_name = std::path::Path::new(file_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string());
    let name = label
        .or_else(|| (!imported.comment.is_empty()).then(|| imported.comment.clone()))
        .or(file_name)
        .unwrap_or_else(|| "SSH Key (imported)".to_string());

    let ssh_data = SshKeyData {
        private_key: imported.private_key_pem.clone(),
        public_key: imported.public_key.clone(),
        key_type: imported.key_type.clone(),
        passphrase: None,
    };
    let cred = service
        .create_credential(
            identity.id,
            name,
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(ssh_data),
        )
        .await?;

    println!("{} Imported SSH key:", "✓".green().bold());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Name: {}", cred.name.cyan());
    println!("  Type: {}", imported.key_type.cyan());
    println!("  Fingerprint: {}", imported.fingerprint.yellow());
    println!("  Public: {}", imported.public_key);
    println!("  ID: {}", cred.id);
    Ok(())
}

pub(crate) async fn export_pubkey(
    id: uuid::Uuid,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    if let Some(cred) = service.get_credential(&id).await? {
        if !matches!(cred.credential_type, CredentialType::SshKey) {
            anyhow::bail!("Credential is not an SSH key");
        }
        if let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&id).await? {
            println!("{}", ssh.public_key);
            Ok(())
        } else {
            anyhow::bail!("Unable to decrypt SSH key (locked?)");
        }
    } else {
        anyhow::bail!("Credential not found");
    }
}

/// 从保险库收集全部可用作签名的 SSH key：(seed, 公钥行, 凭据 id, 身份 id)。
/// 解不开（已锁定/损坏）的凭据跳过——不能拿来签的东西不该中断签名流程，
/// 但如果全军覆没，resolve_signing_key 会以空列表报错。
pub(crate) async fn vault_ssh_keys(
    service: &PersonaService,
) -> Result<Vec<([u8; 32], String, Uuid, Uuid)>> {
    let mut keys = Vec::new();
    for identity in service.get_identities().await? {
        let creds = service.get_credentials_for_identity(&identity.id).await?;
        for cred in creds {
            if !matches!(cred.credential_type, CredentialType::SshKey) {
                continue;
            }
            let (seed, public_line) = match service.get_credential_data(&cred.id).await? {
                Some(CredentialData::SshKey(ssh)) => match decode_seed(&ssh) {
                    Ok(seed) => (seed, ssh.public_key),
                    Err(err) => {
                        eprintln!("{} Skipping SSH key {}: {}", "!".yellow(), cred.id, err);
                        continue;
                    }
                },
                _ => continue,
            };
            keys.push((seed, public_line, cred.id, identity.id));
        }
    }
    Ok(keys)
}

/// SshKeyData.private_key 是 base64 的 32 字节 ed25519 seed（与
/// agents/ssh-agent 同一约定）。
pub(crate) fn decode_seed(ssh: &SshKeyData) -> Result<[u8; 32]> {
    let raw = BASE64
        .decode(ssh.private_key.trim().as_bytes())
        .context("SSH key private material is not valid base64")?;
    if raw.len() != 32 {
        anyhow::bail!("SSH key seed must be 32 bytes, got {}", raw.len());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(seed)
}
