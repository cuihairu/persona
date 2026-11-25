use super::keys::vault_ssh_keys;
use super::*;

/// The key blob from an authorized_keys line (2nd whitespace-separated field).
fn public_key_blob(line: &str) -> Option<&str> {
    line.split_whitespace().nth(1)
}

/// Resolve the `-f` keyspec into a signable seed. Four forms are accepted:
/// `persona:ssh:<uuid>`, a bare credential UUID (git's recommended
/// user.signingkey form), an `ssh-ed25519 <b64>` public key line literal, or
/// the path of a file holding a public key line; with no spec, the vault must
/// hold exactly one SSH key.
async fn resolve_signing_key(
    service: &PersonaService,
    spec: Option<&str>,
) -> Result<([u8; 32], String, Uuid, Uuid)> {
    let mut keys = vault_ssh_keys(service).await?;
    if keys.is_empty() {
        anyhow::bail!("No SSH keys in the vault; run `persona ssh generate` first");
    }
    let spec = match spec {
        None => {
            return if keys.len() == 1 {
                Ok(keys.remove(0))
            } else {
                anyhow::bail!(
                    "{} SSH keys in the vault; pick one with -f <credential-id> \
                     (or set git's user.signingkey)",
                    keys.len()
                );
            };
        }
        Some(spec) => spec.trim(),
    };
    let uuid_text = spec.strip_prefix("persona:ssh:").unwrap_or(spec);
    if let Ok(id) = Uuid::parse_str(uuid_text) {
        return keys
            .into_iter()
            .find(|(_, _, cred_id, _)| *cred_id == id)
            .ok_or_else(|| anyhow::anyhow!("Credential {id} is not an SSH key in this vault"));
    }
    // Public key line literal or file path (git allows user.signingkey to be a .pub file)
    let line = match std::fs::read_to_string(spec) {
        Ok(text) => text,
        Err(_) => spec.to_string(),
    };
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some("ssh-ed25519") => {}
        _ => anyhow::bail!(
            "Key spec is neither a credential UUID, nor a readable key file, \
             nor an ssh-ed25519 public key line"
        ),
    }
    let blob = tokens.next().context("Public key line has no key blob")?;
    keys.into_iter()
        .find(|(_, public_line, _, _)| public_key_blob(public_line) == Some(blob))
        .ok_or_else(|| {
            anyhow::anyhow!("No vault SSH key matches this public key; import or generate it first")
        })
}

/// `-Y sign`: read file → SSHSIG sign → armored output to disk. The output
/// is byte-for-byte compatible with `ssh-keygen -Y sign -n <namespace>`
/// (ed25519 signatures are deterministic), so this can act directly as git's
/// `gpg.format=ssh` signer (the persona-ssh-sign shim).
pub(crate) async fn gpg_sign(
    mode: &str,
    namespace: &str,
    key: Option<String>,
    file: &str,
    output: Option<String>,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    if mode != "sign" {
        anyhow::bail!("Only `-Y sign` is supported (got -Y {})", mode);
    }
    let message = std::fs::read(file).with_context(|| format!("Cannot read {file}"))?;
    let service = ensure_service(config, ui).await?;
    let (seed, public_line, cred_id, identity_id) =
        resolve_signing_key(&service, key.as_deref()).await?;
    let blob = persona_core::crypto::sshsig::sign(&seed, namespace, &message);
    // Self-verify before writing: the signature is mathematically valid and the embedded key is the chosen vault key
    let embedded = persona_core::crypto::sshsig::verify(&blob, namespace, &message)
        .context("Just-created signature failed self-verification")?;
    if BASE64.encode(&embedded) != public_key_blob(&public_line).unwrap_or_default() {
        anyhow::bail!("Signature embeds an unexpected public key");
    }
    let out_path = output.unwrap_or_else(|| format!("{file}.sig"));
    std::fs::write(&out_path, persona_core::crypto::sshsig::armor(&blob))
        .with_context(|| format!("Cannot write {out_path}"))?;
    println!("{} Signed {} -> {}", "✓".green(), file, out_path);
    println!("  Key: {} ({})", public_line, cred_id);
    // Audit fields: same action name as the agent's `ssh_sign`, with
    // via/namespace/digest recorded in metadata (best-effort, never blocks the main flow)
    audit_ssh_event(
        &config.get_database_path(),
        "ssh_sign",
        Some(identity_id),
        Some(cred_id),
        &[
            ("via", "gpg-sign".to_string()),
            ("namespace", namespace.to_string()),
            (
                "data_sha256",
                persona_core::crypto::hashing::Sha256Hasher::hash_hex(&message),
            ),
            ("output", out_path),
        ],
    )
    .await;
    Ok(())
}

/// Audit event (established convention, same as agents/ssh-agent): a
/// short-lived connection writes an `audit_log` row; failures only warn and
/// never block the main flow.
pub(crate) async fn audit_ssh_event(
    db_path: &Path,
    action: &str,
    identity_id: Option<Uuid>,
    credential_id: Option<Uuid>,
    metadata: &[(&str, String)],
) {
    let outcome = (async {
        use persona_core::models::{AuditAction, AuditLog, ResourceType};
        use persona_core::storage::AuditLogRepository;
        use persona_core::Repository;
        let db: persona_core::Database =
            Database::from_file::<std::path::PathBuf>(db_path.to_owned())
                .await
                .into_anyhow()?;
        db.migrate().await?;
        let repo = AuditLogRepository::new(db);
        let mut log = AuditLog::new(
            AuditAction::Custom(action.to_string()),
            ResourceType::Credential,
            true,
        )
        .with_identity_id(identity_id)
        .with_credential_id(credential_id);
        for (key, value) in metadata {
            log = log.with_metadata((*key).to_string(), value.clone());
        }
        repo.create(&log).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await;
    if let Err(err) = outcome {
        eprintln!("{} audit log: {err}", "!".yellow());
    }
}
