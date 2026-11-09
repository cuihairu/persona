use super::*;

/// Metadata-only candidates for the extension's save/update bar: password
/// items bound to this host whose username matches the submitted one. No
/// secret material is returned, so like `get_suggestions` this is
/// session-authenticated but not gesture-gated.
pub(super) async fn find_credentials_for_save(
    db_path: &Path,
    host: &str,
    username: Option<&str>,
) -> Result<Vec<FindForSaveMatch>> {
    let db = open_db(db_path).await?;
    let active_identity_id = get_active_identity_id(&db).await;
    let repo = CredentialRepository::new(db);
    let all = match active_identity_id {
        Some(identity_id) => repo.find_by_identity(&identity_id).await?,
        None => repo.find_all().await?,
    };

    let submitted = username
        .map(|u| u.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut matches = Vec::new();
    for cred in all {
        if !cred.is_active || cred.credential_type != CredentialType::Password {
            continue;
        }
        // Same binding rule as fills: at least TLD+1 match with the
        // requesting host. Items without a URL can't be attributed to a
        // site, so they are never offered as update targets.
        if !validate_origin_binding(host, cred.url.as_deref()) {
            continue;
        }
        let stored = cred
            .username
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if stored != submitted {
            continue;
        }
        matches.push(FindForSaveMatch {
            item_id: cred.id.to_string(),
            name: cred.name,
            username: cred.username,
        });
    }

    debug!(
        host = %host,
        candidates = matches.len(),
        "find_for_save candidates retrieved"
    );
    Ok(matches)
}

/// Body of `save_credential`: create a new password item or apply an
/// item_id-qualified password update. Every write is behind the gesture
/// gate + desktop approval + audit, mirroring the passkey create flow.
pub(super) async fn run_save_credential(
    db_path: &Path,
    request_id: Option<String>,
    parsed: SaveCredentialPayload,
) -> Result<BridgeResponse<serde_json::Value>> {
    if gesture_required() && !parsed.user_gesture {
        warn!(
            origin = %parsed.origin,
            "save_credential rejected: user_gesture required"
        );
        return Err(anyhow!(
            "user_gesture_required: saving must be confirmed by explicit user action"
        ));
    }
    if parsed.password.is_empty() {
        return Err(anyhow!("invalid_payload: password must not be empty"));
    }
    let host = origin_to_host(&parsed.origin)?;

    // Second consent line, same as passkey writes: a running desktop gets
    // to approve before the vault changes. Auto mode falls back to the
    // gesture gate when no desktop is around.
    match desktop_approval_gate(
        "credential_save",
        Some(&host),
        &parsed.origin,
        parsed.username.as_deref(),
        parsed.item_id.as_deref(),
    )
    .await?
    {
        #[cfg(unix)]
        DesktopApproval::Approved => {}
        #[cfg(unix)]
        DesktopApproval::Denied(reason) => {
            warn!(origin = %parsed.origin, %reason, "save_credential denied by desktop");
            return Err(anyhow!(
                "save_desktop_denied: save rejected by desktop approval ({reason})"
            ));
        }
        DesktopApproval::Unavailable => {}
    }

    let (service, active_identity_id) = open_unlocked_service(db_path).await?;
    let username = parsed
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let (item_id, name, action) = match parsed.item_id.as_deref() {
        Some(id_str) => {
            let item_id = uuid::Uuid::parse_str(id_str)
                .map_err(|e| anyhow!("invalid_payload: item_id uuid: {e}"))?;
            let cred = service
                .get_credential(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;
            if cred.credential_type != CredentialType::Password {
                return Err(anyhow!("unsupported_credential_type"));
            }
            if let Some(active) = active_identity_id {
                if cred.identity_id != active {
                    return Err(anyhow!(
                        "wrong_identity: switch active identity to update this credential"
                    ));
                }
            }
            // Same binding rule as fills. An item without a URL is allowed
            // through: the update is an explicit user-picked target from
            // find_for_save, so there is no attribution ambiguity to guard.
            if let Some(url) = cred.url.as_deref() {
                if !validate_origin_binding(&host, Some(url)) {
                    warn!(
                        origin = %parsed.origin,
                        host = %host,
                        cred_url = url,
                        item_id = %item_id,
                        "save_credential rejected: origin mismatch"
                    );
                    return Err(anyhow!(
                        "origin_mismatch: request origin does not match credential URL"
                    ));
                }
            }

            // Replace only the password inside the existing payload — email
            // and security questions survive untouched.
            let existing = match service.get_credential_data(&item_id).await? {
                Some(CredentialData::Password(p)) => p,
                Some(_) => return Err(anyhow!("unsupported_credential_type")),
                None => return Err(anyhow!("not_found")),
            };
            let updated_data = CredentialData::Password(PasswordCredentialData {
                password: parsed.password,
                email: existing.email,
                security_questions: existing.security_questions,
            });
            service
                .update_credential_data(&item_id, &updated_data)
                .await?;
            (item_id, cred.name, "updated")
        }
        None => {
            let identity_id = active_identity_id.ok_or_else(|| {
                anyhow!("no_active_identity: switch to an identity before saving a login")
            })?;
            let name = parsed
                .name_hint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&host)
                .to_string();
            let data = CredentialData::Password(PasswordCredentialData {
                password: parsed.password,
                email: username
                    .as_deref()
                    .filter(|u| u.contains('@'))
                    .map(str::to_string),
                security_questions: Vec::new(),
            });

            // create_credential only fills the encrypted payload; url and
            // username are presentation fields patched on afterwards (same
            // pattern as the desktop create flows).
            let mut credential = service
                .create_credential(
                    identity_id,
                    name,
                    CredentialType::Password,
                    persona_core::models::SecurityLevel::High,
                    &data,
                )
                .await?;
            credential.url = Some(parsed.origin.clone());
            credential.username = username;
            let credential = service.update_credential(&credential).await?;
            (credential.id, credential.name, "created")
        }
    };

    info!(
        event = "bridge_save_credential",
        action,
        origin = %parsed.origin,
        host = %host,
        item_id = %item_id,
        user_gesture = parsed.user_gesture,
        "credential saved via bridge"
    );

    Ok(ok(
        request_id,
        "save_credential_response",
        serde_json::to_value(SaveCredentialResponse {
            item_id: item_id.to_string(),
            action: action.to_string(),
            name,
        })?,
    ))
}

/// Generate a password/passphrase via the bridge (protocol v5).
/// No vault write — pure generation. Still requires authenticated session
/// (pairing + gesture gate) so only authorized extensions can use it.
pub(super) async fn run_generate_password(
    _db_path: &Path,
    request_id: Option<String>,
    parsed: GeneratePasswordPayload,
) -> Result<BridgeResponse<serde_json::Value>> {
    // Validate words mode range (core enforces 3-10).
    if let Some(words) = parsed.words {
        if !(3..=10).contains(&words) {
            return Err(anyhow!("invalid_payload: words must be between 3 and 10"));
        }
    }

    // Validate length bounds (core rejects < 4; keep the payload
    // error at the bridge so the extension shows invalid_payload,
    // not generation_failed).
    if parsed.length < 4 || parsed.length > 10_000 {
        return Err(anyhow!("invalid_payload: length must be 4..10000"));
    }

    // At least one character set must be enabled unless words mode.
    if parsed.words.is_none() {
        let any_set = parsed.include_lowercase
            || parsed.include_uppercase
            || parsed.include_digits
            || parsed.include_symbols;
        if !any_set {
            return Err(anyhow!(
                "invalid_payload: at least one character set must be enabled (or use words mode)"
            ));
        }
    }

    let options = PasswordGeneratorOptions {
        length: parsed.length,
        include_lowercase: parsed.include_lowercase,
        include_uppercase: parsed.include_uppercase,
        include_numbers: parsed.include_digits,
        include_symbols: parsed.include_symbols,
        pronounceable: parsed.pronounceable,
        words: parsed.words,
    };

    let password =
        PasswordGenerator::generate(&options).map_err(|e| anyhow!("generation_failed: {e}"))?;

    info!(
        event = "bridge_generate_password",
        length = parsed.length,
        words = parsed.words,
        pronounceable = parsed.pronounceable,
        "password generated via bridge"
    );

    Ok(ok(
        request_id,
        "generate_password_response",
        serde_json::to_value(GeneratePasswordResponse { password })?,
    ))
}
