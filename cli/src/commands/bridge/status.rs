use super::*;

pub(super) async fn compute_status(db_path: &Path) -> Result<(bool, Option<String>)> {
    let db = open_db(db_path).await?;
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .map_err(|e| anyhow!("failed to create service: {e}"))?;

    let has_users = service.has_users().await?;
    let locked = if !has_users {
        true
    } else {
        // If a master password is available, try to authenticate to report "unlocked".
        if let Ok(pw) = std::env::var("PERSONA_MASTER_PASSWORD") {
            if !pw.trim().is_empty() {
                let auth = service.authenticate_user(&pw).await?;
                auth != persona_core::auth::authentication::AuthResult::Success
            } else {
                true
            }
        } else {
            true
        }
    };

    // Best-effort active identity from workspace metadata.
    let active_identity = {
        let repo = WorkspaceRepository::new(db);
        // Single-workspace MVP: just pick the first row.
        match repo.find_all().await {
            Ok(mut rows) => rows
                .pop()
                .and_then(|ws| ws.active_identity_id.map(|id| id.to_string())),
            Err(_) => None,
        }
    };

    Ok((locked, active_identity))
}

pub(super) async fn get_credential_suggestions(
    db_path: &Path,
    host: &str,
    form_type: &str,
    context: Option<&ContextSuggestion>,
) -> Result<Vec<SuggestionItem>> {
    let db = open_db(db_path).await?;
    let active_identity_id = get_active_identity_id(&db).await;

    // Stage 4: resolve the suggested identity (by name) so its credentials
    // merge into the candidate pool ahead of the active identity's. Core
    // suggest() already filters invalid names; resolution is belt and braces.
    let irepo = IdentityRepository::new(db.clone());
    let identities = irepo.find_all().await.unwrap_or_default();
    let name_of = |id: &uuid::Uuid| {
        identities
            .iter()
            .find(|i| &i.id == id)
            .map(|i| i.name.clone())
    };
    let suggested_id = context.as_ref().and_then(|s| {
        identities
            .iter()
            .find(|i| i.name == s.identity)
            .map(|i| i.id)
    });

    let repo = CredentialRepository::new(db);
    let mut all = Vec::new();
    match active_identity_id {
        Some(identity_id) => all.extend(repo.find_by_identity(&identity_id).await?),
        None => all = repo.find_all().await?,
    }
    if let Some(sid) = suggested_id {
        if Some(sid) != active_identity_id {
            all.extend(repo.find_by_identity(&sid).await?);
        }
    }

    // Card fills intentionally skip URL matching: a bank card has no canonical
    // site (checkout pages differ per merchant), so every active BankCard is a
    // candidate and the user picks one in the popup — same as 1Password.
    let want_cards = form_type.eq_ignore_ascii_case("card");

    let mut out: Vec<(SuggestionItem, bool)> = Vec::new();
    for cred in all {
        if !cred.is_active {
            continue;
        }
        let owner = name_of(&cred.identity_id);
        let boosted = context
            .as_ref()
            .is_some_and(|s| owner.as_deref() == Some(s.identity.as_str()));
        if want_cards {
            if cred.credential_type != CredentialType::BankCard {
                continue;
            }
            out.push((
                SuggestionItem {
                    item_id: cred.id.to_string(),
                    title: cred.name,
                    username_hint: None,
                    match_strength: 100,
                    credential_type: "bank_card".to_string(),
                    identity: owner,
                },
                boosted,
            ));
            continue;
        }
        let kind = match cred.credential_type {
            CredentialType::Password => "password",
            CredentialType::TwoFactor => "totp",
            _ => continue,
        };

        if cred.url.is_none() {
            continue;
        }

        // Calculate match strength based on URL similarity.
        let match_strength = compute_match_strength(host, cred.url.as_deref().unwrap_or_default());

        if match_strength == 0 {
            continue;
        }

        out.push((
            SuggestionItem {
                item_id: cred.id.to_string(),
                title: cred.name,
                username_hint: cred.username,
                match_strength,
                credential_type: kind.to_string(),
                identity: owner,
            },
            boosted,
        ));
    }

    // Sort: context-suggested identity first, then match strength descending.
    out.sort_by_key(|(item, boosted)| (!*boosted, std::cmp::Reverse(item.match_strength)));

    debug!(
        host = %host,
        form_type = %form_type,
        suggestions = out.len(),
        context = context.as_ref().map(|c| c.identity.as_str()),
        "credential suggestions retrieved"
    );

    Ok(out.into_iter().map(|(item, _)| item).collect())
}

/// Stage 4 map paths for the bridge context layer. `repo_local` exists only
/// when the request carried a `cwd` signal; the global map always does.
pub(super) struct BridgeMapPaths {
    pub(super) global: PathBuf,
    pub(super) repo_local: Option<PathBuf>,
}

impl BridgeMapPaths {
    fn current(cwd: &Option<String>) -> BridgeMapPaths {
        BridgeMapPaths {
            global: crate::commands::suggest::global_map_path(),
            repo_local: cwd
                .as_deref()
                .map(|c| Path::new(c).join(".persona").join("context.toml")),
        }
    }
}

/// Stage 4 bridge context suggestion (design §6): score the request's
/// host/cwd signals through the same core `suggest()` every entry point
/// uses, so all clients rank candidates identically. Returns None when
/// nothing matched or the layer is degraded — suggestions never block the
/// flow. Host signal precedence: explicit `host` field > origin host.
pub(super) async fn context_suggestion_for_bridge(
    db_path: &Path,
    page_host: &str,
    parsed: &SuggestionsPayload,
) -> Option<ContextSuggestion> {
    let maps = BridgeMapPaths::current(&parsed.cwd);
    context_suggestion_for_bridge_with(db_path, page_host, parsed, &maps).await
}

/// Same as [`context_suggestion_for_bridge`] with injected map paths (the
/// Windows dirs-sys constraint: `dirs::home_dir()` ignores HOME, so tests
/// redirect by injecting paths).
pub(super) async fn context_suggestion_for_bridge_with(
    db_path: &Path,
    page_host: &str,
    parsed: &SuggestionsPayload,
    maps: &BridgeMapPaths,
) -> Option<ContextSuggestion> {
    // 整层开关（与 shell hook / ssh run 同一口径）：非空即关闭。
    if std::env::var("PERSONA_NO_CONTEXT")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return None;
    }
    let explicit_host = parsed
        .host
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty());
    let signals = ContextSignals {
        cwd: PathBuf::new(),
        repo: parsed
            .cwd
            .as_deref()
            .and_then(|c| discover_git_repo(Path::new(c))),
        host: Some(explicit_host.unwrap_or(page_host).to_string()),
    };
    let db = open_db(db_path).await.ok()?;
    let irepo = IdentityRepository::new(db.clone());
    let valid_names: BTreeSet<String> = irepo
        .find_all()
        .await
        .ok()?
        .into_iter()
        .map(|i| i.name)
        .collect();
    let active = match get_active_identity_id(&db).await {
        Some(id) => irepo.find_by_id(&id).await.ok().flatten().map(|i| i.name),
        None => None,
    };
    let (global, _) = crate::commands::suggest::read_map_or_empty(&maps.global);
    let (repo_local, _) = match &maps.repo_local {
        Some(path) => crate::commands::suggest::read_map_or_empty(path),
        None => (ContextMapFile::default(), None),
    };
    // Bridge log pollution is stdout-forbidden: load warnings degrade silently
    // (design §10), same as the ssh-run host suggestion.
    let env_override = std::env::var("PERSONA_CONTEXT_OVERRIDE").ok();
    let result = context_suggest(
        &signals,
        Some(&repo_local),
        Some(&global),
        env_override.as_deref(),
        active.as_deref(),
        &valid_names,
        None,
    );
    result.candidates.first().map(|c| ContextSuggestion {
        identity: c.identity.clone(),
        score: c.score,
        reason: c.reason.clone(),
    })
}

pub(super) async fn get_active_identity_id(db: &Database) -> Option<uuid::Uuid> {
    let repo = WorkspaceRepository::new(db.clone());
    match repo.find_all().await {
        Ok(mut rows) => rows.pop().and_then(|ws| ws.active_identity_id),
        Err(_) => None,
    }
}

/// Compute match strength between request host and credential URL.
///
/// Returns:
/// - 100: Exact host match (e.g., "github.com" == "github.com")
/// - 90: Subdomain match (e.g., "api.github.com" matches "github.com")
/// - 80: Host contained in URL (e.g., "github.com" in "https://github.com/login")
/// - 60: TLD+1 match (e.g., "www.github.com" matches "github.com")
/// - 0: No match
pub(super) fn compute_match_strength(request_host: &str, cred_url: &str) -> u8 {
    // Extract host from credential URL.
    let cred_host = match Url::parse(cred_url) {
        Ok(url) => url.host_str().map(|s| s.to_lowercase()),
        Err(_) => {
            // Try treating it as a bare hostname.
            Some(cred_url.to_lowercase())
        }
    };

    let cred_host = match cred_host {
        Some(h) => h,
        None => return 0,
    };

    let req_host = request_host.to_lowercase();

    // Exact match.
    if req_host == cred_host {
        return 100;
    }

    // Request is subdomain of credential host (e.g., api.github.com -> github.com).
    if req_host.ends_with(&format!(".{cred_host}")) {
        return 90;
    }

    // Credential is subdomain of request host (e.g., github.com -> www.github.com).
    if cred_host.ends_with(&format!(".{req_host}")) {
        return 90;
    }

    // Check if they share the same registrable domain (TLD+1).
    // Simple heuristic: compare last two parts.
    let req_parts: Vec<&str> = req_host.split('.').collect();
    let cred_parts: Vec<&str> = cred_host.split('.').collect();

    if req_parts.len() >= 2 && cred_parts.len() >= 2 {
        let req_tld1 = format!(
            "{}.{}",
            req_parts[req_parts.len() - 2],
            req_parts[req_parts.len() - 1]
        );
        let cred_tld1 = format!(
            "{}.{}",
            cred_parts[cred_parts.len() - 2],
            cred_parts[cred_parts.len() - 1]
        );

        if req_tld1 == cred_tld1 {
            return 60;
        }
    }

    // Fallback: simple contains check (legacy behavior).
    if cred_url.contains(&req_host) {
        return 80;
    }

    0
}

/// Validate that the request origin is allowed to access the credential.
///
/// Security: This prevents credential filling on mismatched domains.
pub(super) fn validate_origin_binding(request_host: &str, cred_url: Option<&str>) -> bool {
    let cred_url = match cred_url {
        Some(url) => url,
        // No URL stored = no origin binding (allow any).
        // This is intentional for credentials without a URL.
        None => return true,
    };

    let match_strength = compute_match_strength(request_host, cred_url);

    // Require at least TLD+1 match (60+) for fill operations.
    // This is stricter than suggestions (which show anything > 0).
    match_strength >= 60
}

pub(super) fn origin_to_host(origin: &str) -> Result<String> {
    // Accept either an origin ("https://example.com") or a full URL.
    let url = Url::parse(origin).or_else(|_| Url::parse(&format!("https://{origin}")))?;
    url.host_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("invalid_origin"))
}
