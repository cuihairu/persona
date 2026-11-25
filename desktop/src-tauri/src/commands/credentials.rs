use super::*;

/// Read-only favicon flag: an unopenable vault / missing row is always
/// treated as off.
///
/// This is the backend fallback gate for favicon outbound fetching — it does
/// not rely on the frontend hiding the button: with the flag off,
/// `fetch_credential_favicon` refuses outright and `get_favicons` silently
/// returns empty.
pub(crate) async fn favicon_flag_enabled(db_path: &str) -> bool {
    let Ok(db) = Database::from_file(db_path).await else {
        return false;
    };
    if db.migrate().await.is_err() {
        return false;
    }
    let workspace_path = workspace_path_for_db_path(db_path);
    let repo = WorkspaceRepository::new(db);
    match repo.find_by_path(&workspace_path).await {
        Ok(Some(ws)) => ws.settings.features.fetch_favicons,
        _ => false,
    }
}

/// Create a new credential
#[command]
pub async fn create_credential(
    request: CreateCredentialRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.identity_id) {
            Ok(identity_uuid) => {
                let credential_type = match request.credential_type.as_str() {
                    "Password" => CredentialType::Password,
                    "CryptoWallet" => CredentialType::CryptoWallet,
                    "SshKey" => CredentialType::SshKey,
                    "ApiKey" => CredentialType::ApiKey,
                    "BankCard" => CredentialType::BankCard,
                    "GameAccount" => CredentialType::GameAccount,
                    "ServerConfig" => CredentialType::ServerConfig,
                    "Certificate" => CredentialType::Certificate,
                    "TwoFactor" => CredentialType::TwoFactor,
                    "SecureNote" => CredentialType::SecureNote,
                    "Identity" => CredentialType::Identity,
                    "SoftwareLicense" => CredentialType::SoftwareLicense,
                    custom => CredentialType::Custom(custom.to_string()),
                };

                let security_level = match request.security_level.as_str() {
                    "Critical" => SecurityLevel::Critical,
                    "High" => SecurityLevel::High,
                    "Medium" => SecurityLevel::Medium,
                    "Low" => SecurityLevel::Low,
                    _ => SecurityLevel::Medium,
                };

                let credential_data = request.credential_data.to_credential_data();

                match service
                    .create_credential(
                        identity_uuid,
                        request.name,
                        credential_type,
                        security_level,
                        &credential_data,
                    )
                    .await
                {
                    Ok(mut credential) => {
                        if let Some(url) = request.url {
                            credential.url = Some(url);
                        }
                        if let Some(username) = request.username {
                            credential.username = Some(username);
                        }
                        if let Some(notes) = request.notes {
                            let trimmed = notes.trim().to_string();
                            credential.notes = if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed)
                            };
                        }
                        if let Some(tags) = request.tags {
                            credential.tags = tags
                                .into_iter()
                                .map(|t| t.trim().to_string())
                                .filter(|t| !t.is_empty())
                                .collect();
                        }

                        match service.update_credential(&credential).await {
                            Ok(updated_credential) => {
                                Ok(ApiResponse::success(updated_credential.into()))
                            }
                            Err(e) => Ok(ApiResponse::error(format!(
                                "Failed to update credential: {}",
                                e
                            ))),
                        }
                    }
                    Err(e) => Ok(ApiResponse::error(format!(
                        "Failed to create credential: {}",
                        e
                    ))),
                }
            }
            Err(_) => Ok(ApiResponse::error(
                "Invalid identity UUID format".to_string(),
            )),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Edit credential metadata (name/username/url/notes/tags/security_level;
/// the item type is immutable, and payload edits go through
/// update_credential_data)
#[command]
pub async fn update_credential(
    request: UpdateCredentialRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.id) {
            Ok(uuid) => match service.get_credential(&uuid).await {
                Ok(Some(mut credential)) => {
                    credential.name = request.name;
                    if let Some(level) = request.security_level {
                        credential.security_level = match level.as_str() {
                            "Critical" => SecurityLevel::Critical,
                            "High" => SecurityLevel::High,
                            "Medium" => SecurityLevel::Medium,
                            "Low" => SecurityLevel::Low,
                            _ => credential.security_level.clone(),
                        };
                    }
                    if let Some(url) = request.url {
                        let trimmed = url.trim().to_string();
                        credential.url = if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        };
                    }
                    if let Some(username) = request.username {
                        let trimmed = username.trim().to_string();
                        credential.username = if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        };
                    }
                    if let Some(notes) = request.notes {
                        let trimmed = notes.trim().to_string();
                        credential.notes = if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        };
                    }
                    if let Some(tags) = request.tags {
                        credential.tags = tags
                            .into_iter()
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect();
                    }

                    match service.update_credential(&credential).await {
                        Ok(updated) => Ok(ApiResponse::success(updated.into())),
                        Err(e) => {
                            let (code, msg) = map_persona_error(&e);
                            match code {
                                Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                                None => Ok(ApiResponse::error(format!(
                                    "Failed to update credential: {}",
                                    msg
                                ))),
                            }
                        }
                    }
                }
                Ok(None) => Ok(ApiResponse::error(format!(
                    "Credential {} not found",
                    request.id
                ))),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to update credential: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Edit a credential's encrypted payload (sensitive: the original item key
/// is reused for resealing, and attachments are unaffected; goes through
/// the sensitive-operation gate, so a reauth timeout returns
/// REAUTH_REQUIRED)
#[command]
pub async fn update_credential_data(
    request: UpdateCredentialDataRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&request.credential_id) {
            Ok(uuid) => {
                let credential_data = request.credential_data.to_credential_data();
                match service
                    .update_credential_data(&uuid, &credential_data)
                    .await
                {
                    Ok(updated) => Ok(ApiResponse::success(updated.into())),
                    Err(e) => {
                        let (code, msg) = map_persona_error(&e);
                        match code {
                            Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                            None => Ok(ApiResponse::error(format!(
                                "Failed to update credential data: {}",
                                msg
                            ))),
                        }
                    }
                }
            }
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get credentials for an identity
#[command(rename_all = "snake_case")]
pub async fn get_credentials_for_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableCredential>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&identity_id) {
            Ok(uuid) => match service.get_credentials_for_identity(&uuid).await {
                Ok(credentials) => {
                    let serializable: Vec<SerializableCredential> =
                        credentials.into_iter().map(|cred| cred.into()).collect();
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to get credentials: {}",
                    e
                ))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get credential data (decrypted)
#[command(rename_all = "snake_case")]
pub async fn get_credential_data(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<SerializableCredentialData>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.get_credential_data(&uuid).await {
                Ok(credential_data) => {
                    let serializable = credential_data.map(|data| SerializableCredentialData {
                        credential_type: match &data {
                            CredentialData::Password(_) => "Password".to_string(),
                            CredentialData::CryptoWallet(_) => "CryptoWallet".to_string(),
                            CredentialData::SshKey(_) => "SshKey".to_string(),
                            CredentialData::ApiKey(_) => "ApiKey".to_string(),
                            CredentialData::BankCard(_) => "BankCard".to_string(),
                            CredentialData::ServerConfig(_) => "ServerConfig".to_string(),
                            CredentialData::TwoFactor(_) => "TwoFactor".to_string(),
                            CredentialData::Raw(_) => "Raw".to_string(),
                            CredentialData::GameToken(_) => "GameToken".to_string(),
                            CredentialData::SecureNote(_) => "SecureNote".to_string(),
                            CredentialData::Identity(_) => "Identity".to_string(),
                            CredentialData::SoftwareLicense(_) => "SoftwareLicense".to_string(),
                        },
                        data: credential_data_to_json(&data),
                    });
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to get credential data: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Structured custom fields of a credential (1Password parity). Values are
/// sealed under the credential's per-item key, so this needs an unlocked
/// vault; a credential without fields returns an empty list.
#[command(rename_all = "snake_case")]
pub async fn get_credential_custom_fields(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableCustomField>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.custom_fields(&uuid).await {
                Ok(fields) => Ok(ApiResponse::success(
                    fields.into_iter().map(Into::into).collect(),
                )),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to get custom fields: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Replace a credential's structured custom fields (empty list removes
/// them). Client may send `id: ""` for newly added rows — ids are
/// generated here; ids must be unique within the list.
#[command(rename_all = "snake_case")]
pub async fn set_credential_custom_fields(
    credential_id: String,
    fields: Vec<SerializableCustomField>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableCustomField>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => {
                let mut core_fields = Vec::with_capacity(fields.len());
                for f in fields {
                    let mut f = f;
                    if f.id.trim().is_empty() {
                        f.id = Uuid::new_v4().to_string();
                    }
                    match CustomField::try_from(f) {
                        Ok(cf) => core_fields.push(cf),
                        Err(e) => return Ok(ApiResponse::error(e.to_string())),
                    }
                }
                match service.set_custom_fields(&uuid, core_fields).await {
                    Ok(_) => match service.custom_fields(&uuid).await {
                        Ok(fields) => Ok(ApiResponse::success(
                            fields.into_iter().map(Into::into).collect(),
                        )),
                        Err(e) => Ok(ApiResponse::error(format!(
                            "Failed to read back custom fields: {}",
                            e
                        ))),
                    },
                    Err(e) => {
                        let (code, msg) = map_persona_error(&e);
                        match code {
                            Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                            None => Ok(ApiResponse::error(format!(
                                "Failed to set custom fields: {}",
                                msg
                            ))),
                        }
                    }
                }
            }
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get change history for a credential (item history; metadata-only,
/// field-level diffs contain no ciphertext/key material)
#[command(rename_all = "snake_case")]
pub async fn get_credential_history(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableChangeHistory>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service
                .get_entity_history(persona_core::models::EntityType::Credential, &uuid)
                .await
            {
                Ok(history) => {
                    let serializable: Vec<SerializableChangeHistory> =
                        history.into_iter().map(|entry| entry.into()).collect();
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to get credential history: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Restore a credential's metadata to an earlier item-history version.
/// Only metadata is rolled back (the 9 fields name/username/url/notes/tags
/// etc.); history snapshots never contain ciphertext, so secrets such as
/// passwords are not rolled back. Deleted rows have no restorable state,
/// so rebuilding a deleted item is not supported.
#[command(rename_all = "snake_case")]
pub async fn restore_credential_version(
    credential_id: String,
    version: u32,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.restore_credential_version(&uuid, version).await {
                Ok(restored) => Ok(ApiResponse::success(restored.into())),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to restore credential version: {}",
                            msg
                        ))),
                    }
                }
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Generate a TOTP code for a TwoFactor credential (without exposing the secret)
#[command(rename_all = "snake_case")]
pub async fn get_totp_code(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TotpCodeResponse>, String> {
    let service_guard = state.service.lock().await;
    let service = ok_or_error_response!(service_guard
        .as_ref()
        .ok_or_else(|| "Service not initialized".to_string()));

    let uuid = ok_or_error_response!(
        Uuid::from_str(&credential_id).map_err(|_| "Invalid UUID format".to_string())
    );
    let credential_data = ok_or_error_response_ctx!(
        service.get_credential_data(&uuid).await,
        "Failed to get credential data: {}"
    );

    let data =
        ok_or_error_response!(credential_data.ok_or_else(|| "Credential not found".to_string()));
    match data {
        CredentialData::TwoFactor(tf) => {
            // HOTP is counter-based; the desktop has no counter concept —
            // fail explicitly (pointing at the CLI's --counter usage)
            // rather than returning an error code about a time window.
            if tf.hotp.unwrap_or(false) {
                return Ok(ApiResponse::error(
                    "HOTP entries require an explicit counter — use `persona totp code <id> --counter N`"
                        .to_string(),
                ));
            }
            // The protocol logic is pushed down into core (RFC 4226/6238);
            // the desktop side only calls it.
            let generated = ok_or_error_response_ctx!(
                persona_core::crypto::totp::totp_now(&tf),
                "Failed to generate TOTP code: {}"
            );

            Ok(ApiResponse::success(TotpCodeResponse {
                code: generated.code,
                remaining_seconds: generated.remaining_seconds,
                period: tf.period.max(1),
                digits: tf.digits.clamp(4, 10),
                algorithm: tf.algorithm,
                issuer: tf.issuer,
                account_name: tf.account_name,
            }))
        }
        // Game tokens go through core's unified scheduler (Steam Guard can
        // be computed offline; a binding-bound provider errors here rather
        // than emitting an error code)
        CredentialData::GameToken(gt) => {
            let generated = ok_or_error_response_ctx!(
                persona_core::crypto::game_token::generate_game_token_code_now(&gt),
                "Failed to generate game token code: {}"
            );

            Ok(ApiResponse::success(TotpCodeResponse {
                code: generated.code,
                remaining_seconds: generated.remaining_seconds,
                period: generated.period,
                digits: persona_core::crypto::STEAM_GUARD_DIGITS as u8,
                algorithm: gt.provider.to_ascii_uppercase(),
                issuer: gt.issuer,
                account_name: gt.account_name,
            }))
        }
        _ => Ok(ApiResponse::error(
            "Credential is not a TwoFactor entry".to_string(),
        )),
    }
}

/// Search credentials
#[command]
pub async fn search_credentials(
    query: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableCredential>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.search_credentials(&query).await {
            Ok(credentials) => {
                let serializable: Vec<SerializableCredential> =
                    credentials.into_iter().map(|cred| cred.into()).collect();
                Ok(ApiResponse::success(serializable))
            }
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to search credentials: {}",
                e
            ))),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Generate password
#[command(rename_all = "snake_case")]
pub async fn generate_password(
    length: usize,
    include_symbols: bool,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            let password = service.generate_password(length, include_symbols);
            Ok(ApiResponse::success(password))
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Generate passwords with full generator options (desktop Generator panel).
///
/// Pure computation (`core::PasswordGenerator`), touches neither the vault
/// nor the master key — no unlock needed to call it (the follow-up Quick
/// Access / lock screen scenarios can reuse it directly). length is
/// clamped to 4..=256, count to 1..=10 (the slider UI is naturally
/// constrained; this is the backstop against abuse); invalid option
/// combinations (no character set / pronounceable without letters /
/// words out of range) pass through core's validation errors.
///
/// `rename_all = "snake_case"`: Tauri 2 looks up invoke argument keys as
/// camelCase by default (the macro default is `ArgumentCase::Camel`, where
/// `v.get(key)` matches exactly with no case fallback), but the frontend
/// api.ts sends snake_case keys throughout — without this attribute it
/// reports "missing required key includeLowercase". The key contract is
/// pinned by
/// `command_layer_tests::generate_password_advanced_ipc_arg_contract`.
///
/// 8 flat arguments exceed clippy's `too_many_arguments` threshold (7): this
/// is the IPC wire format, and the key names are the frontend's `invoke`
/// payload keys, pinned by the audit regression above — it cannot be
/// changed to a request struct just to satisfy the lint (that would alter
/// the published wire format). Other flat-options functions in the repo are
/// handled the same way (10 sites in core/cli share this cause) with lint
/// exemptions.
#[allow(clippy::too_many_arguments)]
#[command(rename_all = "snake_case")]
pub async fn generate_password_advanced(
    length: usize,
    include_lowercase: bool,
    include_uppercase: bool,
    include_numbers: bool,
    include_symbols: bool,
    pronounceable: bool,
    count: usize,
    words: Option<usize>,
) -> std::result::Result<ApiResponse<GeneratedPasswords>, String> {
    use persona_core::password::{PasswordGenerator, PasswordGeneratorOptions};

    let options = PasswordGeneratorOptions {
        length: length.clamp(4, 256),
        include_lowercase,
        include_uppercase,
        include_numbers,
        include_symbols,
        pronounceable,
        words,
    };
    let count = count.clamp(1, 10);

    let mut passwords = Vec::with_capacity(count);
    for _ in 0..count {
        match PasswordGenerator::generate(&options) {
            Ok(password) => passwords.push(password),
            Err(e) => return Ok(ApiResponse::error(e.to_string())),
        }
    }

    let (entropy_bits, pool_size) = estimate_generator_entropy(&options);
    Ok(ApiResponse::success(GeneratedPasswords {
        passwords,
        entropy_bits,
        pool_size,
    }))
}

/// Generator entropy estimate (display reference only):
/// - Random mode: `log2(character pool) x length` (core guarantees at least
///   one character from each enabled set; this approximates with uniform
///   sampling, i.e. one short of the shuffle entropy — ignored);
/// - Pronounceable mode: isomorphic to core's consonant/vowel alternation
///   algorithm, accumulating `log2(current position pool)` per position
///   (injecting digits/symbols adds no entropy, conservatively ignored).
/// - Word passphrase mode: `log2(7772) x word_count` (EFF large wordlist size).
pub(crate) fn estimate_generator_entropy(
    options: &persona_core::password::PasswordGeneratorOptions,
) -> (f64, usize) {
    if let Some(word_count) = options.words {
        // Words mode: EFF large wordlist = 7772 words
        let pool = 7772;
        ((pool as f64).log2() * word_count as f64, pool)
    } else if options.pronounceable {
        // Consonant pool 21, vowel pool 5; with both cases on, each doubles
        // (matching the core constants)
        let letter_sets = options.include_lowercase as usize + options.include_uppercase as usize;
        let consonants = 21 * letter_sets;
        let vowels = 5 * letter_sets;
        if consonants + vowels == 0 {
            return (0.0, 0);
        }
        let mut bits = 0.0;
        let mut max_pool = 0;
        let mut use_consonant = true;
        for _ in 0..options.length {
            let pool = if use_consonant && consonants > 0 {
                consonants
            } else if vowels > 0 {
                vowels
            } else {
                consonants
            };
            bits += (pool as f64).log2();
            max_pool = max_pool.max(pool);
            use_consonant = !use_consonant;
        }
        (bits, max_pool)
    } else {
        let mut pool = 0;
        if options.include_lowercase {
            pool += 26;
        }
        if options.include_uppercase {
            pool += 26;
        }
        if options.include_numbers {
            pool += 10;
        }
        if options.include_symbols {
            pool += 24;
        }
        if pool == 0 {
            return (0.0, 0);
        }
        ((pool as f64).log2() * options.length as f64, pool)
    }
}

/// Get service statistics
#[command]
pub async fn get_statistics(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_statistics().await {
            Ok(stats) => {
                let json_stats = serde_json::json!({
                    "total_identities": stats.total_identities,
                    "total_credentials": stats.total_credentials,
                    "active_credentials": stats.active_credentials,
                    "favorite_credentials": stats.favorite_credentials,
                    "credential_types": stats.credential_types,
                    "security_levels": stats.security_levels,
                });
                Ok(ApiResponse::success(json_stats))
            }
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to get statistics: {}",
                e
            ))),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Toggle credential favorite status
#[command(rename_all = "snake_case")]
pub async fn toggle_credential_favorite(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.get_credential(&uuid).await {
                Ok(Some(mut credential)) => {
                    credential.is_favorite = !credential.is_favorite;
                    match service.update_credential(&credential).await {
                        Ok(updated_credential) => {
                            Ok(ApiResponse::success(updated_credential.into()))
                        }
                        Err(e) => Ok(ApiResponse::error(format!(
                            "Failed to update credential: {}",
                            e
                        ))),
                    }
                }
                Ok(None) => Ok(ApiResponse::error("Credential not found".to_string())),
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to get credential: {}",
                    e
                ))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Fetch the favicon for a credential's site on demand and cache it (privacy
/// red line: this is the only outbound entry point, triggered by the detail
/// panel's "Fetch icon" button; with the flag off the backend refuses as
/// the fallback).
#[command(rename_all = "snake_case")]
pub async fn fetch_credential_favicon(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableFavicon>, String> {
    // Check order follows set_feature_flags: service status first (so the
    // error semantics win), the flag gate second (the IO of opening a new DB
    // connection is not done while holding the service lock)
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(db_path) => db_path,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    };
    if !favicon_flag_enabled(&db_path).await {
        return Ok(ApiResponse::error(
            "Favicon fetching is disabled in settings".to_string(),
        ));
    }

    let service_guard = state.service.lock().await;
    let service = match service_guard.as_ref() {
        Some(service) => service,
        None => return Ok(ApiResponse::error("Service not initialized".to_string())),
    };
    if !service.is_unlocked() {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let uuid = match Uuid::from_str(&credential_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };

    let fetcher = match persona_core::favicon::FaviconFetcher::new() {
        Ok(fetcher) => fetcher,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Failed to fetch favicon: {}",
                e
            )))
        }
    };

    match service.fetch_favicon_for_credential(&uuid, &fetcher).await {
        Ok(entry) => Ok(ApiResponse::success(entry.into())),
        Err(e) => Ok(ApiResponse::error(format!(
            "Failed to fetch favicon: {}",
            e
        ))),
    }
}

/// Read the cached favicons in bulk (purely local reads, never outbound).
///
/// With the flag off / uninitialized / locked, always silently return an
/// empty array — the bulk read is a background optimization path for list
/// rendering, so missing entries just fall back to a static icon and an
/// error would be meaningless.
#[command]
pub async fn get_favicons(
    hosts: Vec<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableFavicon>>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::success(Vec::new())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::success(Vec::new()));
    }

    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(db_path) => db_path,
            None => return Ok(ApiResponse::success(Vec::new())),
        }
    };
    if !favicon_flag_enabled(&db_path).await {
        return Ok(ApiResponse::success(Vec::new()));
    }

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_cached_favicons(&hosts).await {
            Ok(entries) => Ok(ApiResponse::success(
                entries.into_iter().map(Into::into).collect(),
            )),
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to load favicons: {}",
                e
            ))),
        },
        None => Ok(ApiResponse::success(Vec::new())),
    }
}

/// Delete a credential
#[command(rename_all = "snake_case")]
pub async fn delete_credential(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.delete_credential(&uuid).await {
                Ok(deleted) => Ok(ApiResponse::success(deleted)),
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to delete credential: {}",
                    e
                ))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}
