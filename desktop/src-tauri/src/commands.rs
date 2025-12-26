use crate::types::*;
use persona_core::*;
use persona_core::models::CredentialType;
use persona_core::models::wallet::CryptoWallet;
use persona_core::models::wallet::BlockchainNetwork;
use persona_core::storage::{CryptoWalletRepository, Database};
use tauri::{command, State};
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use std::str::FromStr;
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;
use std::sync::Arc;
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Initialize the Persona service with master password
#[command]
pub async fn init_service(
    request: InitRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = request.db_path.unwrap_or_else(|| {
        let app_data_dir = dirs::data_dir()
            .unwrap_or_else(|| std::env::current_dir().unwrap())
            .join("persona");
        std::fs::create_dir_all(&app_data_dir).ok();
        app_data_dir.join("persona.db").to_string_lossy().to_string()
    });

    // Store db_path
    {
        let mut db_path_guard = state.db_path.lock().await;
        *db_path_guard = Some(db_path.clone());
    }

    match Database::from_file(&db_path).await {
        Ok(db) => {
            if let Err(e) = db.migrate().await {
                return Ok(ApiResponse::error(format!("Database migration failed: {}", e)));
            }

            match PersonaService::new(db).await {
                Ok(mut service) => {
                    // Check if this is first-time setup or existing user
                    let is_first_time = !service.has_users().await.unwrap_or(false);

                    if is_first_time {
                        // First-time setup: initialize user with master password
                        match service.initialize_user(&request.master_password).await {
                            Ok(_user_id) => {
                                let mut service_guard = state.service.lock().await;
                                *service_guard = Some(service);
                                Ok(ApiResponse::success(true))
                            }
                            Err(e) => Ok(ApiResponse::error(format!("Failed to initialize user: {}", e))),
                        }
                    } else {
                        // Existing user: authenticate with stored credentials
                        match service.authenticate_user(&request.master_password).await {
                            Ok(auth_result) => {
                                match auth_result {
                                    persona_core::AuthResult::Success => {
                                        let mut service_guard = state.service.lock().await;
                                        *service_guard = Some(service);
                                        Ok(ApiResponse::success(true))
                                    }
                                    persona_core::AuthResult::InvalidCredentials => {
                                        Ok(ApiResponse::error("Invalid master password".to_string()))
                                    }
                                    persona_core::AuthResult::AccountLocked => {
                                        Ok(ApiResponse::error("Account is locked due to too many failed attempts".to_string()))
                                    }
                                    persona_core::AuthResult::PasswordChangeRequired => {
                                        Ok(ApiResponse::error("Password change required".to_string()))
                                    }
                                    _ => {
                                        Ok(ApiResponse::error("Authentication failed".to_string()))
                                    }
                                }
                            }
                            Err(e) => Ok(ApiResponse::error(format!("Authentication error: {}", e))),
                        }
                    }
                }
                Err(e) => Ok(ApiResponse::error(format!("Failed to create service: {}", e))),
            }
        }
        Err(e) => Ok(ApiResponse::error(format!("Database connection failed: {}", e))),
    }
}

/// Lock the service
#[command]
pub async fn lock_service(state: State<'_, AppState>) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    if let Some(service) = service_guard.as_mut() {
        service.lock();
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error("Service not initialized".to_string()))
    }
}

/// Check if service is unlocked
#[command]
pub async fn is_service_unlocked(state: State<'_, AppState>) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => Ok(ApiResponse::success(service.is_unlocked())),
        None => Ok(ApiResponse::success(false)),
    }
}

/// Create a new identity
#[command]
pub async fn create_identity(
    request: CreateIdentityRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableIdentity>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            let identity_type = match request.identity_type.as_str() {
                "Personal" => IdentityType::Personal,
                "Work" => IdentityType::Work,
                "Social" => IdentityType::Social,
                "Financial" => IdentityType::Financial,
                "Gaming" => IdentityType::Gaming,
                custom => IdentityType::Custom(custom.to_string()),
            };

            match service.create_identity(request.name, identity_type).await {
                Ok(mut identity) => {
                    if let Some(desc) = request.description {
                        identity.description = Some(desc);
                    }
                    if let Some(email) = request.email {
                        identity.email = Some(email);
                    }
                    if let Some(phone) = request.phone {
                        identity.phone = Some(phone);
                    }

                    match service.update_identity(&identity).await {
                        Ok(updated_identity) => Ok(ApiResponse::success(updated_identity.into())),
                        Err(e) => Ok(ApiResponse::error(format!("Failed to update identity: {}", e))),
                    }
                }
                Err(e) => Ok(ApiResponse::error(format!("Failed to create identity: {}", e))),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get all identities
#[command]
pub async fn get_identities(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableIdentity>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match service.get_identities().await {
                Ok(identities) => {
                    let serializable: Vec<SerializableIdentity> = identities.into_iter().map(|id| id.into()).collect();
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => Ok(ApiResponse::error(format!("Failed to get identities: {}", e))),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get identity by ID
#[command]
pub async fn get_identity(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<SerializableIdentity>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match Uuid::from_str(&id) {
                Ok(uuid) => {
                    match service.get_identity(&uuid).await {
                        Ok(identity) => Ok(ApiResponse::success(identity.map(|id| id.into()))),
                        Err(e) => Ok(ApiResponse::error(format!("Failed to get identity: {}", e))),
                    }
                }
                Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Update an existing identity
#[command]
pub async fn update_identity(
    request: UpdateIdentityRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableIdentity>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            let uuid = match Uuid::from_str(&request.id) {
                Ok(uuid) => uuid,
                Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
            };

            match service.get_identity(&uuid).await {
                Ok(Some(mut identity)) => {
                    let identity_type = match request.identity_type.as_str() {
                        "Personal" => IdentityType::Personal,
                        "Work" => IdentityType::Work,
                        "Social" => IdentityType::Social,
                        "Financial" => IdentityType::Financial,
                        "Gaming" => IdentityType::Gaming,
                        custom => IdentityType::Custom(custom.to_string()),
                    };

                    identity.name = request.name.trim().to_string();
                    identity.identity_type = identity_type;
                    identity.description = request.description.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() { None } else { Some(trimmed) }
                    });
                    identity.email = request.email.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() { None } else { Some(trimmed) }
                    });
                    identity.phone = request.phone.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() { None } else { Some(trimmed) }
                    });
                    if let Some(tags) = request.tags {
                        identity.tags = tags
                            .into_iter()
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect();
                    }

                    match service.update_identity(&identity).await {
                        Ok(updated_identity) => Ok(ApiResponse::success(updated_identity.into())),
                        Err(e) => Ok(ApiResponse::error(format!("Failed to update identity: {}", e))),
                    }
                }
                Ok(None) => Ok(ApiResponse::error("Identity not found".to_string())),
                Err(e) => Ok(ApiResponse::error(format!("Failed to get identity: {}", e))),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete an identity
#[command]
pub async fn delete_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&identity_id) {
            Ok(uuid) => match service.delete_identity(&uuid).await {
                Ok(ok) => Ok(ApiResponse::success(ok)),
                Err(e) => Ok(ApiResponse::error(format!("Failed to delete identity: {}", e))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
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
        Some(service) => {
            match Uuid::from_str(&request.identity_id) {
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

                    match service.create_credential(
                        identity_uuid,
                        request.name,
                        credential_type,
                        security_level,
                        &credential_data,
                    ).await {
                        Ok(mut credential) => {
                            if let Some(url) = request.url {
                                credential.url = Some(url);
                            }
                            if let Some(username) = request.username {
                                credential.username = Some(username);
                            }
                            if let Some(notes) = request.notes {
                                let trimmed = notes.trim().to_string();
                                credential.notes = if trimmed.is_empty() { None } else { Some(trimmed) };
                            }
                            if let Some(tags) = request.tags {
                                credential.tags = tags
                                    .into_iter()
                                    .map(|t| t.trim().to_string())
                                    .filter(|t| !t.is_empty())
                                    .collect();
                            }

                            match service.update_credential(&credential).await {
                                Ok(updated_credential) => Ok(ApiResponse::success(updated_credential.into())),
                                Err(e) => Ok(ApiResponse::error(format!("Failed to update credential: {}", e))),
                            }
                        }
                        Err(e) => Ok(ApiResponse::error(format!("Failed to create credential: {}", e))),
                    }
                }
                Err(_) => Ok(ApiResponse::error("Invalid identity UUID format".to_string())),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get credentials for an identity
#[command]
pub async fn get_credentials_for_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableCredential>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match Uuid::from_str(&identity_id) {
                Ok(uuid) => {
                    match service.get_credentials_for_identity(&uuid).await {
                        Ok(credentials) => {
                            let serializable: Vec<SerializableCredential> = credentials.into_iter().map(|cred| cred.into()).collect();
                            Ok(ApiResponse::success(serializable))
                        }
                        Err(e) => Ok(ApiResponse::error(format!("Failed to get credentials: {}", e))),
                    }
                }
                Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get credential data (decrypted)
#[command]
pub async fn get_credential_data(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<SerializableCredentialData>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match Uuid::from_str(&credential_id) {
                Ok(uuid) => {
                    match service.get_credential_data(&uuid).await {
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
                                },
                                data: credential_data_to_json(&data),
                            });
                            Ok(ApiResponse::success(serializable))
                        }
                        Err(e) => Ok(ApiResponse::error(format!("Failed to get credential data: {}", e))),
                    }
                }
                Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Generate a TOTP code for a TwoFactor credential (without exposing the secret)
#[command]
pub async fn get_totp_code(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<TotpCodeResponse>, String> {
    let service_guard = state.service.lock().await;
    let service = service_guard
        .as_ref()
        .ok_or_else(|| "Service not initialized".to_string())?;

    let uuid = Uuid::from_str(&credential_id).map_err(|_| "Invalid UUID format".to_string())?;
    let credential_data = service
        .get_credential_data(&uuid)
        .await
        .map_err(|e| format!("Failed to get credential data: {}", e))?;

    let data = credential_data.ok_or_else(|| "Credential not found".to_string())?;
    match data {
        CredentialData::TwoFactor(tf) => {
            let secret_bytes = decode_totp_secret(&tf.secret_key)?;
            let now = chrono::Utc::now();
            let period = tf.period.max(1) as u64;
            let timestamp = now.timestamp().max(0) as u64;
            let counter = timestamp / period;
            let digits = tf.digits.clamp(4, 10) as u32;
            let code_num = hotp(&secret_bytes, counter, &tf.algorithm)?;
            let modulo = 10_u32.pow(digits);
            let value = code_num % modulo;
            let code = format!("{:0width$}", value, width = digits as usize);
            let remaining = (period - (timestamp % period)) as u32;

            Ok(ApiResponse::success(TotpCodeResponse {
                code,
                remaining_seconds: remaining,
                period: tf.period.max(1),
                digits: tf.digits.clamp(4, 10),
                algorithm: tf.algorithm,
                issuer: tf.issuer,
                account_name: tf.account_name,
            }))
        }
        _ => Ok(ApiResponse::error("Credential is not a TwoFactor entry".to_string())),
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
        Some(service) => {
            match service.search_credentials(&query).await {
                Ok(credentials) => {
                    let serializable: Vec<SerializableCredential> = credentials.into_iter().map(|cred| cred.into()).collect();
                    Ok(ApiResponse::success(serializable))
                }
                Err(e) => Ok(ApiResponse::error(format!("Failed to search credentials: {}", e))),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

fn hotp(secret: &[u8], counter: u64, algorithm: &str) -> std::result::Result<u32, String> {
    let msg = counter.to_be_bytes();
    let algo = algorithm.to_ascii_uppercase();

    let hash = if algo == "SHA256" {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| "Invalid secret".to_string())?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else if algo == "SHA512" {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(secret).map_err(|_| "Invalid secret".to_string())?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else {
        type HmacSha1 = Hmac<Sha1>;
        let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| "Invalid secret".to_string())?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    };

    let offset = (hash.last().copied().unwrap_or(0) & 0x0f) as usize;
    if offset + 4 > hash.len() {
        return Err("Invalid HMAC output".to_string());
    }
    let slice = &hash[offset..offset + 4];
    let binary = ((slice[0] as u32 & 0x7f) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | slice[3] as u32;
    Ok(binary)
}

fn decode_totp_secret(secret: &str) -> std::result::Result<Vec<u8>, String> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect::<String>()
        .trim_matches('=')
        .to_string();

    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|e| format!("Invalid base32 secret: {}", e))
}

/// Generate password
#[command]
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

/// Get service statistics
#[command]
pub async fn get_statistics(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match service.get_statistics().await {
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
                Err(e) => Ok(ApiResponse::error(format!("Failed to get statistics: {}", e))),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Toggle credential favorite status
#[command]
pub async fn toggle_credential_favorite(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match Uuid::from_str(&credential_id) {
                Ok(uuid) => {
                    match service.get_credential(&uuid).await {
                        Ok(Some(mut credential)) => {
                            credential.is_favorite = !credential.is_favorite;
                            match service.update_credential(&credential).await {
                                Ok(updated_credential) => Ok(ApiResponse::success(updated_credential.into())),
                                Err(e) => Ok(ApiResponse::error(format!("Failed to update credential: {}", e))),
                            }
                        }
                        Ok(None) => Ok(ApiResponse::error("Credential not found".to_string())),
                        Err(e) => Ok(ApiResponse::error(format!("Failed to get credential: {}", e))),
                    }
                }
                Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete a credential
#[command]
pub async fn delete_credential(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match Uuid::from_str(&credential_id) {
                Ok(uuid) => {
                    match service.delete_credential(&uuid).await {
                        Ok(deleted) => Ok(ApiResponse::success(deleted)),
                        Err(e) => Ok(ApiResponse::error(format!("Failed to delete credential: {}", e))),
                    }
                }
                Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get SSH agent runtime status
#[command]
pub async fn get_ssh_agent_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SshAgentStatus>, String> {
    let running = state
        .agent_handle
        .lock()
        .await
        .as_ref()
        .map(|handle| !handle.is_finished())
        .unwrap_or(false);
    let status = read_agent_status(running);
    Ok(ApiResponse::success(status))
}

/// Start the embedded SSH agent
#[command]
pub async fn start_ssh_agent(
    request: StartAgentRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SshAgentStatus>, String> {
    let db_path = {
        let guard = state.db_path.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let already_running = state
        .agent_handle
        .lock()
        .await
        .as_ref()
        .map(|handle| !handle.is_finished())
        .unwrap_or(false);
    if already_running {
        return get_ssh_agent_status(state).await;
    }

    let mut handle_guard = state.agent_handle.lock().await;
    let password = request.master_password.clone();
    let db_path_clone = db_path.clone();
    let state_dir = agent_state_dir().to_string_lossy().to_string();
    let handle = tokio::spawn(async move {
        if let Some(pass) = password {
            std::env::set_var("PERSONA_MASTER_PASSWORD", pass);
        } else {
            std::env::remove_var("PERSONA_MASTER_PASSWORD");
        }
        std::env::set_var("PERSONA_DB_PATH", &db_path_clone);
        std::env::set_var("PERSONA_AGENT_STATE_DIR", &state_dir);
        if let Err(err) = persona_ssh_agent::run_agent().await {
            eprintln!("SSH agent exited: {}", err);
        }
        let _ = std::env::remove_var("PERSONA_AGENT_STATE_DIR");
    });
    *handle_guard = Some(handle);
    drop(handle_guard);

    sleep(Duration::from_millis(400)).await;
    let status = read_agent_status(true);
    Ok(ApiResponse::success(status))
}

/// Stop the embedded SSH agent
#[command]
pub async fn stop_ssh_agent(state: State<'_, AppState>) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(handle) = state.agent_handle.lock().await.take() {
        handle.abort();
    }
    cleanup_agent_state_files();
    Ok(ApiResponse::success(true))
}

/// List stored SSH key credentials
#[command]
pub async fn get_ssh_keys(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SshKeySummary>>, String> {
    let identities = {
        let service_guard = state.service.lock().await;
        let service = match service_guard.as_ref() {
            Some(service) => service,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        };
        service
            .get_identities()
            .await
            .map_err(|e| format!("Failed to load identities: {}", e))?
    };
    let mut identity_map: HashMap<Uuid, String> = HashMap::new();
    for identity in &identities {
        identity_map.insert(identity.id, identity.name.clone());
    }

    let mut summaries = Vec::new();
    for identity in identities {
        let creds = {
            let service_guard = state.service.lock().await;
            let service = match service_guard.as_ref() {
                Some(service) => service,
                None => return Ok(ApiResponse::error("Service not initialized".to_string())),
            };
            service
                .get_credentials_for_identity(&identity.id)
                .await
                .map_err(|e| format!("Failed to load credentials: {}", e))?
        };
        for credential in creds {
            if credential.credential_type == CredentialType::SshKey {
                summaries.push(SshKeySummary {
                    id: credential.id.to_string(),
                    identity_id: credential.identity_id.to_string(),
                    identity_name: identity_map
                        .get(&credential.identity_id)
                        .cloned()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    name: credential.name,
                    tags: credential.tags,
                    created_at: credential.created_at.to_rfc3339(),
                    updated_at: credential.updated_at.to_rfc3339(),
                });
            }
        }
    }

    Ok(ApiResponse::success(summaries))
}

#[command]
pub async fn wallet_list(
    identity_id: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletListResponse>, String> {
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
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallets = match identity_id {
        Some(identity_id) => {
            let uuid = Uuid::from_str(&identity_id)
                .map_err(|_| "Invalid identity UUID format".to_string())?;
            repo.find_by_identity(&uuid).await.map_err(|e| e.to_string())?
        }
        None => repo.find_all().await.map_err(|e| e.to_string())?,
    };

    let serializable = wallets
        .into_iter()
        .map(|wallet| SerializableWallet {
            id: wallet.id.to_string(),
            name: wallet.name,
            network: wallet.network.to_string(),
            wallet_type: format!("{:?}", wallet.wallet_type),
            balance: "-".to_string(),
            address_count: wallet.addresses.len(),
            watch_only: wallet.watch_only,
            security_level: wallet.security_level.to_string(),
            created_at: wallet.created_at.to_rfc3339(),
            updated_at: wallet.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(ApiResponse::success(WalletListResponse { wallets: serializable }))
}

#[command]
pub async fn wallet_list_addresses(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletAddressesResponse>, String> {
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
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let uuid = Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())?;
    let wallet: CryptoWallet = match repo.find_by_id(&uuid).await.map_err(|e| e.to_string())? {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let addresses = wallet
        .addresses
        .into_iter()
        .map(|addr| SerializableWalletAddress {
            address: addr.address,
            address_type: match addr.address_type {
                persona_core::models::wallet::AddressType::P2PKH => "P2PKH".to_string(),
                persona_core::models::wallet::AddressType::P2SH => "P2SH".to_string(),
                persona_core::models::wallet::AddressType::P2WPKH => "P2WPKH".to_string(),
                persona_core::models::wallet::AddressType::P2TR => "P2TR".to_string(),
                persona_core::models::wallet::AddressType::Ethereum => "ETH".to_string(),
                persona_core::models::wallet::AddressType::Solana => "SOL".to_string(),
                persona_core::models::wallet::AddressType::Custom(name) => name,
            },
            index: addr.index,
            used: addr.used,
            balance: addr.balance.unwrap_or_else(|| "-".to_string()),
            derivation_path: addr.derivation_path,
        })
        .collect();

    Ok(ApiResponse::success(WalletAddressesResponse { addresses }))
}

#[command]
pub async fn wallet_generate(
    identity_id: String,
    request: WalletGenerateRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletGenerateResponse>, String> {
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

    let identity_id = Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())?;
    let network = parse_network(&request.network)?;
    let address_count = request.address_count.unwrap_or(5);

    if request.password.len() < 8 {
        return Ok(ApiResponse::error(
            "Wallet password must be at least 8 characters".to_string(),
        ));
    }

    let mnemonic = persona_core::crypto::wallet_crypto::SecureMnemonic::generate(
        persona_core::crypto::wallet_crypto::MnemonicWordCount::Words24,
    )
    .map_err(|e| e.to_string())?;
    let mnemonic_phrase = mnemonic.phrase();

    let derivation_path = match request.wallet_type.to_lowercase().as_str() {
        "hd" | "hierarchical" | "hierarchical_deterministic" => None,
        other => {
            return Ok(ApiResponse::error(format!(
                "Unsupported wallet_type '{}'. Use 'hd'.",
                other
            )))
        }
    };

    let wallet = persona_core::crypto::wallet_import_export::import_from_mnemonic(
        identity_id,
        request.name.clone(),
        &mnemonic_phrase,
        "",
        network,
        derivation_path,
        address_count,
        &request.password,
    )
    .map_err(|e| e.to_string())?;

    let db_path = {
        let guard = state.db_path.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let created = repo.create(&wallet).await.map_err(|e| e.to_string())?;
    let first_address = created
        .addresses
        .first()
        .map(|addr| addr.address.clone())
        .unwrap_or_else(|| "-".to_string());

    Ok(ApiResponse::success(WalletGenerateResponse {
        wallet_id: created.id.to_string(),
        name: created.name,
        network: created.network.to_string(),
        mnemonic: mnemonic_phrase,
        first_address,
    }))
}

#[command]
pub async fn wallet_import(
    identity_id: String,
    request: WalletImportRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableWallet>, String> {
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

    let identity_id = Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())?;
    let network = parse_network(&request.network)?;

    if request.password.len() < 8 {
        return Ok(ApiResponse::error(
            "Wallet password must be at least 8 characters".to_string(),
        ));
    }

    let address_count = request.address_count.unwrap_or(5);
    let wallet = match request.import_type.to_lowercase().as_str() {
        "mnemonic" | "phrase" | "seed" => persona_core::crypto::wallet_import_export::import_from_mnemonic(
            identity_id,
            request.name.clone(),
            request.data.trim(),
            "",
            network,
            None,
            address_count,
            &request.password,
        )
        .map_err(|e| e.to_string())?,
        "private_key" | "privatekey" | "key" => persona_core::crypto::wallet_import_export::import_from_private_key(
            identity_id,
            request.name.clone(),
            request.data.trim(),
            network,
            &request.password,
        )
        .map_err(|e| e.to_string())?,
        other => {
            return Ok(ApiResponse::error(format!(
                "Unsupported import_type '{}'. Use 'mnemonic' or 'private_key'.",
                other
            )))
        }
    };

    let db_path = {
        let guard = state.db_path.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let created = repo.create(&wallet).await.map_err(|e| e.to_string())?;
    Ok(ApiResponse::success(SerializableWallet {
        id: created.id.to_string(),
        name: created.name,
        network: created.network.to_string(),
        wallet_type: format!("{:?}", created.wallet_type),
        balance: "-".to_string(),
        address_count: created.addresses.len(),
        watch_only: created.watch_only,
        security_level: created.security_level.to_string(),
        created_at: created.created_at.to_rfc3339(),
        updated_at: created.updated_at.to_rfc3339(),
    }))
}

#[command]
pub async fn wallet_add_address(
    wallet_id: String,
    password: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableWalletAddress>, String> {
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

    let wallet_id = Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())?;
    if password.len() < 8 {
        return Ok(ApiResponse::error(
            "Wallet password must be at least 8 characters".to_string(),
        ));
    }

    let db_path = {
        let guard = state.db_path.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet: CryptoWallet = match repo.find_by_id(&wallet_id).await.map_err(|e| e.to_string())? {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    if wallet.watch_only {
        return Ok(ApiResponse::error(
            "Address generation for watch-only wallets is not implemented yet.".to_string(),
        ));
    }

    if !matches!(
        wallet.wallet_type,
        persona_core::models::wallet::WalletType::HierarchicalDeterministic { .. }
    ) {
        return Ok(ApiResponse::error(
            "Address generation is only supported for HD wallets.".to_string(),
        ));
    }

    let derivation_path =
        wallet
            .derivation_path
            .clone()
            .unwrap_or_else(|| CryptoWallet::recommended_derivation_path(&wallet.network, 0));

    let next_index = wallet
        .addresses
        .iter()
        .map(|addr| addr.index)
        .max()
        .map(|v| v + 1)
        .unwrap_or(0);

    let encrypted_key: persona_core::crypto::wallet_encryption::EncryptedWalletKey =
        serde_json::from_slice(&wallet.encrypted_private_key)
            .map_err(|e| format!("Invalid wallet key encoding: {}", e))?;
    let master_key = persona_core::crypto::wallet_encryption::decrypt_master_key(&encrypted_key, &password)
        .map_err(|e| e.to_string())?;

    let parent = master_key
        .derive_path(&derivation_path)
        .map_err(|e| e.to_string())?;
    let child = parent
        .derive_child(next_index, false)
        .map_err(|e| e.to_string())?;

    let (address_string, address_type) = match wallet.network {
        BlockchainNetwork::Bitcoin => (
            persona_core::crypto::address_generator::generate_bitcoin_address(
                &child,
                persona_core::crypto::address_generator::BitcoinAddressType::P2WPKH,
                false,
            )
            .map_err(|e| e.to_string())?,
            persona_core::models::wallet::AddressType::P2WPKH,
        ),
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => (
            persona_core::crypto::address_generator::generate_ethereum_address_checksummed(&child)
                .map_err(|e| e.to_string())?,
            persona_core::models::wallet::AddressType::Ethereum,
        ),
        other => {
            return Ok(ApiResponse::error(format!(
                "Address generation not implemented for {}",
                other
            )))
        }
    };

    let wallet_address = persona_core::models::wallet::WalletAddress {
        address: address_string,
        address_type,
        derivation_path: Some(format!("{}/{}", derivation_path, next_index)),
        index: next_index,
        used: false,
        balance: None,
        last_activity: None,
        metadata: HashMap::new(),
        created_at: chrono::Utc::now(),
    };

    repo.add_address(&wallet_id, &wallet_address)
        .await
        .map_err(|e| e.to_string())?;
    repo.touch(&wallet_id).await.map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(serialize_wallet_address(wallet_address)))
}

#[command]
pub async fn wallet_export(
    request: WalletExportRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
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
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet_id =
        Uuid::from_str(&request.wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())?;
    let wallet = match repo
        .find_by_id(&wallet_id)
        .await
        .map_err(|e| e.to_string())?
    {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let format = persona_core::crypto::wallet_import_export::parse_export_format(&request.format)
        .map_err(|e| e.to_string())?;

    let exported = match format {
        persona_core::crypto::wallet_import_export::ExportFormat::Json => {
            persona_core::crypto::wallet_import_export::export_to_json(
                &wallet,
                request.include_private,
                request.password.as_deref(),
            )
            .map_err(|e| e.to_string())?
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Mnemonic => {
            persona_core::crypto::wallet_import_export::export_mnemonic(
                &wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for mnemonic export".to_string())?,
            )
            .map_err(|e| e.to_string())?
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Xpub => {
            persona_core::crypto::wallet_import_export::export_xpub(&wallet)
                .map_err(|e| e.to_string())?
        }
        persona_core::crypto::wallet_import_export::ExportFormat::PrivateKey => {
            persona_core::crypto::wallet_import_export::export_private_key(
                &wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for private key export".to_string())?,
            )
            .map_err(|e| e.to_string())?
        }
    };

    Ok(ApiResponse::success(exported))
}

fn parse_network(network_str: &str) -> std::result::Result<BlockchainNetwork, String> {
    match network_str.to_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(BlockchainNetwork::Bitcoin),
        "ethereum" | "eth" => Ok(BlockchainNetwork::Ethereum),
        "solana" | "sol" => Ok(BlockchainNetwork::Solana),
        "bitcoin-cash" | "bitcoin cash" | "bitcoincash" | "bch" => Ok(BlockchainNetwork::BitcoinCash),
        "litecoin" | "ltc" => Ok(BlockchainNetwork::Litecoin),
        "dogecoin" | "doge" => Ok(BlockchainNetwork::Dogecoin),
        "polygon" | "matic" => Ok(BlockchainNetwork::Polygon),
        "arbitrum" | "arb" => Ok(BlockchainNetwork::Arbitrum),
        "optimism" | "op" => Ok(BlockchainNetwork::Optimism),
        "binance" | "bsc" | "bnb" | "binance smart chain" => Ok(BlockchainNetwork::BinanceSmartChain),
        other => Ok(BlockchainNetwork::Custom(other.to_string())),
    }
}

fn serialize_wallet_address(addr: persona_core::models::wallet::WalletAddress) -> SerializableWalletAddress {
    SerializableWalletAddress {
        address: addr.address,
        address_type: match addr.address_type {
            persona_core::models::wallet::AddressType::P2PKH => "P2PKH".to_string(),
            persona_core::models::wallet::AddressType::P2SH => "P2SH".to_string(),
            persona_core::models::wallet::AddressType::P2WPKH => "P2WPKH".to_string(),
            persona_core::models::wallet::AddressType::P2TR => "P2TR".to_string(),
            persona_core::models::wallet::AddressType::Ethereum => "ETH".to_string(),
            persona_core::models::wallet::AddressType::Solana => "SOL".to_string(),
            persona_core::models::wallet::AddressType::Custom(name) => name,
        },
        index: addr.index,
        used: addr.used,
        balance: addr.balance.unwrap_or_else(|| "-".to_string()),
        derivation_path: addr.derivation_path,
    }
}

fn agent_state_dir() -> PathBuf {
    std::env::var("PERSONA_AGENT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
        })
}

fn cleanup_agent_state_files() {
    let dir = agent_state_dir();
    for name in &["ssh-agent.sock", "ssh-agent.pid"] {
        let path = dir.join(name);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
}

fn read_agent_status(running_hint: bool) -> SshAgentStatus {
    let dir = agent_state_dir();
    let sock_path = dir.join("ssh-agent.sock");
    let pid_path = dir.join("ssh-agent.pid");
    let socket_value = if sock_path.exists() {
        fs::read_to_string(&sock_path).ok().map(|s| s.trim().to_string())
    } else {
        None
    };
    let pid_value = if pid_path.exists() {
        fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    } else {
        None
    };
    let key_count = socket_value
        .as_deref()
        .and_then(|sock| query_agent_key_count(sock).ok());

    SshAgentStatus {
        running: running_hint || socket_value.is_some() || pid_value.is_some(),
        socket_path: socket_value,
        pid: pid_value,
        key_count,
        state_dir: dir.to_string_lossy().to_string(),
    }
}

#[cfg(unix)]
fn query_agent_key_count(sock_path: &str) -> std::result::Result<usize, String> {
    use byteorder::{BigEndian, ByteOrder};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("Failed to connect to agent: {}", e))?;
    // request identities: len=1 payload 11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11;
    stream.write_all(&pkt).map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(|e| e.to_string())?;
    if resp.is_empty() || resp[0] != 12 {
        return Err("Unexpected agent response".to_string());
    }
    if resp.len() < 5 {
        return Err("Malformed agent response".to_string());
    }
    let count = BigEndian::read_u32(&resp[1..5]) as usize;
    Ok(count)
}

#[cfg(not(unix))]
fn query_agent_key_count(_sock_path: &str) -> std::result::Result<usize, String> {
    Err("Agent key count not supported on this platform".to_string())
}
