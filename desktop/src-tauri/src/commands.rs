use crate::types::*;
use persona_core::*;
use tauri::{command, State};
use uuid::Uuid;
use std::str::FromStr;

/// Initialize the Persona service with master password
#[command]
pub async fn init_service(
    request: InitRequest,
    state: State<'_, AppState>,
) -> Result<ApiResponse<bool>, String> {
    let db_path = request.db_path.unwrap_or_else(|| {
        let app_data_dir = dirs::data_dir()
            .unwrap_or_else(|| std::env::current_dir().unwrap())
            .join("persona");
        std::fs::create_dir_all(&app_data_dir).ok();
        app_data_dir.join("persona.db").to_string_lossy().to_string()
    });

    // Store db_path
    {
        let mut db_path_guard = state.db_path.lock().unwrap();
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
                                let mut service_guard = state.service.lock().unwrap();
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
                                        let mut service_guard = state.service.lock().unwrap();
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
pub async fn lock_service(state: State<'_, AppState>) -> Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().unwrap();
    if let Some(service) = service_guard.as_mut() {
        service.lock();
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error("Service not initialized".to_string()))
    }
}

/// Check if service is unlocked
#[command]
pub async fn is_service_unlocked(state: State<'_, AppState>) -> Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<SerializableIdentity>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<Vec<SerializableIdentity>>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<Option<SerializableIdentity>>, String> {
    let service_guard = state.service.lock().unwrap();
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

/// Create a new credential
#[command]
pub async fn create_credential(
    request: CreateCredentialRequest,
    state: State<'_, AppState>,
) -> Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<Vec<SerializableCredential>>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<Option<SerializableCredentialData>>, String> {
    let service_guard = state.service.lock().unwrap();
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
                                    CredentialData::Raw(_) => "Raw".to_string(),
                                    _ => "Unknown".to_string(),
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

/// Search credentials
#[command]
pub async fn search_credentials(
    query: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<Vec<SerializableCredential>>, String> {
    let service_guard = state.service.lock().unwrap();
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

/// Generate password
#[command]
pub async fn generate_password(
    length: usize,
    include_symbols: bool,
    state: State<'_, AppState>,
) -> Result<ApiResponse<String>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<serde_json::Value>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<SerializableCredential>, String> {
    let service_guard = state.service.lock().unwrap();
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
) -> Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().unwrap();
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