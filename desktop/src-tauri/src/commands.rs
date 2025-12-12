use crate::types::*;
use persona_core::*;
use persona_core::models::CredentialType;
use tauri::{command, State};
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use std::str::FromStr;
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;

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

/// Get SSH agent runtime status
#[command]
pub async fn get_ssh_agent_status(
    state: State<'_, AppState>,
) -> Result<ApiResponse<SshAgentStatus>, String> {
    let running = {
        let guard = state.agent_handle.lock().unwrap();
        guard
            .as_ref()
            .map(|handle| !handle.is_finished())
            .unwrap_or(false)
    };
    let status = read_agent_status(running);
    Ok(ApiResponse::success(status))
}

/// Start the embedded SSH agent
#[command]
pub async fn start_ssh_agent(
    request: StartAgentRequest,
    state: State<'_, AppState>,
) -> Result<ApiResponse<SshAgentStatus>, String> {
    let db_path = {
        let guard = state.db_path.lock().unwrap();
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    {
        let guard = state.agent_handle.lock().unwrap();
        if let Some(handle) = guard.as_ref() {
            if !handle.is_finished() {
                drop(guard);
                return get_ssh_agent_status(state).await;
            }
        }
    }

    let mut handle_guard = state.agent_handle.lock().unwrap();
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
pub async fn stop_ssh_agent(state: State<'_, AppState>) -> Result<ApiResponse<bool>, String> {
    if let Some(handle) = state.agent_handle.lock().unwrap().take() {
        handle.abort();
    }
    cleanup_agent_state_files();
    Ok(ApiResponse::success(true))
}

/// List stored SSH key credentials
#[command]
pub async fn get_ssh_keys(
    state: State<'_, AppState>,
) -> Result<ApiResponse<Vec<SshKeySummary>>, String> {
    let service_guard = state.service.lock().unwrap();
    let service = match service_guard.as_ref() {
        Some(service) => service,
        None => return Ok(ApiResponse::error("Service not initialized".to_string())),
    };

    let identities = service
        .get_identities()
        .await
        .map_err(|e| format!("Failed to load identities: {}", e))?;
    let mut identity_map: HashMap<Uuid, String> = HashMap::new();
    for identity in &identities {
        identity_map.insert(identity.id, identity.name.clone());
    }

    let mut summaries = Vec::new();
    for identity in identities {
        let creds = service
            .get_credentials_for_identity(&identity.id)
            .await
            .map_err(|e| format!("Failed to load credentials: {}", e))?;
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
fn query_agent_key_count(sock_path: &str) -> Result<usize, String> {
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
fn query_agent_key_count(_sock_path: &str) -> Result<usize, String> {
    Err("Agent key count not supported on this platform".to_string())
}
