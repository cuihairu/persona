use crate::error::map_persona_error;
use crate::types::*;
use persona_core::models::wallet::BlockchainNetwork;
use persona_core::models::wallet::CryptoWallet;
use persona_core::models::CredentialType;
use persona_core::storage::{CryptoWalletRepository, Database, WorkspaceRepository};
use persona_core::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tauri::{command, Emitter, State};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

fn workspace_path_for_db_path(db_path: &str) -> String {
    Path::new(db_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_string_lossy()
        .to_string()
}

async fn ensure_workspace_for_path(
    db: &Database,
    workspace_path: &str,
) -> std::result::Result<persona_core::models::Workspace, String> {
    let repo = WorkspaceRepository::new(db.clone());

    if let Some(ws) = repo
        .find_by_path(workspace_path)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(ws);
    }

    let mut all = repo.find_all().await.map_err(|e| e.to_string())?;
    if all.len() == 1 {
        let mut ws = all.remove(0);
        ws.path = PathBuf::from(workspace_path);
        ws.touch();
        let updated = repo.update(&ws).await.map_err(|e| e.to_string())?;
        return Ok(updated);
    }

    let name = PathBuf::from(workspace_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Persona".to_string());

    let ws = persona_core::models::Workspace::new(PathBuf::from(workspace_path), name);
    repo.create(&ws).await.map_err(|e| e.to_string())
}

/// 把 PersonaService 的 auto-lock 事件桥接到前端 + 强制落锁闭环。
///
/// - 任何事件都 `emit("persona://auto-lock", …)` 给前端（倒计时横幅/回解锁屏）
/// - `Locked` 事件时在独立任务里直接 `service.lock()` 清掉内存主密钥——
///   不依赖前端存活（AutoLockManager 只锁 session，不清主密钥）
///
/// 回调只注册一次（`AtomicBool` 防重复，多次 init_service 安全）。
async fn register_auto_lock_bridge(state: &State<'_, AppState>, app: &tauri::AppHandle) {
    use std::sync::atomic::Ordering;

    if state.auto_lock_registered.swap(true, Ordering::SeqCst) {
        return;
    }

    let service_arc = Arc::clone(&state.service);
    let app_handle = app.clone();
    let callback = Arc::new(move |event: persona_core::AutoLockEvent| {
        let is_locked = matches!(&event, persona_core::AutoLockEvent::Locked { .. });
        let payload = SerializableAutoLockEvent::from(event);
        if let Err(e) = app_handle.emit("persona://auto-lock", payload) {
            tracing::warn!("failed to emit auto-lock event: {}", e);
        }

        if is_locked {
            let service_arc = Arc::clone(&service_arc);
            tauri::async_runtime::spawn(async move {
                let mut guard = service_arc.lock().await;
                if let Some(service) = guard.as_mut() {
                    service.lock();
                }
            });
        }
    });

    let service_guard = state.service.lock().await;
    if let Some(service) = service_guard.as_ref() {
        service.register_auto_lock_callback(callback).await;
    }
}

/// Initialize the Persona service with master password
#[command]
pub async fn init_service(
    request: InitRequest,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> std::result::Result<ApiResponse<bool>, String> {
    let db_path = request.db_path.unwrap_or_else(|| {
        let app_data_dir = dirs::data_dir()
            .unwrap_or_else(|| std::env::current_dir().unwrap())
            .join("persona");
        std::fs::create_dir_all(&app_data_dir).ok();
        app_data_dir
            .join("persona.db")
            .to_string_lossy()
            .to_string()
    });

    // Store db_path
    {
        let mut db_path_guard = state.db_path.lock().await;
        *db_path_guard = Some(db_path.clone());
    }

    match Database::from_file(&db_path).await {
        Ok(db) => {
            if let Err(e) = db.migrate().await {
                return Ok(ApiResponse::error(format!(
                    "Database migration failed: {}",
                    e
                )));
            }

            let workspace_path = workspace_path_for_db_path(&db_path);
            if let Err(e) = ensure_workspace_for_path(&db, &workspace_path).await {
                return Ok(ApiResponse::error(format!(
                    "Failed to initialize workspace metadata: {}",
                    e
                )));
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
                                register_auto_lock_bridge(&state, &app).await;
                                Ok(ApiResponse::success(true))
                            }
                            Err(e) => Ok(ApiResponse::error(format!(
                                "Failed to initialize user: {}",
                                e
                            ))),
                        }
                    } else {
                        // Existing user: authenticate with stored credentials
                        match service.authenticate_user(&request.master_password).await {
                            Ok(auth_result) => match auth_result {
                                persona_core::AuthResult::Success => {
                                    let mut service_guard = state.service.lock().await;
                                    *service_guard = Some(service);
                                    register_auto_lock_bridge(&state, &app).await;
                                    Ok(ApiResponse::success(true))
                                }
                                persona_core::AuthResult::InvalidCredentials => {
                                    Ok(ApiResponse::error("Invalid master password".to_string()))
                                }
                                persona_core::AuthResult::AccountLocked => Ok(ApiResponse::error(
                                    "Account is locked due to too many failed attempts".to_string(),
                                )),
                                persona_core::AuthResult::PasswordChangeRequired => {
                                    Ok(ApiResponse::error("Password change required".to_string()))
                                }
                                _ => Ok(ApiResponse::error("Authentication failed".to_string())),
                            },
                            Err(e) => {
                                Ok(ApiResponse::error(format!("Authentication error: {}", e)))
                            }
                        }
                    }
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to create service: {}",
                    e
                ))),
            }
        }
        Err(e) => Ok(ApiResponse::error(format!(
            "Database connection failed: {}",
            e
        ))),
    }
}

/// Lock the service
#[command]
pub async fn lock_service(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
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
pub async fn is_service_unlocked(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => Ok(ApiResponse::success(service.is_unlocked())),
        None => Ok(ApiResponse::success(false)),
    }
}

/// Get the active identity ID for this workspace (if any).
#[command]
pub async fn get_active_identity(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<String>>, String> {
    let db_path = {
        let guard = state.db_path.lock().await;
        match guard.clone() {
            Some(p) => p,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;

    let workspace_path = workspace_path_for_db_path(&db_path);
    let ws = ensure_workspace_for_path(&db, &workspace_path).await?;
    Ok(ApiResponse::success(
        ws.active_identity_id.map(|id| id.to_string()),
    ))
}

/// Set the active identity ID for this workspace.
#[command]
pub async fn set_active_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
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

    let identity_id =
        Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())?;

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

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = ensure_workspace_for_path(&db, &workspace_path).await?;
    ws.switch_identity(identity_id);
    repo.update(&ws).await.map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(true))
}

/// Clear the active identity for this workspace.
#[command]
pub async fn clear_active_identity(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
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

    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = ensure_workspace_for_path(&db, &workspace_path).await?;
    ws.clear_active_identity();
    repo.update(&ws).await.map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(true))
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
                        Ok(updated_identity) => {
                            // If this is the first identity, make it the active one for this workspace.
                            if let Some(db_path) = state.db_path.lock().await.clone() {
                                if let Ok(db) = Database::from_file(&db_path).await {
                                    let _ = db.migrate().await;
                                    let workspace_path = workspace_path_for_db_path(&db_path);
                                    if let Ok(ws) =
                                        ensure_workspace_for_path(&db, &workspace_path).await
                                    {
                                        if ws.active_identity_id.is_none() {
                                            let repo = WorkspaceRepository::new(db.clone());
                                            let mut ws = ws;
                                            ws.switch_identity(updated_identity.id);
                                            let _ = repo.update(&ws).await;
                                        }
                                    }
                                }
                            }

                            Ok(ApiResponse::success(updated_identity.into()))
                        }
                        Err(e) => Ok(ApiResponse::error(format!(
                            "Failed to update identity: {}",
                            e
                        ))),
                    }
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to create identity: {}",
                    e
                ))),
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
        Some(service) => match service.get_identities().await {
            Ok(identities) => {
                let serializable: Vec<SerializableIdentity> =
                    identities.into_iter().map(|id| id.into()).collect();
                Ok(ApiResponse::success(serializable))
            }
            Err(e) => Ok(ApiResponse::error(format!(
                "Failed to get identities: {}",
                e
            ))),
        },
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
        Some(service) => match Uuid::from_str(&id) {
            Ok(uuid) => match service.get_identity(&uuid).await {
                Ok(identity) => Ok(ApiResponse::success(identity.map(|id| id.into()))),
                Err(e) => Ok(ApiResponse::error(format!("Failed to get identity: {}", e))),
            },
            Err(_) => Ok(ApiResponse::error("Invalid UUID format".to_string())),
        },
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
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    });
                    identity.email = request.email.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    });
                    identity.phone = request.phone.and_then(|s| {
                        let trimmed = s.trim().to_string();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
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
                        Err(e) => Ok(ApiResponse::error(format!(
                            "Failed to update identity: {}",
                            e
                        ))),
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
                Ok(ok) => {
                    if ok {
                        if let Some(db_path) = state.db_path.lock().await.clone() {
                            if let Ok(db) = Database::from_file(&db_path).await {
                                let _ = db.migrate().await;
                                let workspace_path = workspace_path_for_db_path(&db_path);
                                if let Ok(ws) =
                                    ensure_workspace_for_path(&db, &workspace_path).await
                                {
                                    if ws.active_identity_id == Some(uuid) {
                                        let repo = WorkspaceRepository::new(db.clone());
                                        let mut ws = ws;
                                        ws.clear_active_identity();
                                        let _ = repo.update(&ws).await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(ApiResponse::success(ok))
                }
                Err(e) => Ok(ApiResponse::error(format!(
                    "Failed to delete identity: {}",
                    e
                ))),
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

/// Get credentials for an identity
#[command]
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
#[command]
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
            // 协议逻辑统一下沉到 core（RFC 4226/6238），桌面端只做调用。
            let generated = persona_core::crypto::totp::totp_now(&tf)
                .map_err(|e| format!("Failed to generate TOTP code: {}", e))?;

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
#[command]
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

/// Delete a credential
#[command]
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
    app: tauri::AppHandle,
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
    // Desktop has no TTY: route RequireConfirm prompts through the GUI.
    // PERSONA_AGENT_REQUIRE_CONFIRM=1 enables the confirm policy (read by
    // PolicyEnforcer::from_env inside Agent::new).
    std::env::set_var("PERSONA_AGENT_REQUIRE_CONFIRM", "1");
    let handler = Arc::new(crate::approval::DesktopApprovalHandler::new(
        app,
        state.ssh_approvals.clone(),
    ));
    let handle = tokio::spawn(async move {
        if let Some(pass) = password {
            std::env::set_var("PERSONA_MASTER_PASSWORD", pass);
        } else {
            std::env::remove_var("PERSONA_MASTER_PASSWORD");
        }
        std::env::set_var("PERSONA_DB_PATH", &db_path_clone);
        std::env::set_var("PERSONA_AGENT_STATE_DIR", &state_dir);
        if let Err(err) = persona_ssh_agent::run_agent_with_approval(Some(
            handler as Arc<dyn persona_ssh_agent::ApprovalHandler>,
        ))
        .await
        {
            eprintln!("SSH agent exited: {}", err);
        }
        std::env::remove_var("PERSONA_AGENT_STATE_DIR");
        std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");
    });
    *handle_guard = Some(handle);
    drop(handle_guard);

    sleep(Duration::from_millis(400)).await;
    let status = read_agent_status(true);
    Ok(ApiResponse::success(status))
}

/// Stop the embedded SSH agent
#[command]
pub async fn stop_ssh_agent(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(handle) = state.agent_handle.lock().await.take() {
        handle.abort();
    }
    // 丢弃所有未应答审批：sender 被 drop 后 agent 侧收到断连 → 拒签
    if let Ok(mut map) = state.ssh_approvals.lock() {
        map.clear();
    }
    std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");
    cleanup_agent_state_files();
    Ok(ApiResponse::success(true))
}

/// Answer a pending SSH signature approval (from the approval modal).
///
/// Unknown/already-answered ids resolve to deny so double-clicks and
/// stale modals can never approve anything.
#[derive(serde::Deserialize)]
pub struct SshApprovalRespondRequest {
    pub request_id: String,
    pub allow: bool,
}

#[command]
pub async fn ssh_approval_respond(
    request: SshApprovalRespondRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let delivered =
        crate::approval::resolve_from_map(&state.ssh_approvals, &request.request_id, request.allow);
    if delivered {
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error(format!(
            "Unknown or expired approval request: {}",
            request.request_id
        )))
    }
}

/// Answer a pending bridge passkey approval (from the approval modal).
///
/// Unknown/already-answered ids resolve to deny so double-clicks and
/// stale modals can never approve anything.
#[derive(serde::Deserialize)]
pub struct PasskeyApprovalRespondRequest {
    pub request_id: String,
    pub allow: bool,
}

#[command]
pub async fn passkey_approval_respond(
    request: PasskeyApprovalRespondRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let delivered = crate::approval::resolve_from_map(
        &state.passkey_approvals,
        &request.request_id,
        request.allow,
    );
    if delivered {
        Ok(ApiResponse::success(true))
    } else {
        Ok(ApiResponse::error(format!(
            "Unknown or expired approval request: {}",
            request.request_id
        )))
    }
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
            repo.find_by_identity(&uuid)
                .await
                .map_err(|e| e.to_string())?
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

    Ok(ApiResponse::success(WalletListResponse {
        wallets: serializable,
    }))
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

    let identity_id =
        Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())?;
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

    let identity_id =
        Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())?;
    let wallet = match import_wallet_from_request(identity_id, &request) {
        Ok(wallet) => wallet,
        Err(error) => return Ok(ApiResponse::error(error)),
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
    Ok(ApiResponse::success(serialize_wallet_summary(&created)))
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

    let wallet_id =
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())?;
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

    let wallet: CryptoWallet = match repo
        .find_by_id(&wallet_id)
        .await
        .map_err(|e| e.to_string())?
    {
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

    let derivation_path = wallet
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
    let master_key =
        persona_core::crypto::wallet_encryption::decrypt_master_key(&encrypted_key, &password)
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

    Ok(ApiResponse::success(serialize_wallet_address(
        wallet_address,
    )))
}

#[command]
pub async fn wallet_delete(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
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
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())?;

    let deleted = repo.delete(&wallet_id).await.map_err(|e| e.to_string())?;
    if !deleted {
        return Ok(ApiResponse::error("Wallet not found".to_string()));
    }

    Ok(ApiResponse::success(true))
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

    let exported = match export_wallet_from_request(&wallet, &request) {
        Ok(exported) => exported,
        Err(error) => return Ok(ApiResponse::error(error)),
    };

    Ok(ApiResponse::success(exported))
}

// ---------------------------------------------------------------------------
// 钱包交易：创建 / 待签列表 / 签名确认（对齐 CLI wallet sign 流程）
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct WalletCreateTransactionRequest {
    pub wallet_id: String,
    pub to_address: String,
    /// 最小单位字符串（wei / satoshi / lamport）
    pub amount: String,
    pub fee: String,
    pub gas_price: Option<String>,
    pub gas_limit: Option<u64>,
    pub nonce: Option<u64>,
    pub memo: Option<String>,
    pub expires_in_minutes: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct WalletSignTransactionRequest {
    pub transaction_id: String,
    pub password: String,
}

/// 从数据库加载钱包交易仓库。
///
/// 钱包命令绕过 PersonaService 直用 `CryptoWalletRepository`（既有架构决策）。
async fn wallet_db(state: &State<'_, AppState>) -> std::result::Result<Database, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Err("Service not initialized".to_string()),
        }
    };
    if !service_unlocked {
        return Err("Service is locked".to_string());
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
    Ok(db)
}

/// Create a pending transaction request for a wallet
#[command]
pub async fn wallet_create_transaction(
    request: WalletCreateTransactionRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    use persona_core::models::wallet::TransactionRequest;

    let wallet_id =
        Uuid::from_str(&request.wallet_id).map_err(|_| "Invalid wallet_id".to_string())?;
    let db = wallet_db(&state).await?;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet = match repo
        .find_by_id(&wallet_id)
        .await
        .map_err(|e| e.to_string())?
    {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let from_address = wallet
        .addresses
        .first()
        .map(|a| a.address.clone())
        .ok_or_else(|| "Wallet has no addresses".to_string())?;

    let transaction = TransactionRequest {
        id: Uuid::new_v4(),
        wallet_id: wallet.id,
        network: wallet.network.clone(),
        from_address,
        to_address: request.to_address,
        amount: request.amount,
        fee: request.fee,
        gas_price: request.gas_price,
        gas_limit: request.gas_limit,
        nonce: request.nonce,
        memo: request.memo,
        raw_transaction_data: None,
        required_signatures: 1,
        created_at: chrono::Utc::now(),
        expires_at: request
            .expires_in_minutes
            .map(|mins| chrono::Utc::now() + chrono::Duration::minutes(mins as i64)),
        metadata: HashMap::new(),
    };

    let created = repo
        .create_transaction_request(&transaction)
        .await
        .map_err(|e| format!("Failed to create transaction: {}", e))?;
    let value = serde_json::to_value(&created)
        .map_err(|e| format!("Failed to serialize transaction: {}", e))?;
    Ok(ApiResponse::success(value))
}

/// List pending (unsigned) transaction requests for a wallet
#[command]
pub async fn wallet_pending_transactions(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<serde_json::Value>>, String> {
    let wallet_id = Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet_id".to_string())?;
    let db = wallet_db(&state).await?;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let requests = repo
        .get_pending_requests(&wallet_id)
        .await
        .map_err(|e| format!("Failed to list pending transactions: {}", e))?;
    requests
        .into_iter()
        .map(|r| serde_json::to_value(&r).map_err(|e| e.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map(ApiResponse::success)
}

/// Sign a pending transaction (derive key → sign → verify → persist).
///
/// 流程与 CLI `wallet --sign` 一致：签名后先本地验签，验签失败拒绝落库。
#[command]
pub async fn wallet_sign_transaction(
    request: WalletSignTransactionRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    let request_id = Uuid::from_str(&request.transaction_id)
        .map_err(|_| "Invalid transaction_id".to_string())?;
    let db = wallet_db(&state).await?;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let transaction = match repo
        .get_request_by_id(&request_id)
        .await
        .map_err(|e| format!("Failed to load transaction: {}", e))?
    {
        Some(tx) => tx,
        None => return Ok(ApiResponse::error("Transaction not found".to_string())),
    };

    let wallet = match repo
        .find_by_id(&transaction.wallet_id)
        .await
        .map_err(|e| format!("Failed to load wallet: {}", e))?
    {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let signed = sign_wallet_transaction(&repo, &wallet, &transaction, &request.password).await?;
    let value = serde_json::to_value(&signed)
        .map_err(|e| format!("Failed to serialize signed transaction: {}", e))?;
    Ok(ApiResponse::success(value))
}

/// 按地址派生签名钥 → 签名 → 本地验签 → 落库。
///
/// 与 CLI `CreateTransaction { sign: true }` 保持一致；验签失败时
/// **拒绝落库**（不产生 signed_transactions 记录）。
async fn sign_wallet_transaction(
    repo: &CryptoWalletRepository,
    wallet: &CryptoWallet,
    request: &persona_core::models::wallet::TransactionRequest,
    password: &str,
) -> std::result::Result<persona_core::models::wallet::SignedTransaction, String> {
    use persona_core::crypto::transaction_signing::{
        build_raw_transaction, sign_transaction, verify_ethereum_transaction,
        verify_solana_transaction,
    };
    use persona_core::crypto::wallet_import_export::signing_key_for_address;
    use persona_core::models::wallet::{BroadcastStatus, SignedTransaction};
    use sha2::Digest;

    let key = signing_key_for_address(wallet, password, &request.from_address)
        .map_err(|e| format!("Failed to derive signing key (wrong password?): {}", e))?;
    let signature = sign_transaction(request, &key)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    // 本地验签：失败一律拒绝落库
    match request.network {
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => {
            let ok = verify_ethereum_transaction(request, &signature)
                .map_err(|e| format!("Verification error: {}", e))?;
            if !ok {
                return Err(
                    "Signature verification failed; refusing to store signed transaction"
                        .to_string(),
                );
            }
        }
        BlockchainNetwork::Solana => {
            let message = request
                .raw_transaction_data
                .clone()
                .ok_or_else(|| "Solana signing requires raw_transaction_data".to_string())?;
            let ok = verify_solana_transaction(&signature, &message)
                .map_err(|e| format!("Verification error: {}", e))?;
            if !ok {
                return Err(
                    "Signature verification failed; refusing to store signed transaction"
                        .to_string(),
                );
            }
        }
        _ => {}
    }

    // Bitcoin 等需要 UTXO 集的网络：raw 组装失败时只落审计签名记录
    let (raw_bytes, tx_hash) = match build_raw_transaction(request, &key) {
        Ok(raw) => (raw.raw, raw.hash),
        Err(e) => {
            tracing::warn!(
                "raw transaction not assembled ({}); storing audit-only record",
                e
            );
            let audit_hash = format!(
                "audit:{}",
                hex::encode(sha2::Sha256::digest(&signature.signature))
            );
            (Vec::new(), audit_hash)
        }
    };

    let signed = SignedTransaction {
        id: Uuid::new_v4(),
        request: request.clone(),
        signatures: vec![signature],
        raw_signed_transaction: raw_bytes,
        transaction_hash: tx_hash,
        signed_at: chrono::Utc::now(),
        broadcast_status: BroadcastStatus::NotBroadcast,
    };

    repo.create_signed_transaction(&signed)
        .await
        .map_err(|e| format!("Failed to store signed transaction: {}", e))
}

fn parse_network(network_str: &str) -> std::result::Result<BlockchainNetwork, String> {
    match network_str.to_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(BlockchainNetwork::Bitcoin),
        "ethereum" | "eth" => Ok(BlockchainNetwork::Ethereum),
        "solana" | "sol" => Ok(BlockchainNetwork::Solana),
        "bitcoin-cash" | "bitcoin cash" | "bitcoincash" | "bch" => {
            Ok(BlockchainNetwork::BitcoinCash)
        }
        "litecoin" | "ltc" => Ok(BlockchainNetwork::Litecoin),
        "dogecoin" | "doge" => Ok(BlockchainNetwork::Dogecoin),
        "polygon" | "matic" => Ok(BlockchainNetwork::Polygon),
        "arbitrum" | "arb" => Ok(BlockchainNetwork::Arbitrum),
        "optimism" | "op" => Ok(BlockchainNetwork::Optimism),
        "binance" | "bsc" | "bnb" | "binance smart chain" => {
            Ok(BlockchainNetwork::BinanceSmartChain)
        }
        other => Ok(BlockchainNetwork::Custom(other.to_string())),
    }
}

fn serialize_wallet_address(
    addr: persona_core::models::wallet::WalletAddress,
) -> SerializableWalletAddress {
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

fn serialize_wallet_summary(wallet: &CryptoWallet) -> SerializableWallet {
    SerializableWallet {
        id: wallet.id.to_string(),
        name: wallet.name.clone(),
        network: wallet.network.to_string(),
        wallet_type: format!("{:?}", wallet.wallet_type),
        balance: "-".to_string(),
        address_count: wallet.addresses.len(),
        watch_only: wallet.watch_only,
        security_level: wallet.security_level.to_string(),
        created_at: wallet.created_at.to_rfc3339(),
        updated_at: wallet.updated_at.to_rfc3339(),
    }
}

fn import_wallet_from_request(
    identity_id: Uuid,
    request: &WalletImportRequest,
) -> std::result::Result<CryptoWallet, String> {
    if request.password.len() < 8 {
        return Err("Wallet password must be at least 8 characters".to_string());
    }

    let address_count = request.address_count.unwrap_or(5);
    match request.import_type.to_lowercase().as_str() {
        "mnemonic" | "phrase" | "seed" => {
            let network = parse_network(&request.network)?;
            persona_core::crypto::wallet_import_export::import_from_mnemonic(
                identity_id,
                request.name.clone(),
                request.data.trim(),
                "",
                network,
                None,
                address_count,
                &request.password,
            )
            .map_err(|e| e.to_string())
        }
        "private_key" | "privatekey" | "key" => {
            let network = parse_network(&request.network)?;
            persona_core::crypto::wallet_import_export::import_from_private_key(
                identity_id,
                request.name.clone(),
                request.data.trim(),
                network,
                &request.password,
            )
            .map_err(|e| e.to_string())
        }
        "wif" => persona_core::crypto::wallet_import_export::import_from_wif(
            identity_id,
            request.name.clone(),
            request.data.trim(),
            &request.password,
        )
        .map_err(|e| e.to_string()),
        other => Err(format!(
            "Unsupported import_type '{}'. Use 'mnemonic', 'private_key', or 'wif'.",
            other
        )),
    }
}

fn export_wallet_from_request(
    wallet: &CryptoWallet,
    request: &WalletExportRequest,
) -> std::result::Result<String, String> {
    let format = persona_core::crypto::wallet_import_export::parse_export_format(&request.format)
        .map_err(|e| e.to_string())?;

    match format {
        persona_core::crypto::wallet_import_export::ExportFormat::Json => {
            persona_core::crypto::wallet_import_export::export_to_json(
                wallet,
                request.include_private,
                request.password.as_deref(),
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Mnemonic => {
            persona_core::crypto::wallet_import_export::export_mnemonic(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for mnemonic export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Xpub => {
            persona_core::crypto::wallet_import_export::export_xpub(wallet)
                .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::PrivateKey => {
            persona_core::crypto::wallet_import_export::export_private_key(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for private key export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Wif => {
            persona_core::crypto::wallet_import_export::export_to_wif(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for WIF export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Auto-lock 配置与状态
// ---------------------------------------------------------------------------

/// Configure auto-lock settings (requires unlocked service)
#[command]
pub async fn configure_auto_lock(
    request: AutoLockConfigRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => {
            let config = persona_core::auth::AutoLockConfig {
                inactivity_timeout_secs: request.inactivity_timeout_secs,
                absolute_timeout_secs: request.absolute_timeout_secs.unwrap_or(0),
                require_reauth_sensitive: request.require_reauth_sensitive.unwrap_or(false),
                ..Default::default()
            };
            match service.configure_auto_lock(config).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to configure auto-lock: {}",
                            msg
                        ))),
                    }
                }
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get auto-lock status
#[command]
pub async fn get_auto_lock_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AutoLockStatusResponse>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => Ok(ApiResponse::success(AutoLockStatusResponse {
            is_unlocked: service.is_unlocked(),
            session_locked: service.is_session_locked().await,
            needs_reauth: service.needs_reauth().await,
            inactivity_timeout_secs: service.inactivity_timeout_secs(),
        })),
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Report user activity to postpone auto-lock
#[command]
pub async fn touch_activity(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            service.touch_activity();
            Ok(ApiResponse::success(true))
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Start background auto-lock monitoring
#[command]
pub async fn start_auto_lock_monitoring(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.start_auto_lock_monitoring().await {
            Ok(()) => Ok(ApiResponse::success(true)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to start auto-lock monitoring: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Stop background auto-lock monitoring
#[command]
pub async fn stop_auto_lock_monitoring(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            service.stop_auto_lock_monitoring().await;
            Ok(ApiResponse::success(true))
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// 审计查询（只读，不含敏感负载）
// ---------------------------------------------------------------------------

/// Query audit logs with filters
#[command]
pub async fn audit_query(
    request: AuditQueryRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableAuditLog>>, String> {
    let query = match build_audit_query(&request) {
        Ok(q) => q,
        Err(msg) => return Ok(ApiResponse::error(msg)),
    };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.query_audit_logs(query).await {
            Ok(logs) => Ok(ApiResponse::success(
                logs.into_iter().map(SerializableAuditLog::from).collect(),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!("Audit query failed: {}", msg))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get audit statistics
#[command]
pub async fn audit_statistics(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableAuditStatistics>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.audit_log_statistics().await {
            Ok(stats) => Ok(ApiResponse::success(SerializableAuditStatistics {
                total_logs: stats.total_logs,
                failed_operations: stats.failed_operations,
                recent_login_attempts: stats.recent_login_attempts,
                active_users_last_week: stats.active_users_last_week,
            })),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Audit statistics failed: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete audit logs older than `retain_days` (destructive; requires unlocked service)
#[command]
pub async fn audit_cleanup(
    retain_days: u32,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<u64>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.cleanup_audit_logs(retain_days).await {
            Ok(deleted) => Ok(ApiResponse::success(deleted)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!("Audit cleanup failed: {}", msg))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Parse an `AuditQueryRequest` into the core `AuditLogQuery`.
///
/// Separated as a pure function so invalid IDs/actions are testable without
/// a running service.
fn build_audit_query(
    request: &AuditQueryRequest,
) -> std::result::Result<persona_core::AuditLogQuery, String> {
    let identity_id = match &request.identity_id {
        Some(raw) => {
            Some(Uuid::from_str(raw).map_err(|_| format!("Invalid identity_id: {}", raw))?)
        }
        None => None,
    };
    let action = match &request.action {
        Some(raw) => Some(
            persona_core::AuditAction::from_str(raw)
                .map_err(|_| format!("Unknown audit action: {}", raw))?,
        ),
        None => None,
    };
    let time_range = match &request.time_range {
        Some((start, end)) => {
            let start = chrono::DateTime::parse_from_rfc3339(start)
                .map_err(|e| format!("Invalid time_range start: {}", e))?
                .with_timezone(&chrono::Utc);
            let end = chrono::DateTime::parse_from_rfc3339(end)
                .map_err(|e| format!("Invalid time_range end: {}", e))?
                .with_timezone(&chrono::Utc);
            Some((start, end))
        }
        None => None,
    };

    Ok(persona_core::AuditLogQuery {
        user_id: request.user_id.clone(),
        identity_id,
        action,
        failures_only: request.failures_only.unwrap_or(false),
        security_sensitive_only: request.security_sensitive_only.unwrap_or(false),
        time_range,
        limit: request.limit,
    })
}

// ---------------------------------------------------------------------------
// Watchtower 健康扫描（只读聚合；报告只含元数据、不含密文）
// ---------------------------------------------------------------------------

/// 可选请求字段 → core 扫描配置；缺省字段回落 core 默认值。
/// 独立成纯函数以便无需运行中的服务即可测试。
fn build_health_scan_config(request: &HealthScanRequest) -> persona_core::HealthScanConfig {
    persona_core::HealthScanConfig {
        min_password_score: request
            .min_password_score
            .unwrap_or(persona_core::DEFAULT_MIN_PASSWORD_SCORE),
        expiry_warning_days: request
            .expiry_warning_days
            .unwrap_or(persona_core::DEFAULT_EXPIRY_WARNING_DAYS),
        stale_after_days: request
            .stale_after_days
            .unwrap_or(persona_core::DEFAULT_STALE_AFTER_DAYS),
    }
}

/// Run the Watchtower health scan (weak / reused / expired / stale).
///
/// The report is metadata only — credential names and issue kinds, never
/// the decrypted secrets — and the scan writes one aggregate audit entry.
#[command]
pub async fn health_scan(
    request: Option<HealthScanRequest>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<HealthReport>, String> {
    let request = request.unwrap_or_default();
    let config = build_health_scan_config(&request);

    // check_breaches → HIBP k-anonymity checker；构造失败（罕见）降级为
    // 离线扫描而非报错，网络失败在 scan_health_with 内部也只告警。
    let checker: Option<std::sync::Arc<dyn persona_core::BreachChecker>> =
        if request.check_breaches.unwrap_or(false) {
            match persona_core::HibpBreachChecker::new() {
                Ok(checker) => Some(std::sync::Arc::new(checker)),
                Err(e) => {
                    tracing::warn!("health scan: breach checker unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.scan_health_with(config, checker.as_deref()).await {
            Ok(report) => Ok(ApiResponse::success(report)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!("Health scan failed: {}", msg))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// Passkey 管理（P3 命令层接缝）
// ---------------------------------------------------------------------------

/// List passkeys for an identity
#[command]
pub async fn passkey_list(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializablePasskey>>, String> {
    let uuid = match Uuid::from_str(&identity_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.list_passkeys(&uuid).await {
            Ok(items) => Ok(ApiResponse::success(
                items.into_iter().map(SerializablePasskey::from).collect(),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to list passkeys: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// List passkeys by relying-party ID
#[command]
pub async fn passkey_list_by_rp(
    rp_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializablePasskey>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.list_passkeys_by_rp(&rp_id).await {
            Ok(items) => Ok(ApiResponse::success(
                items.into_iter().map(SerializablePasskey::from).collect(),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to list passkeys: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Get a single passkey by ID
#[command]
pub async fn passkey_get(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Option<SerializablePasskey>>, String> {
    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_passkey(&uuid).await {
            Ok(item) => Ok(ApiResponse::success(item.map(SerializablePasskey::from))),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to get passkey: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Delete a passkey
#[command]
pub async fn passkey_delete(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.delete_passkey(&uuid).await {
            Ok(deleted) => Ok(ApiResponse::success(deleted)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to delete passkey: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Create a passkey (software authenticator registration ceremony)
#[command]
pub async fn passkey_create(
    request: CreatePasskeyRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<PasskeyCreationResponse>, String> {
    use base64::Engine;

    let identity_id = match Uuid::from_str(&request.identity_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid identity_id".to_string())),
    };

    let engine = base64::engine::general_purpose::STANDARD;
    let client_data_json = match engine.decode(&request.client_data_json_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Invalid client_data_json_b64: {}",
                e
            )))
        }
    };
    let user_handle = match &request.user_handle_b64 {
        Some(raw) => match engine.decode(raw) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Invalid user_handle_b64: {}",
                    e
                )))
            }
        },
        None => None,
    };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => {
            match service
                .create_passkey_full(
                    identity_id,
                    request.rp_id.clone(),
                    &request.origin,
                    &client_data_json,
                    user_handle,
                    request.user_name.clone(),
                    request.user_display_name.clone(),
                    request.user_verification,
                )
                .await
            {
                Ok(creation) => Ok(ApiResponse::success(PasskeyCreationResponse {
                    passkey: SerializablePasskey::from(creation.item),
                    attestation_object_b64: engine.encode(creation.attestation_object),
                })),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to create passkey: {}",
                            msg
                        ))),
                    }
                }
            }
        }
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Run a passkey self-test (sign + verify round-trip; sensitive, re-auth gated)
#[command]
pub async fn passkey_self_test(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.passkey_self_test(&uuid).await {
            Ok(()) => Ok(ApiResponse::success(true)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Passkey self-test failed: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Export a passkey private key (base64; sensitive, re-auth gated + audited)
#[command]
pub async fn passkey_export_private_key(
    id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
    use base64::Engine;

    let uuid = match Uuid::from_str(&id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.export_passkey_private_key(&uuid).await {
            Ok(bytes) => Ok(ApiResponse::success(
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to export passkey private key: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// 身份导出
// ---------------------------------------------------------------------------

/// Export an identity with its credentials (audited by core; metadata only —
/// no ciphertext/secret material is included in the payload)
#[command]
pub async fn export_identity(
    identity_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableIdentityExport>, String> {
    let uuid = match Uuid::from_str(&identity_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.export_identity(&uuid).await {
            Ok(export) => Ok(ApiResponse::success(SerializableIdentityExport {
                exported_at: chrono::Utc::now().to_rfc3339(),
                data: serde_json::json!({
                    "identity": SerializableIdentity::from(export.identity),
                    "credentials": export
                        .credentials
                        .into_iter()
                        .map(SerializableCredential::from)
                        .collect::<Vec<_>>(),
                }),
            })),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to export identity: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// 敏感字段 reveal + 重新认证
// ---------------------------------------------------------------------------

/// Extract a named secret field from decrypted credential data.
///
/// Pure function so the full field×type matrix is unit-testable.
/// Returns `Err` on invalid field names and on field/type mismatches
/// (e.g. requesting "ssh_private_key" from a Password credential).
fn extract_secret_field(data: &CredentialData, field: &str) -> std::result::Result<String, String> {
    match (data, field) {
        (CredentialData::Password(p), "password") => Ok(p.password.clone()),
        (CredentialData::Password(p), "security_questions") => serde_json::to_string(
            &p.security_questions
                .iter()
                .map(|q| serde_json::json!({ "question": q.question, "answer": q.answer }))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string()),
        (CredentialData::CryptoWallet(w), "wallet_private_key") => w
            .private_key
            .clone()
            .ok_or_else(|| "This wallet has no stored private key".to_string()),
        (CredentialData::CryptoWallet(w), "wallet_mnemonic") => w
            .mnemonic_phrase
            .clone()
            .ok_or_else(|| "This wallet has no stored mnemonic phrase".to_string()),
        (CredentialData::SshKey(k), "ssh_private_key") => Ok(k.private_key.clone()),
        (CredentialData::SshKey(k), "ssh_passphrase") => k
            .passphrase
            .clone()
            .ok_or_else(|| "This SSH key has no stored passphrase".to_string()),
        (CredentialData::ApiKey(a), "api_key") => Ok(a.api_key.clone()),
        (CredentialData::ApiKey(a), "api_secret") => a
            .api_secret
            .clone()
            .ok_or_else(|| "This API credential has no stored secret".to_string()),
        (CredentialData::ApiKey(a), "token") => a
            .token
            .clone()
            .ok_or_else(|| "This API credential has no stored token".to_string()),
        (CredentialData::Raw(raw), "raw_data") => {
            String::from_utf8(raw.clone()).map_err(|_| "Raw data is not valid UTF-8".to_string())
        }
        _ => Err(format!(
            "Field '{}' is not available for this credential type",
            field
        )),
    }
}

/// Reveal a single secret field of a credential (sensitive; re-auth gated +
/// audited via the underlying decrypt)
#[command]
pub async fn reveal_credential_secret(
    request: RevealSecretRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SecretRevealResponse>, String> {
    let uuid = match Uuid::from_str(&request.credential_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.get_credential_data(&uuid).await {
            Ok(Some(data)) => match extract_secret_field(&data, &request.field) {
                Ok(value) => Ok(ApiResponse::success(SecretRevealResponse {
                    field: request.field,
                    value,
                })),
                Err(msg) => Ok(ApiResponse::error(msg)),
            },
            Ok(None) => Ok(ApiResponse::error("Credential not found".to_string())),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Failed to reveal secret: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

/// Verify the master password to re-authorize sensitive operations
#[command]
pub async fn reauth_verify(
    request: ReauthRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => match service.authenticate_user(&request.master_password).await {
            Ok(persona_core::AuthResult::Success) => {
                // 恢复会话并刷新活动时间，让后续敏感操作直接放行
                if let Err(e) = service.unlock_session().await {
                    tracing::warn!("unlock_session after re-auth failed: {}", e);
                }
                service.touch_activity();
                Ok(ApiResponse::success(true))
            }
            Ok(_) => Ok(ApiResponse::error("Invalid master password".to_string())),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!(
                        "Re-authentication failed: {}",
                        msg
                    ))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}

// ---------------------------------------------------------------------------
// SSH agent 状态探测（平台相关 helper，供命令与测试共用）
// ---------------------------------------------------------------------------

pub(crate) fn agent_state_dir() -> PathBuf {
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
        fs::read_to_string(&sock_path)
            .ok()
            .map(|s| s.trim().to_string())
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

    let mut stream =
        UnixStream::connect(sock_path).map_err(|e| format!("Failed to connect to agent: {}", e))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use persona_core::models::Identity;

    async fn setup_wallet_test_db() -> (tempfile::TempDir, Database, Identity) {
        // 委托共享夹具（test_support.rs），避免每套测试重建样板
        let fixture = crate::test_support::test_db().await;
        (fixture._dir, fixture.db, fixture.identity)
    }

    #[tokio::test]
    async fn wallet_import_request_imports_bitcoin_wif_as_single_address_wallet() {
        let (_dir, _db, identity) = setup_wallet_test_db().await;
        let request = WalletImportRequest {
            name: "BTC WIF".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "wif".to_string(),
            data: "KzgibHVnBeHWb4vnmrqXfJcEcfPQbYC2xPxz932rCiHxSc8u3GhA".to_string(),
            password: "test_password".to_string(),
            address_count: None,
        };

        let wallet = import_wallet_from_request(identity.id, &request).unwrap();

        assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
        assert!(matches!(
            wallet.wallet_type,
            persona_core::models::wallet::WalletType::SingleAddress
        ));
        assert_eq!(wallet.addresses.len(), 1);
        assert!(!wallet.watch_only);
    }

    #[tokio::test]
    async fn wallet_import_request_rejects_short_passwords() {
        let (_dir, _db, identity) = setup_wallet_test_db().await;
        let request = WalletImportRequest {
            name: "Bad Wallet".to_string(),
            network: "Ethereum".to_string(),
            import_type: "private_key".to_string(),
            data: "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b".to_string(),
            password: "short".to_string(),
            address_count: None,
        };

        let error = import_wallet_from_request(identity.id, &request).unwrap_err();
        assert_eq!(error, "Wallet password must be at least 8 characters");
    }

    #[tokio::test]
    async fn wallet_export_request_requires_password_for_wif() {
        let (_dir, _db, identity) = setup_wallet_test_db().await;
        let import_request = WalletImportRequest {
            name: "BTC WIF".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "private_key".to_string(),
            data: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            password: "test_password".to_string(),
            address_count: None,
        };
        let wallet = import_wallet_from_request(identity.id, &import_request).unwrap();

        let export_request = WalletExportRequest {
            wallet_id: wallet.id.to_string(),
            format: "wif".to_string(),
            include_private: false,
            password: None,
        };

        let error = export_wallet_from_request(&wallet, &export_request).unwrap_err();
        assert_eq!(error, "Password required for WIF export");
    }

    #[tokio::test]
    async fn wallet_delete_removes_wallet_from_repository() {
        let (_dir, db, identity) = setup_wallet_test_db().await;
        let repo = CryptoWalletRepository::new(Arc::new(db));
        let request = WalletImportRequest {
            name: "ETH Wallet".to_string(),
            network: "Ethereum".to_string(),
            import_type: "private_key".to_string(),
            data: "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b".to_string(),
            password: "test_password".to_string(),
            address_count: None,
        };
        let wallet = import_wallet_from_request(identity.id, &request).unwrap();
        let created = repo.create(&wallet).await.unwrap();

        let deleted = repo.delete(&created.id).await.unwrap();
        let fetched = repo.find_by_id(&created.id).await.unwrap();

        assert!(deleted);
        assert!(fetched.is_none());
    }

    // -------------------------------------------------------------------------
    // extract_secret_field：字段 × 类型矩阵
    // -------------------------------------------------------------------------

    fn password_data() -> CredentialData {
        CredentialData::Password(PasswordCredentialData {
            password: "hunter2".to_string(),
            email: Some("a@b.c".to_string()),
            security_questions: vec![SecurityQuestion {
                question: "Pet?".to_string(),
                answer: "Cat".to_string(),
            }],
        })
    }

    #[test]
    fn reveal_extracts_password_and_questions() {
        let data = password_data();
        assert_eq!(extract_secret_field(&data, "password").unwrap(), "hunter2");
        let qs = extract_secret_field(&data, "security_questions").unwrap();
        assert!(qs.contains("Pet?") && qs.contains("Cat"));
    }

    #[test]
    fn reveal_extracts_ssh_key_and_flags_missing_passphrase() {
        let data = CredentialData::SshKey(SshKeyData {
            private_key: "-----BEGIN".to_string(),
            public_key: "ssh-ed25519 AAA".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        });
        assert_eq!(
            extract_secret_field(&data, "ssh_private_key").unwrap(),
            "-----BEGIN"
        );
        assert!(extract_secret_field(&data, "ssh_passphrase").is_err());
        // 跨类型取 password 必须失败
        assert!(extract_secret_field(&data, "password").is_err());
    }

    #[test]
    fn reveal_extracts_api_fields_and_flags_missing_ones() {
        let data = CredentialData::ApiKey(ApiKeyData {
            api_key: "key123".to_string(),
            api_secret: Some("secret456".to_string()),
            token: None,
            permissions: vec![],
            expires_at: None,
        });
        assert_eq!(extract_secret_field(&data, "api_key").unwrap(), "key123");
        assert_eq!(
            extract_secret_field(&data, "api_secret").unwrap(),
            "secret456"
        );
        assert!(extract_secret_field(&data, "token").is_err());
    }

    #[test]
    fn reveal_extracts_wallet_secrets_only_when_present() {
        let empty = CredentialData::CryptoWallet(CryptoWalletData {
            wallet_type: "evm".to_string(),
            mnemonic_phrase: None,
            private_key: None,
            public_key: "pub".to_string(),
            address: "0x0".to_string(),
            network: "Ethereum".to_string(),
        });
        assert!(extract_secret_field(&empty, "wallet_private_key").is_err());
        assert!(extract_secret_field(&empty, "wallet_mnemonic").is_err());

        let full = CredentialData::CryptoWallet(CryptoWalletData {
            wallet_type: "evm".to_string(),
            mnemonic_phrase: Some("test test".to_string()),
            private_key: Some("0xabc".to_string()),
            public_key: "pub".to_string(),
            address: "0x0".to_string(),
            network: "Ethereum".to_string(),
        });
        assert_eq!(
            extract_secret_field(&full, "wallet_private_key").unwrap(),
            "0xabc"
        );
    }

    #[test]
    fn reveal_raw_requires_utf8_and_unknown_field_fails() {
        let raw = CredentialData::Raw("hello".to_string().into_bytes());
        assert_eq!(extract_secret_field(&raw, "raw_data").unwrap(), "hello");
        assert!(extract_secret_field(&raw, "nope").is_err());
        assert!(
            extract_secret_field(&CredentialData::Raw(vec![0xff]), "raw_data").is_err(),
            "非 UTF-8 原始数据必须报错"
        );
    }

    // -------------------------------------------------------------------------
    // build_health_scan_config：扫描参数解析
    // -------------------------------------------------------------------------

    #[test]
    fn health_scan_empty_request_uses_core_defaults() {
        let c = build_health_scan_config(&HealthScanRequest::default());
        assert_eq!(
            c,
            persona_core::HealthScanConfig {
                min_password_score: persona_core::DEFAULT_MIN_PASSWORD_SCORE,
                expiry_warning_days: persona_core::DEFAULT_EXPIRY_WARNING_DAYS,
                stale_after_days: persona_core::DEFAULT_STALE_AFTER_DAYS,
            }
        );
    }

    #[test]
    fn health_scan_request_overrides_each_field() {
        let raw = serde_json::json!({
            "min_password_score": 2,
            "expiry_warning_days": 7,
            "stale_after_days": 90
        });
        let request: HealthScanRequest = serde_json::from_value(raw).unwrap();
        let c = build_health_scan_config(&request);
        assert_eq!(c.min_password_score, 2);
        assert_eq!(c.expiry_warning_days, 7);
        assert_eq!(c.stale_after_days, 90);

        // 前端可以只传部分字段，其余回落默认值
        let partial: HealthScanRequest =
            serde_json::from_value(serde_json::json!({ "min_password_score": 1 })).unwrap();
        let c = build_health_scan_config(&partial);
        assert_eq!(c.min_password_score, 1);
        assert_eq!(
            c,
            persona_core::HealthScanConfig {
                min_password_score: 1,
                expiry_warning_days: persona_core::DEFAULT_EXPIRY_WARNING_DAYS,
                stale_after_days: persona_core::DEFAULT_STALE_AFTER_DAYS,
            }
        );
    }

    #[test]
    fn health_scan_check_breaches_flag_parses_with_default_off() {
        // 缺省 = 不查泄露库
        let absent: HealthScanRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(absent.check_breaches, None);

        let on: HealthScanRequest =
            serde_json::from_value(serde_json::json!({ "check_breaches": true })).unwrap();
        assert_eq!(on.check_breaches, Some(true));
        // flag 不影响扫描配置本体
        assert_eq!(build_health_scan_config(&on), HealthScanConfig::default());
    }

    // -------------------------------------------------------------------------
    // build_audit_query：过滤参数解析
    // -------------------------------------------------------------------------

    #[test]
    fn audit_query_empty_request_uses_defaults() {
        let q = build_audit_query(&AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        })
        .unwrap();
        assert!(!q.failures_only);
        assert!(!q.security_sensitive_only);
        assert!(q.time_range.is_none() && q.action.is_none() && q.limit.is_none());
    }

    #[test]
    fn audit_query_parses_action_time_and_rejects_garbage() {
        let q = build_audit_query(&AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: Some("identity_created".to_string()),
            failures_only: Some(true),
            security_sensitive_only: None,
            time_range: Some((
                "2026-01-01T00:00:00Z".to_string(),
                "2026-02-01T00:00:00Z".to_string(),
            )),
            limit: Some(50),
        })
        .unwrap();
        assert!(q.failures_only);
        assert_eq!(q.limit, Some(50));
        assert!(q.time_range.is_some());

        let mut bad = AuditQueryRequest {
            action: Some("not_a_real_action".to_string()),
            ..AuditQueryRequest {
                user_id: None,
                identity_id: None,
                action: None,
                failures_only: None,
                security_sensitive_only: None,
                time_range: None,
                limit: None,
            }
        };
        // 未知动作名按 core 语义解析为 Custom（查询合法，结果为空），不报错
        assert!(build_audit_query(&bad).is_ok());
        bad.action = None;
        bad.identity_id = Some("not-a-uuid".to_string());
        assert!(build_audit_query(&bad).is_err());
    }
}
