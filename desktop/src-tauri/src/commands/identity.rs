use super::*;

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
#[command(rename_all = "snake_case")]
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
