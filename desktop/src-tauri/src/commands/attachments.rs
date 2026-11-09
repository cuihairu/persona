use super::*;

/// List attachments for a credential (metadata only; no blob content)
#[command(rename_all = "snake_case")]
pub async fn list_attachments(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<SerializableAttachment>>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.get_attachments(&uuid).await {
                Ok(attachments) => Ok(ApiResponse::success(
                    attachments.into_iter().map(|a| a.into()).collect(),
                )),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to list attachments: {}",
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

/// Attach a local file to a credential. `file_path` comes from the native
/// file dialog on the frontend; the blob is sealed under the credential's
/// per-item key when `encrypt` is set.
#[command(rename_all = "snake_case")]
pub async fn attach_file_to_credential(
    credential_id: String,
    file_path: String,
    encrypt: bool,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableAttachment>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => match Uuid::from_str(&credential_id) {
            Ok(uuid) => match service.attach_file(uuid, &file_path, encrypt).await {
                Ok(attachment_id) => {
                    let attachment = service
                        .get_attachments(&uuid)
                        .await
                        .ok()
                        .and_then(|list| list.into_iter().find(|a| a.id == attachment_id));
                    match attachment {
                        Some(a) => Ok(ApiResponse::success(a.into())),
                        None => Ok(ApiResponse::error(
                            "Attachment stored but metadata could not be read back".to_string(),
                        )),
                    }
                }
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to attach file: {}",
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

/// Save an attachment to disk (decrypted). `output_path` comes from the
/// native save dialog on the frontend.
#[command(rename_all = "snake_case")]
pub async fn save_attachment_to_file(
    attachment_id: String,
    output_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match Uuid::from_str(&attachment_id) {
            Ok(uuid) => match service.save_attachment(&uuid, &output_path, true).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to save attachment: {}",
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

/// Delete an attachment (blob + metadata)
#[command(rename_all = "snake_case")]
pub async fn delete_attachment(
    attachment_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let mut service_guard = state.service.lock().await;
    match service_guard.as_mut() {
        Some(service) => match Uuid::from_str(&attachment_id) {
            Ok(uuid) => match service.delete_attachment(&uuid).await {
                Ok(()) => Ok(ApiResponse::success(true)),
                Err(e) => {
                    let (code, msg) = map_persona_error(&e);
                    match code {
                        Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                        None => Ok(ApiResponse::error(format!(
                            "Failed to delete attachment: {}",
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
