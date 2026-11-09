use super::*;

/// Extract a named secret field from decrypted credential data.
///
/// Pure function so the full field×type matrix is unit-testable.
/// Returns `Err` on invalid field names and on field/type mismatches
/// (e.g. requesting "ssh_private_key" from a Password credential).
pub(crate) fn extract_secret_field(
    data: &CredentialData,
    field: &str,
) -> std::result::Result<String, String> {
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
        (CredentialData::CryptoWallet(w), "wallet_bip39_passphrase") => w
            .bip39_passphrase
            .clone()
            .ok_or_else(|| "This wallet has no BIP-39 passphrase".to_string()),
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

/// 钱包条目级独立密码守卫：种子材料三个字段（助记词/私钥/第 25 词）在条目
/// 设置了 `item_password_hash` 时需额外比对（防解锁态顺手窥探的第二因子）。
/// 缺参 → `ITEM_PASSWORD_REQUIRED`；不匹配 → `ITEM_PASSWORD_WRONG`。
/// 非钱包字段 / 未设密码的条目不受影响。
/// 返回 `None` 表示放行；`Some((code, message))` 表示拦截，code 为空串表示无专用错误码。
/// （不用 `Result`：persona_core 通配导出的单参 `Result` 别名在此签名里撞 E0107。）
pub(crate) fn ensure_item_password_ok(
    data: &CredentialData,
    field: &str,
    item_password: Option<&str>,
) -> Option<(String, String)> {
    const GUARDED_FIELDS: [&str; 3] = [
        "wallet_mnemonic",
        "wallet_private_key",
        "wallet_bip39_passphrase",
    ];
    let (CredentialData::CryptoWallet(w), true) = (data, GUARDED_FIELDS.contains(&field)) else {
        return None;
    };
    let Some(hash) = &w.item_password_hash else {
        return None;
    };
    let Some(pwd) = item_password else {
        return Some((
            crate::error::CODE_ITEM_PASSWORD_REQUIRED.to_string(),
            "This wallet requires its item password to reveal seed material".to_string(),
        ));
    };
    match persona_core::crypto::hashing::PasswordHasher::new().verify_password(pwd, hash) {
        Ok(true) => None,
        Ok(false) => Some((
            crate::error::CODE_ITEM_PASSWORD_WRONG.to_string(),
            "Item password is incorrect".to_string(),
        )),
        Err(e) => Some((String::new(), format!("Item password check failed: {e}"))),
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
            Ok(Some(data)) => {
                if let Some((code, msg)) =
                    ensure_item_password_ok(&data, &request.field, request.item_password.as_deref())
                {
                    if code.is_empty() {
                        return Ok(ApiResponse::error(msg));
                    }
                    return Ok(ApiResponse::error_with_code(code, msg));
                }
                match extract_secret_field(&data, &request.field) {
                    Ok(value) => Ok(ApiResponse::success(SecretRevealResponse {
                        field: request.field,
                        value,
                    })),
                    Err(msg) => Ok(ApiResponse::error(msg)),
                }
            }
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

/// 为钱包条目设置/更换独立密码（CryptoWallet 专属）。密码 Argon2id hash
/// 后随条目密文存储；提示为明文低敏字段。设置后 reveal 种子材料需携带
/// 该密码（第二因子）。
#[command(rename_all = "snake_case")]
pub async fn wallet_set_item_password(
    credential_id: String,
    password: String,
    hint: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let uuid = match Uuid::from_str(&credential_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let trimmed = password.trim();
    if trimmed.chars().count() < 4 {
        return Ok(ApiResponse::error(
            "Item password must be at least 4 characters".to_string(),
        ));
    }
    let hash = match persona_core::crypto::hashing::PasswordHasher::new().hash_password(trimmed) {
        Ok(h) => h,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Failed to hash item password: {e}"
            )))
        }
    };
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return Ok(ApiResponse::error("Service not initialized".to_string()));
    };
    let mut data = match service.get_credential_data(&uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(ApiResponse::error("Credential not found".to_string())),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            return Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(format!("Failed to load credential: {msg}")),
            });
        }
    };
    let CredentialData::CryptoWallet(ref mut w) = data else {
        return Ok(ApiResponse::error(
            "Item password is only supported for CryptoWallet credentials".to_string(),
        ));
    };
    w.item_password_hash = Some(hash);
    w.item_password_hint = hint.map(|h| h.trim().to_string()).filter(|h| !h.is_empty());
    match service.update_credential_data(&uuid, &data).await {
        Ok(_) => Ok(ApiResponse::success(true)),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(format!("Failed to save item password: {msg}")),
            })
        }
    }
}

/// 清除钱包条目独立密码：需携带当前条目密码验证（防解锁态下直接摘除
/// 保护）。未设置时幂等成功。
#[command(rename_all = "snake_case")]
pub async fn wallet_clear_item_password(
    credential_id: String,
    item_password: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let uuid = match Uuid::from_str(&credential_id) {
        Ok(u) => u,
        Err(_) => return Ok(ApiResponse::error("Invalid UUID format".to_string())),
    };
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return Ok(ApiResponse::error("Service not initialized".to_string()));
    };
    let mut data = match service.get_credential_data(&uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(ApiResponse::error("Credential not found".to_string())),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            return Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(format!("Failed to load credential: {msg}")),
            });
        }
    };
    let CredentialData::CryptoWallet(ref mut w) = data else {
        return Ok(ApiResponse::error(
            "Item password is only supported for CryptoWallet credentials".to_string(),
        ));
    };
    if let Some(hash) = w.item_password_hash.clone() {
        match persona_core::crypto::hashing::PasswordHasher::new()
            .verify_password(item_password.trim(), &hash)
        {
            Ok(true) => {}
            Ok(false) => {
                return Ok(ApiResponse::error_with_code(
                    crate::error::CODE_ITEM_PASSWORD_WRONG.to_string(),
                    "Item password is incorrect".to_string(),
                ))
            }
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Item password check failed: {e}"
                )))
            }
        }
    }
    w.item_password_hash = None;
    w.item_password_hint = None;
    match service.update_credential_data(&uuid, &data).await {
        Ok(_) => Ok(ApiResponse::success(true)),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(format!("Failed to save credential: {msg}")),
            })
        }
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
            Ok(persona_core::AuthResult::PasswordChangeRequired) => {
                Ok(ApiResponse::error_with_code(
                    crate::error::CODE_PASSWORD_CHANGE_REQUIRED.to_string(),
                    "Master password change required".to_string(),
                ))
            }
            Ok(persona_core::AuthResult::AccountLocked) => Ok(ApiResponse::error(
                "Account is locked due to too many failed attempts".to_string(),
            )),
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
