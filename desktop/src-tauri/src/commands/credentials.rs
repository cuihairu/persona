use super::*;

/// 只读 favicon 开关：vault 打不开/行不存在一律视为关。
///
/// 这是 favicon 外联的后端兜底门禁——不依赖前端藏按钮，开关关闭时
/// `fetch_credential_favicon` 直接拒绝、`get_favicons` 静默回空。
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

/// Edit credential metadata（name/username/url/notes/tags/security_level；
/// 条目类型不可变，payload 编辑走 update_credential_data）
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

/// Edit a credential's encrypted payload（敏感：复用原 item key 重封，
/// 附件不受影响；走敏感门禁，reauth 超时返回 REAUTH_REQUIRED）
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
/// 字段级 diff 不含任何密文/密钥材料)
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
/// 只回滚元数据（name/username/url/notes/tags 等 9 字段）；历史快照从不含
/// 密文，密码等秘密不会被回滚。删除行无可恢复状态，不支持重建已删条目。
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
            // HOTP 是计数器型，桌面端没有计数器概念：明确报错（指向 CLI
            // 的 --counter 用法），而不是按时间窗返回错误码。
            if tf.hotp.unwrap_or(false) {
                return Ok(ApiResponse::error(
                    "HOTP entries require an explicit counter — use `persona totp code <id> --counter N`"
                        .to_string(),
                ));
            }
            // 协议逻辑统一下沉到 core（RFC 4226/6238），桌面端只做调用。
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
        // 游戏令牌经 core 统一调度器（Steam Guard 离线可算；绑定型
        // provider 在此报错而不是生成错误码）
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
/// 纯计算（`core::PasswordGenerator`），不触碰库与主密钥——无需解锁即可
/// 调用（后续 Quick Access/锁屏场景可直接复用）。length 夹取到 4..=256、
/// count 夹取到 1..=10（滑杆 UI 天然受限，这里兜底防滥用）；选项组合
/// 非法（无字符集/可发音无字母/words越界）透传 core 的校验错误。
///
/// `rename_all = "snake_case"`：Tauri 2 默认按 camelCase 查 invoke 参数键
/// （宏默认 `ArgumentCase::Camel`，`v.get(key)` 精确匹配、无大小写回退），
/// 而前端 api.ts 全文件统一发 snake_case 键——缺此属性会报
/// "missing required key includeLowercase"。键契约由
/// `command_layer_tests::generate_password_advanced_ipc_arg_contract` 钉住。
///
/// 8 个平铺参数超 clippy `too_many_arguments` 阈值（7）：这是 IPC 线格式，
/// 键名即前端 `invoke` 载荷键，由上面的审计回归钉死，不能为了过 lint 改成
/// 请求结构体（会改动已发布的线格式）。与仓库其他平铺选项函数同样按
/// lint 豁免处理（core/cli 共 10 处同因）。
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

/// 生成器熵值估计（仅显示参考）：
/// - 随机模式：`log2(字符池) × 长度`（core 保证每个启用集至少出一字符，
///   这里按均匀采样近似，差一位 shuffle 熵，忽略）；
/// - 可发音模式：与 core 的辅音/元音交替算法同构，按位累加 `log2(当前位池)`
///   （数字/符号的注入替换不增熵，保守忽略）。
/// - 单词式 passphrase 模式：`log2(7772) × word_count`（EFF large wordlist 大小）。
pub(crate) fn estimate_generator_entropy(
    options: &persona_core::password::PasswordGeneratorOptions,
) -> (f64, usize) {
    if let Some(word_count) = options.words {
        // Words mode: EFF large wordlist = 7772 words
        let pool = 7772;
        ((pool as f64).log2() * word_count as f64, pool)
    } else if options.pronounceable {
        // 辅音池 21、元音池 5；大小写同开时各翻倍（与 core 常量一致）
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

/// 按需抓取凭据对应站点的 favicon 并入缓存（隐私红线：唯一外联入口，
/// 由详情面板 "Fetch icon" 按钮触发；flag 关闭时后端兜底拒绝）。
#[command(rename_all = "snake_case")]
pub async fn fetch_credential_favicon(
    credential_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableFavicon>, String> {
    // 检查顺序照 set_feature_flags：service 状态在先（错误语义优先），
    // flag 门禁随后（开新 DB 连接的 IO 不持 service 锁做）
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

/// 批量读已缓存的 favicon（纯本地读，绝不外联）。
///
/// flag 关闭 / 未初始化 / 锁定一律静默回空数组——批量读是列表渲染的
/// 后台优化路径，缺席项回退静态图标即可，报错无意义。
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
