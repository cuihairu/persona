use super::*;

/// Export an identity with its credentials (audited by core; metadata only —
/// no ciphertext/secret material is included in the payload)
#[command(rename_all = "snake_case")]
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

/// `backup_export_to_file` 请求：目标文件路径 + 备份口令。
///
/// 备份口令与主密码相互独立（设计稿 §6.5：主库不解密、主密码不参与备份
/// 链路）；强度要求由前端把关，后端只做非空校验。口令本身永不落盘。
#[derive(Debug, Deserialize)]
pub struct BackupExportRequest {
    pub path: String,
    pub passphrase: String,
}

/// 导出结果（非敏感元数据，与 WorkspaceSettings.backup 的
/// BackupEvidence 对账）。
#[derive(Debug, Serialize)]
pub struct BackupExportOutcome {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub exported_at: String,
}

/// 整库加密备份导出到本地文件（S5 自救口第一批）。
///
/// 流程：VACUUM INTO 快照 → gzip → 口令加密 → 同目录 `.part` 临时文件
/// + rename 原子落盘 → 导出凭证（BackupEvidence）写入 workspace
/// settings。主库全程不解密、不需要主密码；导出中途失败不毁旧备份文件。
#[command(rename_all = "snake_case")]
pub async fn backup_export_to_file(
    request: BackupExportRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BackupExportOutcome>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    if request.passphrase.is_empty() {
        return Ok(ApiResponse::error(
            "Backup passphrase must not be empty".to_string(),
        ));
    }
    if request.path.trim().is_empty() {
        return Ok(ApiResponse::error(
            "Backup destination path must not be empty".to_string(),
        ));
    }
    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);

    let blob = ok_or_error_response_ctx!(
        persona_core::backup::create_backup_bytes(db.pool(), &request.passphrase, None).await,
        "Failed to create backup: {}"
    );

    // 原子落盘：`backup.enc` → `backup.enc.part` 写完再 rename，中途
    // 失败（磁盘满/进程被杀）旧文件原样保留
    let dest = std::path::Path::new(&request.path);
    let part = dest.with_extension(format!(
        "{}part",
        dest.extension()
            .map(|e| format!("{}.", e.to_string_lossy()))
            .unwrap_or_default()
    ));
    if let Err(e) = std::fs::write(&part, &blob.bytes) {
        let _ = std::fs::remove_file(&part);
        return Ok(ApiResponse::error(format!(
            "Failed to write backup file: {e}"
        )));
    }
    if let Err(e) = std::fs::rename(&part, dest) {
        let _ = std::fs::remove_file(&part);
        return Ok(ApiResponse::error(format!(
            "Failed to finalize backup file: {e}"
        )));
    }

    let exported_at = chrono::Utc::now().to_rfc3339();
    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.settings.backup = Some(persona_core::models::workspace::BackupEvidence {
        exported_at: exported_at.clone(),
        destination: "file".to_string(),
        size_bytes: blob.size_bytes,
    });
    ws.touch();
    ok_or_error_response!(repo.update(&ws).await);

    Ok(ApiResponse::success(BackupExportOutcome {
        path: request.path,
        size_bytes: blob.size_bytes,
        sha256: blob.sha256,
        exported_at,
    }))
}

/// `backup_restore_from_file` 请求：本地备份文件路径 + 备份口令。
/// 口令是既有的（导出时用户自定）——不做双录，前端仍应二次确认。
#[derive(Debug, Deserialize)]
pub struct BackupRestoreRequest {
    pub path: String,
    pub passphrase: String,
}

/// 恢复结果：原库副本 `.bak` 的路径（原库不存在 = 无副本，None）。
#[derive(Debug, Serialize)]
pub struct BackupRestoreOutcome {
    pub backup_copy: Option<String>,
}

/// 从本地文件恢复整库（S5 自救口第二批，与 CLI `restore --file` 同语义）。
///
/// 失败口径分两段：
/// - **口令错 / 文件坏 / 头校验失败**：staged `.restore.tmp` 复验阶段就
///   报错——现有库分毫未动、会话不受影响（`current vault was not
///   touched`）。
/// - **换库段**（staged 成功后）：① 排空——先取下 `service` 槽位（drop
///   活跃连接池；正跑持锁的命令等它自然跑完），再**持有 `db_path` 锁到
///   rename 完成**——期间其他需要开库的命令一律排队（这是「连接排空
///   约束」的两半，未排空在 Windows 上 rename 会撞 Access denied）；
///   ② 原库 `fs::copy` 成 `.bak`（留存对价）；③ staged → 原路径同目录
///   原子 rename。
///
/// 换库后 `service` 保持未初始化：恢复出的库主密码可能与当前会话不同，
/// 由前端 `checkServiceStatus` → 解锁屏 → `init_service` 重新走解锁。
/// 命令不持有主密码无法代答；换库段失败同口径（库已保全/未动，会话降锁）。
///
/// staged 复验与换库段都在 [`restore_vault_staged`]（与服务器恢复共用）。
#[command(rename_all = "snake_case")]
pub async fn backup_restore_from_file(
    request: BackupRestoreRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BackupRestoreOutcome>, String> {
    if request.passphrase.is_empty() {
        return Ok(ApiResponse::error(
            "Backup passphrase must not be empty".to_string(),
        ));
    }
    if request.path.trim().is_empty() {
        return Ok(ApiResponse::error(
            "Backup file path must not be empty".to_string(),
        ));
    }
    let src = std::path::Path::new(&request.path);
    if !src.is_file() {
        return Ok(ApiResponse::error(format!(
            "Backup file not found: {}",
            src.display()
        )));
    }
    let ciphertext = match std::fs::read(src) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Failed to read backup file: {e}"
            )))
        }
    };
    let backup_copy =
        ok_or_error_response!(restore_vault_staged(&state, &ciphertext, &request.passphrase).await);
    Ok(ApiResponse::success(BackupRestoreOutcome { backup_copy }))
}

/// staged 复验 + 换库段的共享实现（文件恢复与服务器恢复同语义，见
/// `backup_restore_from_file` 文档）。
///
/// 失败返回用户可读消息（`Ok(ApiResponse::error)` 口径由调用方包一层）：
/// - staged 复验失败 → 现有库分毫未动、会话不受影响（`was not touched`）；
/// - 换库段失败 → 原库已保全为 `.bak` / 未动（`restore aborted` / `.bak`）。
///
/// 成功返回原库 `.bak` 副本路径（原库不存在 = `None`），且 `service` 槽位
/// 已取下（由调用方驱动前端回解锁屏重新走 `init_service`）。
pub(crate) async fn restore_vault_staged(
    state: &State<'_, AppState>,
    ciphertext: &[u8],
    passphrase: &str,
) -> std::result::Result<Option<String>, String> {
    let db_path = match require_db_path(state).await {
        Some(db_path) => db_path,
        None => return Err("Database path unavailable. Initialize the service first.".to_string()),
    };

    // staged 复验：解密 + gzip + SQLite 头校验写到同目录 `.restore.tmp`。
    // 这一步只碰 staged 文件——失败时现有库与会话都不受影响。
    let mut staged = std::path::PathBuf::from(&db_path);
    staged.set_extension("restore.tmp");
    if let Err(e) = persona_core::backup::restore_backup_bytes(ciphertext, passphrase, &staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(format!(
            "Backup restore failed; the current vault was not touched: {e}"
        ));
    }

    // ---- 换库段：排空（service 取下在前，db_path 闸持到 rename 完成）----
    *state.service.lock().await = None;
    let db_path_guard = state.db_path.lock().await;
    let db_path = db_path_guard.clone().unwrap_or(db_path);
    let dbp = std::path::Path::new(&db_path);

    if let Some(parent) = dbp.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "Failed to prepare vault directory; restore aborted: {e}"
            ));
        }
    }

    let mut backup_copy = None;
    if dbp.exists() {
        let mut bak = std::path::PathBuf::from(&db_path);
        bak.set_extension("bak");
        if let Err(e) = std::fs::copy(dbp, &bak) {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "Failed to back up the current vault; restore aborted: {e}"
            ));
        }
        backup_copy = Some(bak.to_string_lossy().to_string());
    }
    if let Err(e) = std::fs::rename(&staged, dbp) {
        let _ = std::fs::remove_file(&staged);
        return Err(format!(
            "Failed to move the restored file into place; the previous vault is kept as .bak: {e}"
        ));
    }
    drop(db_path_guard);

    Ok(backup_copy)
}

/// `backup_push_to_server` 请求：备份口令。服务器收到的已是密文
/// （VACUUM INTO 快照 → gzip → 口令加密），口令与主密码永不离开本机。
#[derive(Debug, Deserialize)]
pub struct BackupPushRequest {
    pub passphrase: String,
}

/// 推送结果：服务器返回的元数据（`PushResult` 镜像）+ 本地导出凭证时刻。
#[derive(Debug, Serialize)]
pub struct BackupPushOutcome {
    pub backup_id: String,
    pub device_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: String,
    /// 同设备最新版本 sha256 相同时服务器去重（200），未产生新版本。
    pub deduplicated: bool,
    pub exported_at: String,
}

/// 整库加密备份推送到服务器密文仓（S5-d，与 CLI `backup push` 同语义）。
///
/// 流程：快照加密（同文件导出）→ `BackupClient.push`（token 由
/// settings.sync + OS keyring 提供）→ 导出凭证（`destination: "server"`）
/// 写入 workspace settings。要求已解锁（快照需要读库；与文件导出同门禁）。
#[command(rename_all = "snake_case")]
pub async fn backup_push_to_server(
    request: BackupPushRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BackupPushOutcome>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    if request.passphrase.is_empty() {
        return Ok(ApiResponse::error(
            "Backup passphrase must not be empty".to_string(),
        ));
    }
    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);

    let blob = ok_or_error_response_ctx!(
        persona_core::backup::create_backup_bytes(db.pool(), &request.passphrase, None).await,
        "Failed to create backup: {}"
    );

    let (server_url, token) = ok_or_error_response!(sync_server_creds_for(&state).await);
    let client = ok_or_error_response_ctx!(
        persona_core::backup::BackupClient::new(&server_url, token),
        "Invalid sync server configuration: {}"
    );
    let pushed = ok_or_error_response_ctx!(
        client.push(&blob.bytes).await,
        "Failed to push backup to server: {}"
    );

    let exported_at = chrono::Utc::now().to_rfc3339();
    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.settings.backup = Some(persona_core::models::workspace::BackupEvidence {
        exported_at: exported_at.clone(),
        destination: "server".to_string(),
        size_bytes: blob.size_bytes,
    });
    ws.touch();
    ok_or_error_response!(repo.update(&ws).await);

    Ok(ApiResponse::success(BackupPushOutcome {
        backup_id: pushed.id,
        device_name: pushed.device_name,
        size_bytes: pushed.size_bytes,
        sha256: pushed.sha256,
        created_at: pushed.created_at,
        deduplicated: pushed.deduplicated,
        exported_at,
    }))
}

/// `backup_list_server_versions` 请求：页大小（1-100，缺省 20）。
#[derive(Debug, Deserialize)]
pub struct BackupServerListRequest {
    #[serde(default)]
    pub limit: Option<u32>,
}

/// 服务器侧备份版本的桌面视图（`BackupMeta` 镜像，id 改名 backup_id）。
#[derive(Debug, Serialize)]
pub struct BackupVersionView {
    pub backup_id: String,
    pub device_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: String,
}

/// 列出服务器密文仓的备份版本（倒序：新→旧）。
///
/// 免解锁：锁屏救库也要能先看服务器上有哪些版本（与恢复同门禁——只要
/// db_path 已知 + sync 配置齐备）。
#[command(rename_all = "snake_case")]
pub async fn backup_list_server_versions(
    request: BackupServerListRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<BackupVersionView>>, String> {
    let limit = request.limit.unwrap_or(20).clamp(1, 100);
    let (server_url, token) = ok_or_error_response!(sync_server_creds_for(&state).await);
    let client = ok_or_error_response_ctx!(
        persona_core::backup::BackupClient::new(&server_url, token),
        "Invalid sync server configuration: {}"
    );
    let page = ok_or_error_response_ctx!(
        client.list(limit, None).await,
        "Failed to list server backups: {}"
    );
    Ok(ApiResponse::success(
        page.backups
            .into_iter()
            .map(|meta| BackupVersionView {
                backup_id: meta.id,
                device_name: meta.device_name,
                size_bytes: meta.size_bytes,
                sha256: meta.sha256,
                created_at: meta.created_at,
            })
            .collect(),
    ))
}

/// `backup_restore_from_server` 请求：备份 ID + 备份口令。
#[derive(Debug, Deserialize)]
pub struct BackupServerRestoreRequest {
    pub backup_id: String,
    pub passphrase: String,
}

/// 从服务器密文仓恢复整库（S5-d，与 CLI `backup pull` + `restore --file`
/// 组合同语义）。
///
/// 免解锁（锁屏救库是核心场景，与文件恢复的锁定态自救同口径），但要求
/// db_path 已知。下载即做 ETag sha256 完整性自检（`BackupClient` 内）；
/// staged 复验失败库不动、换库段排空 + `.bak` 保全，全部走
/// [`restore_vault_staged`]。
#[command(rename_all = "snake_case")]
pub async fn backup_restore_from_server(
    request: BackupServerRestoreRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BackupRestoreOutcome>, String> {
    if request.passphrase.is_empty() {
        return Ok(ApiResponse::error(
            "Backup passphrase must not be empty".to_string(),
        ));
    }
    if request.backup_id.trim().is_empty() {
        return Ok(ApiResponse::error(
            "Backup ID must not be empty".to_string(),
        ));
    }
    // 门禁前置：db_path 未知时立刻拒（restore_vault_staged 内会再取一次）
    let _ = db_path_or_return!(state);
    let (server_url, token) = ok_or_error_response!(sync_server_creds_for(&state).await);
    let client = ok_or_error_response_ctx!(
        persona_core::backup::BackupClient::new(&server_url, token),
        "Invalid sync server configuration: {}"
    );
    let downloaded = ok_or_error_response_ctx!(
        client.download(request.backup_id.trim()).await,
        "Failed to download backup from server: {}"
    );
    let backup_copy = ok_or_error_response!(
        restore_vault_staged(&state, &downloaded.bytes, &request.passphrase).await
    );
    Ok(ApiResponse::success(BackupRestoreOutcome { backup_copy }))
}

/// `backup_delete_server_version` 请求：备份 ID。
#[derive(Debug, Deserialize)]
pub struct BackupServerDeleteRequest {
    pub backup_id: String,
}

/// 删除结果（服务器 404 幂等视为成功，`deleted` 恒 true）。
#[derive(Debug, Serialize)]
pub struct BackupServerDeleteOutcome {
    pub deleted: bool,
}

/// 删除服务器上的备份版本（幂等：已删除时 404 视为成功）。免解锁。
#[command(rename_all = "snake_case")]
pub async fn backup_delete_server_version(
    request: BackupServerDeleteRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<BackupServerDeleteOutcome>, String> {
    if request.backup_id.trim().is_empty() {
        return Ok(ApiResponse::error(
            "Backup ID must not be empty".to_string(),
        ));
    }
    let (server_url, token) = ok_or_error_response!(sync_server_creds_for(&state).await);
    let client = ok_or_error_response_ctx!(
        persona_core::backup::BackupClient::new(&server_url, token),
        "Invalid sync server configuration: {}"
    );
    ok_or_error_response_ctx!(
        client.delete(request.backup_id.trim()).await,
        "Failed to delete server backup: {}"
    );
    Ok(ApiResponse::success(BackupServerDeleteOutcome {
        deleted: true,
    }))
}
