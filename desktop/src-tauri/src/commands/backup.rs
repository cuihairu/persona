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

/// `backup_export_to_file` request: destination file path + backup passphrase.
///
/// The backup passphrase is fully independent of the master password
/// (design spec §6.5: the primary vault is never decrypted and the master
/// password never enters the backup chain); strength requirements are the
/// frontend's job, the backend only checks non-emptiness. The passphrase
/// itself is never written to disk.
#[derive(Debug, Deserialize)]
pub struct BackupExportRequest {
    pub path: String,
    pub passphrase: String,
}

/// Export result (non-sensitive metadata, reconciled against the
/// WorkspaceSettings.backup BackupEvidence).
#[derive(Debug, Serialize)]
pub struct BackupExportOutcome {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub exported_at: String,
}

/// Export a full encrypted vault backup to a local file (first batch of the
/// S5 self-rescue exits).
///
/// Flow: VACUUM INTO snapshot -> gzip -> passphrase encryption -> a
/// same-directory `.part` temp file + rename for an atomic landing -> the
/// export evidence (BackupEvidence) written into workspace settings. The
/// primary vault is never decrypted and no master password is needed; a
/// mid-export failure does not destroy the previous backup file.
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

    // Atomic landing: `backup.enc` -> `backup.enc.part`, renamed once fully
    // written; a mid-flight failure (disk full / process killed) leaves the
    // previous file untouched
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

/// `backup_restore_from_file` request: local backup file path + backup
/// passphrase. The passphrase is the existing one (chosen by the user at
/// export time) — no double-entry here; the frontend should still confirm.
#[derive(Debug, Deserialize)]
pub struct BackupRestoreRequest {
    pub path: String,
    pub passphrase: String,
}

/// Restore result: the path of the original vault's `.bak` copy (no copy was
/// made when the vault did not exist -> None).
#[derive(Debug, Serialize)]
pub struct BackupRestoreOutcome {
    pub backup_copy: Option<String>,
}

/// Restore the full vault from a local file (second batch of the S5
/// self-rescue exits, same semantics as the CLI `restore --file`).
///
/// Failure behavior is split into two phases:
/// - **Wrong passphrase / corrupt file / header check failure**: errors out
///   at the staged `.restore.tmp` re-verification stage — the current vault
///   is untouched and the session unaffected (`current vault was not
///   touched`).
/// - **Vault-swap phase** (after staging succeeds): (1) drain — first take
///   down the `service` slot (dropping the active connection pool; commands
///   already holding the lock run to completion naturally), then **hold the
///   `db_path` lock until the rename completes** — other commands that need
///   to open the vault queue in the meantime (these are the two halves of
///   the "connection drain constraint"; without draining, the rename hits
///   Access denied on Windows); (2) `fs::copy` the original vault to
///   `.bak` (preservation hedge); (3) atomically rename the staged file
///   over the original path in the same directory.
///
/// After the swap `service` stays uninitialized: the restored vault's
/// master password may differ from the current session, so the frontend
/// goes through `checkServiceStatus` -> unlock screen -> `init_service`
/// to re-unlock. The command does not hold the master password and cannot
/// answer on the user's behalf; a vault-swap failure follows the same
/// convention (vault preserved or untouched, session downgraded to locked).
///
/// Both the staged re-verification and the vault swap live in
/// [`restore_vault_staged`] (shared with the server restore).
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

/// Shared implementation of the staged re-verification + vault swap (same
/// semantics for file and server restore, see the
/// `backup_restore_from_file` docs).
///
/// On failure returns a user-readable message (the caller wraps it into the
/// `Ok(ApiResponse::error)` convention):
/// - staged re-verification failure -> the current vault is untouched and
///   the session unaffected (`was not touched`);
/// - vault-swap failure -> the original vault was preserved as `.bak` /
///   untouched (`restore aborted` / `.bak`).
///
/// On success returns the original vault's `.bak` copy path (`None` when the
/// vault did not exist), and the `service` slot has been taken down (the
/// caller drives the frontend back to the unlock screen to run
/// `init_service` again).
pub(crate) async fn restore_vault_staged(
    state: &State<'_, AppState>,
    ciphertext: &[u8],
    passphrase: &str,
) -> std::result::Result<Option<String>, String> {
    let db_path = match require_db_path(state).await {
        Some(db_path) => db_path,
        None => return Err("Database path unavailable. Initialize the service first.".to_string()),
    };

    // Staged re-verification: decrypt + gunzip + SQLite header check written
    // to a same-directory `.restore.tmp`. This step only touches the staged
    // file — on failure the current vault and session are unaffected.
    let mut staged = std::path::PathBuf::from(&db_path);
    staged.set_extension("restore.tmp");
    if let Err(e) = persona_core::backup::restore_backup_bytes(ciphertext, passphrase, &staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(format!(
            "Backup restore failed; the current vault was not touched: {e}"
        ));
    }

    // ---- Vault-swap phase: drain (service taken down first; the db_path
    // gate is held until the rename completes) ----
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

/// `backup_push_to_server` request: backup passphrase. What the server
/// receives is already ciphertext (VACUUM INTO snapshot -> gzip ->
/// passphrase encryption); the passphrase and master password never leave
/// this machine.
#[derive(Debug, Deserialize)]
pub struct BackupPushRequest {
    pub passphrase: String,
}

/// Push result: the server-returned metadata (a `PushResult` mirror) plus
/// the local export-evidence timestamp.
#[derive(Debug, Serialize)]
pub struct BackupPushOutcome {
    pub backup_id: String,
    pub device_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: String,
    /// The server deduplicated (200) because it matched the newest version's
    /// sha256 for the same device; no new version was created.
    pub deduplicated: bool,
    pub exported_at: String,
}

/// Push the full encrypted vault backup to the server ciphertext store
/// (S5-d, same semantics as the CLI `backup push`).
///
/// Flow: snapshot encryption (same as the file export) -> `BackupClient.push`
/// (token from settings.sync + OS keyring) -> export evidence
/// (`destination: "server"`) written into workspace settings. Requires being
/// unlocked (the snapshot needs to read the vault; same gate as the file
/// export).
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

/// `backup_list_server_versions` request: page size (1-100, default 20).
#[derive(Debug, Deserialize)]
pub struct BackupServerListRequest {
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Desktop view of server-side backup versions (a `BackupMeta` mirror with
/// id renamed to backup_id).
#[derive(Debug, Serialize)]
pub struct BackupVersionView {
    pub backup_id: String,
    pub device_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: String,
}

/// List backup versions in the server ciphertext store (newest first).
///
/// No unlock required: even from the lock screen you need to see which
/// versions exist on the server before rescuing the vault (same gate as
/// restore — only db_path known + sync configuration complete).
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

/// `backup_restore_from_server` request: backup ID + backup passphrase.
#[derive(Debug, Deserialize)]
pub struct BackupServerRestoreRequest {
    pub backup_id: String,
    pub passphrase: String,
}

/// Restore the full vault from the server ciphertext store (S5-d, same
/// semantics as the CLI `backup pull` + `restore --file` combination).
///
/// No unlock required (rescuing the vault from the lock screen is the core
/// scenario, same convention as the locked-state self-rescue of the file
/// restore), but db_path must be known. The download performs an ETag
/// sha256 integrity self-check (inside `BackupClient`); a staged
/// re-verification failure leaves the vault untouched, and the vault-swap
/// phase drains + preserves a `.bak` — all handled by
/// [`restore_vault_staged`].
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
    // Gate first: reject immediately when db_path is unknown
    // (restore_vault_staged will fetch it again)
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

/// `backup_delete_server_version` request: backup ID.
#[derive(Debug, Deserialize)]
pub struct BackupServerDeleteRequest {
    pub backup_id: String,
}

/// Delete result (a server 404 is treated as idempotent success; `deleted`
/// is always true).
#[derive(Debug, Serialize)]
pub struct BackupServerDeleteOutcome {
    pub deleted: bool,
}

/// Delete a backup version on the server (idempotent: a 404 for an already
/// deleted version counts as success). No unlock required.
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
