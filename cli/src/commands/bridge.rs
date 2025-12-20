use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use clap::Args;
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha2::Sha256;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};
use url::Url;

use persona_core::models::{CredentialData, CredentialType, TwoFactorData};
use persona_core::storage::{CredentialRepository, WorkspaceRepository};
use persona_core::{Database, PersonaService, Repository};

/// Native Messaging host for the Persona browser extension.
///
/// Chrome Native Messaging uses 4-byte little-endian length prefix followed by a UTF-8 JSON payload.
/// This command implements a minimal "Bridge Protocol v1" so the extension can query status and
/// request autofill suggestions from the local vault.
#[derive(Args, Clone)]
pub struct BridgeArgs {
    /// Path to the Persona SQLite database file.
    ///
    /// If omitted, uses `PERSONA_DB_PATH` or `~/.persona/identities.db`.
    #[arg(long)]
    pub db_path: Option<PathBuf>,

    /// Approve a pending pairing request by code (prints result then exits).
    #[arg(long)]
    pub approve_code: Option<String>,

    /// Directory used to persist bridge pairing state.
    ///
    /// If omitted, uses `PERSONA_BRIDGE_STATE_DIR` or `~/.persona/bridge`.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct BridgeRequest {
    #[serde(default)]
    request_id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    payload: serde_json::Value,
    #[serde(default)]
    auth: Option<BridgeAuth>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct BridgeResponse<T: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct BridgeAuth {
    /// Session ID issued by the native host in `hello_response`.
    #[serde(default)]
    session_id: Option<String>,
    /// Milliseconds since UNIX epoch (client clock).
    ts_ms: i64,
    /// Unique nonce per request.
    nonce: String,
    /// Base64url(no-pad) HMAC-SHA256 signature.
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct HelloPayload {
    extension_id: String,
    #[serde(default)]
    extension_version: Option<String>,
    #[serde(default)]
    protocol_version: Option<u32>,
    #[serde(default)]
    client_instance_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PairingRequestPayload {
    extension_id: String,
    client_instance_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PairingFinalizePayload {
    extension_id: String,
    client_instance_id: String,
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SuggestionsPayload {
    origin: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct SuggestionItem {
    item_id: String,
    title: String,
    username_hint: Option<String>,
    match_strength: u8,
    credential_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct SuggestionsResponse {
    items: Vec<SuggestionItem>,
    suggesting_for: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FillPayload {
    origin: String,
    item_id: String,
    /// Indicates this request was triggered by an explicit user action (click, keyboard).
    /// Required for fill operations to prevent background credential exfiltration.
    #[serde(default)]
    user_gesture: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct FillResponse {
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct TotpPayload {
    origin: String,
    item_id: String,
    /// Indicates this request was triggered by an explicit user action (click, keyboard).
    #[serde(default)]
    user_gesture: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct TotpResponse {
    code: String,
    remaining_seconds: u32,
    period: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct CopyPayload {
    origin: String,
    item_id: String,
    field: String,
    /// Indicates this request was triggered by an explicit user action (click, keyboard).
    #[serde(default)]
    user_gesture: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct CopyResponse {
    copied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    clear_after_seconds: Option<u32>,
}

pub async fn execute(args: BridgeArgs) -> Result<()> {
    let db_path = resolve_db_path(args.db_path);
    let state_dir = resolve_state_dir(args.state_dir);

    if let Some(code) = args.approve_code {
        approve_pairing(&state_dir, &code)?;
        return Ok(());
    }

    // Read/write raw protocol frames over stdio.
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    loop {
        let frame = match read_frame(&mut stdin).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break, // EOF
            Err(e) => {
                // If stdin is malformed, there's not much to do besides exit.
                return Err(e);
            }
        };

        let req: BridgeRequest = match serde_json::from_slice(&frame) {
            Ok(req) => req,
            Err(e) => {
                let resp = BridgeResponse::<serde_json::Value> {
                    request_id: None,
                    kind: "error".to_string(),
                    ok: false,
                    error: Some(format!("invalid_json: {e}")),
                    payload: None,
                };
                write_frame(&mut stdout, &resp).await?;
                continue;
            }
        };

        let request_id = req.request_id.clone();
        let resp = handle_request(&db_path, &state_dir, req)
            .await
            .unwrap_or_else(|e| BridgeResponse::<serde_json::Value> {
                request_id,
                kind: "error".to_string(),
                ok: false,
                error: Some(e.to_string()),
                payload: None,
            });

        write_frame(&mut stdout, &resp).await?;
    }

    Ok(())
}

async fn handle_request(
    db_path: &PathBuf,
    state_dir: &PathBuf,
    req: BridgeRequest,
) -> Result<BridgeResponse<serde_json::Value>> {
    match req.kind.as_str() {
        "hello" => {
            let parsed: HelloPayload =
                serde_json::from_value(req.payload).context("invalid payload for hello")?;

            let require_pairing = std::env::var("PERSONA_BRIDGE_REQUIRE_PAIRING")
                .map(|v| v != "0" && v.to_lowercase() != "false")
                .unwrap_or(true);

            let client_instance_id = parsed.client_instance_id.clone().unwrap_or_default();

            let session = if require_pairing && !client_instance_id.is_empty() {
                ensure_session(state_dir, &parsed.extension_id, &client_instance_id)?
            } else {
                None
            };

            let payload = serde_json::json!({
                "server_version": "0.1.0",
                "capabilities": ["status", "pairing_request", "pairing_finalize", "get_suggestions", "request_fill", "get_totp", "copy"],
                "pairing_required": require_pairing && session.is_none(),
                "paired": session.is_some(),
                "session_id": session.as_ref().map(|s| s.session_id.clone()),
                "session_expires_at_ms": session.as_ref().map(|s| s.expires_at_ms),
            });
            Ok(ok(req.request_id, "hello_response", payload))
        }
        "status" => {
            let (locked, active_identity) = compute_status(db_path).await?;
            let payload = serde_json::json!({
                "locked": locked,
                "active_identity": active_identity
            });
            Ok(ok(req.request_id, "status_response", payload))
        }
        "pairing_request" => {
            let parsed: PairingRequestPayload = serde_json::from_value(req.payload)
                .context("invalid payload for pairing_request")?;
            let pending = create_pairing_request(state_dir, parsed)?;
            let payload = serde_json::json!({
                "code": pending.code,
                "expires_at_ms": pending.expires_at_ms,
                "approval_command": format!("persona bridge --approve-code {}", pending.code),
            });
            Ok(ok(req.request_id, "pairing_response", payload))
        }
        "pairing_finalize" => {
            let parsed: PairingFinalizePayload = serde_json::from_value(req.payload)
                .context("invalid payload for pairing_finalize")?;
            let pairing = finalize_pairing(state_dir, parsed)?;
            let session = pairing
                .session
                .as_ref()
                .ok_or_else(|| anyhow!("internal_error: missing session after pairing"))?;
            let payload = serde_json::json!({
                "paired": true,
                "pairing_key_b64": pairing.key_b64,
                "session_id": session.session_id,
                "session_expires_at_ms": session.expires_at_ms,
            });
            Ok(ok(req.request_id, "pairing_finalize_response", payload))
        }
        "get_suggestions" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: SuggestionsPayload = serde_json::from_value(req.payload)
                .context("invalid payload for get_suggestions")?;
            let host = origin_to_host(&parsed.origin)?;
            let items = get_credential_suggestions(db_path, &host).await?;
            let payload = serde_json::to_value(SuggestionsResponse {
                items,
                suggesting_for: host,
            })?;
            Ok(ok(req.request_id, "suggestions_response", payload))
        }
        "request_fill" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: FillPayload =
                serde_json::from_value(req.payload).context("invalid payload for request_fill")?;
            let host = origin_to_host(&parsed.origin)?;

            // Security: Require user gesture for fill operations.
            // This prevents malicious scripts from silently exfiltrating credentials.
            let require_gesture = std::env::var("PERSONA_BRIDGE_REQUIRE_GESTURE")
                .map(|v| v != "0" && v.to_lowercase() != "false")
                .unwrap_or(true); // Default: require gesture

            if require_gesture && !parsed.user_gesture {
                warn!(
                    origin = %parsed.origin,
                    item_id = %parsed.item_id,
                    "fill request rejected: user_gesture required but not provided"
                );
                return Err(anyhow!("user_gesture_required: fill operations must be triggered by explicit user action"));
            }

            // For now, require a master password via environment variable for automation.
            // In the 1Password-like model, this step should be delegated to Desktop (UI + biometrics).
            let master_password = std::env::var("PERSONA_MASTER_PASSWORD")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| anyhow!("locked: PERSONA_MASTER_PASSWORD not set"))?;

            // Open DB + unlock.
            let db = open_db(db_path).await?;
            let active_identity_id = get_active_identity_id(&db).await;
            let mut service = PersonaService::new(db)
                .await
                .map_err(|e| anyhow!("failed to create service: {e}"))?;
            let auth = service.authenticate_user(&master_password).await?;
            if auth != persona_core::auth::authentication::AuthResult::Success {
                return Err(anyhow!("authentication_failed"));
            }

            // Fetch decrypted credential data.
            let item_id = uuid::Uuid::parse_str(&parsed.item_id)
                .map_err(|e| anyhow!("invalid item_id uuid: {e}"))?;
            let data = service
                .get_credential_data(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;

            // Only allow filling password credentials.
            let cred = service
                .get_credential(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;
            if let Some(active) = active_identity_id {
                if cred.identity_id != active {
                    return Err(anyhow!("wrong_identity: switch active identity to access this credential"));
                }
            }
            if cred.credential_type != CredentialType::Password {
                return Err(anyhow!("unsupported_credential_type"));
            }

            // Security: Origin binding - verify the request origin matches the credential's URL.
            let origin_valid = validate_origin_binding(&host, cred.url.as_deref());
            if !origin_valid {
                warn!(
                    origin = %parsed.origin,
                    host = %host,
                    cred_url = ?cred.url,
                    item_id = %parsed.item_id,
                    "fill request rejected: origin mismatch"
                );
                return Err(anyhow!(
                    "origin_mismatch: request origin does not match credential URL"
                ));
            }

            let fill = match data {
                CredentialData::Password(p) => FillResponse {
                    username: cred.username.clone().or(p.email.clone()),
                    password: Some(p.password),
                },
                CredentialData::Raw(_) => FillResponse {
                    username: cred.username.clone(),
                    password: None,
                },
                _ => FillResponse {
                    username: cred.username.clone(),
                    password: None,
                },
            };

            // Audit log: successful fill
            info!(
                event = "bridge_fill_success",
                origin = %parsed.origin,
                host = %host,
                item_id = %parsed.item_id,
                item_name = %cred.name,
                user_gesture = parsed.user_gesture,
                "credential fill completed"
            );

            let payload = serde_json::to_value(fill)?;
            Ok(ok(req.request_id, "fill_response", payload))
        }
        "get_totp" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: TotpPayload =
                serde_json::from_value(req.payload).context("invalid payload for get_totp")?;
            let host = origin_to_host(&parsed.origin)?;

            let require_gesture = std::env::var("PERSONA_BRIDGE_REQUIRE_GESTURE")
                .map(|v| v != "0" && v.to_lowercase() != "false")
                .unwrap_or(true);
            if require_gesture && !parsed.user_gesture {
                warn!(
                    origin = %parsed.origin,
                    item_id = %parsed.item_id,
                    "totp request rejected: user_gesture required but not provided"
                );
                return Err(anyhow!("user_gesture_required: totp must be triggered by explicit user action"));
            }

            let master_password = std::env::var("PERSONA_MASTER_PASSWORD")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| anyhow!("locked: PERSONA_MASTER_PASSWORD not set"))?;

            let db = open_db(db_path).await?;
            let active_identity_id = get_active_identity_id(&db).await;
            let mut service = PersonaService::new(db)
                .await
                .map_err(|e| anyhow!("failed to create service: {e}"))?;
            let auth = service.authenticate_user(&master_password).await?;
            if auth != persona_core::auth::authentication::AuthResult::Success {
                return Err(anyhow!("authentication_failed"));
            }

            let item_id = uuid::Uuid::parse_str(&parsed.item_id)
                .map_err(|e| anyhow!("invalid item_id uuid: {e}"))?;

            let cred = service
                .get_credential(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;
            if let Some(active) = active_identity_id {
                if cred.identity_id != active {
                    return Err(anyhow!("wrong_identity: switch active identity to access this credential"));
                }
            }
            if cred.credential_type != CredentialType::TwoFactor {
                return Err(anyhow!("unsupported_credential_type"));
            }

            if cred.url.is_none() {
                return Err(anyhow!("origin_binding_required: totp entries must have a URL set"));
            }

            if !validate_origin_binding(&host, cred.url.as_deref()) {
                warn!(
                    origin = %parsed.origin,
                    host = %host,
                    cred_url = ?cred.url,
                    item_id = %parsed.item_id,
                    "totp request rejected: origin mismatch"
                );
                return Err(anyhow!(
                    "origin_mismatch: request origin does not match credential URL"
                ));
            }

            let data = service
                .get_credential_data(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;

            let tf = match data {
                CredentialData::TwoFactor(tf) => tf,
                _ => return Err(anyhow!("unsupported_credential_type")),
            };

            let (code, remaining_seconds, period) = generate_totp_code_from_data(&tf)?;

            info!(
                event = "bridge_totp_success",
                origin = %parsed.origin,
                host = %host,
                item_id = %parsed.item_id,
                item_name = %cred.name,
                "totp code generated"
            );

            Ok(ok(
                req.request_id,
                "totp_response",
                serde_json::to_value(TotpResponse {
                    code,
                    remaining_seconds,
                    period,
                })?,
            ))
        }
        "copy" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: CopyPayload =
                serde_json::from_value(req.payload).context("invalid payload for copy")?;

            let require_gesture = std::env::var("PERSONA_BRIDGE_REQUIRE_GESTURE")
                .map(|v| v != "0" && v.to_lowercase() != "false")
                .unwrap_or(true);

            if require_gesture && !parsed.user_gesture {
                warn!(
                    origin = %parsed.origin,
                    item_id = %parsed.item_id,
                    field = %parsed.field,
                    "copy request rejected: user_gesture required but not provided"
                );
                return Err(anyhow!("user_gesture_required: copy must be triggered by explicit user action"));
            }

            let host = origin_to_host(&parsed.origin)?;
            let field = parsed.field.trim().to_ascii_lowercase();

            let master_password = std::env::var("PERSONA_MASTER_PASSWORD")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| anyhow!("locked: PERSONA_MASTER_PASSWORD not set"))?;

            let db = open_db(db_path).await?;
            let active_identity_id = get_active_identity_id(&db).await;
            let mut service = PersonaService::new(db)
                .await
                .map_err(|e| anyhow!("failed to create service: {e}"))?;
            let auth = service.authenticate_user(&master_password).await?;
            if auth != persona_core::auth::authentication::AuthResult::Success {
                return Err(anyhow!("authentication_failed"));
            }

            let item_id = uuid::Uuid::parse_str(&parsed.item_id)
                .map_err(|e| anyhow!("invalid item_id uuid: {e}"))?;
            let cred = service
                .get_credential(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;
            if let Some(active) = active_identity_id {
                if cred.identity_id != active {
                    return Err(anyhow!("wrong_identity: switch active identity to access this credential"));
                }
            }

            if !validate_origin_binding(&host, cred.url.as_deref()) {
                warn!(
                    origin = %parsed.origin,
                    host = %host,
                    cred_url = ?cred.url,
                    item_id = %parsed.item_id,
                    field = %field,
                    "copy request rejected: origin mismatch"
                );
                return Err(anyhow!(
                    "origin_mismatch: request origin does not match credential URL"
                ));
            }

            let text = match field.as_str() {
                "username" => cred
                    .username
                    .clone()
                    .or_else(|| cred.metadata.get("email").cloned())
                    .ok_or_else(|| anyhow!("not_found: username not available"))?,
                "password" => {
                    if cred.credential_type != CredentialType::Password {
                        return Err(anyhow!("unsupported_credential_type"));
                    }
                    let data = service
                        .get_credential_data(&item_id)
                        .await?
                        .ok_or_else(|| anyhow!("not_found"))?;
                    match data {
                        CredentialData::Password(p) => p.password,
                        _ => return Err(anyhow!("unsupported_credential_type")),
                    }
                }
                "totp" => {
                    if cred.credential_type != CredentialType::TwoFactor {
                        return Err(anyhow!("unsupported_credential_type"));
                    }
                    let data = service
                        .get_credential_data(&item_id)
                        .await?
                        .ok_or_else(|| anyhow!("not_found"))?;
                    let tf = match data {
                        CredentialData::TwoFactor(tf) => tf,
                        _ => return Err(anyhow!("unsupported_credential_type")),
                    };
                    let (code, _remaining, _period) = generate_totp_code_from_data(&tf)?;
                    code
                }
                other => return Err(anyhow!("invalid_payload: unknown field '{other}'")),
            };

            copy_text_to_clipboard(&text)?;

            info!(
                event = "bridge_copy_success",
                origin = %parsed.origin,
                host = %host,
                item_id = %parsed.item_id,
                item_name = %cred.name,
                field = %field,
                "copied to clipboard"
            );

            Ok(ok(
                req.request_id,
                "copy_response",
                serde_json::to_value(CopyResponse {
                    copied: true,
                    clear_after_seconds: None,
                })?,
            ))
        }
        other => Ok(err(
            req.request_id,
            "error",
            format!("unknown_type: {other}"),
        )),
    }
}

fn ok<T: Serialize>(request_id: Option<String>, kind: &str, payload: T) -> BridgeResponse<T> {
    BridgeResponse {
        request_id,
        kind: kind.to_string(),
        ok: true,
        error: None,
        payload: Some(payload),
    }
}

fn err<T: Serialize>(request_id: Option<String>, kind: &str, error: String) -> BridgeResponse<T> {
    BridgeResponse {
        request_id,
        kind: kind.to_string(),
        ok: false,
        error: Some(error),
        payload: None,
    }
}

fn resolve_db_path(override_path: Option<PathBuf>) -> PathBuf {
    override_path
        .or_else(|| std::env::var("PERSONA_DB_PATH").ok().map(PathBuf::from))
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
                .join("identities.db")
        })
}

fn resolve_state_dir(override_path: Option<PathBuf>) -> PathBuf {
    override_path
        .or_else(|| {
            std::env::var("PERSONA_BRIDGE_STATE_DIR")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
                .join("bridge")
        })
}

async fn open_db(db_path: &PathBuf) -> Result<Database> {
    let db = Database::from_file(db_path).await?;
    db.migrate().await?;
    Ok(db)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SessionInfo {
    session_id: String,
    expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PairingInfo {
    extension_id: String,
    client_instance_id: String,
    key_b64: String,
    paired_at_ms: i64,
    #[serde(default)]
    session: Option<SessionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PendingPairing {
    code: String,
    extension_id: String,
    client_instance_id: String,
    key_b64: String,
    requested_at_ms: i64,
    expires_at_ms: i64,
    approved: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct BridgeStateFile {
    version: u32,
    #[serde(default)]
    pairings: Vec<PairingInfo>,
    #[serde(default)]
    pending: Vec<PendingPairing>,
}

fn now_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as i64
}

fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("state.json")
}

fn load_state(state_dir: &Path) -> Result<BridgeStateFile> {
    let path = state_path(state_dir);
    if !path.exists() {
        return Ok(BridgeStateFile {
            version: 1,
            ..Default::default()
        });
    }
    let bytes = fs::read(&path)?;
    let mut state: BridgeStateFile = serde_json::from_slice(&bytes)?;
    if state.version == 0 {
        state.version = 1;
    }
    Ok(state)
}

fn save_state(state_dir: &Path, state: &BridgeStateFile) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = state_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(state)?;
    fs::write(&tmp, data)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn normalize_pairing_code(code: &str) -> String {
    code.trim().replace(' ', "").to_ascii_uppercase()
}

fn purge_expired(state: &mut BridgeStateFile) {
    let now = now_ms();
    state.pending.retain(|p| p.expires_at_ms > now);
    for pairing in &mut state.pairings {
        if let Some(session) = &pairing.session {
            if session.expires_at_ms <= now {
                pairing.session = None;
            }
        }
    }
}

fn load_pairing(
    state_dir: &Path,
    extension_id: &str,
    client_instance_id: &str,
) -> Result<Option<PairingInfo>> {
    let mut state = load_state(state_dir)?;
    purge_expired(&mut state);
    Ok(state
        .pairings
        .into_iter()
        .find(|p| p.extension_id == extension_id && p.client_instance_id == client_instance_id))
}

fn generate_session() -> SessionInfo {
    SessionInfo {
        session_id: uuid::Uuid::new_v4().to_string(),
        expires_at_ms: now_ms() + 24 * 60 * 60 * 1000, // 24h
    }
}

fn ensure_session(
    state_dir: &Path,
    extension_id: &str,
    client_instance_id: &str,
) -> Result<Option<SessionInfo>> {
    let mut state = load_state(state_dir)?;
    purge_expired(&mut state);

    let idx = state.pairings.iter().position(|p| {
        p.extension_id == extension_id && p.client_instance_id == client_instance_id
    });

    let Some(idx) = idx else {
        return Ok(None);
    };

    if state.pairings[idx].session.is_none() {
        state.pairings[idx].session = Some(generate_session());
        save_state(state_dir, &state)?;
    }

    Ok(state.pairings[idx].session.clone())
}

fn require_authenticated_session(state_dir: &Path, req: &BridgeRequest) -> Result<()> {
    let require_pairing = std::env::var("PERSONA_BRIDGE_REQUIRE_PAIRING")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    if !require_pairing {
        // Allow development / local testing without pairing & auth.
        return Ok(());
    }

    let auth = req
        .auth
        .as_ref()
        .ok_or_else(|| anyhow!("pairing_required"))?;
    let session_id = auth
        .session_id
        .as_deref()
        .ok_or_else(|| anyhow!("pairing_required"))?;

    // Reject stale timestamps to reduce replay window.
    let max_skew_ms: i64 = std::env::var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5 * 60 * 1000);
    let skew = (now_ms() - auth.ts_ms).abs();
    if skew > max_skew_ms {
        return Err(anyhow!("authentication_failed: stale timestamp"));
    }

    let mut state = load_state(state_dir)?;
    purge_expired(&mut state);

    let pairing = state
        .pairings
        .iter()
        .find(|p| p.session.as_ref().map(|s| s.session_id.as_str()) == Some(session_id))
        .cloned()
        .ok_or_else(|| anyhow!("session_expired"))?;

    verify_signature(&pairing, req, auth)?;
    Ok(())
}

fn verify_signature(pairing: &PairingInfo, req: &BridgeRequest, auth: &BridgeAuth) -> Result<()> {
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&pairing.key_b64)
        .map_err(|e| anyhow!("authentication_failed: invalid key ({e})"))?;

    let payload_json = serde_json::to_string(&canonicalize_json_value(&req.payload))?;
    let request_id = req.request_id.as_deref().unwrap_or("");
    let session_id = auth.session_id.as_deref().unwrap_or("");

    let signing_input = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.kind, request_id, payload_json, session_id, auth.ts_ms, auth.nonce
    );

    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&auth.signature)
        .map_err(|e| anyhow!("authentication_failed: invalid signature encoding ({e})"))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|e| anyhow!("authentication_failed: invalid hmac key ({e})"))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| anyhow!("authentication_failed"))?;
    Ok(())
}

fn canonicalize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    out.insert(key, canonicalize_json_value(v));
                }
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

fn create_pairing_request(
    state_dir: &Path,
    payload: PairingRequestPayload,
) -> Result<PendingPairing> {
    if payload.extension_id.trim().is_empty() || payload.client_instance_id.trim().is_empty() {
        return Err(anyhow!(
            "invalid_payload: extension_id and client_instance_id are required"
        ));
    }

    let mut state = load_state(state_dir)?;
    purge_expired(&mut state);

    // If already paired, don't create a new pending request.
    if state.pairings.iter().any(|p| {
        p.extension_id == payload.extension_id && p.client_instance_id == payload.client_instance_id
    }) {
        return Err(anyhow!("already_paired"));
    }

    // Create a 6-digit pairing code (formatted as XXX-XXX).
    let mut rng = OsRng;
    let code_num: u32 = (rng.next_u32() % 1_000_000) as u32;
    let code_raw = format!("{code_num:06}");
    let code = format!("{}-{}", &code_raw[0..3], &code_raw[3..6]);

    // Generate a random 32-byte pairing key.
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);

    let pending = PendingPairing {
        code: code.clone(),
        extension_id: payload.extension_id,
        client_instance_id: payload.client_instance_id,
        key_b64,
        requested_at_ms: now_ms(),
        expires_at_ms: now_ms() + 10 * 60 * 1000, // 10 min
        approved: false,
    };

    state.pending.push(pending.clone());
    save_state(state_dir, &state)?;
    Ok(pending)
}

fn approve_pairing(state_dir: &Path, code: &str) -> Result<()> {
    let code = normalize_pairing_code(code);
    let mut state = load_state(state_dir)?;
    purge_expired(&mut state);

    let pending = state
        .pending
        .iter_mut()
        .find(|p| normalize_pairing_code(&p.code) == code)
        .ok_or_else(|| anyhow!("pairing_not_found_or_expired"))?;

    pending.approved = true;
    let (approved_code, extension_id, client_instance_id) = (
        pending.code.clone(),
        pending.extension_id.clone(),
        pending.client_instance_id.clone(),
    );
    save_state(state_dir, &state)?;

    println!(
        "Approved Persona bridge pairing: code={} extension_id={} client_instance_id={}",
        approved_code, extension_id, client_instance_id
    );
    Ok(())
}

fn finalize_pairing(state_dir: &Path, payload: PairingFinalizePayload) -> Result<PairingInfo> {
    let code = normalize_pairing_code(&payload.code);
    let mut state = load_state(state_dir)?;
    purge_expired(&mut state);

    let pos = state.pending.iter().position(|p| {
        normalize_pairing_code(&p.code) == code
            && p.extension_id == payload.extension_id
            && p.client_instance_id == payload.client_instance_id
    });

    let idx = pos.ok_or_else(|| anyhow!("pairing_not_found_or_expired"))?;
    let pending = state.pending.remove(idx);

    if !pending.approved {
        // Require explicit user approval via `persona bridge --approve-code <code>`.
        return Err(anyhow!("pairing_not_approved"));
    }

    let session = generate_session();
    let pairing = PairingInfo {
        extension_id: pending.extension_id,
        client_instance_id: pending.client_instance_id,
        key_b64: pending.key_b64,
        paired_at_ms: now_ms(),
        session: Some(session.clone()),
    };

    state.pairings.retain(|p| {
        !(p.extension_id == pairing.extension_id
            && p.client_instance_id == pairing.client_instance_id)
    });
    state.pairings.push(pairing.clone());
    save_state(state_dir, &state)?;

    let mut out = pairing.clone();
    out.session = Some(session);
    Ok(out)
}

async fn compute_status(db_path: &PathBuf) -> Result<(bool, Option<String>)> {
    let db = open_db(db_path).await?;
    let mut service = PersonaService::new(db.clone())
        .await
        .map_err(|e| anyhow!("failed to create service: {e}"))?;

    let has_users = service.has_users().await?;
    let locked = if !has_users {
        true
    } else {
        // If a master password is available, try to authenticate to report "unlocked".
        if let Ok(pw) = std::env::var("PERSONA_MASTER_PASSWORD") {
            if !pw.trim().is_empty() {
                let auth = service.authenticate_user(&pw).await?;
                auth != persona_core::auth::authentication::AuthResult::Success
            } else {
                true
            }
        } else {
            true
        }
    };

    // Best-effort active identity from workspace metadata.
    let active_identity = {
        let repo = WorkspaceRepository::new(db);
        // Single-workspace MVP: just pick the first row.
        match repo.find_all().await {
            Ok(mut rows) => rows
                .pop()
                .and_then(|ws| ws.active_identity_id.map(|id| id.to_string())),
            Err(_) => None,
        }
    };

    Ok((locked, active_identity))
}

async fn get_credential_suggestions(db_path: &PathBuf, host: &str) -> Result<Vec<SuggestionItem>> {
    let db = open_db(db_path).await?;
    let active_identity_id = get_active_identity_id(&db).await;
    let repo = CredentialRepository::new(db);
    let all = match active_identity_id {
        Some(identity_id) => repo.find_by_identity(&identity_id).await?,
        None => repo.find_all().await?,
    };

    let mut out = Vec::new();
    for cred in all {
        if !cred.is_active {
            continue;
        }
        let kind = match cred.credential_type {
            CredentialType::Password => "password",
            CredentialType::TwoFactor => "totp",
            _ => continue,
        };

        if cred.url.is_none() {
            continue;
        }

        // Calculate match strength based on URL similarity.
        let match_strength = compute_match_strength(host, cred.url.as_deref().unwrap_or_default());

        if match_strength == 0 {
            continue;
        }

        out.push(SuggestionItem {
            item_id: cred.id.to_string(),
            title: cred.name,
            username_hint: cred.username,
            match_strength,
            credential_type: kind.to_string(),
        });
    }

    // Sort by match strength descending.
    out.sort_by(|a, b| b.match_strength.cmp(&a.match_strength));

    debug!(
        host = %host,
        suggestions = out.len(),
        "password suggestions retrieved"
    );

    Ok(out)
}

async fn get_active_identity_id(db: &Database) -> Option<uuid::Uuid> {
    let repo = WorkspaceRepository::new(db.clone());
    match repo.find_all().await {
        Ok(mut rows) => rows.pop().and_then(|ws| ws.active_identity_id),
        Err(_) => None,
    }
}

/// Compute match strength between request host and credential URL.
///
/// Returns:
/// - 100: Exact host match (e.g., "github.com" == "github.com")
/// - 90: Subdomain match (e.g., "api.github.com" matches "github.com")
/// - 80: Host contained in URL (e.g., "github.com" in "https://github.com/login")
/// - 60: TLD+1 match (e.g., "www.github.com" matches "github.com")
/// - 0: No match
fn compute_match_strength(request_host: &str, cred_url: &str) -> u8 {
    // Extract host from credential URL.
    let cred_host = match Url::parse(cred_url) {
        Ok(url) => url.host_str().map(|s| s.to_lowercase()),
        Err(_) => {
            // Try treating it as a bare hostname.
            Some(cred_url.to_lowercase())
        }
    };

    let cred_host = match cred_host {
        Some(h) => h,
        None => return 0,
    };

    let req_host = request_host.to_lowercase();

    // Exact match.
    if req_host == cred_host {
        return 100;
    }

    // Request is subdomain of credential host (e.g., api.github.com -> github.com).
    if req_host.ends_with(&format!(".{cred_host}")) {
        return 90;
    }

    // Credential is subdomain of request host (e.g., github.com -> www.github.com).
    if cred_host.ends_with(&format!(".{req_host}")) {
        return 90;
    }

    // Check if they share the same registrable domain (TLD+1).
    // Simple heuristic: compare last two parts.
    let req_parts: Vec<&str> = req_host.split('.').collect();
    let cred_parts: Vec<&str> = cred_host.split('.').collect();

    if req_parts.len() >= 2 && cred_parts.len() >= 2 {
        let req_tld1 = format!(
            "{}.{}",
            req_parts[req_parts.len() - 2],
            req_parts[req_parts.len() - 1]
        );
        let cred_tld1 = format!(
            "{}.{}",
            cred_parts[cred_parts.len() - 2],
            cred_parts[cred_parts.len() - 1]
        );

        if req_tld1 == cred_tld1 {
            return 60;
        }
    }

    // Fallback: simple contains check (legacy behavior).
    if cred_url.contains(&req_host) {
        return 80;
    }

    0
}

/// Validate that the request origin is allowed to access the credential.
///
/// Security: This prevents credential filling on mismatched domains.
fn validate_origin_binding(request_host: &str, cred_url: Option<&str>) -> bool {
    let cred_url = match cred_url {
        Some(url) => url,
        // No URL stored = no origin binding (allow any).
        // This is intentional for credentials without a URL.
        None => return true,
    };

    let match_strength = compute_match_strength(request_host, cred_url);

    // Require at least TLD+1 match (60+) for fill operations.
    // This is stricter than suggestions (which show anything > 0).
    match_strength >= 60
}

fn origin_to_host(origin: &str) -> Result<String> {
    // Accept either an origin ("https://example.com") or a full URL.
    let url = Url::parse(origin).or_else(|_| Url::parse(&format!("https://{origin}")))?;
    url.host_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("invalid_origin"))
}

fn generate_totp_code_from_data(data: &TwoFactorData) -> Result<(String, u32, u32)> {
    let secret_bytes = decode_totp_secret(&data.secret_key)?;
    let now = chrono::Utc::now();
    let period = data.period.max(1) as u64;
    let timestamp = now.timestamp().max(0) as u64;
    let counter = timestamp / period;
    let digits = data.digits.clamp(4, 10) as u32;
    let code_num = hotp(&secret_bytes, counter, &data.algorithm)?;
    let modulo = 10_u32.pow(digits);
    let value = code_num % modulo;
    let code = format!("{:0width$}", value, width = digits as usize);
    let remaining = (period - (timestamp % period)) as u32;
    Ok((code, remaining, data.period.max(1)))
}

fn hotp(secret: &[u8], counter: u64, algorithm: &str) -> Result<u32> {
    let msg = counter.to_be_bytes();
    let algo = algorithm.to_ascii_uppercase();
    let hash = if algo == "SHA256" {
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).context("invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else if algo == "SHA512" {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(secret).context("invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else {
        type HmacSha1 = Hmac<sha1::Sha1>;
        let mut mac = HmacSha1::new_from_slice(secret).context("invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    };

    let offset = (hash.last().copied().unwrap_or(0) & 0x0f) as usize;
    if offset + 4 > hash.len() {
        return Err(anyhow!("invalid_hmac_output"));
    }
    let slice = &hash[offset..offset + 4];
    let binary = ((slice[0] as u32 & 0x7f) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | slice[3] as u32;
    Ok(binary)
}

fn decode_totp_secret(secret: &str) -> Result<Vec<u8>> {
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
        .map_err(|e| anyhow!("invalid_base32_secret: {e}"))
}

fn copy_text_to_clipboard(text: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        return pipe_to_command("pbcopy", &[], text);
    }

    if cfg!(target_os = "windows") {
        if pipe_to_command("cmd", &["/C", "clip"], text).is_ok() {
            return Ok(());
        }
        return pipe_to_command(
            "powershell",
            &["-NoProfile", "-Command", "Set-Clipboard"],
            text,
        );
    }

    // Linux / other unix: try wl-copy (Wayland), then xclip/xsel (X11).
    if pipe_to_command("wl-copy", &[], text).is_ok() {
        return Ok(());
    }
    if pipe_to_command("xclip", &["-selection", "clipboard"], text).is_ok() {
        return Ok(());
    }
    if pipe_to_command("xsel", &["--clipboard", "--input"], text).is_ok() {
        return Ok(());
    }

    Err(anyhow!("copy_failed: no supported clipboard command found (try installing wl-clipboard or xclip)"))
}

fn pipe_to_command(cmd: &str, args: &[&str], text: &str) -> Result<()> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("copy_failed: failed to start {cmd}: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| anyhow!("copy_failed: failed to write stdin for {cmd}: {e}"))?;
    }

    let status = child
        .wait()
        .map_err(|e| anyhow!("copy_failed: failed to wait for {cmd}: {e}"))?;
    if !status.success() {
        return Err(anyhow!("copy_failed: {cmd} exited with {status}"));
    }
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 10 * 1024 * 1024 {
        return Err(anyhow!("invalid_frame_length: {len}"));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<()> {
    let payload = serde_json::to_vec(msg)?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}
