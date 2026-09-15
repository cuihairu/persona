use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::Args;
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::Sha512;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};
use url::Url;

use persona_core::crypto::{parse_creation_options, validate_origin_matches_rp_id};
use persona_core::models::{CredentialData, CredentialType, TwoFactorData};
use persona_core::storage::{CredentialRepository, WorkspaceRepository};
use persona_core::{Database, PersonaError, PersonaService, Repository};

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
    _extension_version: Option<String>,
    #[serde(default)]
    _protocol_version: Option<u32>,
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

// ---------------------------------------------------------------------------
// Bridge protocol v2: passkey (WebAuthn software authenticator) messages
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PasskeyListPayload {
    origin: String,
    /// Indicates this request was triggered by an explicit user action
    /// (the WebAuthn call Persona intercepts). Required.
    #[serde(default)]
    user_gesture: bool,
    /// Relying party ID. Defaults to the origin's effective host.
    #[serde(default)]
    rp_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PasskeyCreatePayload {
    origin: String,
    /// Indicates this request was triggered by an explicit user action.
    #[serde(default)]
    user_gesture: bool,
    /// `PublicKeyCredentialCreationOptions` in JSON form; BufferSource fields
    /// (challenge, user.id, ...) are base64url strings serialized by the
    /// extension before forwarding.
    request_json: serde_json::Value,
    /// Raw clientDataJSON bytes produced by the browser (base64url, no pad).
    /// The core only hashes these — never reassembled or inspected further.
    client_data_json_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PasskeyAssertPayload {
    origin: String,
    /// Indicates this request was triggered by an explicit user action
    /// (the selection-UI click). Required — silent signing is refused.
    #[serde(default)]
    user_gesture: bool,
    /// The passkey the user picked in the selection UI. Missing ⇒ refuse.
    item_id: String,
    /// Raw clientDataJSON bytes produced by the browser (base64url, no pad).
    client_data_json_b64: String,
    /// Mirror of `PublicKeyCredentialRequestOptions.userVerification`:
    /// the extension maps "discouraged" to false. Default true.
    #[serde(default = "default_true")]
    user_verification: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct PasskeyListItem {
    id: String,
    rp_id: String,
    user_name: Option<String>,
    user_display_name: Option<String>,
    identity_name: Option<String>,
    created_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct PasskeyCreateResponse {
    item_id: String,
    credential_id_b64: String,
    /// `none`-format attestation object (CBOR bytes, base64url).
    attestation_object_b64: String,
    /// Echoed back so the page's PublicKeyCredential can carry the exact
    /// bytes the authenticator attested over.
    client_data_json_b64: String,
    transports: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct PasskeyAssertResponse {
    item_id: String,
    credential_id_b64: String,
    authenticator_data_b64: String,
    signature_der_b64: String,
    user_handle_b64: String,
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
    db_path: &Path,
    state_dir: &Path,
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
                "protocol_version": 2,
                "capabilities": ["status", "pairing_request", "pairing_finalize", "get_suggestions", "request_fill", "get_totp", "copy", "passkey_list", "passkey_create", "passkey_assert"],
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
            let require_gesture = gesture_required();

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
            let (service, active_identity_id) = open_unlocked_service(db_path).await?;

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
                    return Err(anyhow!(
                        "wrong_identity: switch active identity to access this credential"
                    ));
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

            let require_gesture = gesture_required();

            if require_gesture && !parsed.user_gesture {
                warn!(
                    origin = %parsed.origin,
                    item_id = %parsed.item_id,
                    "totp request rejected: user_gesture required but not provided"
                );
                return Err(anyhow!(
                    "user_gesture_required: totp must be triggered by explicit user action"
                ));
            }

            let (service, active_identity_id) = open_unlocked_service(db_path).await?;

            let item_id = uuid::Uuid::parse_str(&parsed.item_id)
                .map_err(|e| anyhow!("invalid item_id uuid: {e}"))?;

            let cred = service
                .get_credential(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;
            if let Some(active) = active_identity_id {
                if cred.identity_id != active {
                    return Err(anyhow!(
                        "wrong_identity: switch active identity to access this credential"
                    ));
                }
            }
            if cred.credential_type != CredentialType::TwoFactor {
                return Err(anyhow!("unsupported_credential_type"));
            }

            if cred.url.is_none() {
                return Err(anyhow!(
                    "origin_binding_required: totp entries must have a URL set"
                ));
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

            let require_gesture = gesture_required();

            if require_gesture && !parsed.user_gesture {
                warn!(
                    origin = %parsed.origin,
                    item_id = %parsed.item_id,
                    field = %parsed.field,
                    "copy request rejected: user_gesture required but not provided"
                );
                return Err(anyhow!(
                    "user_gesture_required: copy must be triggered by explicit user action"
                ));
            }

            let host = origin_to_host(&parsed.origin)?;
            let field = parsed.field.trim().to_ascii_lowercase();

            let (service, active_identity_id) = open_unlocked_service(db_path).await?;

            let item_id = uuid::Uuid::parse_str(&parsed.item_id)
                .map_err(|e| anyhow!("invalid item_id uuid: {e}"))?;
            let cred = service
                .get_credential(&item_id)
                .await?
                .ok_or_else(|| anyhow!("not_found"))?;
            if let Some(active) = active_identity_id {
                if cred.identity_id != active {
                    return Err(anyhow!(
                        "wrong_identity: switch active identity to access this credential"
                    ));
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
        "passkey_list" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: PasskeyListPayload =
                serde_json::from_value(req.payload).context("invalid payload for passkey_list")?;

            if gesture_required() && !parsed.user_gesture {
                warn!(origin = %parsed.origin, "passkey_list rejected: user_gesture required");
                return Err(anyhow!(
                    "user_gesture_required: passkey enumeration requires user action"
                ));
            }

            let rp_id = match &parsed.rp_id {
                Some(rp_id) => {
                    validate_origin_matches_rp_id(&parsed.origin, rp_id).map_err(|_| {
                        anyhow!("passkey_rp_mismatch: rp_id does not match request origin")
                    })?;
                    rp_id.clone()
                }
                None => origin_to_host(&parsed.origin)?,
            };

            let (service, _) = open_unlocked_service(db_path).await?;
            let passkeys = service.list_passkeys_by_rp(&rp_id).await?;
            let mut items = Vec::with_capacity(passkeys.len());
            for pk in passkeys {
                let identity_name = service.get_identity(&pk.identity_id).await?.map(|i| i.name);
                items.push(PasskeyListItem {
                    id: pk.id.to_string(),
                    rp_id: pk.rp_id,
                    user_name: pk.user_name,
                    user_display_name: pk.user_display_name,
                    identity_name,
                    created_at: pk.created_at.timestamp(),
                });
            }
            debug!(event = "bridge_passkey_list", rp_id = %rp_id, count = items.len());

            Ok(ok(
                req.request_id,
                "passkey_list_response",
                serde_json::json!({ "items": items, "rp_id": rp_id }),
            ))
        }
        "passkey_create" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: PasskeyCreatePayload = serde_json::from_value(req.payload)
                .context("invalid payload for passkey_create")?;

            if gesture_required() && !parsed.user_gesture {
                warn!(origin = %parsed.origin, "passkey_create rejected: user_gesture required");
                return Err(anyhow!(
                    "user_gesture_required: passkey creation must be triggered by explicit user action"
                ));
            }

            let client_data_json = URL_SAFE_NO_PAD
                .decode(parsed.client_data_json_b64.as_bytes())
                .context("invalid_request: client_data_json_b64 must be base64url")?;
            let options = parse_creation_options(&parsed.request_json, &parsed.origin)
                .map_err(flat_persona_error)?;

            // Second consent line: a running desktop must approve before
            // anything is signed or stored.
            match desktop_approval_gate(
                "passkey_create",
                Some(&options.rp_id),
                &parsed.origin,
                options.user_name.as_deref(),
                None,
            )
            .await?
            {
                DesktopApproval::Approved => {}
                DesktopApproval::Denied(reason) => {
                    warn!(origin = %parsed.origin, %reason, "passkey_create denied by desktop");
                    return Err(anyhow!(
                        "passkey_desktop_denied: creation rejected by desktop approval ({reason})"
                    ));
                }
                DesktopApproval::Unavailable => {}
            }

            let (service, active_identity_id) = open_unlocked_service(db_path).await?;
            let identity_id = active_identity_id.ok_or_else(|| {
                anyhow!("no_active_identity: switch to an identity before creating a passkey")
            })?;

            // The bridge session just authenticated with the master password,
            // so the user-verification flag truthfully reflects local auth.
            let creation = service
                .create_passkey_full(
                    identity_id,
                    options.rp_id.clone(),
                    &parsed.origin,
                    &client_data_json,
                    Some(options.user_handle),
                    options.user_name,
                    options.user_display_name.or(options.rp_name),
                    true,
                )
                .await?;
            let item = &creation.item;

            info!(
                event = "bridge_passkey_create",
                rp_id = %item.rp_id,
                origin = %parsed.origin,
                item_id = %item.id,
                "passkey created via bridge"
            );

            Ok(ok(
                req.request_id,
                "passkey_create_response",
                serde_json::to_value(PasskeyCreateResponse {
                    item_id: item.id.to_string(),
                    credential_id_b64: URL_SAFE_NO_PAD.encode(&item.credential_id),
                    attestation_object_b64: URL_SAFE_NO_PAD.encode(&creation.attestation_object),
                    client_data_json_b64: parsed.client_data_json_b64,
                    transports: vec!["internal".to_string()],
                })?,
            ))
        }
        "passkey_assert" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: PasskeyAssertPayload = serde_json::from_value(req.payload)
                .context("invalid payload for passkey_assert")?;

            if gesture_required() && !parsed.user_gesture {
                warn!(origin = %parsed.origin, "passkey_assert rejected: user_gesture required");
                return Err(anyhow!(
                    "user_gesture_required: passkey assertions require an explicit selection click"
                ));
            }

            // Second consent line: a running desktop must approve before
            // anything is signed. rp_id/user_name live on the stored item;
            // the desktop dialog shows origin + item id.
            match desktop_approval_gate(
                "passkey_assert",
                None,
                &parsed.origin,
                None,
                Some(&parsed.item_id),
            )
            .await?
            {
                DesktopApproval::Approved => {}
                DesktopApproval::Denied(reason) => {
                    warn!(origin = %parsed.origin, %reason, "passkey_assert denied by desktop");
                    return Err(anyhow!(
                        "passkey_desktop_denied: assertion rejected by desktop approval ({reason})"
                    ));
                }
                DesktopApproval::Unavailable => {}
            }

            let item_id = uuid::Uuid::parse_str(&parsed.item_id)
                .map_err(|e| anyhow!("invalid_request: item_id uuid: {e}"))?;
            let client_data_json = URL_SAFE_NO_PAD
                .decode(parsed.client_data_json_b64.as_bytes())
                .context("invalid_request: client_data_json_b64 must be base64url")?;

            let (service, active_identity_id) = open_unlocked_service(db_path).await?;

            // Preflight the item so error codes stay precise; the assertion
            // re-validates origin↔rp_id inside core regardless.
            let item = service
                .get_passkey(&item_id)
                .await?
                .ok_or_else(|| anyhow!("passkey_item_not_found"))?;
            if let Some(active) = active_identity_id {
                if item.identity_id != active {
                    return Err(anyhow!(
                        "wrong_identity: switch active identity to use this passkey"
                    ));
                }
            }
            validate_origin_matches_rp_id(&parsed.origin, &item.rp_id).map_err(|_| {
                anyhow!("passkey_rp_mismatch: origin does not match the passkey's rp_id")
            })?;

            let assertion = service
                .passkey_assertion(
                    &item_id,
                    &parsed.origin,
                    &client_data_json,
                    parsed.user_verification,
                )
                .await
                .map_err(|e| {
                    let not_found = e
                        .downcast_ref::<PersonaError>()
                        .is_some_and(|pe| matches!(pe, PersonaError::NotFound(_)));
                    if not_found {
                        anyhow!("passkey_item_not_found")
                    } else {
                        anyhow!("passkey_assert_failed: {e}")
                    }
                })?;

            info!(
                event = "bridge_passkey_assert",
                rp_id = %item.rp_id,
                origin = %parsed.origin,
                item_id = %item.id,
                user_gesture = parsed.user_gesture,
                "passkey assertion signed via bridge"
            );

            Ok(ok(
                req.request_id,
                "passkey_assert_response",
                serde_json::to_value(PasskeyAssertResponse {
                    item_id: item.id.to_string(),
                    credential_id_b64: URL_SAFE_NO_PAD.encode(&assertion.credential_id),
                    authenticator_data_b64: URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
                    signature_der_b64: URL_SAFE_NO_PAD.encode(&assertion.signature_der),
                    user_handle_b64: URL_SAFE_NO_PAD.encode(&assertion.user_handle),
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

async fn open_db(db_path: &Path) -> Result<Database> {
    let db = Database::from_file(db_path).await?;
    db.migrate().await?;
    Ok(db)
}

/// Whether fill/copy/totp/passkey requests must carry `user_gesture: true`
/// (default yes; `PERSONA_BRIDGE_REQUIRE_GESTURE=0` disables).
fn gesture_required() -> bool {
    std::env::var("PERSONA_BRIDGE_REQUIRE_GESTURE")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Desktop approval gate (Passkeys P3)
//
// A running Persona desktop app exposes a local confirmation socket; before
// signing or storing anything for a passkey request, the bridge can ask it
// for an explicit approval — a second consent line behind the extension's
// own selection/confirmation UI (defense against a compromised extension).
// ---------------------------------------------------------------------------

/// Overall deadline for one approval round-trip. The desktop side denies on
/// its own after 120s; this only guards against a hung server.
const DESKTOP_APPROVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesktopApprovalMode {
    /// Consult the desktop when its approval socket exists (default).
    Auto,
    /// Always require desktop approval; fail closed when unreachable.
    Require,
    /// Never ask the desktop.
    Off,
}

fn desktop_approval_mode() -> DesktopApprovalMode {
    match std::env::var("PERSONA_BRIDGE_DESKTOP_APPROVAL") {
        Ok(v) if v.eq_ignore_ascii_case("require") => DesktopApprovalMode::Require,
        Ok(v) if v.eq_ignore_ascii_case("off") || v == "0" || v.eq_ignore_ascii_case("false") => {
            DesktopApprovalMode::Off
        }
        _ => DesktopApprovalMode::Auto,
    }
}

/// Approval socket next to the SSH agent state dir (`~/.persona/` by
/// default); `PERSONA_PASSKEY_APPROVAL_SOCKET` overrides (tests).
fn desktop_approval_socket_path() -> PathBuf {
    std::env::var("PERSONA_PASSKEY_APPROVAL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let dir = std::env::var("PERSONA_AGENT_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".persona")
                });
            dir.join("passkey-approval.sock")
        })
}

/// What the desktop answered for one passkey request.
#[derive(Debug, PartialEq, Eq)]
enum DesktopApproval {
    Approved,
    Denied(String),
    /// No desktop to ask (socket missing/unreachable, or a platform without
    /// Unix sockets): the caller falls back to the existing gesture gate.
    Unavailable,
}

#[derive(Debug, Serialize)]
struct DesktopApprovalRequest<'a> {
    v: u8,
    op: &'a str,
    rp_id: Option<&'a str>,
    origin: &'a str,
    user_name: Option<&'a str>,
    item_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct DesktopApprovalResponse {
    #[serde(default)]
    approved: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// Ask the running desktop app to confirm one passkey request.
///
/// `PERSONA_BRIDGE_DESKTOP_APPROVAL` controls the policy: `auto` (default)
/// consults the desktop when its socket exists and falls back to the plain
/// gesture gate otherwise; `require` fails the request when the desktop
/// cannot be reached; `off` skips the gate entirely.
async fn desktop_approval_gate(
    op: &str,
    rp_id: Option<&str>,
    origin: &str,
    user_name: Option<&str>,
    item_id: Option<&str>,
) -> Result<DesktopApproval> {
    let mode = desktop_approval_mode();
    if mode == DesktopApprovalMode::Off {
        return Ok(DesktopApproval::Unavailable);
    }

    #[cfg(unix)]
    {
        let request = DesktopApprovalRequest {
            v: 1,
            op,
            rp_id,
            origin,
            user_name,
            item_id,
        };
        match ask_desktop_approval(&request, &desktop_approval_socket_path()).await {
            Ok(resp) if resp.approved => Ok(DesktopApproval::Approved),
            Ok(resp) => Ok(DesktopApproval::Denied(
                resp.reason.unwrap_or_else(|| "denied".to_string()),
            )),
            Err(e) => {
                warn!(op, error = %e, "desktop approval unavailable");
                if mode == DesktopApprovalMode::Require {
                    Err(anyhow!(
                        "passkey_desktop_approval_required: desktop approval is mandatory but the desktop app is unreachable"
                    ))
                } else {
                    Ok(DesktopApproval::Unavailable)
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (op, rp_id, origin, user_name, item_id);
        if mode == DesktopApprovalMode::Require {
            return Err(anyhow!(
                "passkey_desktop_approval_required: desktop approval is mandatory but unavailable on this platform"
            ));
        }
        Ok(DesktopApproval::Unavailable)
    }
}

/// One request, one connection: send the JSON line, read the answer.
#[cfg(unix)]
async fn ask_desktop_approval(
    request: &DesktopApprovalRequest<'_>,
    socket_path: &Path,
) -> Result<DesktopApprovalResponse> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut line = serde_json::to_string(request)?;
    line.push('\n');

    let io = async {
        let stream = tokio::net::UnixStream::connect(socket_path).await?;
        let mut stream = stream;
        stream.write_all(line.as_bytes()).await?;
        let mut reader = BufReader::new(stream);
        let mut answer = String::new();
        reader.read_line(&mut answer).await?;
        Ok::<_, std::io::Error>(answer)
    };
    let answer = tokio::time::timeout(DESKTOP_APPROVAL_TIMEOUT, io)
        .await
        .map_err(|_| anyhow!("desktop approval timed out"))??;

    if answer.trim().is_empty() {
        return Err(anyhow!("desktop approval closed the connection"));
    }
    serde_json::from_str(&answer).with_context(|| format!("invalid approval response: {answer}"))
}

/// Flatten a `PersonaError` into a wire message that starts with the protocol
/// error code — its `Display` wraps the code in a human prefix ("Invalid
/// input: …"), which would leak into the bridge error response.
fn flat_persona_error(e: PersonaError) -> anyhow::Error {
    let msg = e.to_string();
    match msg.split_once(": ") {
        Some((_prefix, rest)) => anyhow!(rest.to_string()),
        None => anyhow!(msg),
    }
}

/// Open the database and unlock the service with the master password from
/// `PERSONA_MASTER_PASSWORD` (the bridge's lock state). Returns the service
/// plus the active identity (if one is set).
async fn open_unlocked_service(db_path: &Path) -> Result<(PersonaService, Option<uuid::Uuid>)> {
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
    Ok((service, active_identity_id))
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

    let idx = state
        .pairings
        .iter()
        .position(|p| p.extension_id == extension_id && p.client_instance_id == client_instance_id);

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
    let mut rng = rand::rng();
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

async fn compute_status(db_path: &Path) -> Result<(bool, Option<String>)> {
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

async fn get_credential_suggestions(db_path: &Path, host: &str) -> Result<Vec<SuggestionItem>> {
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
    out.sort_by_key(|b| std::cmp::Reverse(b.match_strength));

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
    // 10^10 exceeds u32::MAX, so the power and modulus are computed in u64.
    let modulo = 10_u64.pow(digits);
    let value = u64::from(code_num) % modulo;
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

    Err(anyhow!(
        "copy_failed: no supported clipboard command found (try installing wl-clipboard or xclip)"
    ))
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use persona_core::models::IdentityType;
    use std::sync::Mutex;

    /// Guards the process-global env vars used by the bridge below — all
    /// passkey bridge cases run inside one #[tokio::test] so they never
    /// overlap, but other tests must not mutate these vars concurrently.
    /// `pub(crate)` so config tests can coordinate on the same vars.
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

    const PASSWORD: &str = "bridge-test-password";

    async fn seeded_bridge() -> (tempfile::TempDir, PathBuf, PathBuf, uuid::Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("identities.db");
        let state_dir = dir.path().join("bridge");
        std::fs::create_dir_all(&state_dir).unwrap();

        let db = open_db(&db_path).await.unwrap();
        let mut service = PersonaService::new(db.clone()).await.unwrap();
        service.initialize_user(PASSWORD).await.unwrap();
        let identity = service
            .create_identity("Bridge Identity".to_string(), IdentityType::Personal)
            .await
            .unwrap();

        // Mark the identity active in workspace v2 (what the bridge reads).
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            r#"INSERT INTO workspaces (id, name, created_at, updated_at, is_active, active_identity_id, settings)
               VALUES (?, ?, ?, ?, 1, ?, '{}')"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("test")
        .bind(&now)
        .bind(&now)
        .bind(identity.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();

        let client_data = local_client_data_for("https://example.com", "Y2hhbGxlbmdl");
        let _ = service
            .create_passkey(
                identity.id,
                "example.com".to_string(),
                "https://example.com",
                &client_data,
                Some(b"user-handle-bytes".to_vec()),
                Some("alice@example.com".to_string()),
                Some("Alice".to_string()),
                true,
            )
            .await
            .unwrap();
        drop(service);
        drop(db);
        (dir, db_path, state_dir, identity.id)
    }

    fn local_client_data_for(origin: &str, challenge: &str) -> Vec<u8> {
        format!(r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{origin}"}}"#)
            .into_bytes()
    }

    fn request(kind: &str, payload: serde_json::Value) -> BridgeRequest {
        BridgeRequest {
            request_id: Some("req-1".to_string()),
            kind: kind.to_string(),
            payload,
            auth: None,
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn passkey_bridge_protocol_cases() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
        // Deterministic desktop-approval state: auto mode with no socket, so
        // every case below exercises the plain gesture-gate behavior.
        std::env::remove_var("PERSONA_BRIDGE_DESKTOP_APPROVAL");
        let no_socket = std::env::temp_dir().join(format!(
            "persona-no-approval-{}-passkey-protocol",
            std::process::id()
        ));
        std::env::set_var("PERSONA_PASSKEY_APPROVAL_SOCKET", &no_socket);

        let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

        // ---- hello: protocol v2 advertises the passkey capabilities ----
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "hello",
                serde_json::json!({
                    "extension_id": "test-extension",
                    "extension_version": "0.1.0",
                    "protocol_version": 2,
                    "client_instance_id": "instance-1"
                }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "hello must succeed: {:?}", resp.error);
        let payload = resp.payload.unwrap();
        assert_eq!(payload["protocol_version"], 2);
        for capability in ["passkey_list", "passkey_create", "passkey_assert"] {
            assert!(
                payload["capabilities"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|c| c == capability),
                "capability {capability} must be advertised"
            );
        }
        let options_json = serde_json::json!({
            "rp": { "id": "example.com", "name": "Example" },
            "user": {
                "id": URL_SAFE_NO_PAD.encode(b"bridge-user-handle"),
                "name": "bob@example.com",
                "displayName": "Bob"
            },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        });
        let non_es256_options = serde_json::json!({
            "rp": { "id": "example.com" },
            "user": { "id": URL_SAFE_NO_PAD.encode(b"u"), "name": "b@example.com" },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -257 }],
        });

        // ---- passkey_list: happy path returns the seeded credential ----
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_list",
                serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "list must succeed: {:?}", resp.error);
        let items = resp.payload.unwrap()["items"].as_array().unwrap().clone();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["rp_id"], "example.com");
        assert_eq!(items[0]["user_name"], "alice@example.com");
        assert!(items[0].get("credential_id").is_none(), "no key material");

        // ---- passkey_list: rp_id that doesn't match the origin ----
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_list",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "rp_id": "evil.example"
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("passkey_rp_mismatch"));

        // ---- passkey_list: missing gesture ----
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_list",
                serde_json::json!({ "origin": "https://example.com" }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("user_gesture_required"));

        // ---- passkey_create: happy path ----
        let client_data = local_client_data_for("https://example.com", "Y3JlYXRlLWNoYWxsZW5nZQ");
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "request_json": options_json,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
                }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "create must succeed: {:?}", resp.error);
        let payload = resp.payload.unwrap();
        let attestation = URL_SAFE_NO_PAD
            .decode(payload["attestation_object_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            payload["transports"][0], "internal",
            "transports must be present"
        );
        assert!(attestation.len() > 100);

        // ---- passkey_create: non-ES256 algorithm refused ----
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "request_json": non_es256_options,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("passkey_alg_unsupported"));

        // ---- passkey_create: no active identity ----
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = NULL")
            .execute(db.pool())
            .await
            .unwrap();
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "request_json": options_json,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("no_active_identity"));
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(identity_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        // ---- passkey_create: missing gesture ----
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({
                    "origin": "https://example.com",
                    "request_json": options_json,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("user_gesture_required"));

        // ---- passkey_assert: happy path, verified by core's RP-check ----
        // The list's single item plus the one created above.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_list",
                serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
            ),
        )
        .await
        .unwrap();
        let items = resp.payload.unwrap()["items"].as_array().unwrap().clone();
        // The create case above added a second credential for the same RP;
        // assert against the seeded one explicitly (list order is not fixed).
        let item_id = items
            .iter()
            .find(|i| i["user_name"] == "alice@example.com")
            .expect("seeded passkey must be listed")["id"]
            .as_str()
            .unwrap()
            .to_string();

        let get_client_data =
            r#"{"type":"webauthn.get","challenge":"YXNzZXJ0LWNoYWxsZW5nZQ","origin":"https://example.com"}"#.to_string()
                .into_bytes();
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "item_id": item_id,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
                }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "assert must succeed: {:?}", resp.error);
        let payload = resp.payload.unwrap();
        let auth_data = URL_SAFE_NO_PAD
            .decode(payload["authenticator_data_b64"].as_str().unwrap())
            .unwrap();
        let signature = URL_SAFE_NO_PAD
            .decode(payload["signature_der_b64"].as_str().unwrap())
            .unwrap();
        let credential_id = URL_SAFE_NO_PAD
            .decode(payload["credential_id_b64"].as_str().unwrap())
            .unwrap();
        let user_handle = URL_SAFE_NO_PAD
            .decode(payload["user_handle_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(user_handle, b"user-handle-bytes");

        // Rebuild the public key from the stored COSE and verify like an RP.
        let db = open_db(&db_path).await.unwrap();
        let repo = persona_core::storage::PasskeyRepository::new(std::sync::Arc::new(db));
        let all = repo.find_by_rp_id("example.com").await.unwrap();
        let stored = all
            .iter()
            .find(|p| p.credential_id == credential_id)
            .expect("asserted credential must exist");
        persona_core::crypto::verify_assertion(
            &stored.public_key_cose,
            "example.com",
            &get_client_data,
            &auth_data,
            &signature,
        )
        .expect("bridge assertion must verify against the stored public key");

        // ---- passkey_list: explicit rp_id that matches the origin ----
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_list",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "rp_id": "example.com"
                }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "list with rp_id must succeed: {:?}", resp.error);

        // ---- passkey_assert: passkey belongs to another identity ----
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(db.pool())
            .await
            .unwrap();
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "item_id": item_id,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("wrong_identity"));
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(identity_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        // ---- unknown message type yields an error response ----
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("definitely_not_a_type", serde_json::json!({})),
        )
        .await
        .unwrap();
        assert!(!resp.ok, "unknown type must not succeed");
        assert!(
            resp.error
                .as_deref()
                .is_some_and(|e| e.starts_with("unknown_type")),
            "unexpected error: {:?}",
            resp.error
        );

        // ---- passkey_assert: origin does not match the passkey's rp_id ----
        let evil_client_data = local_client_data_for("https://evil.example", "ZXZpbA");
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://evil.example",
                    "user_gesture": true,
                    "item_id": item_id,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&evil_client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("passkey_rp_mismatch"));

        // ---- passkey_assert: unknown item ----
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "item_id": uuid::Uuid::new_v4().to_string(),
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("passkey_item_not_found"));

        // ---- passkey_assert: silent signing refused ----
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": item_id,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("user_gesture_required"));

        // ---- passkey_assert: corrupted sealed key surfaces as assert_failed ----
        // (last data-touching case: it invalidates the stored key material)
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE passkeys SET encrypted_private_key = x'00', wrapped_item_key = x'00' WHERE id = ?")
            .bind(item_id.clone())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "item_id": item_id,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("passkey_assert_failed"));

        // ---- locked vault (no PERSONA_MASTER_PASSWORD) ----
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_list",
                serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("locked:"));
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

        // ---- passkey_create: require mode with no desktop fails closed ----
        std::env::set_var("PERSONA_BRIDGE_DESKTOP_APPROVAL", "require");
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "request_json": options_json,
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(local_client_data_for(
                        "https://example.com",
                        "Y3JlYXRlLWNoYWxsZW5nZQ",
                    )),
                }),
            ),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("passkey_desktop_approval_required"),
            "got: {err}"
        );
        std::env::remove_var("PERSONA_BRIDGE_DESKTOP_APPROVAL");

        std::env::remove_var("PERSONA_PASSKEY_APPROVAL_SOCKET");
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    // ---- desktop approval gate (Passkeys P3) ----

    /// A fake desktop approval server: accepts one connection, reads the
    /// request line, replies with the configured verdict, and resolves with
    /// the received line so tests can pin the wire format. The `TempDir`
    /// keeps the socket file alive for the duration of the test.
    async fn spawn_fake_desktop(
        approved: bool,
        reason: Option<&'static str>,
    ) -> (tempfile::TempDir, PathBuf, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passkey-approval.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            let mut reader = BufReader::new(stream);
            reader.read_line(&mut line).await.unwrap();
            let mut writer = reader.into_inner();
            let reply = serde_json::json!({ "approved": approved, "reason": reason });
            let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
            line
        });
        (dir, path, handle)
    }

    /// Points the gate at `path` (or nowhere) under the caller's env lock.
    fn set_gate_env(socket: Option<&Path>, mode: Option<&str>) {
        match socket {
            Some(p) => std::env::set_var("PERSONA_PASSKEY_APPROVAL_SOCKET", p),
            None => std::env::remove_var("PERSONA_PASSKEY_APPROVAL_SOCKET"),
        }
        match mode {
            Some(m) => std::env::set_var("PERSONA_BRIDGE_DESKTOP_APPROVAL", m),
            None => std::env::remove_var("PERSONA_BRIDGE_DESKTOP_APPROVAL"),
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn desktop_approval_roundtrip_pins_wire_format() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (_dir, path, server) = spawn_fake_desktop(true, None).await;
        set_gate_env(Some(&path), None); // auto

        let verdict = desktop_approval_gate(
            "passkey_assert",
            None,
            "https://example.com",
            None,
            Some("item-uuid"),
        )
        .await
        .unwrap();
        assert_eq!(verdict, DesktopApproval::Approved);

        let line = server.await.unwrap();
        let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(req["v"], 1);
        assert_eq!(req["op"], "passkey_assert");
        assert_eq!(req["origin"], "https://example.com");
        assert_eq!(req["item_id"], "item-uuid");
        // Privacy pin: the approval wire carries request metadata only.
        assert!(
            line.trim().len() < 200,
            "no client data on the wire: {line}"
        );
        assert!(!line.contains("client_data"), "no client data: {line}");

        set_gate_env(None, None);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn desktop_approval_denied_and_auto_fallback() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Explicit denial from the desktop.
        let (_dir, path, _server) = spawn_fake_desktop(false, Some("timeout")).await;
        set_gate_env(Some(&path), None);
        let verdict =
            desktop_approval_gate("passkey_assert", None, "https://example.com", None, None)
                .await
                .unwrap();
        assert_eq!(verdict, DesktopApproval::Denied("timeout".to_string()));

        // auto + unreachable socket → fall back to the gesture gate.
        let nowhere = std::env::temp_dir().join(format!(
            "persona-no-approval-{}-fallback",
            std::process::id()
        ));
        set_gate_env(Some(&nowhere), None);
        let verdict =
            desktop_approval_gate("passkey_assert", None, "https://example.com", None, None)
                .await
                .unwrap();
        assert_eq!(verdict, DesktopApproval::Unavailable);

        set_gate_env(None, None);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn desktop_approval_require_fails_closed_and_off_skips() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // require + no desktop → hard error (fail closed).
        let nowhere = std::env::temp_dir().join(format!(
            "persona-no-approval-{}-require",
            std::process::id()
        ));
        set_gate_env(Some(&nowhere), Some("require"));
        let err = desktop_approval_gate(
            "passkey_create",
            Some("example.com"),
            "https://example.com",
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("passkey_desktop_approval_required"),
            "got: {err}"
        );

        // off → never contacts the desktop, even when a socket exists.
        let (_dir, path, server) = spawn_fake_desktop(true, None).await;
        set_gate_env(Some(&path), Some("off"));
        let verdict =
            desktop_approval_gate("passkey_assert", None, "https://example.com", None, None)
                .await
                .unwrap();
        assert_eq!(verdict, DesktopApproval::Unavailable);
        tokio::time::timeout(std::time::Duration::from_millis(150), server)
            .await
            .expect_err("off mode must not contact the fake desktop");

        set_gate_env(None, None);
    }

    #[test]
    fn path_resolvers_honor_override_and_environment() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("PERSONA_DB_PATH");
        std::env::remove_var("PERSONA_BRIDGE_STATE_DIR");

        // explicit override wins
        let override_path = std::path::PathBuf::from("/tmp/custom.db");
        assert_eq!(resolve_db_path(Some(override_path.clone())), override_path);
        let override_state = std::path::PathBuf::from("/tmp/bridge-state");
        assert_eq!(
            resolve_state_dir(Some(override_state.clone())),
            override_state
        );

        // environment fallback
        std::env::set_var("PERSONA_DB_PATH", "/tmp/env.db");
        assert_eq!(
            resolve_db_path(None),
            std::path::PathBuf::from("/tmp/env.db")
        );
        std::env::remove_var("PERSONA_DB_PATH");

        std::env::set_var("PERSONA_BRIDGE_STATE_DIR", "/tmp/env-state");
        assert_eq!(
            resolve_state_dir(None),
            std::path::PathBuf::from("/tmp/env-state")
        );
        std::env::remove_var("PERSONA_BRIDGE_STATE_DIR");

        // default: ~/.persona
        let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        assert_eq!(
            resolve_db_path(None),
            home.join(".persona").join("identities.db")
        );
        assert_eq!(
            resolve_state_dir(None),
            home.join(".persona").join("bridge")
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_pairing_lifecycle() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

        // status before any pairing: no auth needed.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("status", serde_json::json!({})),
        )
        .await
        .unwrap();
        assert!(resp.ok, "status must succeed: {:?}", resp.error);

        // hello without client_instance_id while pairing is required.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("hello", serde_json::json!({ "extension_id": "ext-a" })),
        )
        .await
        .unwrap();
        assert!(resp.ok);
        let payload = resp.payload.unwrap();
        assert_eq!(payload["pairing_required"], true);
        assert!(payload["paired"] == false);

        // pairing_request creates a pending code.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_request",
                serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1" }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "pairing_request must succeed: {:?}", resp.error);
        let code = resp.payload.unwrap()["code"]
            .as_str()
            .expect("pairing code present")
            .to_string();

        // finalize before approval fails.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_finalize",
                serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1", "code": code }),
            ),
        )
        .await
        .expect_err("finalize before approval must fail");
        assert!(
            err.to_string().contains("pairing_not_approved"),
            "got: {err}"
        );

        // Approve via the CLI-side command, then finalize.
        approve_pairing(&state_dir, &code).expect("approve pairing");
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_finalize",
                serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1", "code": code }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "finalize must succeed: {:?}", resp.error);
        let payload = resp.payload.unwrap();
        assert!(payload["pairing_key_b64"].is_string());
        assert!(payload["session_id"].is_string());

        // hello now reports the session (paired).
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "hello",
                serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1" }),
            ),
        )
        .await
        .unwrap();
        let payload = resp.payload.unwrap();
        assert_eq!(payload["paired"], true);
        assert!(payload["session_id"].is_string());

        // Unknown pairing code is rejected.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("pairing_request", serde_json::json!({ "extension_id": "" })),
        )
        .await;
        assert!(err.is_err(), "empty extension_id payload must be rejected");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_fill_totp_copy_and_gesture_paths() {
        use persona_core::models::credential::{
            CredentialData, PasswordCredentialData, SecurityLevel,
        };

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

        let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

        // Seed a password credential bound to example.com.
        let cred_id: uuid::Uuid;
        {
            let db = open_db(&db_path).await.unwrap();
            let mut service = PersonaService::new(db).await.unwrap();
            assert_eq!(
                service.authenticate_user(PASSWORD).await.unwrap(),
                persona_core::auth::authentication::AuthResult::Success
            );
            let mut cred = service
                .create_credential(
                    identity_id,
                    "Example login".to_string(),
                    persona_core::models::credential::CredentialType::Password,
                    SecurityLevel::High,
                    &CredentialData::Password(PasswordCredentialData {
                        password: "hunter2".to_string(),
                        email: Some("alice@example.com".to_string()),
                        security_questions: vec![],
                    }),
                )
                .await
                .unwrap();
            cred.username = Some("alice@example.com".to_string());
            cred.url = Some("https://example.com/login".to_string());
            // Persist the URL/username hints through the repository.
            use persona_core::storage::CredentialRepository;
            use persona_core::Repository;
            let db = open_db(&db_path).await.unwrap();
            CredentialRepository::new(db).update(&cred).await.unwrap();
            cred_id = cred.id;
        }

        // status now reports the active identity.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("status", serde_json::json!({})),
        )
        .await
        .unwrap();
        assert!(resp.ok, "status must succeed: {:?}", resp.error);

        // get_suggestions returns an item for example.com.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_suggestions",
                serde_json::json!({ "origin": "https://example.com" }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "suggestions must succeed: {:?}", resp.error);

        // request_fill without a user gesture is rejected.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({ "origin": "https://example.com", "item_id": uuid::Uuid::new_v4().to_string() }),
            ),
        )
        .await
        .expect_err("fill without gesture must fail");
        assert!(
            err.to_string().contains("user_gesture_required"),
            "got: {err}"
        );

        // Unknown host origin is rejected outright.
        let _err = handle_request(
            &db_path,
            &state_dir,
            request("request_fill", serde_json::json!({ "origin": "not a url" })),
        )
        .await
        .expect_err("invalid origin must fail");

        // copy with an unknown field is rejected (item exists; field check runs
        // only after the item lookup succeeds).
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": cred_id.to_string(),
                    "field": "bogus",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("copy unknown field must fail");
        assert!(err.to_string().contains("unknown field"), "got: {err}");

        // copy of a ghost item reports not_found.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": uuid::Uuid::new_v4().to_string(),
                    "field": "username",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("copy ghost item must fail");
        assert!(err.to_string().contains("not_found"), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // Additional coverage: per-kind branches, helpers, codec, and the
    // authenticated-session signature flow.
    // -----------------------------------------------------------------------

    /// Seed a password credential through the service and persist the URL /
    /// username hints. Requires `PERSONA_MASTER_PASSWORD` to be set already.
    async fn seed_password_credential(
        db_path: &Path,
        identity_id: uuid::Uuid,
        name: &str,
        url: Option<&str>,
        username: Option<&str>,
        password: &str,
    ) -> uuid::Uuid {
        use persona_core::models::credential::{PasswordCredentialData, SecurityLevel};

        let db = open_db(db_path).await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();
        assert_eq!(
            service.authenticate_user(PASSWORD).await.unwrap(),
            persona_core::auth::authentication::AuthResult::Success
        );
        let mut cred = service
            .create_credential(
                identity_id,
                name.to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                &CredentialData::Password(PasswordCredentialData {
                    password: password.to_string(),
                    email: username.map(|s| s.to_string()),
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        cred.username = username.map(|s| s.to_string());
        cred.url = url.map(|s| s.to_string());
        let db = open_db(db_path).await.unwrap();
        CredentialRepository::new(db).update(&cred).await.unwrap();
        cred.id
    }

    /// Seed a TOTP (two-factor) credential with a fixed base32 secret.
    async fn seed_totp_credential(
        db_path: &Path,
        identity_id: uuid::Uuid,
        name: &str,
        url: Option<&str>,
    ) -> uuid::Uuid {
        use persona_core::models::credential::SecurityLevel;

        let db = open_db(db_path).await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();
        assert_eq!(
            service.authenticate_user(PASSWORD).await.unwrap(),
            persona_core::auth::authentication::AuthResult::Success
        );
        let mut cred = service
            .create_credential(
                identity_id,
                name.to_string(),
                CredentialType::TwoFactor,
                SecurityLevel::High,
                &CredentialData::TwoFactor(TwoFactorData {
                    secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                    issuer: "Example".to_string(),
                    account_name: "alice@example.com".to_string(),
                    algorithm: "SHA1".to_string(),
                    digits: 6,
                    period: 30,
                }),
            )
            .await
            .unwrap();
        cred.url = url.map(|s| s.to_string());
        let db = open_db(db_path).await.unwrap();
        CredentialRepository::new(db).update(&cred).await.unwrap();
        cred.id
    }

    /// Seed an API-key credential (a type the bridge never suggests or fills).
    async fn seed_api_key_credential(
        db_path: &Path,
        identity_id: uuid::Uuid,
        name: &str,
        url: Option<&str>,
    ) -> uuid::Uuid {
        use persona_core::models::credential::{ApiKeyData, SecurityLevel};

        let db = open_db(db_path).await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();
        assert_eq!(
            service.authenticate_user(PASSWORD).await.unwrap(),
            persona_core::auth::authentication::AuthResult::Success
        );
        let mut cred = service
            .create_credential(
                identity_id,
                name.to_string(),
                CredentialType::ApiKey,
                SecurityLevel::High,
                &CredentialData::ApiKey(ApiKeyData {
                    api_key: "key".to_string(),
                    api_secret: None,
                    token: None,
                    permissions: vec![],
                    expires_at: None,
                }),
            )
            .await
            .unwrap();
        cred.url = url.map(|s| s.to_string());
        let db = open_db(db_path).await.unwrap();
        CredentialRepository::new(db).update(&cred).await.unwrap();
        cred.id
    }

    fn clipboard_available() -> bool {
        if cfg!(target_os = "macos") {
            return Command::new("which")
                .arg("pbcopy")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }
        if cfg!(target_os = "windows") {
            // `cmd /C clip` is always present on Windows; verify it is
            // callable rather than just checking the binary exists.
            return Command::new("cmd")
                .args(["/C", "echo", "test", "|", "clip"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }
        // A clipboard binary alone isn't enough on headless machines:
        // wl-copy needs WAYLAND_DISPLAY, xclip/xsel need DISPLAY. Mirror the
        // real preconditions so the probe agrees with actual copy success.
        let has_display = !std::env::var("WAYLAND_DISPLAY")
            .unwrap_or_default()
            .is_empty()
            || !std::env::var("DISPLAY").unwrap_or_default().is_empty();
        has_display
            && ["wl-copy", "xclip", "xsel"].iter().any(|cmd| {
                Command::new("which")
                    .arg(cmd)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
    }

    /// Copy outcomes depend on the host having a clipboard utility; assert the
    /// protocol outcome for whichever way the environment goes.
    fn assert_copy_outcome(
        result: anyhow::Result<BridgeResponse<serde_json::Value>>,
        clip_ok: bool,
    ) {
        if clip_ok {
            let resp = result.expect("copy must succeed when a clipboard tool exists");
            assert!(resp.ok, "copy must succeed: {:?}", resp.error);
            assert_eq!(resp.kind, "copy_response");
            assert_eq!(resp.payload.unwrap()["copied"], true);
        } else {
            let err = result.expect_err("copy must fail without a clipboard tool");
            assert!(err.to_string().contains("copy_failed"), "got: {err}");
        }
    }

    /// Build a request with a correctly computed HMAC auth block, mirroring
    /// `verify_signature`'s canonical signing input.
    fn signed_request(
        kind: &str,
        payload: serde_json::Value,
        request_id: &str,
        session_id: &str,
        key_b64: &str,
        ts_ms: i64,
        nonce: &str,
    ) -> BridgeRequest {
        let key = URL_SAFE_NO_PAD
            .decode(key_b64)
            .expect("pairing key must be valid base64url");
        let payload_json = serde_json::to_string(&canonicalize_json_value(&payload)).unwrap();
        let signing_input = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            kind, request_id, payload_json, session_id, ts_ms, nonce
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        BridgeRequest {
            request_id: Some(request_id.to_string()),
            kind: kind.to_string(),
            payload,
            auth: Some(BridgeAuth {
                session_id: Some(session_id.to_string()),
                ts_ms,
                nonce: nonce.to_string(),
                signature,
            }),
        }
    }

    /// Run the full pairing handshake (request, approve, finalize) and return
    /// the issued session id and shared key.
    async fn pair_extension(state_dir: &Path, ext: &str, inst: &str) -> (String, String) {
        let resp = handle_request(
            Path::new(""),
            state_dir,
            request(
                "pairing_request",
                serde_json::json!({
                    "extension_id": ext,
                    "client_instance_id": inst
                }),
            ),
        )
        .await
        .expect("pairing_request must succeed");
        let code = resp.payload.unwrap()["code"]
            .as_str()
            .expect("pairing code present")
            .to_string();
        approve_pairing(state_dir, &code).expect("approve pairing");
        let resp = handle_request(
            Path::new(""),
            state_dir,
            request(
                "pairing_finalize",
                serde_json::json!({
                    "extension_id": ext,
                    "client_instance_id": inst,
                    "code": code
                }),
            ),
        )
        .await
        .expect("pairing_finalize must succeed");
        let payload = resp.payload.unwrap();
        (
            payload["session_id"].as_str().unwrap().to_string(),
            payload["pairing_key_b64"].as_str().unwrap().to_string(),
        )
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_hello_bad_payload_and_pairing_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

        let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

        // Malformed payload surfaces the context error.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("hello", serde_json::json!({})),
        )
        .await
        .expect_err("hello without extension_id must fail");
        assert!(
            err.to_string().contains("invalid payload for hello"),
            "got: {err}"
        );

        // With pairing disabled, hello reports no pairing and no session.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "hello",
                serde_json::json!({
                    "extension_id": "ext-hello",
                    "extension_version": "1.2.3",
                    "protocol_version": 2,
                    "client_instance_id": "inst-hello"
                }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "hello must succeed: {:?}", resp.error);
        assert_eq!(resp.kind, "hello_response");
        assert_eq!(resp.request_id.as_deref(), Some("req-1"));
        let payload = resp.payload.unwrap();
        assert_eq!(payload["pairing_required"], false);
        assert_eq!(payload["paired"], false);
        assert!(payload["session_id"].is_null());
        assert!(payload["session_expires_at_ms"].is_null());
        assert_eq!(payload["protocol_version"], 2);
        assert!(payload["server_version"].is_string());
        let caps = payload["capabilities"].as_array().unwrap();
        for capability in [
            "status",
            "pairing_request",
            "pairing_finalize",
            "get_suggestions",
            "request_fill",
            "get_totp",
            "copy",
        ] {
            assert!(
                caps.iter().any(|c| c == capability),
                "capability {capability} must be advertised"
            );
        }

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_status_reports_lock_state_and_active_identity() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

        // A fresh database without user rows is locked with no identity.
        let empty_dir = tempfile::tempdir().unwrap();
        let empty_db = empty_dir.path().join("empty.db");
        let resp = handle_request(
            &empty_db,
            &state_dir,
            request("status", serde_json::json!({})),
        )
        .await
        .unwrap();
        assert!(resp.ok, "status must succeed: {:?}", resp.error);
        let payload = resp.payload.unwrap();
        assert_eq!(payload["locked"], true);
        assert!(payload["active_identity"].is_null());

        // Seeded vault without a master password: locked, identity reported.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("status", serde_json::json!({})),
        )
        .await
        .unwrap();
        let payload = resp.payload.unwrap();
        assert_eq!(payload["locked"], true);
        assert_eq!(payload["active_identity"], identity_id.to_string());

        // Correct master password reports the vault as unlocked.
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("status", serde_json::json!({})),
        )
        .await
        .unwrap();
        assert_eq!(resp.payload.unwrap()["locked"], false);

        // Wrong password is locked again.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "definitely-wrong");
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("status", serde_json::json!({})),
        )
        .await
        .unwrap();
        assert_eq!(resp.payload.unwrap()["locked"], true);

        // A blank password counts as absent.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "   ");
        let resp = handle_request(
            &db_path,
            &state_dir,
            request("status", serde_json::json!({})),
        )
        .await
        .unwrap();
        assert_eq!(resp.payload.unwrap()["locked"], true);

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_pairing_request_and_finalize_error_paths() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");

        let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

        // Bad payload -> context error.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_request",
                serde_json::json!({ "extension_id": "ext-a" }),
            ),
        )
        .await
        .expect_err("pairing_request missing client_instance_id must fail");
        assert!(
            err.to_string()
                .contains("invalid payload for pairing_request"),
            "got: {err}"
        );

        // Blank fields are rejected by create_pairing_request itself.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_request",
                serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "   " }),
            ),
        )
        .await
        .expect_err("blank client_instance_id must fail");
        assert!(
            err.to_string().starts_with("invalid_payload:"),
            "got: {err}"
        );

        // Bad payload for finalize.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("pairing_finalize", serde_json::json!({ "code": "111-222" })),
        )
        .await
        .expect_err("pairing_finalize missing fields must fail");
        assert!(
            err.to_string()
                .contains("invalid payload for pairing_finalize"),
            "got: {err}"
        );

        // Unknown finalize code.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_finalize",
                serde_json::json!({
                    "extension_id": "ext-a",
                    "client_instance_id": "inst-a",
                    "code": "000-000"
                }),
            ),
        )
        .await
        .expect_err("unknown code must fail");
        assert!(
            err.to_string().contains("pairing_not_found_or_expired"),
            "got: {err}"
        );

        // Full pairing, then a duplicate pairing_request reports already_paired.
        pair_extension(&state_dir, "ext-dup", "inst-dup").await;
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_request",
                serde_json::json!({
                    "extension_id": "ext-dup",
                    "client_instance_id": "inst-dup"
                }),
            ),
        )
        .await
        .expect_err("second pairing_request for a paired client must fail");
        assert!(err.to_string().contains("already_paired"), "got: {err}");

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_get_suggestions_filters_and_orders_items() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

        let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

        let exact = seed_password_credential(
            &db_path,
            identity_id,
            "Exact match",
            Some("https://example.com/login"),
            Some("alice@example.com"),
            "pw-exact",
        )
        .await;
        let _sub = seed_password_credential(
            &db_path,
            identity_id,
            "Subdomain match",
            Some("https://api.example.com/signin"),
            Some("bob@example.com"),
            "pw-sub",
        )
        .await;
        let _zero = seed_password_credential(
            &db_path,
            identity_id,
            "Unrelated site",
            Some("https://unrelated.org/x"),
            Some("eve@example.com"),
            "pw-zero",
        )
        .await;
        let _nourl = seed_password_credential(
            &db_path,
            identity_id,
            "No URL",
            None,
            Some("no-url@example.com"),
            "pw-nourl",
        )
        .await;
        let inactive = seed_password_credential(
            &db_path,
            identity_id,
            "Inactive entry",
            Some("https://example.com/inactive"),
            Some("inactive@example.com"),
            "pw-inactive",
        )
        .await;
        let _api = seed_api_key_credential(
            &db_path,
            identity_id,
            "API key",
            Some("https://example.com/api"),
        )
        .await;

        // Deactivate one credential directly in the store.
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE credentials SET is_active = 0 WHERE id = ?")
            .bind(inactive.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        // Bad payload -> context error.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("get_suggestions", serde_json::json!({})),
        )
        .await
        .expect_err("get_suggestions without origin must fail");
        assert!(
            err.to_string()
                .contains("invalid payload for get_suggestions"),
            "got: {err}"
        );

        // Unparseable origin -> error from origin_to_host.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_suggestions",
                serde_json::json!({ "origin": "not a url" }),
            ),
        )
        .await
        .expect_err("invalid origin must fail");

        assert!(!err.to_string().is_empty());

        // Only the exact (100) and subdomain (90) matches survive filtering,
        // ordered by descending match strength.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_suggestions",
                serde_json::json!({ "origin": "https://example.com" }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "suggestions must succeed: {:?}", resp.error);
        assert_eq!(resp.kind, "suggestions_response");
        assert_eq!(resp.request_id.as_deref(), Some("req-1"));
        let payload = resp.payload.unwrap();
        assert_eq!(payload["suggesting_for"], "example.com");
        let items = payload["items"].as_array().unwrap();
        assert_eq!(items.len(), 2, "expected exactly the two matching items");
        assert_eq!(items[0]["match_strength"], 100);
        assert_eq!(items[0]["item_id"], exact.to_string());
        assert_eq!(items[0]["credential_type"], "password");
        assert_eq!(items[0]["username_hint"], "alice@example.com");
        assert_eq!(items[1]["match_strength"], 90);

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_request_fill_success_and_error_branches() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

        let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
        let pw_id = seed_password_credential(
            &db_path,
            identity_id,
            "Fill me",
            Some("https://example.com/login"),
            Some("alice@example.com"),
            "hunter2",
        )
        .await;
        let totp_id = seed_totp_credential(
            &db_path,
            identity_id,
            "TOTP entry",
            Some("https://example.com/totp"),
        )
        .await;

        // Happy path: kind, request id, and decrypted payload fields.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "fill must succeed: {:?}", resp.error);
        assert_eq!(resp.kind, "fill_response");
        assert_eq!(resp.request_id.as_deref(), Some("req-1"));
        let payload = resp.payload.unwrap();
        assert_eq!(payload["username"], "alice@example.com");
        assert_eq!(payload["password"], "hunter2");

        // Bad payload -> context error.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("request_fill", serde_json::json!({})),
        )
        .await
        .expect_err("fill without payload fields must fail");
        assert!(
            err.to_string().contains("invalid payload for request_fill"),
            "got: {err}"
        );

        // Non-UUID item id.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": "not-a-uuid",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("fill with a non-uuid item must fail");
        assert!(
            err.to_string().starts_with("invalid item_id uuid"),
            "got: {err}"
        );

        // Ghost item reports not_found.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": uuid::Uuid::new_v4().to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("fill of a ghost item must fail");
        assert!(err.to_string().contains("not_found"), "got: {err}");

        // Filling a TOTP credential is unsupported.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": totp_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("fill of a totp credential must fail");
        assert!(
            err.to_string().contains("unsupported_credential_type"),
            "got: {err}"
        );

        // Origin mismatch is rejected.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({
                    "origin": "https://evil.com",
                    "item_id": pw_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("fill from a mismatched origin must fail");
        assert!(err.to_string().starts_with("origin_mismatch"), "got: {err}");

        // Credential owned by another identity.
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("fill for a foreign identity must fail");
        assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(identity_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        // With the gesture requirement disabled, a gestureless fill passes.
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "0");
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "request_fill",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string()
                }),
            ),
        )
        .await
        .unwrap();
        assert!(
            resp.ok,
            "gestureless fill must pass when requirement disabled: {:?}",
            resp.error
        );

        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_get_totp_success_and_error_branches() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

        let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
        let pw_id = seed_password_credential(
            &db_path,
            identity_id,
            "Password entry",
            Some("https://example.com/login"),
            Some("alice@example.com"),
            "hunter2",
        )
        .await;
        let totp_id = seed_totp_credential(
            &db_path,
            identity_id,
            "TOTP entry",
            Some("https://example.com/totp"),
        )
        .await;

        // Happy path: a six digit code for a 30s period.
        let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": totp_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .unwrap();
        assert!(resp.ok, "totp must succeed: {:?}", resp.error);
        assert_eq!(resp.kind, "totp_response");
        assert_eq!(resp.request_id.as_deref(), Some("req-1"));
        let payload = resp.payload.unwrap();
        let code = payload["code"].as_str().unwrap();
        assert_eq!(code.len(), 6, "code must be six digits");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(payload["period"], 30);
        let remaining = payload["remaining_seconds"].as_u64().unwrap();
        assert!((1..=30).contains(&remaining));

        // Bad payload -> context error.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("get_totp", serde_json::json!({})),
        )
        .await
        .expect_err("get_totp without payload fields must fail");
        assert!(
            err.to_string().contains("invalid payload for get_totp"),
            "got: {err}"
        );

        // Non-UUID item id.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": "nope",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("get_totp with a non-uuid item must fail");
        assert!(
            err.to_string().starts_with("invalid item_id uuid"),
            "got: {err}"
        );

        // Ghost item.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": uuid::Uuid::new_v4().to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("get_totp of a ghost item must fail");
        assert!(err.to_string().contains("not_found"), "got: {err}");

        // TOTP on a password credential is unsupported.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("totp of a password credential must fail");
        assert!(
            err.to_string().contains("unsupported_credential_type"),
            "got: {err}"
        );

        // Type/data mismatch: row says TwoFactor but the sealed data is a
        // password. Hit through a direct store rewrite.
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE credentials SET credential_type = 'TwoFactor' WHERE id = ?")
            .bind(pw_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("totp with mismatched data must fail");
        assert!(
            err.to_string().contains("unsupported_credential_type"),
            "got: {err}"
        );
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE credentials SET credential_type = 'Password' WHERE id = ?")
            .bind(pw_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        // A TOTP entry without a URL has no origin binding.
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE credentials SET url = NULL WHERE id = ?")
            .bind(totp_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": totp_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("totp without a bound URL must fail");
        assert!(
            err.to_string().starts_with("origin_binding_required"),
            "got: {err}"
        );
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE credentials SET url = 'https://example.com/totp' WHERE id = ?")
            .bind(totp_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        // Origin mismatch.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://evil.com",
                    "item_id": totp_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("totp from a mismatched origin must fail");
        assert!(err.to_string().starts_with("origin_mismatch"), "got: {err}");

        // Credential owned by another identity.
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "get_totp",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": totp_id.to_string(),
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("totp for a foreign identity must fail");
        assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(identity_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_copy_success_and_error_branches() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
        let clip_ok = clipboard_available();

        let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
        let pw_id = seed_password_credential(
            &db_path,
            identity_id,
            "Copy target",
            Some("https://example.com/login"),
            Some("alice@example.com"),
            "hunter2",
        )
        .await;
        let totp_id = seed_totp_credential(
            &db_path,
            identity_id,
            "TOTP entry",
            Some("https://example.com/totp"),
        )
        .await;
        // A credential with no username and no URL; metadata carries an email
        // so the username fallback can be exercised.
        let anon_id = seed_password_credential(
            &db_path,
            identity_id,
            "Anonymous entry",
            None,
            None,
            "anon-pw",
        )
        .await;
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE credentials SET metadata = ? WHERE id = ?")
            .bind(r#"{"email":"meta@example.com"}"#)
            .bind(anon_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        // Happy path: copy the username.
        let result = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "field": "username",
                    "user_gesture": true
                }),
            ),
        )
        .await;
        assert_copy_outcome(result, clip_ok);

        // Happy path: copy the password (case-insensitive field name).
        let result = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "field": "PASSWORD",
                    "user_gesture": true
                }),
            ),
        )
        .await;
        assert_copy_outcome(result, clip_ok);

        // Happy path: copy a TOTP code.
        let result = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": totp_id.to_string(),
                    "field": "totp",
                    "user_gesture": true
                }),
            ),
        )
        .await;
        assert_copy_outcome(result, clip_ok);

        // Username falls back to the metadata email.
        let result = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": anon_id.to_string(),
                    "field": "username",
                    "user_gesture": true
                }),
            ),
        )
        .await;
        assert_copy_outcome(result, clip_ok);

        // Clearing metadata leaves no username -> not_found (before clipboard).
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE credentials SET metadata = '{}' WHERE id = ?")
            .bind(anon_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": anon_id.to_string(),
                    "field": "username",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("copy without any username must fail");
        assert!(
            err.to_string()
                .contains("not_found: username not available"),
            "got: {err}"
        );

        // Bad payload -> context error.
        let err = handle_request(&db_path, &state_dir, request("copy", serde_json::json!({})))
            .await
            .expect_err("copy without payload fields must fail");
        assert!(
            err.to_string().contains("invalid payload for copy"),
            "got: {err}"
        );

        // Missing gesture is rejected before anything else.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "field": "password"
                }),
            ),
        )
        .await
        .expect_err("copy without a gesture must fail");
        assert!(
            err.to_string().starts_with("user_gesture_required"),
            "got: {err}"
        );

        // Password field on a TOTP credential is unsupported.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": totp_id.to_string(),
                    "field": "password",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("copy password of a totp credential must fail");
        assert!(
            err.to_string().contains("unsupported_credential_type"),
            "got: {err}"
        );

        // TOTP field on a password credential is unsupported.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "field": "totp",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("copy totp of a password credential must fail");
        assert!(
            err.to_string().contains("unsupported_credential_type"),
            "got: {err}"
        );

        // Origin mismatch.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://evil.com",
                    "item_id": pw_id.to_string(),
                    "field": "username",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("copy from a mismatched origin must fail");
        assert!(err.to_string().starts_with("origin_mismatch"), "got: {err}");

        // Credential owned by another identity.
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "copy",
                serde_json::json!({
                    "origin": "https://example.com",
                    "item_id": pw_id.to_string(),
                    "field": "username",
                    "user_gesture": true
                }),
            ),
        )
        .await
        .expect_err("copy for a foreign identity must fail");
        assert!(err.to_string().starts_with("wrong_identity"), "got: {err}");
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("UPDATE workspaces SET active_identity_id = ?")
            .bind(identity_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_passkey_payload_validation_errors() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

        let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;
        let good_client_data = local_client_data_for("https://example.com", "Y2hhbGxlbmdl");

        // passkey_list: malformed payload.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("passkey_list", serde_json::json!({})),
        )
        .await
        .expect_err("passkey_list without origin must fail");
        assert!(
            err.to_string().contains("invalid payload for passkey_list"),
            "got: {err}"
        );

        // passkey_create: malformed payload (no request_json at all).
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
            ),
        )
        .await
        .expect_err("passkey_create without request_json must fail");
        assert!(
            err.to_string()
                .contains("invalid payload for passkey_create"),
            "got: {err}"
        );

        // passkey_create: client_data_json_b64 is not base64url.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "request_json": {
                        "rp": { "id": "example.com" },
                        "user": {
                            "id": URL_SAFE_NO_PAD.encode(b"u"),
                            "name": "b@example.com"
                        },
                        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
                    },
                    "client_data_json_b64": "!!!not-base64url!!!"
                }),
            ),
        )
        .await
        .expect_err("non-base64url client data must fail");
        assert!(
            err.to_string()
                .contains("client_data_json_b64 must be base64url"),
            "got: {err}"
        );

        // passkey_create: creation options rejected by core; the PersonaError
        // prefix is flattened away by flat_persona_error.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_create",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "request_json": {
                        "rp": { "id": "example.com" },
                        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
                    },
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&good_client_data)
                }),
            ),
        )
        .await
        .expect_err("creation options without user must fail");
        assert!(
            err.to_string().starts_with("invalid_request"),
            "flat_persona_error must strip the human prefix, got: {err}"
        );

        // passkey_assert: malformed payload.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({ "origin": "https://example.com", "user_gesture": true }),
            ),
        )
        .await
        .expect_err("passkey_assert without item_id must fail");
        assert!(
            err.to_string()
                .contains("invalid payload for passkey_assert"),
            "got: {err}"
        );

        // passkey_assert: non-UUID item id.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "item_id": "not-a-uuid",
                    "client_data_json_b64": URL_SAFE_NO_PAD.encode(&good_client_data)
                }),
            ),
        )
        .await
        .expect_err("passkey_assert with a non-uuid item must fail");
        assert!(
            err.to_string().starts_with("invalid_request: item_id uuid"),
            "got: {err}"
        );

        // passkey_assert: client_data_json_b64 is not base64url.
        let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "passkey_assert",
                serde_json::json!({
                    "origin": "https://example.com",
                    "user_gesture": true,
                    "item_id": uuid::Uuid::new_v4().to_string(),
                    "client_data_json_b64": "!!!not-base64url!!!"
                }),
            ),
        )
        .await
        .expect_err("non-base64url assert client data must fail");
        assert!(
            err.to_string()
                .contains("client_data_json_b64 must be base64url"),
            "got: {err}"
        );

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn bridge_authenticated_session_signature_enforcement() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
        std::env::remove_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;
        let origin_payload = serde_json::json!({ "origin": "https://example.com" });

        // No auth block at all -> pairing_required.
        let err = handle_request(
            &db_path,
            &state_dir,
            request("get_suggestions", origin_payload.clone()),
        )
        .await
        .expect_err("unauthenticated request must fail");
        assert!(
            err.to_string().starts_with("pairing_required"),
            "got: {err}"
        );

        // Auth block without a session id -> pairing_required.
        let req = BridgeRequest {
            request_id: Some("req-1".to_string()),
            kind: "get_suggestions".to_string(),
            payload: origin_payload.clone(),
            auth: Some(BridgeAuth {
                session_id: None,
                ts_ms: now_ms(),
                nonce: "n1".to_string(),
                signature: "AA".to_string(),
            }),
        };
        let err = handle_request(&db_path, &state_dir, req)
            .await
            .expect_err("auth without session_id must fail");
        assert!(
            err.to_string().starts_with("pairing_required"),
            "got: {err}"
        );

        // Pair for real so a session and key exist.
        let (session_id, key_b64) = pair_extension(&state_dir, "ext-sign", "inst-sign").await;

        // Unknown session id -> session_expired.
        let req = signed_request(
            "get_suggestions",
            origin_payload.clone(),
            "req-1",
            "00000000-0000-0000-0000-000000000000",
            &key_b64,
            now_ms(),
            "nonce-unknown",
        );
        let err = handle_request(&db_path, &state_dir, req)
            .await
            .expect_err("unknown session must fail");
        assert!(err.to_string().starts_with("session_expired"), "got: {err}");

        // Valid signature passes.
        let req = signed_request(
            "get_suggestions",
            origin_payload.clone(),
            "req-1",
            &session_id,
            &key_b64,
            now_ms(),
            "nonce-ok",
        );
        let resp = handle_request(&db_path, &state_dir, req).await.unwrap();
        assert!(
            resp.ok,
            "correctly signed request must succeed: {:?}",
            resp.error
        );

        // Tampered but well-formed signature -> authentication_failed.
        let mut req = signed_request(
            "get_suggestions",
            origin_payload.clone(),
            "req-1",
            &session_id,
            &key_b64,
            now_ms(),
            "nonce-bad",
        );
        if let Some(auth) = req.auth.as_mut() {
            auth.signature = "AAAA".to_string();
        }
        let err = handle_request(&db_path, &state_dir, req)
            .await
            .expect_err("tampered signature must fail");
        assert_eq!(err.to_string(), "authentication_failed");

        // Stale timestamp is rejected under the default 5 minute skew.
        let req = signed_request(
            "get_suggestions",
            origin_payload.clone(),
            "req-1",
            &session_id,
            &key_b64,
            now_ms() - 10 * 60 * 1000,
            "nonce-stale",
        );
        let err = handle_request(&db_path, &state_dir, req)
            .await
            .expect_err("stale timestamp must fail");
        assert!(
            err.to_string()
                .starts_with("authentication_failed: stale timestamp"),
            "got: {err}"
        );

        // A larger configured skew lets the very same request through.
        std::env::set_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS", "3600000");
        let req = signed_request(
            "get_suggestions",
            origin_payload.clone(),
            "req-1",
            &session_id,
            &key_b64,
            now_ms() - 10 * 60 * 1000,
            "nonce-skew",
        );
        let resp = handle_request(&db_path, &state_dir, req).await.unwrap();
        assert!(
            resp.ok,
            "stale request must pass with a raised skew: {:?}",
            resp.error
        );
        std::env::remove_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS");

        // A pairing whose key is not valid base64url -> invalid key.
        save_state(
            &state_dir,
            &BridgeStateFile {
                version: 1,
                pairings: vec![PairingInfo {
                    extension_id: "ext-evil".to_string(),
                    client_instance_id: "inst-evil".to_string(),
                    key_b64: "!!!not-base64".to_string(),
                    paired_at_ms: now_ms(),
                    session: Some(SessionInfo {
                        session_id: "session-evil".to_string(),
                        expires_at_ms: now_ms() + 60_000,
                    }),
                }],
                pending: vec![],
            },
        )
        .unwrap();
        let req = BridgeRequest {
            request_id: Some("req-1".to_string()),
            kind: "get_suggestions".to_string(),
            payload: origin_payload.clone(),
            auth: Some(BridgeAuth {
                session_id: Some("session-evil".to_string()),
                ts_ms: now_ms(),
                nonce: "n".to_string(),
                signature: "AA".to_string(),
            }),
        };
        let err = handle_request(&db_path, &state_dir, req)
            .await
            .expect_err("corrupt pairing key must fail");
        assert!(
            err.to_string()
                .starts_with("authentication_failed: invalid key"),
            "got: {err}"
        );

        // A valid key but non-base64url signature encoding.
        save_state(
            &state_dir,
            &BridgeStateFile {
                version: 1,
                pairings: vec![PairingInfo {
                    extension_id: "ext-enc".to_string(),
                    client_instance_id: "inst-enc".to_string(),
                    key_b64: URL_SAFE_NO_PAD.encode([9u8; 32]),
                    paired_at_ms: now_ms(),
                    session: Some(SessionInfo {
                        session_id: "session-enc".to_string(),
                        expires_at_ms: now_ms() + 60_000,
                    }),
                }],
                pending: vec![],
            },
        )
        .unwrap();
        let req = BridgeRequest {
            request_id: Some("req-1".to_string()),
            kind: "get_suggestions".to_string(),
            payload: origin_payload,
            auth: Some(BridgeAuth {
                session_id: Some("session-enc".to_string()),
                ts_ms: now_ms(),
                nonce: "n".to_string(),
                signature: "!!!".to_string(),
            }),
        };
        let err = handle_request(&db_path, &state_dir, req)
            .await
            .expect_err("bad signature encoding must fail");
        assert!(
            err.to_string()
                .starts_with("authentication_failed: invalid signature encoding"),
            "got: {err}"
        );

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
        std::env::remove_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS");
    }

    #[test]
    fn bridge_pure_helpers_cover_edge_cases() {
        // ok/err constructors.
        let ok_resp = ok(
            Some("r1".to_string()),
            "kind-x",
            serde_json::json!({"a": 1}),
        );
        assert!(ok_resp.ok);
        assert_eq!(ok_resp.kind, "kind-x");
        assert_eq!(ok_resp.request_id.as_deref(), Some("r1"));
        assert!(ok_resp.error.is_none());
        assert!(ok_resp.payload.is_some());
        let err_resp = err::<serde_json::Value>(None, "error", "boom".to_string());
        assert!(!err_resp.ok);
        assert_eq!(err_resp.kind, "error");
        assert!(err_resp.request_id.is_none());
        assert_eq!(err_resp.error.as_deref(), Some("boom"));
        assert!(err_resp.payload.is_none());

        // normalize_pairing_code trims, strips spaces, and uppercases.
        assert_eq!(normalize_pairing_code("  ab c-12 9 "), "ABC-129");
        assert_eq!(normalize_pairing_code("123-456"), "123-456");

        // state_path and now_ms.
        assert_eq!(
            state_path(Path::new("/tmp/s")),
            PathBuf::from("/tmp/s/state.json")
        );
        assert!(now_ms() > 1_600_000_000_000, "now_ms must be plausible");

        // default_true.
        assert!(default_true());

        // canonicalize_json_value is an identity on parsed JSON, including
        // nested objects, arrays, and scalars.
        let input = serde_json::json!({
            "b": 1,
            "a": [ { "d": 2, "c": 3 }, null, true, "x", 1.5 ],
            "nested": { "z": { "m": [] } }
        });
        assert_eq!(canonicalize_json_value(&input), input);

        // flat_persona_error strips the human prefix but keeps the wire code.
        let flat = flat_persona_error(PersonaError::InvalidInput(
            "invalid_request: missing user".to_string(),
        ));
        assert_eq!(flat.to_string(), "invalid_request: missing user");
        let flat_plain = flat_persona_error(PersonaError::NotFound("item".to_string()));
        assert_eq!(flat_plain.to_string(), "item");

        // compute_match_strength buckets.
        assert_eq!(
            compute_match_strength("github.com", "https://github.com/login"),
            100
        );
        assert_eq!(
            compute_match_strength("GitHub.COM", "https://github.com"),
            100
        );
        assert_eq!(
            compute_match_strength("api.github.com", "https://github.com"),
            90
        );
        assert_eq!(
            compute_match_strength("github.com", "https://api.github.com/x"),
            90
        );
        // Same registrable domain (TLD+1) but no subdomain relation.
        assert_eq!(
            compute_match_strength("a.b.example.com", "https://c.d.example.com/"),
            60
        );
        // Legacy contains fallback for non-URL credential values.
        assert_eq!(
            compute_match_strength("github.com", "not-a-url-but-mentions-github.com"),
            80
        );
        assert_eq!(
            compute_match_strength("github.com", "https://gitlab.com/x"),
            0
        );

        // validate_origin_binding requires TLD+1 or better (or no URL at all).
        assert!(validate_origin_binding("example.com", None));
        assert!(validate_origin_binding(
            "example.com",
            Some("https://example.com/login")
        ));
        assert!(validate_origin_binding(
            "a.example.com",
            Some("https://example.com")
        ));
        assert!(!validate_origin_binding(
            "evil.com",
            Some("https://example.com")
        ));

        // origin_to_host accepts origins, bare hosts, and ports, and rejects
        // schemes without a host part.
        assert_eq!(
            origin_to_host("https://Example.com/path?q=1").unwrap(),
            "example.com"
        );
        assert_eq!(origin_to_host("example.com").unwrap(), "example.com");
        assert_eq!(
            origin_to_host("http://localhost:8080").unwrap(),
            "localhost"
        );
        assert!(origin_to_host("mailto:user@example.com").is_err());
        assert!(origin_to_host("").is_err());
    }

    #[test]
    fn gesture_required_env_parsing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
        assert!(gesture_required(), "default is on");

        for off in ["0", "false", "FALSE"] {
            std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", off);
            assert!(!gesture_required(), "{off} must disable the requirement");
        }
        for on in ["1", "yes", "true"] {
            std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", on);
            assert!(gesture_required(), "{on} must keep the requirement on");
        }

        std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    }

    #[test]
    fn bridge_state_file_helpers_roundtrip_and_purge() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path();
        let now = now_ms();

        // Missing file -> default state with version 1.
        let state = load_state(state_dir).unwrap();
        assert_eq!(state.version, 1);
        assert!(state.pairings.is_empty());
        assert!(state.pending.is_empty());

        // Round trip through save_state.
        let mut st = BridgeStateFile {
            version: 1,
            pairings: vec![PairingInfo {
                extension_id: "ext".to_string(),
                client_instance_id: "inst".to_string(),
                key_b64: URL_SAFE_NO_PAD.encode([1u8; 32]),
                paired_at_ms: now,
                session: Some(SessionInfo {
                    session_id: "s1".to_string(),
                    expires_at_ms: now + 1_000,
                }),
            }],
            pending: vec![PendingPairing {
                code: "111-222".to_string(),
                extension_id: "ext".to_string(),
                client_instance_id: "inst".to_string(),
                key_b64: URL_SAFE_NO_PAD.encode([2u8; 32]),
                requested_at_ms: now,
                expires_at_ms: now + 1_000,
                approved: false,
            }],
        };
        save_state(state_dir, &st).unwrap();
        let loaded = load_state(state_dir).unwrap();
        assert_eq!(loaded.pairings.len(), 1);
        assert_eq!(
            loaded.pairings[0].session.as_ref().unwrap().session_id,
            "s1"
        );
        assert_eq!(loaded.pending.len(), 1);

        // Version 0 files are normalized to 1.
        std::fs::write(state_path(state_dir), br#"{"version": 0}"#).unwrap();
        assert_eq!(load_state(state_dir).unwrap().version, 1);

        // Corrupt JSON is an error, not a panic.
        std::fs::write(state_path(state_dir), b"{nope").unwrap();
        assert!(load_state(state_dir).is_err());

        // purge_expired drops stale pending requests and clears expired
        // sessions while leaving live entries untouched.
        st.pending.push(PendingPairing {
            code: "999-999".to_string(),
            extension_id: "old".to_string(),
            client_instance_id: "old".to_string(),
            key_b64: URL_SAFE_NO_PAD.encode([3u8; 32]),
            requested_at_ms: now - 20 * 60_000,
            expires_at_ms: now - 1,
            approved: false,
        });
        st.pairings.push(PairingInfo {
            extension_id: "dead".to_string(),
            client_instance_id: "dead".to_string(),
            key_b64: URL_SAFE_NO_PAD.encode([4u8; 32]),
            paired_at_ms: now - 90_000,
            session: Some(SessionInfo {
                session_id: "dead-session".to_string(),
                expires_at_ms: now - 1,
            }),
        });
        purge_expired(&mut st);
        assert_eq!(st.pending.len(), 1, "only the live pending request remains");
        assert_eq!(st.pending[0].code, "111-222");
        assert_eq!(st.pairings.len(), 2);
        assert!(
            st.pairings[0].session.is_some(),
            "live session must survive"
        );
        assert!(
            st.pairings[1].session.is_none(),
            "expired session must be cleared"
        );
    }

    #[test]
    fn ensure_session_creates_once_and_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path();

        // Unknown pairing -> no session.
        assert!(ensure_session(state_dir, "ext-s", "inst-s")
            .unwrap()
            .is_none());

        // A stored pairing without a session gets one on the first hello.
        save_state(
            state_dir,
            &BridgeStateFile {
                version: 1,
                pairings: vec![PairingInfo {
                    extension_id: "ext-s".to_string(),
                    client_instance_id: "inst-s".to_string(),
                    key_b64: URL_SAFE_NO_PAD.encode([3u8; 32]),
                    paired_at_ms: now_ms(),
                    session: None,
                }],
                pending: vec![],
            },
        )
        .unwrap();
        let first = ensure_session(state_dir, "ext-s", "inst-s")
            .unwrap()
            .unwrap();
        let second = ensure_session(state_dir, "ext-s", "inst-s")
            .unwrap()
            .unwrap();
        assert_eq!(
            first.session_id, second.session_id,
            "an existing session must be reused"
        );
        assert!(second.expires_at_ms > now_ms());

        // The issued session was persisted.
        let state = load_state(state_dir).unwrap();
        assert_eq!(
            state.pairings[0].session.as_ref().unwrap().session_id,
            first.session_id
        );
    }

    #[test]
    fn totp_helpers_match_rfc_vectors_and_clamps() {
        // RFC 4226 Appendix D reference vectors (HMAC-SHA1, 6 digits).
        let secret = decode_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(secret, b"12345678901234567890".to_vec());
        assert_eq!(hotp(&secret, 0, "SHA1").unwrap() % 1_000_000, 755224);
        assert_eq!(hotp(&secret, 1, "SHA1").unwrap() % 1_000_000, 287082);
        assert_eq!(hotp(&secret, 5, "SHA1").unwrap() % 1_000_000, 254676);
        assert_eq!(hotp(&secret, 9, "SHA1").unwrap() % 1_000_000, 520489);

        // HMAC-SHA256/SHA512 truncated values cross-checked against an
        // independent reference implementation (counter 1, 8 digits).
        // The 30-byte secret "123456789012345678901234567890".
        let s256 = decode_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let s512 = decode_totp_secret(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        )
        .unwrap();
        assert_eq!(hotp(&s256, 1, "SHA256").unwrap() % 100_000_000, 82366409);
        assert_eq!(hotp(&s512, 1, "SHA512").unwrap() % 100_000_000, 98063437);
        // Unknown (and lowercase) algorithms fall back to HMAC-SHA1.
        assert_eq!(hotp(&secret, 1, "sha1").unwrap() % 1_000_000, 287082);
        assert_eq!(hotp(&secret, 1, "MD5").unwrap() % 1_000_000, 287082);

        // decode_totp_secret normalizes case, whitespace, and padding.
        assert_eq!(
            decode_totp_secret("gezd gnbvGY3TQOJQ\nGEZDGNBVGY3TQOJQ").unwrap(),
            secret
        );
        assert_eq!(
            decode_totp_secret("NBSWY3DPFVZWKY3SMV2C2YLCMM======").unwrap(),
            b"hello-secret-abc".to_vec()
        );
        let err = decode_totp_secret("not!base32!").unwrap_err();
        assert!(
            err.to_string().starts_with("invalid_base32_secret"),
            "got: {err}"
        );

        // generate_totp_code_from_data: six digits, remaining within period.
        let (code, remaining, period) = generate_totp_code_from_data(&TwoFactorData {
            secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            issuer: "Issuer".to_string(),
            account_name: "a@b.c".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
        })
        .unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&remaining));
        assert_eq!(period, 30);

        // Digits below 4 clamp up; a zero period becomes one second.
        let (short, remaining0, period0) = generate_totp_code_from_data(&TwoFactorData {
            secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            issuer: "Issuer".to_string(),
            account_name: "a@b.c".to_string(),
            algorithm: "SHA256".to_string(),
            digits: 1,
            period: 0,
        })
        .unwrap();
        assert_eq!(short.len(), 4);
        assert_eq!(remaining0, 1, "period 1 leaves exactly one second");
        assert_eq!(period0, 1);

        // Nine digits still works...
        let (long, _, _) = generate_totp_code_from_data(&TwoFactorData {
            secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            issuer: "Issuer".to_string(),
            account_name: "a@b.c".to_string(),
            algorithm: "SHA512".to_string(),
            digits: 9,
            period: 60,
        })
        .unwrap();
        assert_eq!(long.len(), 9);

        // Regression: 10 digits used to overflow `10_u32.pow(..)` (panic in
        // debug, wrapped modulus in release). The u64 path must format a full
        // 10-digit code.
        let (max_digits, _, _) = generate_totp_code_from_data(&TwoFactorData {
            secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            issuer: "Issuer".to_string(),
            account_name: "a@b.c".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 10,
            period: 30,
        })
        .unwrap();
        assert_eq!(max_digits.len(), 10);
        assert!(max_digits.chars().all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn frame_codec_roundtrip_enforces_length_limits() {
        // Round trip a JSON payload through write_frame/read_frame.
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_frame(&mut client, &serde_json::json!({"hello": "bridge"}))
            .await
            .unwrap();
        let frame = read_frame(&mut server)
            .await
            .unwrap()
            .expect("frame must be present");
        let value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(value["hello"], "bridge");

        // EOF before any bytes means a clean shutdown.
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        assert!(read_frame(&mut server).await.unwrap().is_none());

        // A zero length prefix is rejected.
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&0u32.to_le_bytes()).await.unwrap();
        drop(client);
        let err = read_frame(&mut server).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid_frame_length"),
            "got: {err}"
        );

        // Lengths above the 10 MiB cap are rejected.
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&(10u32 * 1024 * 1024 + 1).to_le_bytes())
            .await
            .unwrap();
        drop(client);
        let err = read_frame(&mut server).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid_frame_length"),
            "got: {err}"
        );

        // A truncated body is an error, not a hang.
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&64u32.to_le_bytes()).await.unwrap();
        client.write_all(b"partial").await.unwrap();
        drop(client);
        assert!(read_frame(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn execute_approve_code_marks_pending_pairing_approved() {
        let (_dir, _db_path, state_dir, _identity_id) = seeded_bridge().await;

        // Create a pending request through the protocol, then approve it via
        // the CLI flag (leading/trailing whitespace is normalized away).
        let resp = handle_request(
            Path::new(""),
            &state_dir,
            request(
                "pairing_request",
                serde_json::json!({
                    "extension_id": "ext-cli",
                    "client_instance_id": "inst-cli"
                }),
            ),
        )
        .await
        .unwrap();
        let code = resp.payload.unwrap()["code"]
            .as_str()
            .expect("pairing code present")
            .to_string();

        execute(BridgeArgs {
            db_path: None,
            approve_code: Some(format!(" {}", code)),
            state_dir: Some(state_dir.clone()),
        })
        .await
        .expect("approve must succeed");

        let state = load_state(&state_dir).unwrap();
        assert_eq!(state.pending.len(), 1);
        assert!(
            state.pending[0].approved,
            "pending request must be marked approved"
        );

        // Unknown codes fail without mutating anything.
        let err = execute(BridgeArgs {
            db_path: None,
            approve_code: Some("000-000".to_string()),
            state_dir: Some(state_dir.clone()),
        })
        .await
        .expect_err("unknown approval code must fail");
        assert!(
            err.to_string().contains("pairing_not_found_or_expired"),
            "got: {err}"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn open_db_and_unlocked_service_report_precise_errors() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let (dir, db_path, _state_dir, identity_id) = seeded_bridge().await;

        // A database in a nonexistent directory fails to open.
        let missing = dir.path().join("no-such-dir").join("missing.db");
        assert!(open_db(&missing).await.is_err(), "missing file must fail");

        // No password in the environment -> locked.
        let err = match open_unlocked_service(&db_path).await {
            Err(e) => e,
            Ok(_) => panic!("locked vault must not open"),
        };
        assert!(err.to_string().starts_with("locked:"), "got: {err}");

        // Wrong password -> authentication_failed.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "definitely-wrong");
        let err = match open_unlocked_service(&db_path).await {
            Err(e) => e,
            Ok(_) => panic!("wrong password must not unlock"),
        };
        assert!(
            err.to_string().starts_with("authentication_failed"),
            "got: {err}"
        );

        // Correct password returns the active identity.
        std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
        let (_service, active) = open_unlocked_service(&db_path).await.unwrap();
        assert_eq!(active, Some(identity_id));
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        // get_active_identity_id is None when no workspace row exists.
        let db = open_db(&db_path).await.unwrap();
        sqlx::query("DELETE FROM workspaces")
            .execute(db.pool())
            .await
            .unwrap();
        drop(db);
        let db = open_db(&db_path).await.unwrap();
        assert_eq!(get_active_identity_id(&db).await, None);
    }
}
