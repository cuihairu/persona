use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::Args;
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use reqwest;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::Sha512;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};
use url::Url;

use persona_core::context::{
    discover_git_repo, suggest as context_suggest, ContextMapFile, ContextSignals,
};
use persona_core::crypto::{parse_creation_options, validate_origin_matches_rp_id};
use persona_core::models::{CredentialData, CredentialType, PasswordCredentialData, TwoFactorData};
use persona_core::password::{PasswordGenerator, PasswordGeneratorOptions};
use persona_core::storage::{CredentialRepository, IdentityRepository, WorkspaceRepository};
use persona_core::{Database, PersonaError, PersonaService, Repository};

mod account;
mod approval;
mod clipboard;
mod pairing;
mod passkey;
mod paths;
mod protocol;
mod save;
mod status;
mod sync;
mod sync_connect;
mod totp;

use self::account::*;
use self::approval::*;
use self::clipboard::*;
use self::pairing::*;
use self::passkey::*;
use self::paths::*;
pub use self::protocol::BridgeArgs;
use self::protocol::*;
use self::save::*;
use self::status::*;
use self::sync::*;
use self::sync_connect::*;
use self::totp::*;

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

    run_bridge(&db_path, &state_dir, &mut stdin, &mut stdout).await
}

/// The frame loop, split from `execute` so tests can drive it over
/// in-memory pipes instead of the process stdio.
pub(super) async fn run_bridge<R, W>(
    db_path: &Path,
    state_dir: &Path,
    reader: &mut R,
    writer: &mut W,
) -> Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    loop {
        let frame = match read_frame(reader).await {
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
                write_frame(writer, &resp).await?;
                continue;
            }
        };

        let request_id = req.request_id.clone();
        let resp = handle_request(db_path, state_dir, req)
            .await
            .unwrap_or_else(|e| BridgeResponse::<serde_json::Value> {
                request_id,
                kind: "error".to_string(),
                ok: false,
                error: Some(e.to_string()),
                payload: None,
            });

        write_frame(writer, &resp).await?;
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

            // Detect running desktop/cli Connect server for unlock linkage.
            let connect_port = detect_connect_server().await;

            let payload = serde_json::json!({
                "server_version": "0.1.0",
                "protocol_version": 7,
                "capabilities": ["status", "pairing_request", "pairing_finalize", "get_suggestions", "request_fill", "get_totp", "copy", "passkey_list", "passkey_create", "passkey_assert", "passkey_credential_provider_list", "passkey_credential_provider_assert", "find_for_save", "save_credential", "generate_password", "sync_connect", "account_login", "account_status", "account_logout", "sync_push_now", "sync_resolve_conflict"],
                "pairing_required": require_pairing && session.is_none(),
                "paired": session.is_some(),
                "session_id": session.as_ref().map(|s| s.session_id.clone()),
                "session_expires_at_ms": session.as_ref().map(|s| s.expires_at_ms),
                "connect_available": connect_port.is_some(),
                "connect_port": connect_port,
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
            let form_type = parsed.form_type.as_deref().unwrap_or("login");

            // Stage 4 (context-aware, bridge half): optional host/cwd signals
            // let the bridge rank the context-suggested identity's
            // credentials first and carry an identity-level `context` field.
            // Old extensions send neither and see byte-identical responses.
            // PERSONA_NO_CONTEXT opts the layer out (gate lives in the seam);
            // any load failure degrades to no suggestion (design §10).
            let context = context_suggestion_for_bridge(db_path, &host, &parsed).await;
            let items =
                get_credential_suggestions(db_path, &host, form_type, context.as_ref()).await?;
            let payload = serde_json::to_value(SuggestionsResponse {
                items,
                suggesting_for: host,
                context,
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
            // Password and BankCard credentials are fillable. Bank cards
            // deliberately skip origin binding below: cred.url is None for
            // cards and validate_origin_binding already allows that.
            if cred.credential_type != CredentialType::Password
                && cred.credential_type != CredentialType::BankCard
            {
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
                    card: None,
                },
                // CVV is intentionally absent: fill targets page DOM inputs
                // readable by page scripts; CVV is copy-only (clipboard).
                CredentialData::BankCard(c) => FillResponse {
                    username: None,
                    password: None,
                    card: Some(CardFillData {
                        card_number: c.card_number,
                        cardholder_name: c.cardholder_name,
                        expiry_date: c.expiry_date,
                    }),
                },
                CredentialData::Raw(_) => FillResponse {
                    username: cred.username.clone(),
                    password: None,
                    card: None,
                },
                _ => FillResponse {
                    username: cred.username.clone(),
                    password: None,
                    card: None,
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

            // HOTP 是计数器型，浏览器填充路径没有计数器概念：明确报错，
            // 而不是按时间窗返回错误码。
            if let CredentialData::TwoFactor(tf) = &data {
                if tf.hotp.unwrap_or(false) {
                    return Err(anyhow!(
                        "hotp_not_supported: HOTP entries need an explicit counter — use persona totp code <id> --counter N"
                    ));
                }
            }

            let (code, remaining_seconds, period) = match data {
                CredentialData::TwoFactor(tf) => generate_totp_code_from_data(&tf)?,
                // 游戏令牌经 core 统一调度器（Steam Guard 离线可算；绑定型
                // provider 在此报 unsupported 而不是生成错误码）
                CredentialData::GameToken(gt) => {
                    let c = persona_core::crypto::game_token::generate_game_token_code_now(&gt)?;
                    (c.code, c.remaining_seconds, c.period)
                }
                _ => return Err(anyhow!("unsupported_credential_type")),
            };

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
                    match data {
                        CredentialData::TwoFactor(tf) => generate_totp_code_from_data(&tf)?.0,
                        CredentialData::GameToken(gt) => {
                            persona_core::crypto::game_token::generate_game_token_code_now(&gt)?
                                .code
                        }
                        _ => return Err(anyhow!("unsupported_credential_type")),
                    }
                }
                // Card fields are copy-only. There is deliberately no card
                // branch under request_fill's `card` payload for CVV: fill
                // targets page DOM (readable by page scripts), copy targets
                // the clipboard — a 60s-window value the user pastes by hand.
                "card_number" | "cardholder_name" | "expiry_date" | "cvv" => {
                    if cred.credential_type != CredentialType::BankCard {
                        return Err(anyhow!("unsupported_credential_type"));
                    }
                    let data = service
                        .get_credential_data(&item_id)
                        .await?
                        .ok_or_else(|| anyhow!("not_found"))?;
                    let card = match data {
                        CredentialData::BankCard(c) => c,
                        _ => return Err(anyhow!("unsupported_credential_type")),
                    };
                    let text = match field.as_str() {
                        "card_number" => card.card_number,
                        "cardholder_name" => card.cardholder_name,
                        "expiry_date" => card.expiry_date,
                        _ => card.cvv,
                    };
                    if text.trim().is_empty() {
                        return Err(anyhow!("not_found: field '{field}' is empty"));
                    }
                    text
                }
                other => return Err(anyhow!("invalid_payload: unknown field '{other}'")),
            };

            copy_text_to_clipboard(&text)?;

            copy_success_response(
                req.request_id,
                &parsed.origin,
                &host,
                &parsed.item_id,
                &cred.name,
                &field,
            )
        }
        "find_for_save" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: FindForSavePayload =
                serde_json::from_value(req.payload).context("invalid payload for find_for_save")?;
            let host = origin_to_host(&parsed.origin)?;
            let matches =
                find_credentials_for_save(db_path, &host, parsed.username.as_deref()).await?;
            Ok(ok(
                req.request_id,
                "find_for_save_response",
                serde_json::to_value(FindForSaveResponse { matches })?,
            ))
        }
        "save_credential" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: SaveCredentialPayload = serde_json::from_value(req.payload)
                .context("invalid payload for save_credential")?;
            run_save_credential(db_path, req.request_id, parsed).await
        }
        "generate_password" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: GeneratePasswordPayload = serde_json::from_value(req.payload)
                .context("invalid payload for generate_password")?;
            run_generate_password(db_path, req.request_id, parsed).await
        }
        "passkey_list" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: PasskeyListPayload =
                serde_json::from_value(req.payload).context("invalid payload for passkey_list")?;
            run_passkey_list(db_path, req.request_id, parsed, "passkey_list").await
        }
        // OS passkey provider 数据源（P4.1）：与 passkey_list 同语义同校验链，
        // 差异仅在消息名与审计/日志的来源口径。
        "passkey_credential_provider_list" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: PasskeyListPayload = serde_json::from_value(req.payload)
                .context("invalid payload for passkey_credential_provider_list")?;
            run_passkey_list(
                db_path,
                req.request_id,
                parsed,
                "passkey_credential_provider_list",
            )
            .await
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
                #[cfg(unix)]
                DesktopApproval::Approved => {}
                #[cfg(unix)]
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
            run_passkey_assert(
                db_path,
                req.request_id,
                parsed,
                "passkey_assert",
                "extension",
            )
            .await
        }
        // OS passkey provider 代断言（P4.1/P4.4）：同一信任链（gesture + 桌面
        // 审批 + core origin↔rp_id + 敏感操作门禁），审计 via=os_provider 区分
        // provider 来源；桌面审批弹窗 op 名透传，UI 可辨识。
        "passkey_credential_provider_assert" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: PasskeyAssertPayload = serde_json::from_value(req.payload)
                .context("invalid payload for passkey_credential_provider_assert")?;
            run_passkey_assert(
                db_path,
                req.request_id,
                parsed,
                "passkey_credential_provider_assert",
                "os_provider",
            )
            .await
        }
        // 云端同步参数发放（协议 v6，M5 批1）：把扩展做 HTTP 直连数据面
        // 所需的三件套（server_url / bearer / group key）经 HMAC 会话发给
        // 扩展——桥此后只做认证与密钥交接，数据面出本地桥（协议设计见
        // BRIDGE_PROTOCOL.md §17）。敏感级：group key 出桥，故在配对会话
        // 之上再要求 user gesture。
        "sync_connect" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: SyncConnectRequest =
                serde_json::from_value(req.payload).context("invalid payload for sync_connect")?;
            if gesture_required() && !parsed.user_gesture {
                warn!("sync_connect rejected: user_gesture required but not provided");
                return Err(anyhow!(
                    "user_gesture_required: sync_connect hands out vault decryption keys and must be triggered by explicit user action"
                ));
            }
            let payload = run_sync_connect(db_path).await?;
            info!(
                event = "bridge_sync_connect",
                device_id = %payload.device_id,
                "sync connect parameters issued to extension"
            );
            Ok(ok(
                req.request_id,
                "sync_connect_response",
                serde_json::to_value(payload)?,
            ))
        }
        // 账号域三件套（协议 v7，M5 批2）：SRP 登录/会话状态/登出，
        // 令牌只落 OS keyring（persona-account 条目），不过桥协议下发。
        "account_login" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: AccountLoginRequest =
                serde_json::from_value(req.payload).context("invalid payload for account_login")?;
            if gesture_required() && !parsed.user_gesture {
                warn!("account_login rejected: user_gesture required but not provided");
                return Err(anyhow!(
                    "user_gesture_required: account_login exchanges the vault password for a session token and must be triggered by explicit user action"
                ));
            }
            let payload = run_account_login(
                db_path,
                &parsed.account_id,
                &parsed.password,
                &parsed.device_name,
                &KeyringAccountTokenStore,
            )
            .await?;
            info!(event = "bridge_account_login", "account login via bridge");
            Ok(ok(
                req.request_id,
                "account_login_response",
                serde_json::to_value(payload)?,
            ))
        }
        "account_status" => {
            require_authenticated_session(state_dir, &req)?;
            let payload = run_account_status(db_path, &KeyringAccountTokenStore).await?;
            Ok(ok(
                req.request_id,
                "account_status_response",
                serde_json::to_value(payload)?,
            ))
        }
        // 云端写路径（协议 v7，M5 批3）：把主库（含经 save_credential 落库
        // 的扩展侧写入）推上云。写操作，配对会话之上再要求 user gesture。
        "sync_push_now" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: SyncPushNowRequest =
                serde_json::from_value(req.payload).context("invalid payload for sync_push_now")?;
            if gesture_required() && !parsed.user_gesture {
                warn!("sync_push_now rejected: user_gesture required but not provided");
                return Err(anyhow!(
                    "user_gesture_required: sync_push_now uploads vault data to the sync server and must be triggered by explicit user action"
                ));
            }
            let payload = run_sync_push_now(db_path).await?;
            info!(
                event = "bridge_sync_push_now",
                pulled = payload.pulled,
                pushed = payload.pushed,
                materialized = payload.materialized,
                "sync cycle completed via bridge"
            );
            Ok(ok(
                req.request_id,
                "sync_push_now_response",
                serde_json::to_value(payload)?,
            ))
        }
        // 冲突裁决（协议 v7，M5 批4）：采纳并发双版本之一，写操作。
        "sync_resolve_conflict" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: SyncResolveConflictRequest = serde_json::from_value(req.payload)
                .context("invalid payload for sync_resolve_conflict")?;
            if gesture_required() && !parsed.user_gesture {
                warn!("sync_resolve_conflict rejected: user_gesture required but not provided");
                return Err(anyhow!(
                    "user_gesture_required: sync_resolve_conflict overwrites the losing copy in the vault and must be triggered by explicit user action"
                ));
            }
            let payload =
                run_sync_resolve_conflict(db_path, &parsed.item_id, &parsed.adopt_op_id).await?;
            info!(
                event = "bridge_sync_resolve_conflict",
                item_id = %parsed.item_id,
                "conflict resolved via bridge"
            );
            Ok(ok(
                req.request_id,
                "sync_resolve_conflict_response",
                serde_json::to_value(payload)?,
            ))
        }
        "account_logout" => {
            require_authenticated_session(state_dir, &req)?;
            let parsed: AccountLogoutRequest = serde_json::from_value(req.payload)
                .context("invalid payload for account_logout")?;
            if gesture_required() && !parsed.user_gesture {
                warn!("account_logout rejected: user_gesture required but not provided");
                return Err(anyhow!(
                    "user_gesture_required: account_logout revokes the account session and must be triggered by explicit user action"
                ));
            }
            let payload =
                run_account_logout(db_path, &parsed.account_id, &KeyringAccountTokenStore).await?;
            info!(event = "bridge_account_logout", "account logout via bridge");
            Ok(ok(
                req.request_id,
                "account_logout_response",
                serde_json::to_value(payload)?,
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

pub(super) async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
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

pub(super) async fn write_frame<W: AsyncWriteExt + Unpin, T: Serialize>(
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
pub(crate) mod tests;
