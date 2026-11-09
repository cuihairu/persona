use super::*;

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

    /// Origin passed by the browser when launched as a native messaging host
    /// (e.g. `chrome-extension://<id>/`). Ignored; accepted so the host
    /// does not exit on the browser-supplied argument.
    #[arg(trailing_var_arg = true, hide = true)]
    pub browser_origin: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct BridgeRequest {
    #[serde(default)]
    pub(super) request_id: Option<String>,
    #[serde(rename = "type")]
    pub(super) kind: String,
    #[serde(default)]
    pub(super) payload: serde_json::Value,
    #[serde(default)]
    pub(super) auth: Option<BridgeAuth>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct BridgeResponse<T: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) request_id: Option<String>,
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) payload: Option<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct BridgeAuth {
    /// Session ID issued by the native host in `hello_response`.
    #[serde(default)]
    pub(super) session_id: Option<String>,
    /// Milliseconds since UNIX epoch (client clock).
    pub(super) ts_ms: i64,
    /// Unique nonce per request.
    pub(super) nonce: String,
    /// Base64url(no-pad) HMAC-SHA256 signature.
    pub(super) signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct HelloPayload {
    pub(super) extension_id: String,
    #[serde(default)]
    pub(super) _extension_version: Option<String>,
    #[serde(default)]
    pub(super) _protocol_version: Option<u32>,
    #[serde(default)]
    pub(super) client_instance_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PairingRequestPayload {
    pub(super) extension_id: String,
    pub(super) client_instance_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PairingFinalizePayload {
    pub(super) extension_id: String,
    pub(super) client_instance_id: String,
    pub(super) code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SuggestionsPayload {
    pub(super) origin: String,
    /// What kind of form the page scanned: "login" (default) or "card".
    /// The extension already sends this; older payloads without it fall
    /// back to "login" so existing behavior is unchanged.
    #[serde(default)]
    pub(super) form_type: Option<String>,
    /// Stage 4 context signals (optional): an explicit host signal, e.g. a
    /// page whose fill happens on another host's form. When omitted the
    /// origin host is the signal.
    #[serde(default)]
    pub(super) host: Option<String>,
    /// Stage 4 context signals (optional): terminal cwd (desktop bridge
    /// case) used for the repo-local map and repo discovery. Browser
    /// extensions never send it; absent signals change nothing.
    #[serde(default)]
    pub(super) cwd: Option<String>,
}

/// Card fields safe for in-page fill. Deliberately excludes CVV: fill
/// targets page DOM inputs that any page script can read; CVV is copy-only
/// (clipboard) — see BRIDGE_PROTOCOL.md.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct CardFillData {
    pub(super) card_number: String,
    pub(super) cardholder_name: String,
    pub(super) expiry_date: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SuggestionItem {
    pub(super) item_id: String,
    pub(super) title: String,
    pub(super) username_hint: Option<String>,
    pub(super) match_strength: u8,
    pub(super) credential_type: String,
    /// Stage 4: identity name that owns the credential. Always present in
    /// bridge responses so the popup can label entries; it is additive for
    /// older extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) identity: Option<String>,
}

/// Stage 4 identity-level suggestion for the requested context. Advisory
/// only — it never switches the active identity and never widens any
/// authorization gate; activation still requires `persona switch`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct ContextSuggestion {
    pub(super) identity: String,
    pub(super) score: f64,
    pub(super) reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SuggestionsResponse {
    pub(super) items: Vec<SuggestionItem>,
    pub(super) suggesting_for: String,
    /// Stage 4 context suggestion; omitted when no candidate (or the layer
    /// is opted out via PERSONA_NO_CONTEXT) so old consumers see exactly the
    /// v7 payload shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) context: Option<ContextSuggestion>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct FillPayload {
    pub(super) origin: String,
    pub(super) item_id: String,
    /// Indicates this request was triggered by an explicit user action (click, keyboard).
    /// Required for fill operations to prevent background credential exfiltration.
    #[serde(default)]
    pub(super) user_gesture: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct FillResponse {
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    /// Present only for BankCard fills; omitted (not null) for logins so the
    /// login response shape is byte-identical to before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) card: Option<CardFillData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct TotpPayload {
    pub(super) origin: String,
    pub(super) item_id: String,
    /// Indicates this request was triggered by an explicit user action (click, keyboard).
    #[serde(default)]
    pub(super) user_gesture: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct TotpResponse {
    pub(super) code: String,
    pub(super) remaining_seconds: u32,
    pub(super) period: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct CopyPayload {
    pub(super) origin: String,
    pub(super) item_id: String,
    pub(super) field: String,
    /// Indicates this request was triggered by an explicit user action (click, keyboard).
    #[serde(default)]
    pub(super) user_gesture: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct CopyResponse {
    pub(super) copied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) clear_after_seconds: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct FindForSavePayload {
    pub(super) origin: String,
    /// Username captured from the submitted form. Matching is
    /// trim + case-insensitive against the stored username.
    #[serde(default)]
    pub(super) username: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct FindForSaveMatch {
    pub(super) item_id: String,
    pub(super) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct FindForSaveResponse {
    pub(super) matches: Vec<FindForSaveMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SaveCredentialPayload {
    pub(super) origin: String,
    /// Explicit user action on the save bar (保存/更新 click). Required —
    /// the host refuses to write the vault behind a silent page event.
    #[serde(default)]
    pub(super) user_gesture: bool,
    /// Present ⇒ update that item's password; absent ⇒ create a new item.
    /// Updates are always item_id-qualified: there is no "pick a target for
    /// me and overwrite" path.
    #[serde(default)]
    pub(super) item_id: Option<String>,
    /// Submitted username (may be absent/empty for username-less forms).
    #[serde(default)]
    pub(super) username: Option<String>,
    /// Submitted password. Required — saving an empty password is refused.
    pub(super) password: String,
    /// Display name hint from the page (title / form context); falls back
    /// to the request host for new items.
    #[serde(default)]
    pub(super) name_hint: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SaveCredentialResponse {
    pub(super) item_id: String,
    /// "created" or "updated".
    pub(super) action: String,
    pub(super) name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct GeneratePasswordPayload {
    /// Total password length (default 16).
    #[serde(default = "default_gen_length")]
    pub(super) length: usize,
    /// Include lowercase (default true).
    #[serde(default = "default_gen_true")]
    pub(super) include_lowercase: bool,
    /// Include uppercase (default true).
    #[serde(default = "default_gen_true")]
    pub(super) include_uppercase: bool,
    /// Include digits (default true).
    #[serde(default = "default_gen_true")]
    pub(super) include_digits: bool,
    /// Include symbols (default true).
    #[serde(default = "default_gen_true")]
    pub(super) include_symbols: bool,
    /// Pronounceable alternating consonant/vowel pattern (default false).
    #[serde(default)]
    pub(super) pronounceable: bool,
    /// Diceware-style passphrase word count (3-10). Overrides length/sets.
    #[serde(default)]
    pub(super) words: Option<usize>,
}

pub(super) fn default_gen_length() -> usize {
    16
}

pub(super) fn default_gen_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct GeneratePasswordResponse {
    pub(super) password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PasskeyListPayload {
    pub(super) origin: String,
    /// Indicates this request was triggered by an explicit user action
    /// (the WebAuthn call Persona intercepts). Required.
    #[serde(default)]
    pub(super) user_gesture: bool,
    /// Relying party ID. Defaults to the origin's effective host.
    #[serde(default)]
    pub(super) rp_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PasskeyCreatePayload {
    pub(super) origin: String,
    /// Indicates this request was triggered by an explicit user action.
    #[serde(default)]
    pub(super) user_gesture: bool,
    /// `PublicKeyCredentialCreationOptions` in JSON form; BufferSource fields
    /// (challenge, user.id, ...) are base64url strings serialized by the
    /// extension before forwarding.
    pub(super) request_json: serde_json::Value,
    /// Raw clientDataJSON bytes produced by the browser (base64url, no pad).
    /// The core only hashes these — never reassembled or inspected further.
    pub(super) client_data_json_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PasskeyAssertPayload {
    pub(super) origin: String,
    /// Indicates this request was triggered by an explicit user action
    /// (the selection-UI click). Required — silent signing is refused.
    #[serde(default)]
    pub(super) user_gesture: bool,
    /// The passkey the user picked in the selection UI. Missing ⇒ refuse.
    pub(super) item_id: String,
    /// Raw clientDataJSON bytes produced by the browser (base64url, no pad).
    pub(super) client_data_json_b64: String,
    /// Mirror of `PublicKeyCredentialRequestOptions.userVerification`:
    /// the extension maps "discouraged" to false. Default true.
    #[serde(default = "default_true")]
    pub(super) user_verification: bool,
}

pub(super) fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PasskeyListItem {
    pub(super) id: String,
    pub(super) rp_id: String,
    pub(super) user_name: Option<String>,
    pub(super) user_display_name: Option<String>,
    pub(super) identity_name: Option<String>,
    pub(super) created_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PasskeyCreateResponse {
    pub(super) item_id: String,
    pub(super) credential_id_b64: String,
    /// `none`-format attestation object (CBOR bytes, base64url).
    pub(super) attestation_object_b64: String,
    /// Echoed back so the page's PublicKeyCredential can carry the exact
    /// bytes the authenticator attested over.
    pub(super) client_data_json_b64: String,
    pub(super) transports: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PasskeyAssertResponse {
    pub(super) item_id: String,
    pub(super) credential_id_b64: String,
    pub(super) authenticator_data_b64: String,
    pub(super) signature_der_b64: String,
    pub(super) user_handle_b64: String,
}
