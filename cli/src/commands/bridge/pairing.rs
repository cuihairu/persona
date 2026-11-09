use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SessionInfo {
    pub(super) session_id: String,
    pub(super) expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PairingInfo {
    pub(super) extension_id: String,
    pub(super) client_instance_id: String,
    pub(super) key_b64: String,
    pub(super) paired_at_ms: i64,
    #[serde(default)]
    pub(super) session: Option<SessionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PendingPairing {
    pub(super) code: String,
    pub(super) extension_id: String,
    pub(super) client_instance_id: String,
    pub(super) key_b64: String,
    pub(super) requested_at_ms: i64,
    pub(super) expires_at_ms: i64,
    pub(super) approved: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct BridgeStateFile {
    pub(super) version: u32,
    #[serde(default)]
    pub(super) pairings: Vec<PairingInfo>,
    #[serde(default)]
    pub(super) pending: Vec<PendingPairing>,
}

pub(super) fn now_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as i64
}

pub(super) fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("state.json")
}

pub(super) fn load_state(state_dir: &Path) -> Result<BridgeStateFile> {
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

pub(super) fn save_state(state_dir: &Path, state: &BridgeStateFile) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = state_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(state)?;
    fs::write(&tmp, data)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub(super) fn normalize_pairing_code(code: &str) -> String {
    code.trim().replace(' ', "").to_ascii_uppercase()
}

pub(super) fn purge_expired(state: &mut BridgeStateFile) {
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

pub(super) fn generate_session() -> SessionInfo {
    SessionInfo {
        session_id: uuid::Uuid::new_v4().to_string(),
        expires_at_ms: now_ms() + 24 * 60 * 60 * 1000, // 24h
    }
}

pub(super) fn ensure_session(
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

pub(super) fn require_authenticated_session(state_dir: &Path, req: &BridgeRequest) -> Result<()> {
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

pub(super) fn verify_signature(
    pairing: &PairingInfo,
    req: &BridgeRequest,
    auth: &BridgeAuth,
) -> Result<()> {
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

pub(super) fn canonicalize_json_value(value: &serde_json::Value) -> serde_json::Value {
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

pub(super) fn create_pairing_request(
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

pub(super) fn approve_pairing(state_dir: &Path, code: &str) -> Result<()> {
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

pub(super) fn finalize_pairing(
    state_dir: &Path,
    payload: PairingFinalizePayload,
) -> Result<PairingInfo> {
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
