use super::*;

pub(super) fn resolve_db_path(override_path: Option<PathBuf>) -> PathBuf {
    override_path
        .or_else(|| std::env::var("PERSONA_DB_PATH").ok().map(PathBuf::from))
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
                .join("identities.db")
        })
}

pub(super) fn resolve_state_dir(override_path: Option<PathBuf>) -> PathBuf {
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

/// Path to the Connect server port file written by desktop/cli `connect_server_start`.
pub(super) const CONNECT_PORT_FILE: &str = "connect.port";

/// Detect a running Connect server (desktop or CLI) by reading the port file
/// and probing `/health`. Returns `Some(port)` if the server is reachable and
/// the vault is unlocked (health returns 200), `None` otherwise.
pub(super) async fn detect_connect_server() -> Option<u16> {
    // Allow explicit override via env (useful for tests / non-standard setups).
    if let Ok(port_str) = std::env::var("PERSONA_CONNECT_PORT") {
        if let Ok(port) = port_str.parse::<u16>() {
            if probe_connect_health(port).await {
                return Some(port);
            }
        }
    }

    // Default: read from ~/.persona/connect.port (written by desktop/cli on start).
    let port_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".persona")
        .join(CONNECT_PORT_FILE);

    if let Ok(content) = std::fs::read_to_string(&port_path) {
        if let Ok(port) = content.trim().parse::<u16>() {
            if probe_connect_health(port).await {
                return Some(port);
            }
        }
    }

    None
}

/// Probe the Connect server's `/health` endpoint. Returns true if the server
/// responds with 200 and `ok: true` (meaning the vault is unlocked and the
/// server is healthy). Any error / non-200 / `ok: false` returns false.
pub(super) async fn probe_connect_health(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/api/v1/connect/health", port);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resp.status().is_success() {
        return false;
    }
    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(_) => return false,
    };
    json.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
}

pub(super) async fn open_db(db_path: &Path) -> Result<Database> {
    let db = Database::from_file(db_path).await?;
    db.migrate().await?;
    Ok(db)
}

/// Whether fill/copy/totp/passkey requests must carry `user_gesture: true`
/// (default yes; `PERSONA_BRIDGE_REQUIRE_GESTURE=0` disables).
pub(super) fn gesture_required() -> bool {
    std::env::var("PERSONA_BRIDGE_REQUIRE_GESTURE")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true)
}

/// Flatten a `PersonaError` into a wire message that starts with the protocol
/// error code — its `Display` wraps the code in a human prefix ("Invalid
/// input: …"), which would leak into the bridge error response.
pub(super) fn flat_persona_error(e: PersonaError) -> anyhow::Error {
    let msg = e.to_string();
    match msg.split_once(": ") {
        Some((_prefix, rest)) => anyhow!(rest.to_string()),
        None => anyhow!(msg),
    }
}

/// Open the database and unlock the service with the master password from
/// `PERSONA_MASTER_PASSWORD` (the bridge's lock state). Returns the service
/// plus the active identity (if one is set).
pub(super) async fn open_unlocked_service(
    db_path: &Path,
) -> Result<(PersonaService, Option<uuid::Uuid>)> {
    let master_password = std::env::var("PERSONA_MASTER_PASSWORD")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("locked: PERSONA_MASTER_PASSWORD not set"))?;

    let db = open_db(db_path).await?;
    let active_identity_id = get_active_identity_id(&db).await;
    let mut service = crate::commands::service::new_service(db)
        .await
        .map_err(|e| anyhow!("failed to create service: {e}"))?;
    let auth = service.authenticate_user(&master_password).await?;
    if auth != persona_core::auth::authentication::AuthResult::Success {
        return Err(anyhow!("authentication_failed"));
    }
    Ok((service, active_identity_id))
}
