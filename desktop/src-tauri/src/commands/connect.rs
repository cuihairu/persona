use super::*;

pub(crate) fn agent_state_dir() -> PathBuf {
    std::env::var("PERSONA_AGENT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
        })
}

pub(crate) fn cleanup_agent_state_files() {
    let dir = agent_state_dir();
    for name in &["ssh-agent.sock", "ssh-agent.pid"] {
        let path = dir.join(name);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
}

pub(crate) fn read_agent_status(running_hint: bool) -> SshAgentStatus {
    let dir = agent_state_dir();
    let sock_path = dir.join("ssh-agent.sock");
    let pid_path = dir.join("ssh-agent.pid");
    let socket_value = if sock_path.exists() {
        fs::read_to_string(&sock_path)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    };
    let pid_value = if pid_path.exists() {
        fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    } else {
        None
    };
    let key_count = socket_value
        .as_deref()
        .and_then(|sock| query_agent_key_count(sock).ok());

    SshAgentStatus {
        // Three-way determination, killing the old `hint || files` false green:
        // - embedded agent (started by desktop): task handle alive + state file present;
        // - external agent (daemon spawned by a standalone CLI process, no handle in
        //   desktop): only counts as running if the socket actually connects
        //   (unix connection probe);
        // - task dead with only the leftover state file from last time: not running
        //   (this is the root of the "clicking start does nothing but the badge
        //   stays green" bug).
        // Windows has no connection probe (query_agent_key_count is unix-only): the
        // embedded case is covered by the handle; external daemon visibility is a
        // known limitation.
        running: (running_hint && (socket_value.is_some() || pid_value.is_some()))
            || (!running_hint && probe_agent_alive(socket_value.as_deref())),
        socket_path: socket_value,
        pid: pid_value,
        key_count,
        state_dir: dir.to_string_lossy().to_string(),
    }
}

/// External agent probe: on unix, run a connect-only liveness check
/// against the socket recorded in the state file (no protocol
/// conversation — it will not block against a leftover socket that never
/// answers).
/// Cannot connect = the agent is dead and the state file is just leftover.
#[cfg(unix)]
pub(crate) fn probe_agent_alive(sock_path: Option<&str>) -> bool {
    use std::os::unix::net::UnixStream;
    // connect-only liveness check: a local unix socket connection completes
    // immediately (success / ECONNREFUSED / ENOENT); no protocol conversation
    // and no blocking window.
    sock_path
        .map(|sock| UnixStream::connect(sock).is_ok())
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub(crate) fn probe_agent_alive(_sock_path: Option<&str>) -> bool {
    // Windows: the embedded agent is covered by the task handle; a named-pipe
    // probe for an external daemon is not implemented and is a known
    // limitation (to be checked together with on-machine Windows acceptance).
    false
}

#[cfg(unix)]
pub(crate) fn query_agent_key_count(sock_path: &str) -> std::result::Result<usize, String> {
    use byteorder::{BigEndian, ByteOrder};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    // Deadline throughout: the status query runs on the UI path, and without
    // a timeout a socket that is "alive but never answers" (leftover listener,
    // wedged daemon) blocks the panel forever. connect on a local unix socket
    // returns immediately; the read/write timeouts cover every protocol stage.
    // (This toolchain's std has no UnixStream::connect_timeout.)
    const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
    let mut stream =
        UnixStream::connect(sock_path).map_err(|e| format!("Failed to connect to agent: {}", e))?;
    stream
        .set_read_timeout(Some(QUERY_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(QUERY_TIMEOUT))
        .map_err(|e| e.to_string())?;
    // request identities: len=1 payload 11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11;
    stream.write_all(&pkt).map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(|e| e.to_string())?;
    if resp.is_empty() || resp[0] != 12 {
        return Err("Unexpected agent response".to_string());
    }
    if resp.len() < 5 {
        return Err("Malformed agent response".to_string());
    }
    let count = BigEndian::read_u32(&resp[1..5]) as usize;
    Ok(count)
}

#[cfg(not(unix))]
pub(crate) fn query_agent_key_count(_sock_path: &str) -> std::result::Result<usize, String> {
    Err("Agent key count not supported on this platform".to_string())
}

/// Connect listener running status (settings-page rendering + automation switch decision).
#[derive(Debug, Serialize)]
pub struct ConnectServerStatus {
    pub running: bool,
    /// The listener's actual port (not running = None; port 0 = the real value
    /// after OS assignment).
    pub port: Option<u16>,
}

/// Token management list view — hashes stripped (hashes never leave the vault;
/// the list only shows fingerprints).
#[derive(Debug, Serialize)]
pub struct ConnectTokenView {
    pub id: String,
    pub label: String,
    pub fingerprint: String,
    pub scope: persona_core::connect::ConnectTokenScope,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub principal: Option<String>,
    pub expires_at: Option<String>,
}

impl From<&persona_core::connect::ConnectTokenRow> for ConnectTokenView {
    fn from(row: &persona_core::connect::ConnectTokenRow) -> Self {
        Self {
            id: row.id.to_string(),
            label: row.label.clone(),
            fingerprint: row.fingerprint.clone(),
            scope: row.scope.clone(),
            created_at: row.created_at.to_rfc3339(),
            last_used_at: row.last_used_at.map(|t| t.to_rfc3339()),
            revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
            principal: row.principal.clone(),
            expires_at: row.expires_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// Creation success response: the plaintext token is shown exactly once
/// (frontend display + copy; it cannot be retrieved again after the dialog closes).
#[derive(Debug, Serialize)]
pub struct ConnectTokenCreatedView {
    pub token: String,
    pub info: ConnectTokenView,
}

pub(crate) async fn connect_server_status_of(state: &State<'_, AppState>) -> ConnectServerStatus {
    let guard = state.connect_server.lock().await;
    match guard.as_ref() {
        Some(handle) => ConnectServerStatus {
            running: true,
            port: Some(handle.port),
        },
        None => ConnectServerStatus {
            running: false,
            port: None,
        },
    }
}

/// Start the Connect listener (bind hardcoded to 127.0.0.1; port None = 0 = OS-assigned).
/// Requires an unlocked session; errors when already running (the frontend
/// should stop it first or render by state).
#[command]
pub async fn connect_server_start(
    state: State<'_, AppState>,
    port: Option<u16>,
) -> std::result::Result<ApiResponse<ConnectServerStatus>, String> {
    {
        let guard = state.connect_server.lock().await;
        if guard.is_some() {
            return Ok(ApiResponse::error(
                "Connect server is already running".to_string(),
            ));
        }
    }
    let unlocked = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => false,
        }
    };
    if !unlocked {
        return Ok(ApiResponse::error_with_code(
            crate::error::CODE_SERVICE_LOCKED.to_string(),
            "Vault must be unlocked before starting the Connect server".to_string(),
        ));
    }
    match crate::connect_server::start_connect_server(state.service.clone(), port.unwrap_or(0))
        .await
    {
        Ok(handle) => {
            let port = handle.port;
            let status = ConnectServerStatus {
                running: true,
                port: Some(port),
            };
            let mut guard = state.connect_server.lock().await;
            // Race defense: on re-entry the latecomer does not write the slot
            // (the earlycomer already owns the listener); the latecomer's handle
            // is simply dropped (dropping the oneshot sender = the never-started
            // shutdown channel is discarded; it does not affect the earlier listener).
            if guard.is_some() {
                drop(handle);
                return Ok(ApiResponse::error(
                    "Connect server is already running".to_string(),
                ));
            }
            *guard = Some(handle);
            // Write port file for bridge unlock linkage (read by CLI bridge on hello).
            let port_path = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".persona")
                .join("connect.port");
            if let Some(parent) = port_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&port_path, port.to_string());
            Ok(ApiResponse::success(status))
        }
        Err(e) => Ok(ApiResponse::error(format!("Failed to start: {}", e))),
    }
}

/// Stop the Connect listener (idempotent: returns running=false when not running).
#[command]
pub async fn connect_server_stop(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<ConnectServerStatus>, String> {
    let handle = state.connect_server.lock().await.take();
    if let Some(handle) = handle {
        handle.stop();
    }
    // Remove port file on stop so bridge detects locked state on next hello.
    let port_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".persona")
        .join("connect.port");
    let _ = std::fs::remove_file(&port_path);
    Ok(ApiResponse::success(ConnectServerStatus {
        running: false,
        port: None,
    }))
}

/// Query the Connect listener's running status.
#[command]
pub async fn connect_server_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<ConnectServerStatus>, String> {
    Ok(ApiResponse::success(connect_server_status_of(&state).await))
}

/// Create a Connect token (sensitive operation: core-authoritative reauth
/// gate; the plaintext is returned exactly once).
#[command]
pub async fn connect_token_create(
    state: State<'_, AppState>,
    label: String,
    scope: persona_core::connect::ConnectTokenScope,
) -> std::result::Result<ApiResponse<ConnectTokenCreatedView>, String> {
    let result = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.create_connect_token(label, scope, None, None).await,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    match result {
        Ok((token, row)) => Ok(ApiResponse::success(ConnectTokenCreatedView {
            token,
            info: ConnectTokenView::from(&row),
        })),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            })
        }
    }
}

/// Token management list (including revoked ones, hashes stripped). Sensitive
/// surface: requires an unlocked session.
#[command]
pub async fn connect_token_list(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<ConnectTokenView>>, String> {
    let result = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.list_connect_tokens().await,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    match result {
        Ok(rows) => Ok(ApiResponse::success(
            rows.iter().map(ConnectTokenView::from).collect(),
        )),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            })
        }
    }
}

/// Revoke a Connect token (idempotent; core-authoritative reauth gate). Takes effect immediately.
#[command]
pub async fn connect_token_revoke(
    state: State<'_, AppState>,
    id: String,
) -> std::result::Result<ApiResponse<bool>, String> {
    let token_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return Ok(ApiResponse::error(format!("Invalid token id: {}", id))),
    };
    let result = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => service.revoke_connect_token(&token_id).await,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    match result {
        Ok(revoked) => Ok(ApiResponse::success(revoked)),
        Err(e) => {
            let (code, msg) = map_persona_error(&e);
            Ok(match code {
                Some(code) => ApiResponse::error_with_code(code, msg),
                None => ApiResponse::error(msg),
            })
        }
    }
}
