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
        // 三态判定，杜绝旧 `hint || files` 的假绿：
        // - 内嵌 agent（desktop 启动）：任务句柄存活 + state 文件在；
        // - 外部 agent（CLI 独立进程起的 daemon，desktop 无句柄）：socket
        //   能真实连上（unix 连接探测）才算运行中；
        // - 任务已死只剩上次残留的 state 文件：不算运行中（这是"点击启动
        //   无效果但徽章恒绿"bug 的根源）。
        // Windows 无连接探测（query_agent_key_count 是 unix 专属）：内嵌
        // 场景由句柄覆盖；外部 daemon 可见性为已知限制。
        running: (running_hint && (socket_value.is_some() || pid_value.is_some()))
            || (!running_hint && probe_agent_alive(socket_value.as_deref())),
        socket_path: socket_value,
        pid: pid_value,
        key_count,
        state_dir: dir.to_string_lossy().to_string(),
    }
}

/// 外部 agent 探测：unix 下对 state 文件记录的 socket 做一次 connect-only
/// 探活（不进行协议对话——对无应答的残留 socket 也不会阻塞）。
/// 连不上 = agent 已死，state 文件只是残留。
#[cfg(unix)]
pub(crate) fn probe_agent_alive(sock_path: Option<&str>) -> bool {
    use std::os::unix::net::UnixStream;
    // connect-only 探活：本地 unix socket 连接即时完成（成功/ECONNREFUSED/
    // ENOENT），不做协议对话，无阻塞窗口。
    sock_path
        .map(|sock| UnixStream::connect(sock).is_ok())
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub(crate) fn probe_agent_alive(_sock_path: Option<&str>) -> bool {
    // Windows：内嵌 agent 由任务句柄覆盖；外部 daemon 的 named pipe 探测
    // 未实现，为已知限制（待 Windows 实机验收一并核对）。
    false
}

#[cfg(unix)]
pub(crate) fn query_agent_key_count(sock_path: &str) -> std::result::Result<usize, String> {
    use byteorder::{BigEndian, ByteOrder};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    // 全程限时：status 查询跑在 UI 路径上，对"活着但不应答"的 socket
    // （残留监听、卡死的 daemon）无超时会永久阻塞面板。connect 在本地
    // unix socket 上即时返回；read/write 超时挡住所有协议阶段挂起。
    // （本工具链的 std 没有 UnixStream::connect_timeout。）
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

/// Connect listener 运行状态（设置页渲染 + 自动化开关判定）。
#[derive(Debug, Serialize)]
pub struct ConnectServerStatus {
    pub running: bool,
    /// listener 实际端口（未运行 = None；端口 0 = OS 分配后的真实值）。
    pub port: Option<u16>,
}

/// token 管理列表视图——剥除哈希（哈希不出库；列表只展示指纹）。
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

/// 创建成功响应：明文 token 只此一次（前端展示 + 复制，关闭后无法再查）。
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

/// 启动 Connect listener（bind 硬编码 127.0.0.1；端口 None = 0 = OS 分配）。
/// 需要解锁会话；已运行时报错（前端先 stop 或按状态渲染）。
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
            // 竞态防御：重入时后到者不写槽（先到者已持有 listener），
            // 后到的 handle 直接 drop（oneshot sender drop = 没有启动过
            // 的 shutdown 通道被丢弃，不影响先到 listener）。
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

/// 停止 Connect listener（幂等：未运行返回 running=false）。
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

/// 查询 Connect listener 运行状态。
#[command]
pub async fn connect_server_status(
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<ConnectServerStatus>, String> {
    Ok(ApiResponse::success(connect_server_status_of(&state).await))
}

/// 创建 Connect token（敏感操作：core 权威 reauth 门禁；明文仅响应一次）。
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

/// token 管理列表（含已吊销，剥除哈希）。敏感面：需解锁会话。
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

/// 吊销 Connect token（幂等；core 权威 reauth 门禁）。即时生效。
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
