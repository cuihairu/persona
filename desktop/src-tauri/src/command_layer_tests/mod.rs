//! Command-level integration tests.
//!
//! The `#[command]` handlers are plain async functions, so each test drives
//! them directly: a `tauri::test::mock_app()` supplies `State<'_, AppState>`
//! (via `manage`) and `AppHandle`, and the database is a per-test temp file.
//! The `sqlite_works_after_mock_app_creation` probe in main.rs guards the
//! mock-runtime/sqlx interaction this relies on.

use crate::commands::*;
use crate::token_store::{InMemoryTokenStore, TokenStore};
use crate::types::*;
use persona_core::models::credential::CredentialData;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Mock app with a fresh, uninitialized `AppState` and explicit backend
/// parts（sync/biometric 两个 keyring 槽 + biometric provider + 包裹层
/// wrapper/存储）。各命令族测试按需注入 fake；默认组合见
/// [`mock_app_with_token_store`] / [`mock_app_with_biometric`] /
/// [`mock_app_with_biometric_wrap`]。
fn mock_app_with_parts(
    token_store: Arc<dyn TokenStore>,
    biometric_provider: Arc<dyn persona_core::BiometricProvider>,
    biometric_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_wrap_parts(
        token_store,
        biometric_provider,
        biometric_store,
        // 默认门禁档桩（= CI/headless 的生产装配：Linux/Windows 无硬件
        // 包裹层，macOS 未开 spike 门控）——门禁层行为测试保持原样
        Arc::new(crate::biometric::GateOnlyKeyWrapper),
        Arc::new(InMemoryTokenStore::default()),
    )
}

/// [`mock_app_with_parts`] + 包裹层（`biometric_wrapper` /
/// `biometric_wrap_store`）注入。硬件绑定路径的命令测试用
/// `MockKeyWrapper` 驱动（`rotate_enrollment` / `set_fail` /
/// `set_user_cancelled` 覆盖回退链分支），blob 落内存 store 便于断言。
fn mock_app_with_wrap_parts(
    token_store: Arc<dyn TokenStore>,
    biometric_provider: Arc<dyn persona_core::BiometricProvider>,
    biometric_store: Arc<dyn TokenStore>,
    biometric_wrapper: Arc<dyn persona_core::BiometricKeyWrapper>,
    biometric_wrap_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    let app = tauri::test::mock_app();
    app.manage(AppState {
        service: Arc::new(Mutex::new(None)),
        db_path: Mutex::new(None),
        agent_handle: Mutex::new(None),
        auto_lock_registered: std::sync::atomic::AtomicBool::new(false),
        passkey_server_started: std::sync::atomic::AtomicBool::new(false),
        passkey_server_shutdown: Mutex::new(None),
        ssh_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
        passkey_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
        sync_emitter: Mutex::new(None),
        // CI/headless 没有 secret service——测试一律走内存 fake
        token_store,
        biometric_provider,
        biometric_store,
        // 包裹层：门禁档桩 / HardwareBound wrapper 由调用方决定
        biometric_wrapper,
        biometric_wrap_store,
        // E2EE sync 设备身份槽：默认内存 fake，sync 命令族测试直接从
        // AppState 取 Arc 写入/断言条目
        device_store: Arc::new(InMemoryTokenStore::default()),
        // 账号 bearer 槽：默认内存 fake，account 命令族测试跨命令断言
        // 令牌生命周期（srp_verify 写入 / create_session 覆盖 /
        // revoke_session 自吊销清除）
        account_token_store: Arc::new(InMemoryTokenStore::default()),
        connect_server: Mutex::new(None),
        // Quick Access 运行态：测试里没有 OS 全局热键可抢注，默认空态
        // （quick_access_* 命令测试直接读写这个槽位断言语义）
        quick_access: std::sync::Mutex::new(crate::quick_access::QuickAccessRuntime::default()),
        // 桌面填充注入目标（#12）：测试环境没有热键唤起路径，默认空态
        //（fill_* 命令测试直接读写这个槽位断言语义）
        fill_target: std::sync::Mutex::new(None),
        // 同步组配对会话槽：默认空表（pairing 命令族测试跨命令断言状态）
        pairing_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        // 同步组组密钥槽：默认内存 fake，配对命令族测试从 AppState 取同
        // 一 Arc 读回命令写入的组密钥做断言
        sync_group_store: Arc::new(InMemoryTokenStore::default()),
    });
    app
}

/// Mock app with a fresh, uninitialized `AppState` and the given token store.
/// biometric 侧默认注入恒通过的 Mock provider + 独立内存 store（biometric
/// 专属命令测试用 `mock_app_with_biometric` 换成可控 stub）。
fn mock_app_with_token_store(
    token_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_parts(
        token_store,
        Arc::new(persona_core::MockBiometricProvider::default()),
        Arc::new(InMemoryTokenStore::default()),
    )
}

/// Mock app with injectable biometric provider/store（biometric 命令族测试
/// 入口；provider 用 MockBiometricProvider 的 available/force_fail 组合
/// 分支，store 通常用 InMemoryTokenStore 便于直接断言条目内容）。
fn mock_app_with_biometric(
    biometric_provider: Arc<dyn persona_core::BiometricProvider>,
    biometric_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_parts(
        Arc::new(InMemoryTokenStore::default()),
        biometric_provider,
        biometric_store,
    )
}

/// Mock app with an injected hardware-bound wrap layer
/// （`MockKeyWrapper` + 内存 blob 存储）：`biometric_enable` /
/// `biometric_unlock` 在这个 app 上走密钥包裹链而非门禁层密码托管链。
fn mock_app_with_biometric_wrap(
    wrapper: Arc<dyn persona_core::BiometricKeyWrapper>,
    wrap_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_wrap_parts(
        Arc::new(InMemoryTokenStore::default()),
        Arc::new(persona_core::MockBiometricProvider::default()),
        Arc::new(InMemoryTokenStore::default()),
        wrapper,
        wrap_store,
    )
}

/// 测试内解 base64 blob（断言"落盘的是密文信封"用；生产路径的编解码
/// 在 commands.rs，测试只读不写）。
fn base64_decode(blob: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(blob)
        .expect("wrap blob must be valid base64")
}

/// Mock app with a fresh, uninitialized `AppState`.
fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_token_store(Arc::new(InMemoryTokenStore::default()))
}

/// Initialize the service against a fresh temp database and return the guard
/// (plus the db_path, for token-store/DB assertions).
async fn init_service_ok(app: &tauri::App<tauri::test::MockRuntime>, password: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cmd.db");
    // Leak the TempDir: the service keeps the file open for the whole test.
    std::mem::forget(dir);
    let db_path = db_path.to_string_lossy().to_string();

    let resp = init_service(
        InitRequest {
            master_password: password.to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "init failed: {:?}", resp.error);
    db_path
}

// ---------------------------------------------------------------------------
// 第二批：credential / wallet / reveal / export / passkey
// ---------------------------------------------------------------------------

/// 建一个已初始化服务的 app + 一条已存在的身份，返回 (app, identity_id)。
async fn app_with_identity() -> (tauri::App<tauri::test::MockRuntime>, String) {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Cred Holder".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let identity = resp.data.expect("identity created");
    (app, identity.id)
}

fn password_credential_request(identity_id: &str) -> CreateCredentialRequest {
    CreateCredentialRequest {
        identity_id: identity_id.to_string(),
        name: "Example Login".to_string(),
        credential_type: "Password".to_string(),
        security_level: "High".to_string(),
        url: Some("https://example.com".to_string()),
        username: Some("alice".to_string()),
        notes: Some("  note with padding  ".to_string()),
        tags: Some(vec![
            "web".to_string(),
            "  ".to_string(),
            "work".to_string(),
        ]),
        credential_data: CredentialDataRequest::Password {
            password: "s3cret-password".to_string(),
            email: Some("alice@example.com".to_string()),
            security_questions: vec![SecurityQuestionRequest {
                question: "pet?".to_string(),
                answer: "cat".to_string(),
            }],
        },
    }
}

// ---- S5 自救口：整库加密备份文件导出（backup_export_to_file）----

// ---- S5 自救口：从本地文件恢复整库（backup_restore_from_file）----

// ---------------------------------------------------------------------------
// S5-d 服务器密文仓（persona-server /api/v1/backups 桌面接线）
//
// 协议正确性归 core（BackupClient）与 server（backups.rs E2E）；这里只测
// 宿主编排：门禁（未初始化/未配置/锁定）、快照+推送+凭证回写、列表映射、
// 下载 → staged 换库（与文件恢复同口径）、删除幂等。中转用手搓 TCP 假
// 服务（与 pairing relay 假服务同构：Bearer 校验 + 内存单槽备份）。
// ---------------------------------------------------------------------------

/// 内存单槽假备份服务：返回 base_url。备份 ID 恒 `bk-1`（push 覆盖写，
/// delete 后 404）；Bearer token 恒 `tok-persona-1`（不符回 401 信封）。
fn spawn_mock_backup_server() -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    struct Stub {
        body: Option<Vec<u8>>,
        deleted: bool,
    }
    let state = Arc::new(std::sync::Mutex::new(Stub {
        body: None,
        deleted: false,
    }));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            let request_line = head.lines().next().unwrap_or_default().to_string();
            let content_length: usize = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split_once(':').and_then(|(_, v)| v.trim().parse().ok()))
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = stream.read_exact(&mut body);
            }
            let method = request_line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let auth = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();

            let mut st = state.lock().unwrap();
            let meta = |bytes: &[u8], id: &str| {
                serde_json::json!({
                    "id": id,
                    "device_name": "stub-device",
                    "size_bytes": bytes.len() as i64,
                    "sha256": sha256_hex(bytes),
                    "created_at": "2026-10-08T00:00:00Z",
                })
            };
            let err = |code: &str, message: &str| {
                serde_json::json!({ "error": { "code": code, "message": message } })
                    .to_string()
                    .into_bytes()
            };
            let (status, content_type, resp_body, etag): (u16, &'static str, Vec<u8>, String) =
                if auth != "Bearer tok-persona-1" {
                    (
                        401,
                        "application/json",
                        err("unauthorized", "bad token"),
                        String::new(),
                    )
                } else if method == "POST" && path == "/api/v1/backups" {
                    st.body = Some(body.clone());
                    st.deleted = false;
                    let mut json = meta(&body, "bk-1");
                    json["deduplicated"] = serde_json::json!(false);
                    (
                        201,
                        "application/json",
                        json.to_string().into_bytes(),
                        String::new(),
                    )
                } else if method == "GET" && path.starts_with("/api/v1/backups?") {
                    let items: Vec<serde_json::Value> = match st.body.as_ref() {
                        Some(bytes) if !st.deleted => vec![meta(bytes, "bk-1")],
                        _ => vec![],
                    };
                    let json = serde_json::json!({ "backups": items, "next_cursor": null });
                    (
                        200,
                        "application/json",
                        json.to_string().into_bytes(),
                        String::new(),
                    )
                } else if method == "GET" && path == "/api/v1/backups/bk-1" {
                    match st.body.as_ref() {
                        Some(bytes) if !st.deleted => {
                            let etag = format!("ETag: \"{}\"\r\n", sha256_hex(bytes));
                            (200, "application/octet-stream", bytes.clone(), etag)
                        }
                        _ => (
                            404,
                            "application/json",
                            err("not_found", "no such backup"),
                            String::new(),
                        ),
                    }
                } else if method == "DELETE" && path == "/api/v1/backups/bk-1" {
                    if st.deleted {
                        (
                            404,
                            "application/json",
                            err("not_found", "no such backup"),
                            String::new(),
                        )
                    } else {
                        st.deleted = true;
                        (204, "application/json", Vec::new(), String::new())
                    }
                } else {
                    (
                        404,
                        "application/json",
                        err("not_found", "no such route"),
                        String::new(),
                    )
                };
            drop(st);

            let reason = match status {
                201 => "Created",
                204 => "No Content",
                401 => "Unauthorized",
                404 => "Not Found",
                _ => "OK",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n",
                resp_body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            if !resp_body.is_empty() {
                let _ = stream.write_all(&resp_body);
            }
        }
    });
    format!("http://{addr}")
}

/// S5-d 前置：sync 配置指向假服务（URL 进 settings，token 进 keyring）。
async fn configure_backup_server(
    app: &tauri::App<tauri::test::MockRuntime>,
    base_url: &str,
    token: &str,
) {
    let resp = set_sync_config(
        true,
        base_url.to_string(),
        token.to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "set_sync_config: {:?}", resp.error);
}

// ---------------------------------------------------------------------------
// 第三批：wallet 交易 / approval respond / SSH agent 状态与生命周期
// ---------------------------------------------------------------------------

/// 沙箱 agent 状态目录：`PERSONA_AGENT_STATE_DIR` 指向 tempdir，drop 恢复。
///
/// env 是进程全局的：并行测试各自 sandbox 会互相改道（socket 落错目录、
/// 状态断言失败），所以持一把进程级锁——同一时刻只有一个测试在改 env。
pub(crate) struct StateDirGuard {
    // 先声明先构造、最后 drop：env 先恢复，锁才释放。
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
    // None = 本 guard 未触碰 SOCKET_PATH；Some(None) = 原值缺失需移除；
    // Some(Some(v)) = 恢复到 v。
    prev_socket: Option<Option<std::ffi::OsString>>,
}

impl StateDirGuard {
    pub(crate) fn sandbox(dir: &tempfile::TempDir) -> Self {
        let lock = agent_env_lock();
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::set_var("PERSONA_AGENT_STATE_DIR", dir.path());
        StateDirGuard {
            _lock: lock,
            prev: prev.map(Into::into),
            prev_socket: None,
        }
    }

    /// sandbox 同时注入 PERSONA_AGENT_SOCKET_PATH：两个 env 必须在同一把
    /// 锁内设置（std Mutex 不可重入，分别构造两个 guard 会死锁）。
    #[cfg(unix)]
    pub(crate) fn sandbox_with_socket(
        dir: &tempfile::TempDir,
        socket_path: &std::path::Path,
    ) -> Self {
        let lock = agent_env_lock();
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::set_var("PERSONA_AGENT_STATE_DIR", dir.path());
        let prev_socket = std::env::var("PERSONA_AGENT_SOCKET_PATH").ok();
        std::env::set_var("PERSONA_AGENT_SOCKET_PATH", socket_path);
        StateDirGuard {
            _lock: lock,
            prev: prev.map(Into::into),
            prev_socket: Some(prev_socket.map(Into::into)),
        }
    }

    /// 互斥地移除 PERSONA_AGENT_STATE_DIR：驱动 `agent_state_dir` 的
    /// home 回退臂。持有同一把进程级锁，恢复时 Drop 会移除 env（prev=None）。
    fn without_env() -> Self {
        let lock = agent_env_lock();
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::remove_var("PERSONA_AGENT_STATE_DIR");
        StateDirGuard {
            _lock: lock,
            prev: prev.map(Into::into),
            prev_socket: None,
        }
    }
}

/// 进程级互斥：agent 相关 env（PERSONA_AGENT_STATE_DIR / SOCKET_PATH）在
/// 并行测试里同进程共享，读写必须串行。
fn agent_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static AGENT_ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let mutex = AGENT_ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Drop for StateDirGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(prev) => std::env::set_var("PERSONA_AGENT_STATE_DIR", prev),
            None => std::env::remove_var("PERSONA_AGENT_STATE_DIR"),
        }
        if let Some(prev_socket) = self.prev_socket.take() {
            match prev_socket {
                Some(prev) => std::env::set_var("PERSONA_AGENT_SOCKET_PATH", prev),
                None => std::env::remove_var("PERSONA_AGENT_SOCKET_PATH"),
            }
        }
    }
}

// 后端防投毒强制检查：to 地址模仿本钱包已知地址时，缺 ack 一律拒绝签名，
// 带 ack 放行（WALLET_DESIGN.md §5 第 3 条）。

// Unix-socket probing (stale file / live listener) has no Windows
// counterpart in this test; the named-pipe flow is a separate work item.

// ---------------------------------------------------------------------------
// 第四批：wallet import/地址管理/导出矩阵、get_ssh_keys、health_scan、门禁
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 第五批：passkey 门禁与错误码、TOTP/凭据数据拒绝路径、审计过滤、工作区改道
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 第六批：reveal 类型矩阵 / 导出与审计门禁 / reauth 余量分支
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 第八批：types 层纯函数矩阵（序列化脱敏 + 转换 + 事件映射）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 第九批：init_service 错误臂 / auto-lock 事件桥闭环 / 路径工具
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 第十批：类型/等级矩阵、get_credential_data 全变体标签、锁定错误码矩阵、
// wallet 网络/DB 失败分支、agent 状态目录回退、agent 协议读错误
// ---------------------------------------------------------------------------

// Unix domain socket 专用路径——与上面的 protocol_matrix 同门禁（缺这条
// 会让 desktop-build windows job 首次编译 test profile 时失败，2026-09-26）

// ---------------------------------------------------------------------------
// 第十一批：active_identity DB 失败、默认 db_path、活跃身份清理、
// 锁定态凭据/审计错误、wallet_generate 类型拒绝、pending 交易与缺 db_path
// ---------------------------------------------------------------------------

/// 互斥地把 XDG_DATA_HOME 指到临时目录（dirs::data_dir 的 Linux 读法），
/// 驱动 init_service 的默认 db_path 分支而不触碰真实用户目录。
struct XdgDataDirGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
}

impl XdgDataDirGuard {
    pub(crate) fn sandbox(dir: &tempfile::TempDir) -> Self {
        static XDG_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let mutex = XDG_LOCK.get_or_init(|| std::sync::Mutex::new(()));
        let lock = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prev = std::env::var("XDG_DATA_HOME").ok();
        std::env::set_var("XDG_DATA_HOME", dir.path());
        XdgDataDirGuard {
            _lock: lock,
            prev: prev.map(Into::into),
        }
    }
}

impl Drop for XdgDataDirGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(prev) => std::env::set_var("XDG_DATA_HOME", prev),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }
}

/// 已解锁但 DB 是垃圾文件的 service：sqlx 连接惰性打开，任何 repo 查询才
/// 报错。init_service 到不了这个状态（migrate 会先失败），所以手工构造
/// service——用它驱动命令层不可绕过的 repo 错误臂。db_path 也指向同一
/// 垃圾文件，让自建连接的 workspace/wallet 命令共享同一错误路径。
async fn app_with_garbage_db_service() -> tauri::App<tauri::test::MockRuntime> {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let bad_path = dir.path().join("garbage.db");
    std::fs::write(&bad_path, "not a sqlite database").unwrap();
    // Leak the TempDir: the service keeps the file open for the whole test.
    std::mem::forget(dir);
    let db = persona_core::Database::from_file(&bad_path).await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("correct-horse", &salt).unwrap();
    *app.state::<AppState>().service.lock().await = Some(service);
    *app.state::<AppState>().db_path.lock().await = Some(bad_path.to_string_lossy().to_string());
    app
}

// ---------------------------------------------------------------------------
// 第十六批：active identity / wallet / ssh 命令的前置条件与死库矩阵
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Workspace settings / feature flags / passkey 审批服务端门禁
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 同步服务器配置（settings.sync）与审计事件上报器接线
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Forced master-password rotation（PASSWORD_CHANGE_REQUIRED 码 / 改密命令 /
// password_expiry_days 窄写）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 旅行模式（Travel Mode）命令族
// ---------------------------------------------------------------------------

/// 初始化服务并建一个 identity，返回其 id。
async fn seeded_identity(app: &tauri::App<tauri::test::MockRuntime>, name: &str) -> String {
    let resp = create_identity(
        CreateIdentityRequest {
            name: name.to_string(),
            identity_type: "work".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    resp.data.expect("created identity returned").id
}

// ---------------------------------------------------------------------------
// Attachments（1Password 对齐）：加密附件经凭据 item key 封存，
// 命令层四命令全链路（list / attach / save / delete）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Biometric unlock：四命令命令层矩阵（provider 用 Mock 的
// available/force_fail 组合分支；store 用 InMemoryTokenStore 直接断言条目）
// ---------------------------------------------------------------------------

fn mock_provider(available: bool, force_fail: bool) -> Arc<persona_core::MockBiometricProvider> {
    Arc::new(persona_core::MockBiometricProvider {
        available,
        force_fail,
        platform: persona_core::BiometricPlatform::Unknown,
    })
}

/// set 恒失败、get/delete 委托内部 InMemory 的 keyring fake——测"写失败
/// 不留半态 / 改密联动 fail-closed 删条目"两条路径（条目需预先放进内部
/// store 模拟既有配置）。
struct FailingSetStore(Arc<InMemoryTokenStore>);
impl TokenStore for FailingSetStore {
    fn set(&self, _: &str, _: &str) -> Result<(), String> {
        Err("no secret service".to_string())
    }
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        self.0.get(key)
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        self.0.delete(key)
    }
}

// ---------------------------------------------------------------------------
// 硬件绑定包裹链（`mock_app_with_biometric_wrap`：MockKeyWrapper 报
// HardwareBound，enable/unlock 走密钥包裹而非门禁层密码托管）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Quick Access（全局热键绑定：落库真值 + 抢注失败如实上报）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 生成器热键（gap #9 余项：与 Quick Access 同一套门禁/落库/抢注语义，
// 独立窗口与独立槽位——改检索绑定不得动生成器，反之亦然）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// E2EE sync 设备管理命令族：协议层在 core（SyncAdminApi 真 TCP 测试在
// server），这里锁宿主编排——keyring 身份三态、门禁、失败不留半态。
// 网络路径一律不可达服务器（http://127.0.0.1:1，同 set_sync_config 族口径）。
// ---------------------------------------------------------------------------

/// 直写 device_store 造一条合法本机身份（join 的网络路径测不了，身份
/// 落 keyring 后的后续命令全靠它驱动）。
async fn seed_device_identity(
    app: &tauri::App<tauri::test::MockRuntime>,
    db_path: &str,
) -> persona_core::sync::device::DeviceIdentity {
    let identity = persona_core::sync::device::DeviceIdentity::generate("seeded-laptop").unwrap();
    app.state::<AppState>()
        .device_store
        .set(db_path, &identity.to_stored_json())
        .unwrap();
    identity
}

// ---------------------------------------------------------------------------
// connect_token_* 命令族（create/list/revoke）：Service 槽降级 + 全生命周期。
// ---------------------------------------------------------------------------

fn read_scope() -> persona_core::connect::ConnectTokenScope {
    persona_core::connect::ConnectTokenScope {
        identities: vec![],
        item_types: vec![],
        verbs: vec![persona_core::connect::ConnectVerb::Read],
    }
}

// ---------------------------------------------------------------------------
// connect_server_* 命令族（start/status/stop）：解锁门禁 + 生命周期 + 幂等。
// listener 只 bind 127.0.0.1:0（OS 分配），无需外部网络。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// set_locale：与 set_feature_flags 同范式（解锁门禁 + 窄写 + 返回全量），
// 加非法 locale 拒绝。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// set_tray_locale：托盘右键菜单文案（真值在前端 i18n locale 表）的无状态
// 渲染通道——无锁屏门禁（锁屏时菜单也要跟界面语言），无托盘时是无害 no-op。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// connect_token_* 的 Err 臂：锁定（error_with_code 路径）与坏库（纯错误
// 路径）——上轮 round-trip 只测了 Ok 臂。
// ---------------------------------------------------------------------------

// ---- 账号体系（M2 tauri 代理层）----
//
// 门禁语义与 sync 命令族同门第：未初始化/未配置服务器/未解锁各态先于
// 任何网络访问被拒；Bearer 端点额外要求 keyring 有账号 bearer（
// fail-closed）。令牌生命周期（srp_verify 写入 → create_session 覆盖
// → revoke_session 自吊销清除、吊销他人会话不动本机令牌）用一次性
// TCP 假服务器做端到端断言。wire 契约（路径/方法/Bearer 有无/请求体
// 透传）由 core accounts::remote 的 16 个用例覆盖，这里不重复。

struct AccountMockRequest {
    method: String,
    path: String,
    auth: Option<String>,
    body: String,
}

/// 一次性账号域假服务器：每连接读一条请求（head + Content-Length 体），
/// 调 handler 得 (状态码, 响应体)，回写极简 HTTP/1.1 响应，循环至测试
/// 结束（监听器随线程生命周期）。
fn spawn_account_mock<F>(handler: F) -> String
where
    F: Fn(&AccountMockRequest) -> (u16, String) + Send + 'static,
{
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            let request_line = head.lines().next().unwrap_or_default().to_string();
            let auth = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .map(|l| {
                    l.split_once(':')
                        .map(|x| x.1)
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                });
            let content_length: usize = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split_once(':')?.1.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = stream.read_exact(&mut body);
            }
            let (status, resp_body) = handler(&AccountMockRequest {
                method: request_line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                path: request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string(),
                auth,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
            let reason = if status == 204 { "" } else { "OK" };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                resp_body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn decode_b64(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

fn encode_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// 同步组配对命令族（S1 桌面接线）
//
// 协议正确性归 core（`sync::pairing` 全握手/错码/篡改/端到端 11 例），这里
// 只测宿主编排：门禁（未解锁/未配置/已入组）、会话状态机、双端组密钥落地。
// 中转用手搓 HTTP 假 relay（与 core 测试同构：内存双向信箱，路由与
// server /pairing/* 一致，单会话）。
// ---------------------------------------------------------------------------

/// 一次性 TCP 假 relay：返回 base_url。session_id 恒 `sess-1`（单会话测试）。
fn spawn_mock_pairing_relay() -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    #[derive(Default)]
    struct Mailbox {
        salt: Option<Vec<u8>>,
        to_host: Vec<Vec<u8>>,
        to_guest: Vec<Vec<u8>>,
    }
    let state = Arc::new(std::sync::Mutex::new(Mailbox::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            let request_line = head.lines().next().unwrap_or_default().to_string();
            let content_length: usize = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split_once(':').and_then(|(_, v)| v.trim().parse().ok()))
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = stream.read_exact(&mut body);
            }
            let method = request_line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let body_str = String::from_utf8_lossy(&body).into_owned();
            use base64::Engine as _;
            let (status, resp_body) = {
                let mut st = state.lock().unwrap();
                let b64d = |v: &str| base64::engine::general_purpose::STANDARD.decode(v).unwrap();
                let b64e = |v: &[u8]| base64::engine::general_purpose::STANDARD.encode(v);
                if method == "POST" && path == "/api/v1/pairing/sessions" {
                    let json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
                    st.salt = Some(b64d(json["salt"].as_str().unwrap()));
                    (
                        201,
                        r#"{"session_id":"sess-1","expires_in_secs":600}"#.to_string(),
                    )
                } else if method == "GET" && path == "/api/v1/pairing/sessions/sess-1" {
                    let json = serde_json::json!({
                        "salt": b64e(st.salt.as_deref().unwrap_or_default()),
                        "expires_in_secs": 600,
                        "to_host_len": st.to_host.len() as i64,
                        "to_guest_len": st.to_guest.len() as i64,
                    });
                    (200, json.to_string())
                } else if path.ends_with("/messages/to-host") && method == "POST" {
                    let json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
                    st.to_host.push(b64d(json["payload"].as_str().unwrap()));
                    (202, "{}".to_string())
                } else if path.ends_with("/messages/to-guest") && method == "POST" {
                    let json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
                    st.to_guest.push(b64d(json["payload"].as_str().unwrap()));
                    (202, "{}".to_string())
                } else if path.ends_with("/messages/to-host") {
                    let msgs: Vec<String> = st.to_host.drain(..).map(|m| b64e(&m)).collect();
                    (200, serde_json::json!({ "messages": msgs }).to_string())
                } else if path.ends_with("/messages/to-guest") {
                    let msgs: Vec<String> = st.to_guest.drain(..).map(|m| b64e(&m)).collect();
                    (200, serde_json::json!({ "messages": msgs }).to_string())
                } else if method == "DELETE" {
                    (204, String::new())
                } else {
                    (404, String::new())
                }
            };
            let reason = if status == 204 { "" } else { "OK" };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                resp_body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// 给已初始化的 vault 写 sync 配置（server_url 指向给定地址）。
async fn set_sync_server_url(
    _app: &tauri::App<tauri::test::MockRuntime>,
    db_path: &str,
    url: &str,
) {
    use persona_core::models::SyncConfig;
    use persona_core::storage::{Database, Repository, WorkspaceRepository};
    let db = Database::from_file(db_path).await.unwrap();
    let workspace_path = crate::commands::workspace_path_for_db_path(db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = crate::commands::ensure_workspace_for_path(&db, &workspace_path)
        .await
        .unwrap();
    ws.settings.sync = Some(SyncConfig {
        enabled: true,
        server_url: url.to_string(),
        server_token: String::new(),
    });
    ws.touch();
    repo.update(&ws).await.unwrap();
}

mod account;
mod approval;
mod biometric;
mod connect;
mod credential_attach;
mod credential_crud;
mod credential_secret;
mod credential_totp;
mod identity;
mod identity_auth;
mod identity_init;
mod ipc_contract;
mod passkey;
mod settings;
mod settings_backup;
mod settings_quick;
mod settings_sync;
mod settings_travel;
mod ssh;
mod sync;
mod wallet;
mod wallet_io;
mod wallet_tx;
