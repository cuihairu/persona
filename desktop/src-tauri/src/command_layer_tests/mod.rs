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
/// parts (two keyring slots for sync/biometric + biometric provider + the wrap
/// layer wrapper/storage). Each command-family test injects fakes as needed;
/// for the default combinations see [`mock_app_with_token_store`] /
/// [`mock_app_with_biometric`] / [`mock_app_with_biometric_wrap`].
fn mock_app_with_parts(
    token_store: Arc<dyn TokenStore>,
    biometric_provider: Arc<dyn persona_core::BiometricProvider>,
    biometric_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_wrap_parts(
        token_store,
        biometric_provider,
        biometric_store,
        // Default gate-tier stub (= the CI/headless production assembly: Linux/Windows
        // have no hardware wrap layer, macOS has no spike gating) -- gate-layer behavior tests stay as-is
        Arc::new(crate::biometric::GateOnlyKeyWrapper),
        Arc::new(InMemoryTokenStore::default()),
    )
}

/// [`mock_app_with_parts`] + wrap layer (`biometric_wrapper` /
/// `biometric_wrap_store`) injection. Hardware-bound path command tests are
/// driven by `MockKeyWrapper` (`rotate_enrollment` / `set_fail` /
/// `set_user_cancelled` cover fallback-chain branches); blobs land in an
/// in-memory store for easy assertions.
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
        // CI/headless has no secret service -- tests always use the in-memory fake
        token_store,
        biometric_provider,
        biometric_store,
        // Wrap layer: gate-tier stub / HardwareBound wrapper is chosen by the caller
        biometric_wrapper,
        biometric_wrap_store,
        // E2EE sync device identity slot: in-memory fake by default; sync command-family
        // tests grab the Arc from AppState to write/assert entries
        device_store: Arc::new(InMemoryTokenStore::default()),
        // Account bearer slot: in-memory fake by default; account command-family tests assert
        // token lifecycle across commands (srp_verify writes / create_session overwrites /
        // revoke_session clears via self-revocation)
        account_token_store: Arc::new(InMemoryTokenStore::default()),
        connect_server: Mutex::new(None),
        // Quick Access runtime state: tests cannot register an OS global hotkey, so the default is empty
        // (quick_access_* command tests read/write this slot directly to assert semantics)
        quick_access: std::sync::Mutex::new(crate::quick_access::QuickAccessRuntime::default()),
        // Desktop fill injection target (#12): the test environment has no hotkey wakeup path, so the
        // default is empty (fill_* command tests read/write this slot directly to assert semantics)
        fill_target: std::sync::Mutex::new(None),
        // Sync-group pairing session slot: empty table by default (pairing command-family tests assert state across commands)
        pairing_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        // Sync-group group key slot: in-memory fake by default; pairing command-family tests grab the
        // same Arc from AppState to read back the group key the command wrote for assertions
        sync_group_store: Arc::new(InMemoryTokenStore::default()),
    });
    app
}

/// Mock app with a fresh, uninitialized `AppState` and the given token store.
/// The biometric side injects a always-passing Mock provider plus a separate
/// in-memory store by default (biometric-specific command tests swap in a
/// controllable stub via `mock_app_with_biometric`).
fn mock_app_with_token_store(
    token_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_parts(
        token_store,
        Arc::new(persona_core::MockBiometricProvider::default()),
        Arc::new(InMemoryTokenStore::default()),
    )
}

/// Mock app with injectable biometric provider/store (entry point for the
/// biometric command-family tests; the provider uses the
/// available/force_fail combination branches of MockBiometricProvider, the
/// store is usually an InMemoryTokenStore for easy direct assertion of entry
/// contents).
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
/// (`MockKeyWrapper` + in-memory blob storage): `biometric_enable` /
/// `biometric_unlock` on this app go through the key wrap chain rather than
/// the gate-tier password escrow chain.
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

/// Decode a base64 blob inside tests (used to assert "what landed on disk is a
/// ciphertext envelope"; the production encode/decode lives in commands.rs --
/// tests only read, never write).
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
// Batch 2: credential / wallet / reveal / export / passkey
// ---------------------------------------------------------------------------

/// Build an app with an initialized service + one existing identity; returns (app, identity_id).
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

// ---- S5 self-rescue hatch: full-vault encrypted backup file export (backup_export_to_file) ----

// ---- S5 self-rescue hatch: restore the whole vault from a local file (backup_restore_from_file) ----

// ---------------------------------------------------------------------------
// S5-d server ciphertext vault (persona-server /api/v1/backups desktop wiring)
//
// Protocol correctness belongs to core (BackupClient) and the server
// (backups.rs E2E); here we only test the host orchestration: gates
// (uninitialized/unconfigured/locked), snapshot+push+evidence writeback, list
// mapping, download -> staged DB swap (same semantics as file restore), and
// delete idempotency. The relay is a hand-rolled TCP fake server (isomorphic
// with the pairing relay fake: Bearer validation + single in-memory backup slot).
// ---------------------------------------------------------------------------

/// In-memory single-slot fake backup server: returns the base_url. The backup ID is
/// always `bk-1` (push overwrites, 404 after delete); the Bearer token is always
/// `tok-persona-1` (a mismatch returns a 401 envelope).
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

/// S5-d prerequisite: the sync config points at the fake server (URL into settings, token into keyring).
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
// Batch 3: wallet transactions / approval respond / SSH agent state and lifecycle
// ---------------------------------------------------------------------------

/// Sandboxed agent state dir: `PERSONA_AGENT_STATE_DIR` points at a tempdir, restored on drop.
///
/// env is process-global: parallel tests sandboxing independently would divert each
/// other (socket landing in the wrong directory, failed status assertions), so a
/// process-level lock is held -- only one test mutates env at a time.
pub(crate) struct StateDirGuard {
    // Declared first, constructed first, dropped last: env is restored before the lock is released.
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
    // None = this guard never touched SOCKET_PATH; Some(None) = the original value
    // was absent and must be removed; Some(Some(v)) = restore to v.
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

    /// The sandbox also injects PERSONA_AGENT_SOCKET_PATH: both envs must be set
    /// under the same lock (std Mutex is not reentrant; constructing two guards
    /// separately deadlocks).
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

    /// Exclusively removes PERSONA_AGENT_STATE_DIR: drives the home fallback arm
    /// of `agent_state_dir`. Holds the same process-level lock; on restore, Drop
    /// removes the env (prev=None).
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

/// Process-level mutex: agent-related envs (PERSONA_AGENT_STATE_DIR / SOCKET_PATH)
/// are shared within one process across parallel tests, so reads and writes must
/// be serialized.
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

// Backend anti-poisoning enforcement: when the to address mimics an address this
// wallet already knows, signing is refused without an ack and allowed with one
// (WALLET_DESIGN.md section 5, item 3).

// Unix-socket probing (stale file / live listener) has no Windows
// counterpart in this test; the named-pipe flow is a separate work item.

// ---------------------------------------------------------------------------
// Batch 4: wallet import/address management/export matrix, get_ssh_keys, health_scan, gates
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Batch 5: passkey gates and error codes, TOTP/credential data rejection paths, audit filtering, workspace diversion
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Batch 6: reveal type matrix / export and audit gates / reauth remaining branches
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Batch 8: types-layer pure function matrix (serialization redaction + conversions + event mapping)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Batch 9: init_service error arms / auto-lock event bridge loop / path utilities
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Batch 10: type/level matrix, get_credential_data all-variant labels, locked error-code matrix,
// wallet network/DB failure branches, agent state dir fallback, agent protocol read errors
// ---------------------------------------------------------------------------

// Unix domain socket specific path -- same gating as protocol_matrix above (missing this
// makes the desktop-build windows job fail on its first test-profile compile, 2026-09-26)

// ---------------------------------------------------------------------------
// Batch 11: active_identity DB failure, default db_path, active identity cleanup,
// locked-state credential/audit errors, wallet_generate type rejection, pending transaction and missing db_path
// ---------------------------------------------------------------------------

/// Exclusively points XDG_DATA_HOME at a temp dir (how dirs::data_dir reads on
/// Linux), driving the default db_path branch of init_service without touching
/// the real user directories.
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

/// A service that is unlocked but whose DB is a garbage file: the sqlx connection opens
/// lazily, so only a repo query errors. init_service cannot reach this state (migrate
/// fails first), so the service is built by hand -- use it to drive the repo error arms
/// the command layer cannot bypass. db_path also points at the same garbage file so
/// workspace/wallet commands that build their own connection share the same error path.
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
// Batch 16: precondition and dead-DB matrix for active identity / wallet / ssh commands
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Workspace settings / feature flags / passkey approval server-side gates
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Sync server config (settings.sync) and audit event emitter wiring
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Forced master-password rotation (PASSWORD_CHANGE_REQUIRED code / password change command /
// password_expiry_days narrow write)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Travel Mode command family
// ---------------------------------------------------------------------------

/// Initialize the service and create an identity, returning its id.
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
// Attachments (1Password-aligned): encrypted attachments are sealed with the credential item key;
// full chain of the four command-layer commands (list / attach / save / delete)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Biometric unlock: four-command command-layer matrix (provider uses the Mock's
// available/force_fail combination branches; store uses InMemoryTokenStore to assert entries directly)
// ---------------------------------------------------------------------------

fn mock_provider(available: bool, force_fail: bool) -> Arc<persona_core::MockBiometricProvider> {
    Arc::new(persona_core::MockBiometricProvider {
        available,
        force_fail,
        platform: persona_core::BiometricPlatform::Unknown,
    })
}

/// A keyring fake whose set always fails and whose get/delete delegate to an
/// internal InMemory store -- tests the two paths "write failure leaves no
/// half-state" / "password-change linkage fail-closed deletes the entry" (the
/// entry must be pre-placed in the internal store to simulate existing config).
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
// Hardware-bound wrap chain (`mock_app_with_biometric_wrap`: MockKeyWrapper reports
// HardwareBound, enable/unlock go through key wrapping rather than gate-tier password escrow)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Quick Access (global hotkey binding: persisted truth value + registration failure reported faithfully)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Generator hotkey (gap #9 remainder: same gate/persist/registration semantics as Quick Access,
// separate window and separate slot -- changing the search binding must not touch the generator,
// and vice versa)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// E2EE sync device management command family: the protocol layer lives in core (SyncAdminApi
// real TCP tests live in server); here we lock down host orchestration -- keyring identity
// tri-state, gates, failures leave no half-state.
// Network paths always hit an unreachable server (http://127.0.0.1:1, same convention as the
// set_sync_config family).
// ---------------------------------------------------------------------------

/// Write a valid local device identity directly into device_store (join's network path
/// cannot be tested; subsequent commands after the identity lands in keyring are all driven by it).
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
// connect_token_* command family (create/list/revoke): Service slot degradation + full lifecycle.
// ---------------------------------------------------------------------------

fn read_scope() -> persona_core::connect::ConnectTokenScope {
    persona_core::connect::ConnectTokenScope {
        identities: vec![],
        item_types: vec![],
        verbs: vec![persona_core::connect::ConnectVerb::Read],
    }
}

// ---------------------------------------------------------------------------
// connect_server_* command family (start/status/stop): unlock gate + lifecycle + idempotency.
// The listener only binds 127.0.0.1:0 (OS-assigned); no external network needed.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// set_locale: same pattern as set_feature_flags (unlock gate + narrow write + full return),
// plus rejection of invalid locales.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// set_tray_locale: the stateless render channel for tray right-click menu text (the truth lives
// in the frontend i18n locale tables) -- no lock-screen gate (the menu follows the UI language
// even when locked), and a harmless no-op when no tray exists.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Err arms of connect_token_*: locked (error_with_code path) and bad DB (pure error
// path) -- the previous round-trip round only tested the Ok arm.
// ---------------------------------------------------------------------------

// ---- Account system (M2 tauri proxy layer) ----
//
// Gate semantics are of the same lineage as the sync command family: uninitialized /
// server not configured / locked states are all rejected before any network access; Bearer
// endpoints additionally require an account bearer in keyring (fail-closed). Token
// lifecycle (srp_verify writes -> create_session overwrites -> revoke_session clears via
// self-revocation, revoking another session leaves this device's token alone) is asserted
// end-to-end with a one-shot TCP fake server. The wire contract (paths/methods/Bearer
// presence/request body passthrough) is covered by core accounts::remote's 16 cases; not
// repeated here.

struct AccountMockRequest {
    method: String,
    path: String,
    auth: Option<String>,
    body: String,
}

/// One-shot account-domain fake server: reads one request per connection (head +
/// Content-Length body), calls the handler for (status code, response body),
/// writes back a minimal HTTP/1.1 response, and loops until the test ends
/// (the listener lives for the thread's lifetime).
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
// Sync-group pairing command family (S1 desktop wiring)
//
// Protocol correctness belongs to core (`sync::pairing` covers all handshakes/error
// codes/tampering/end-to-end in 11 cases); here we only test host orchestration: gates
// (unlocked/not configured/already in a group), the session state machine, and group
// key landing on both ends. The relay is a hand-rolled HTTP fake relay (isomorphic with
// the core tests: in-memory bidirectional mailbox, routes identical to server
// /pairing/*, single session).
// ---------------------------------------------------------------------------

/// One-shot TCP fake relay: returns the base_url. The session_id is always `sess-1` (single-session tests).
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

/// Write sync config into an already-initialized vault (server_url points at the given address).
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
        cloud_drive_dir: None,
        sync_transport: persona_core::SyncTransport::default(),
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
