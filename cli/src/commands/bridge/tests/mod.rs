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
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .unwrap();
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

// ---- desktop approval gate (Passkeys P3) ----

/// A fake desktop approval server: accepts one connection, reads the
/// request line, replies with the configured verdict, and resolves with
/// the received line so tests can pin the wire format. The `TempDir`
/// keeps the socket file alive for the duration of the test.
#[cfg(unix)]
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
/// Only the unix-gated tests call it.
#[cfg(unix)]
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
    let mut service = crate::commands::service::new_service(db).await.unwrap();
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
    let mut service = crate::commands::service::new_service(db).await.unwrap();
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
                hotp: None,
                initial_counter: None,
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

/// Seed a HOTP (RFC 4226) credential with an explicit starting counter.
async fn seed_hotp_credential(
    db_path: &Path,
    identity_id: uuid::Uuid,
    name: &str,
    url: Option<&str>,
    initial_counter: u64,
) -> uuid::Uuid {
    use persona_core::models::credential::SecurityLevel;

    let db = open_db(db_path).await.unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
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
                hotp: Some(true),
                initial_counter: Some(initial_counter),
            }),
        )
        .await
        .unwrap();
    cred.url = url.map(|s| s.to_string());
    let db = open_db(db_path).await.unwrap();
    CredentialRepository::new(db).update(&cred).await.unwrap();
    cred.id
}

/// Seed a game token credential (Steam Guard or an arbitrary provider id).
async fn seed_game_token_credential(
    db_path: &Path,
    identity_id: uuid::Uuid,
    name: &str,
    url: Option<&str>,
    provider: &str,
) -> uuid::Uuid {
    use persona_core::models::credential::{GameTokenData, SecurityLevel};

    let db = open_db(db_path).await.unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
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
            &CredentialData::GameToken(GameTokenData {
                provider: provider.to_string(),
                secret_key: data_encoding::BASE64.encode(b"0123456789abcdefghij"),
                issuer: "Steam".to_string(),
                account_name: "alice_steam".to_string(),
                url: url.map(|s| s.to_string()),
                identity_secret: None,
                device_id: None,
            }),
        )
        .await
        .unwrap();
    cred.url = url.map(|s| s.to_string());
    let db = open_db(db_path).await.unwrap();
    CredentialRepository::new(db).update(&cred).await.unwrap();
    cred.id
}

/// Seed a credential whose row type is Password but whose sealed payload
/// is arbitrary `data` — the type gate passes while the fill match takes
/// the defensive arms.
async fn seed_password_typed_credential(
    db_path: &Path,
    identity_id: uuid::Uuid,
    name: &str,
    url: Option<&str>,
    data: &CredentialData,
) -> uuid::Uuid {
    use persona_core::models::credential::SecurityLevel;

    let db = open_db(db_path).await.unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
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
            data,
        )
        .await
        .unwrap();
    cred.url = url.map(|s| s.to_string());
    let db = open_db(db_path).await.unwrap();
    CredentialRepository::new(db).update(&cred).await.unwrap();
    cred.id
}

/// Seed a BankCard credential. `cvv` may be empty to exercise the
/// copy-empty-field rejection. Bank cards carry no URL (they are not
/// bound to a site), matching how `import_1pux` and the desktop create
/// them; pass `url` to override for origin-binding tests.
async fn seed_bank_card_credential(
    db_path: &Path,
    identity_id: uuid::Uuid,
    name: &str,
    cvv: &str,
) -> uuid::Uuid {
    use persona_core::models::credential::{BankCardData, SecurityLevel};

    let db = open_db(db_path).await.unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    assert_eq!(
        service.authenticate_user(PASSWORD).await.unwrap(),
        persona_core::auth::authentication::AuthResult::Success
    );
    let mut cred = service
        .create_credential(
            identity_id,
            name.to_string(),
            CredentialType::BankCard,
            SecurityLevel::High,
            &CredentialData::BankCard(BankCardData {
                card_number: "4111 1111 1111 1111".to_string(),
                cardholder_name: "ALICE SMITH".to_string(),
                expiry_date: "12/29".to_string(),
                cvv: cvv.to_string(),
                bank_name: "Example Bank".to_string(),
                card_type: "visa".to_string(),
            }),
        )
        .await
        .unwrap();
    cred.url = None;
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
    let mut service = crate::commands::service::new_service(db).await.unwrap();
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

#[cfg(target_os = "macos")]
fn clipboard_available() -> bool {
    Command::new("which")
        .arg("pbcopy")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn clipboard_available() -> bool {
    // `clip` / `Set-Clipboard` take the clipboard while running; under
    // parallel tests a sibling can hold the lock and make a live probe
    // exit non-zero while the real copy (same tools a moment later,
    // with a powershell fallback) succeeds — probe said no, copy said
    // yes, and the outcome-branching assertion flapped (observed on
    // CI runners). Probe PATH resolution instead: `where` touches no
    // clipboard, so the verdict is stable, and it covers both tools
    // the real copy path tries.
    ["clip", "powershell"].iter().any(|cmd| {
        Command::new("where")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn clipboard_available() -> bool {
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
fn assert_copy_outcome(result: anyhow::Result<BridgeResponse<serde_json::Value>>, clip_ok: bool) {
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

// -----------------------------------------------------------------------
// Stage 4 (context-aware bridge): seam tests with injected map paths.
//
// The Windows dirs-sys constraint (`dirs::home_dir()` ignores HOME) means
// the real global map path cannot be redirected by tests, so every case
// below drives `context_suggestion_for_bridge_with` / the merge in
// `get_credential_suggestions` with paths inside a TempDir — the same
// seam pattern as `persona suggest` stage 1-3.
// -----------------------------------------------------------------------

/// Serializes tests that mutate process env vars; restores on drop.
struct EnvRestore {
    name: &'static str,
    original: Option<std::ffi::OsString>,
}

impl EnvRestore {
    fn set(name: &'static str, value: &str) -> Self {
        let original = std::env::var_os(name);
        std::env::set_var(name, value);
        EnvRestore { name, original }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.original {
            Some(v) => std::env::set_var(self.name, v),
            None => std::env::remove_var(self.name),
        }
    }
}

/// Two identities — "Work" (active) and "OpenSource" — no credentials.
async fn seeded_context_bridge() -> (tempfile::TempDir, PathBuf, uuid::Uuid, uuid::Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = open_db(&db_path).await.unwrap();
    let mut service = crate::commands::service::new_service(db.clone())
        .await
        .unwrap();
    service.initialize_user(PASSWORD).await.unwrap();
    let work = service
        .create_identity("Work".to_string(), IdentityType::Work)
        .await
        .unwrap();
    let opensource = service
        .create_identity("OpenSource".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
            r#"INSERT INTO workspaces (id, name, created_at, updated_at, is_active, active_identity_id, settings)
               VALUES (?, ?, ?, ?, 1, ?, '{}')"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("test")
        .bind(&now)
        .bind(&now)
        .bind(work.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(service);
    drop(db);
    (dir, db_path, work.id, opensource.id)
}

/// Injected map paths inside the temp dir (never touch the real HOME).
fn context_maps_for(dir: &Path) -> BridgeMapPaths {
    BridgeMapPaths {
        global: dir.join("global-context.toml"),
        repo_local: Some(dir.join("repo-context.toml")),
    }
}

fn context_payload(origin: &str, host: Option<&str>, cwd: Option<&str>) -> SuggestionsPayload {
    SuggestionsPayload {
        origin: origin.to_string(),
        form_type: None,
        host: host.map(str::to_string),
        cwd: cwd.map(str::to_string),
    }
}

/// generate() 的 device_id 是 nil UUID（登记后回填）——测试里显式
/// 分配不同 id 才能区分「本机」与「他机」。
fn device_identity(seed: u8) -> persona_core::sync::device::DeviceIdentity {
    let id = uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, seed]);
    persona_core::sync::device::DeviceIdentity::generate("test-device")
        .unwrap()
        .with_device_id(id)
}

// ---- account_*（协议 v7，M5 批2）----

/// 内存版账号令牌仓（测试注入；与生产 KeyringAccountTokenStore 同 trait）。
struct InMemoryAccountTokenStore(std::sync::Mutex<std::collections::HashMap<String, String>>);

impl InMemoryAccountTokenStore {
    fn new() -> Self {
        Self(std::sync::Mutex::new(std::collections::HashMap::new()))
    }
}

impl AccountTokenStore for InMemoryAccountTokenStore {
    fn set_token(&self, db_key: &str, token: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(db_key.to_string(), token.to_string());
        Ok(())
    }

    fn get_token(&self, db_key: &str) -> Result<Option<String>> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(db_key)
            .cloned())
    }

    fn delete_token(&self, db_key: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(db_key);
        Ok(())
    }
}

/// 完整 WorkspaceSettings 序列化（带指定 sync 配置）。
fn workspace_settings_json(sync: Option<(String, String)>) -> String {
    let settings = persona_core::models::WorkspaceSettings {
        sync: sync.map(
            |(server_url, server_token)| persona_core::models::SyncConfig {
                enabled: true,
                server_url,
                server_token,
            },
        ),
        ..persona_core::models::WorkspaceSettings::default()
    };
    serde_json::to_string(&settings).unwrap()
}

/// v2 形态 workspace 行（path = 指定目录，settings = 完整 JSON）。
async fn insert_workspace_row(db: &Database, path: &str, settings_json: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
            r#"INSERT INTO workspaces (id, name, path, created_at, updated_at, is_active, active_identity_id, settings)
               VALUES (?, ?, ?, ?, ?, 1, NULL, ?)"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("test")
        .bind(path)
        .bind(&now)
        .bind(&now)
        .bind(settings_json)
        .execute(db.pool())
        .await
        .unwrap();
}

mod account;
mod approval;
mod copy;
mod credentials;
mod fill;
mod frames;
mod helpers;
mod infra;
mod pairing;
mod passkey;
mod state;
mod suggestions;
mod sync;
mod sync_connect;
mod totp;
