use super::*;
use crate::models::{CredentialData, PasswordCredentialData};
use crate::storage::Database;

// ----- Connect 本机自动化(阶段 1:token 生命周期/scope/锁定门禁)-----

use crate::connect::{ConnectItemType, ConnectTokenScope, ConnectVerb};

fn connect_read_scope() -> ConnectTokenScope {
    ConnectTokenScope {
        identities: vec![],
        item_types: vec![],
        verbs: vec![ConnectVerb::Read],
    }
}

/// scope → 测试用 token 行：数据面方法以完整 token 行为入参
/// （拒绝审计需带 token id / 指纹）。
fn token_of(scope: &ConnectTokenScope) -> ConnectTokenRow {
    ConnectTokenRow {
        id: Uuid::new_v4(),
        label: "test".to_string(),
        hash: "hash".to_string(),
        fingerprint: "fingerprint0".to_string(),
        scope: scope.clone(),
        principal: None,
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
        expires_at: None,
    }
}

/// 已解锁服务 + 独立 Database 句柄(直接查表断言哈希存储用)。
async fn connect_fixture() -> (PersonaService, Database) {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db.clone()).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("test_password", &salt).unwrap();
    (service, db)
}

fn assert_vault_locked(err: anyhow::Error) {
    assert!(matches!(
        err.downcast_ref::<PersonaError>(),
        Some(PersonaError::VaultLocked(_))
    ));
}

/// list_connect_tokens 只挂解锁门禁(无 reauth):锁定即 VaultLocked。
fn assert_vault_locked_but_auth_gate_first_free(err: anyhow::Error) {
    assert!(matches!(
        err.downcast_ref::<PersonaError>(),
        Some(PersonaError::VaultLocked(_))
    ));
}

async fn unlocked_service() -> (Database, PersonaService) {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db.clone()).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    (db, service)
}

async fn seed_credential(
    service: &PersonaService,
    identity_id: Uuid,
    name: &str,
    credential_type: CredentialType,
) -> Credential {
    let data = CredentialData::Password(PasswordCredentialData {
        password: "pw".to_string(),
        email: None,
        security_questions: vec![],
    });
    service
        .create_credential(
            identity_id,
            name.to_string(),
            credential_type,
            SecurityLevel::Medium,
            &data,
        )
        .await
        .unwrap()
}

/// Turn a live vault into its pre-migration-021 shape: item keys
/// re-wrapped under the legacy iteration count and the stored count pinned
/// to it. That is exactly what migration 021 produced for vaults created
/// before the count was persisted.
async fn downgrade_to_legacy_kdf(service: &PersonaService) {
    use crate::crypto::{EncryptionService, LEGACY_MASTER_KEY_PBKDF2_ITERATIONS};

    const PASSWORD: &str = "master-pin";
    let user_auth = service.user_auth_repo.get_first().await.unwrap().unwrap();
    let salt = user_auth.get_master_key_salt().unwrap();
    let current_key = service
        .master_key_service
        .derive_master_key(PASSWORD, &salt);
    let legacy_key = service
        .master_key_service
        .derive_master_key_with_iterations(PASSWORD, &salt, LEGACY_MASTER_KEY_PBKDF2_ITERATIONS);
    service
        .rewrap_all_item_keys(
            &EncryptionService::new(&current_key),
            &EncryptionService::new(&legacy_key),
            &user_auth,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE user_auth SET kdf_iterations = ?")
        .bind(i64::from(LEGACY_MASTER_KEY_PBKDF2_ITERATIONS))
        .execute(service.db.pool())
        .await
        .unwrap();
}

fn assert_password_credential(data: CredentialData) {
    match data {
        CredentialData::Password(p) => assert_eq!(p.password, "pw"),
        other => panic!("unexpected credential data: {other:?}"),
    }
}

/// Seed (or update) the workspace row's password expiry policy.
async fn set_password_expiry(db: &Database, days: Option<u32>) {
    let repo = crate::storage::WorkspaceRepository::new(db.clone());
    let created;
    let mut ws = match Repository::find_all(&repo)
        .await
        .unwrap()
        .into_iter()
        .next()
    {
        Some(ws) => {
            created = false;
            ws
        }
        None => {
            created = true;
            Workspace::new("/tmp/persona-test", "test".to_string())
        }
    };
    ws.settings.password_expiry_days = days;
    ws.touch();
    if created {
        Repository::create(&repo, &ws).await.unwrap();
    } else {
        Repository::update(&repo, &ws).await.unwrap();
    }
}

/// Backdate `password_updated_at` so the password looks N days old.
async fn backdate_password_updated_at(db: &Database, days_ago: u64) {
    let old = (chrono::Utc::now() - chrono::Duration::days(days_ago as i64)).to_rfc3339();
    sqlx::query("UPDATE user_auth SET password_updated_at = ?")
        .bind(old)
        .execute(db.pool())
        .await
        .unwrap();
}

/// Seal `data` directly under the master key (legacy row shape) and
/// clear the wrapped key, converting the row to the legacy layout.
async fn convert_credential_to_legacy(
    db: &Database,
    service: &PersonaService,
    credential_id: &Uuid,
) {
    let data = service
        .get_credential_data(credential_id)
        .await
        .unwrap()
        .expect("seeded credential exists");
    let master = service.get_master_encryption_service().unwrap();
    let ciphertext = master.encrypt(&data.to_bytes().unwrap()).unwrap();
    sqlx::query("UPDATE credentials SET encrypted_data = ?, wrapped_item_key = NULL WHERE id = ?")
        .bind(&ciphertext)
        .bind(credential_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
}

/// travel 测试夹具：解锁服务 + workspaces 行（travel_status/enter/exit
/// 读写 settings 需要；unlocked_service 不建行）+ sidecar 目录。
async fn travel_fixture() -> (tempfile::TempDir, Database, PersonaService) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db.clone()).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    let ws_repo = crate::storage::WorkspaceRepository::new(db.clone());
    if Repository::find_all(&ws_repo).await.unwrap().is_empty() {
        Repository::create(
            &ws_repo,
            &crate::models::Workspace::new(dir.path(), "test".to_string()),
        )
        .await
        .unwrap();
    }
    (dir, db, service)
}

// ------------------------------------------------------------------
// Helpers shared by the batches below
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Custom fields（1Password 对齐）：per-item key 密封的 metadata blob
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Item history（1Password 对齐）：create/update/delete 自动记录
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Locked service error paths
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// User lifecycle / authentication
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// PBKDF2 iteration upgrade (migration 021, 2026-10-16 已代决)
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Hardware-bound biometric unlock (auth/biometric_wrap.rs consumers)
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Session / auto-lock surface
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Remote auth / biometric providers
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Attachments
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Export / statistics
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Change history
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Query helpers / password generation
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Identity / credential CRUD
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Credential decryption: legacy (master-key) format and error paths
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Attachments: encrypted storage through the service surface
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// update_credential_data：编辑密文 payload（复用原 item key）
// ------------------------------------------------------------------

// ---- favicon（feature = "favicon"）：编排与缓存语义 ----

// ------------------------------------------------------------------
// Watchtower 扩展规则（1Password 对齐）：软件许可到期 + 2FA available
// ------------------------------------------------------------------

// Breach 规则走 SHA-1 摘要缝：命中 corpus 报 BreachedPassword；checker
// 故障不致命（offline 规则的报告照常返回）。
struct FixedBreaches {
    counts: HashMap<String, u64>,
}

#[async_trait::async_trait]
impl BreachChecker for FixedBreaches {
    async fn breach_counts(&self, digests: &[String]) -> Result<HashMap<String, u64>> {
        Ok(digests
            .iter()
            .map(|d| (d.clone(), self.counts.get(d).copied().unwrap_or(0)))
            .collect())
    }
}

struct DownChecker;

#[async_trait::async_trait]
impl BreachChecker for DownChecker {
    async fn breach_counts(&self, _digests: &[String]) -> Result<HashMap<String, u64>> {
        Err(anyhow::anyhow!("corpus unreachable"))
    }
}

// ------------------------------------------------------------------
// Password expiry policy + master password rotation
// ------------------------------------------------------------------

use crate::models::Workspace;
use crate::storage::UserAuthRepository;

// ------------------------------------------------------------------
// Travel Mode（旅行模式）集成：enter 真移除 → exit 原样恢复
// ------------------------------------------------------------------

// ----- 防御臂覆盖轮（2026-09-30 llvm-cov 缺口最大模块 service.rs）-----

#[cfg(all(test, feature = "favicon"))]
mod favicon_tests {
    use super::*;
    use crate::favicon::FaviconFetcher;
    use std::sync::{Arc, Mutex};

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfake-icon";

    async fn unlocked_service() -> PersonaService {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let mut service = PersonaService::new(db).await.unwrap();
        let salt = service.generate_salt();
        service.unlock("test_password", &salt).unwrap();
        service
    }

    /// 恒 200 + PNG 的 fake favicon 源；返回注入用 base 与请求计数。
    async fn spawn_fake() -> (String, Arc<Mutex<usize>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(Mutex::new(0usize));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    *counter.lock().unwrap() += 1;
                    let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            PNG.len()
                        );
                    let mut out = response.into_bytes();
                    out.extend_from_slice(PNG);
                    let _ = socket.write_all(&out).await;
                });
            }
        });
        (format!("http://{addr}/"), hits)
    }

    async fn credential_with_url(
        service: &PersonaService,
        name: &str,
        url: Option<&str>,
    ) -> Credential {
        let identity = service
            .create_identity(format!("Identity for {name}"), IdentityType::Personal)
            .await
            .unwrap();
        let data = CredentialData::Password(PasswordCredentialData {
            password: "pw".to_string(),
            email: None,
            security_questions: vec![],
        });
        let mut credential = service
            .create_credential(
                identity.id,
                name.to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                &data,
            )
            .await
            .unwrap();
        credential.url = url.map(str::to_string);
        service.update_credential(&credential).await.unwrap()
    }

    #[tokio::test]
    async fn fetch_caches_and_serves_second_call_without_network() {
        let service = unlocked_service().await;
        let credential = credential_with_url(&service, "Site", Some("https://Example.COM/a")).await;
        let (base, hits) = spawn_fake().await;
        let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);

        let first = service
            .fetch_favicon_for_credential(&credential.id, &fetcher)
            .await
            .unwrap();
        assert_eq!(first.host, "example.com");
        assert_eq!(first.mime_type, "image/png");
        assert_eq!(first.data, PNG);
        assert_eq!(*hits.lock().unwrap(), 1);

        // 二次请求走缓存：host 归一后命中，不再外联
        let second = service
            .fetch_favicon_for_credential(&credential.id, &fetcher)
            .await
            .unwrap();
        assert_eq!(second.created_at, first.created_at);
        assert_eq!(*hits.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn fetch_shares_cache_across_credentials_of_same_host() {
        let service = unlocked_service().await;
        let a = credential_with_url(&service, "A", Some("https://a.com")).await;
        let b = credential_with_url(&service, "B", Some("a.com")).await; // 裸域名同 host
        let (base, hits) = spawn_fake().await;
        let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);

        service
            .fetch_favicon_for_credential(&a.id, &fetcher)
            .await
            .unwrap();
        let entry = service
            .fetch_favicon_for_credential(&b.id, &fetcher)
            .await
            .unwrap();

        assert_eq!(entry.host, "a.com");
        assert_eq!(*hits.lock().unwrap(), 1, "同 host 第二条凭据必须共享缓存");
    }

    #[tokio::test]
    async fn fetch_rejects_credential_without_url() {
        let service = unlocked_service().await;
        let credential = credential_with_url(&service, "NoUrl", None).await;
        let fetcher = FaviconFetcher::new().unwrap();

        let err = service
            .fetch_favicon_for_credential(&credential.id, &fetcher)
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_unknown_credential() {
        let service = unlocked_service().await;
        let fetcher = FaviconFetcher::new().unwrap();

        let err = service
            .fetch_favicon_for_credential(&Uuid::new_v4(), &fetcher)
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_non_https_url() {
        let service = unlocked_service().await;
        let credential = credential_with_url(&service, "Http", Some("http://example.com")).await;
        let (base, hits) = spawn_fake().await;
        let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);

        let err = service
            .fetch_favicon_for_credential(&credential.id, &fetcher)
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
            "got: {err}"
        );
        assert_eq!(*hits.lock().unwrap(), 0, "SSRF 拒绝后绝不外联");
    }

    #[tokio::test]
    async fn fetch_requires_unlock() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let service = PersonaService::new(db).await.unwrap();
        let fetcher = FaviconFetcher::new().unwrap();

        let err = service
            .fetch_favicon_for_credential(&Uuid::new_v4(), &fetcher)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Service is locked"), "got: {err}");
    }

    #[tokio::test]
    async fn get_cached_favicons_dedupes_and_returns_hits_only() {
        let service = unlocked_service().await;
        let credential = credential_with_url(&service, "Cached", Some("https://a.com")).await;
        let (base, hits) = spawn_fake().await;
        let fetcher = FaviconFetcher::new().unwrap().with_base_url(base);
        service
            .fetch_favicon_for_credential(&credential.id, &fetcher)
            .await
            .unwrap();

        // 大小写/空白归一去重；b.com 未缓存不出现
        let entries = service
            .get_cached_favicons(&[
                "A.COM".to_string(),
                " a.com ".to_string(),
                "b.com".to_string(),
            ])
            .await
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "a.com");
        assert_eq!(*hits.lock().unwrap(), 1, "批量读绝不外联");
    }

    #[tokio::test]
    async fn get_cached_favicons_enforces_limit() {
        let service = unlocked_service().await;
        let hosts: Vec<String> = (0..=MAX_HOSTS_PER_REQUEST)
            .map(|i| format!("h{i}.com"))
            .collect();
        let err = service.get_cached_favicons(&hosts).await.unwrap_err();
        assert!(
            err.downcast_ref::<PersonaError>()
                .is_some_and(|e| matches!(e, PersonaError::InvalidInput(_))),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn get_cached_favicons_requires_unlock() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let service = PersonaService::new(db).await.unwrap();

        let err = service
            .get_cached_favicons(&["a.com".to_string()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Service is locked"), "got: {err}");
    }
}

mod attachments;
mod audit;
mod auth;
mod connect;
mod credentials;
mod health;
mod history;
mod misc;
mod passkey;
mod session;
mod travel;
