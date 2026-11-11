use super::*;
use crate::test_support::{request, send, setup, setup_with_retention};
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::{json, Value};

const TOKEN: &str = "sync-test-token";

async fn router() -> axum::Router {
    let (router, _state) = setup(Some(TOKEN)).await;
    router
}

fn req(method: &str, uri: &str, body: &str) -> axum::http::Request<String> {
    request(
        method,
        uri,
        Some(&format!("Bearer {TOKEN}")),
        Some("application/json"),
        body,
    )
}

fn get_req(uri: &str) -> axum::http::Request<String> {
    request("GET", uri, Some(&format!("Bearer {TOKEN}")), None, "")
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

async fn register_device(router: &axum::Router, name: &str) -> Uuid {
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/devices",
            &json!({
                "device_name": name,
                "public_key": b64(&[7u8; 32]),
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Uuid::parse_str(body["device_id"].as_str().unwrap()).unwrap()
}

fn put_op_json(op_id: &str, item_id: &str, lamport: u64, device: &Uuid, tag: &[u8]) -> Value {
    json!({
        "op_id": op_id,
        "item_id": item_id,
        "kind": "credential",
        "op": "put",
        "lamport": lamport,
        "device_id": device.to_string(),
        "timestamp": "2026-09-22T00:00:00Z",
        "payload": {
            "ciphertext": b64(tag),
            "wrapped_item_key": b64(&[1u8; 32]),
        }
    })
}

// ---- 并发轮换互斥（§11 开放问题 2：epoch 乐观锁）----

// ---- 库级快照（S2 收口，E2EE_SYNC_DESIGN §5「库级快照与指令压缩」）----

fn put_snapshot_json(seq: i64, device: &Uuid, ciphertext: &str) -> Value {
    json!({
        "seq": seq,
        "device_id": device.to_string(),
        "ciphertext": ciphertext,
    })
}

/// 双设备路由：laptop=token-a，phone=token-b（S4「仅改自己备注」的
/// 隔离面需要两个令牌归属才验得了）。
async fn two_device_router() -> axum::Router {
    let tokens = crate::auth::AuthTokens::parse("laptop:tok-laptop,phone:tok-phone").unwrap();
    let app = crate::state::AppState::new(
        crate::state::test_pool().await,
        Some(tokens),
        std::sync::Arc::new(crate::metrics::Metrics::new(0)),
    );
    crate::build_router(app)
}

fn req_with_token(method: &str, uri: &str, token: &str, body: &str) -> axum::http::Request<String> {
    request(
        method,
        uri,
        Some(&format!("Bearer {token}")),
        Some("application/json"),
        body,
    )
}

/// 双令牌路由用：注册名必须与令牌归属名一致（remark 端点按令牌
/// 归属的 device_name 定位行）。
async fn register_device_with_token(router: &axum::Router, name: &str, token: &str) -> Uuid {
    let (status, body) = send(
        router.clone(),
        req_with_token(
            "POST",
            "/api/v1/sync/devices",
            token,
            &json!({
                "device_name": name,
                "public_key": b64(&[7u8; 32]),
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Uuid::parse_str(body["device_id"].as_str().unwrap()).unwrap()
}

/// 成员设备的本地库：同 id 身份行（身份不经 oplog 同步，测试直接对齐）
/// + 独立主密钥。
async fn member_db(
    identity_id: Uuid,
) -> (
    persona_core::storage::Database,
    persona_core::crypto::encryption::EncryptionService,
) {
    use persona_core::crypto::encryption::EncryptionService;
    use persona_core::models::identity::{Identity, IdentityType};
    use persona_core::storage::repository::IdentityRepository;
    use persona_core::storage::{Database, Repository};

    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut owner = Identity::new("seed".to_string(), IdentityType::Personal);
    owner.id = identity_id;
    IdentityRepository::new(db.clone())
        .create(&owner)
        .await
        .unwrap();
    let master = EncryptionService::new(&EncryptionService::generate_key());
    (db, master)
}

/// 断言库中两条凭据名称与密码和 A 侧种子一致（经本机 master 读回）。
async fn assert_stored_credentials(
    db: &persona_core::storage::Database,
    master: &persona_core::crypto::encryption::EncryptionService,
) {
    use persona_core::crypto::key_hierarchy::KeyHierarchy;
    use persona_core::models::credential::CredentialData;
    use persona_core::storage::CredentialRepository;

    let creds = CredentialRepository::new(db.clone())
        .list_all()
        .await
        .unwrap();
    assert_eq!(creds.len(), 2);
    let hierarchy = KeyHierarchy::new(master);
    let mut found: Vec<(String, String)> = creds
        .iter()
        .map(|cred| {
            let plaintext = hierarchy
                .decrypt_with_wrapped_key(
                    cred.wrapped_item_key.as_deref().expect("wrapped item key"),
                    &cred.encrypted_data,
                )
                .expect("decrypt with local master");
            match CredentialData::from_bytes(&plaintext).unwrap() {
                CredentialData::Password(p) => (cred.name.clone(), p.password),
                other => panic!("unexpected credential data: {other:?}"),
            }
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            ("cred-one".to_string(), "one".to_string()),
            ("cred-two".to_string(), "two".to_string())
        ]
    );
}

mod devices;
mod oplog;
mod rotate;
mod snapshot;
mod status;
mod tcp;
