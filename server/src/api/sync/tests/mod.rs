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

// ---- Concurrent rotation mutual exclusion (§11 open question 2: optimistic epoch locking) ----

// ---- Library-level snapshots (S2 closeout, E2EE_SYNC_DESIGN §5 "library snapshots and op compaction") ----

fn put_snapshot_json(seq: i64, device: &Uuid, ciphertext: &str) -> Value {
    json!({
        "seq": seq,
        "device_id": device.to_string(),
        "ciphertext": ciphertext,
    })
}

/// Two-device router: laptop = token-a, phone = token-b (the S4 "own remark only"
/// isolation surface needs two token identities to be testable).
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

/// For the two-token router: the registration name must match the token identity
/// (the remark endpoint locates the row by the token's device_name).
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

/// A member device's local library: an identity row with the same id (identities are not
/// synced via the oplog, so tests align them directly) plus an independent master key.
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

/// Assert that the two stored credentials' names and passwords match the A-side seed
/// (read back through the local master).
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
