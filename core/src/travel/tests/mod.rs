use super::*;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};

use crate::backup::file_crypto::{encrypt_bytes, is_persona_encrypted, KdfParams};
use crate::backup::snapshot::gzip_bytes;
use crate::models::{Identity, IdentityType};
use crate::storage::repository::{IdentityRepository, Repository};
use crate::storage::Database;

mod blob;
mod codec;
mod pack;
mod tx;

/// Test KDF: 8 MiB (decryption is always 3/1; iterations must not change).
fn fast_kdf() -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        iterations: 3,
        parallelism: 1,
    }
}

async fn seeded_db() -> (tempfile::TempDir, Database) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::from_file(dir.path().join("identities.db"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    // enter/exit both read and write the settings of the first workspaces
    // row; migrate does not create that row, so create it explicitly here to
    // match production `persona init`.
    use crate::models::Workspace;
    use crate::storage::WorkspaceRepository;
    let ws_repo = WorkspaceRepository::new(db.clone());
    crate::storage::Repository::create(&ws_repo, &Workspace::new(dir.path(), "test".to_string()))
        .await
        .unwrap();
    let repo = IdentityRepository::new(db.clone());
    repo.create(&Identity::new("A".to_owned(), IdentityType::Personal))
        .await
        .unwrap();
    repo.create(&Identity::new("B".to_owned(), IdentityType::Work))
        .await
        .unwrap();
    (dir, db)
}

// ---- Defense-arm completion round (2026-09-29 coverage): value-level
// codec / attachment collection / blob IO / bad settings / favicon pruning ----

/// Minimal usable pack: apply_enter_tx only consumes identity_ids and the
/// credentials table, so build it by hand (all fields pub) to reach the
/// branch under test.
fn minimal_pack(identity_ids: Vec<String>) -> TravelPack {
    TravelPack {
        format_name: FORMAT_NAME.to_string(),
        format_version: FORMAT_VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        active_identity_id: None,
        identity_ids,
        tables: std::collections::BTreeMap::new(),
        attachment_files: Vec::new(),
    }
}

/// Insert one credential row directly (url may be NULL -- the favicon
/// pruning collects it as an Option).
async fn insert_credential(pool: &SqlitePool, identity_id: &str, url: Option<&str>) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
            "INSERT INTO credentials (id, identity_id, name, credential_type, security_level, url, encrypted_data, created_at, updated_at)
             VALUES (?, ?, 'probe', 'password', 'medium', ?, X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(&id)
        .bind(identity_id)
        .bind(url)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn identity_id_by_name(pool: &SqlitePool, name: &str) -> String {
    sqlx::query_scalar::<_, String>("SELECT id FROM identities WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}
