use super::*;
use crate::storage::Database;
use std::path::{Path, PathBuf};
use uuid::Uuid;

async fn create_test_db() -> Database {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    db
}

async fn seed_identity_and_credential(db: &Database) -> Uuid {
    let identity_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO identities (
          id, name, identity_type, description, email, phone, ssh_key, gpg_key,
          tags, attributes, created_at, updated_at, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(identity_id.to_string())
    .bind("Test Identity")
    .bind("personal")
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind("[]")
    .bind("{}")
    .bind(&now)
    .bind(&now)
    .bind(true)
    .execute(db.pool())
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO credentials (
          id, identity_id, name, credential_type, security_level, url, username,
          encrypted_data, notes, tags, metadata, created_at, updated_at, last_accessed,
          is_active, is_favorite
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(credential_id.to_string())
    .bind(identity_id.to_string())
    .bind("Test Credential")
    .bind("password")
    .bind("medium")
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind(vec![0u8; 16])
    .bind::<Option<String>>(None)
    .bind("[]")
    .bind("{}")
    .bind(&now)
    .bind(&now)
    .bind::<Option<String>>(None)
    .bind(true)
    .bind(false)
    .execute(db.pool())
    .await
    .unwrap();

    credential_id
}

fn small_test_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
    use std::io::Write;
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(contents).unwrap();
    file.sync_all().unwrap();
    path
}

mod manager;
mod store;
