//! Test hub for the repository split (LAY-017): shared fixtures/helpers + test modules grouped by repository.
//! Each group picks things up via the `use super::*` cascade (helpers and model bindings are visible to descendants).

use super::*;
use crate::models::{
    AuditAction, AuditLog, Credential, CredentialType, Identity, IdentityType, ResourceType,
    SecurityLevel, Workspace,
};
use crate::models::{CredentialData, PasswordCredentialData};
use crate::storage::Database;
use sqlx::AssertSqlSafe;

mod audit;
mod credential;
mod identity;
mod workspace;

async fn test_db() -> Database {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    db
}

fn sample_identity(name: &str) -> Identity {
    Identity::new(name.to_string(), IdentityType::Personal)
}

fn sample_credential(identity_id: Uuid, name: &str) -> Credential {
    let data = CredentialData::Password(PasswordCredentialData {
        password: "pw".to_string(),
        email: None,
        security_questions: vec![],
    });
    let plaintext = data.to_bytes().unwrap();
    let mut cred = Credential::new(
        identity_id,
        name.to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        plaintext.clone(),
        None,
    );
    cred.encrypted_data = plaintext;
    cred
}

fn audit_log(action: AuditAction) -> AuditLog {
    AuditLog::new(action, ResourceType::User, true)
        .with_user_id(Some("tester".to_string()))
        .with_ip_address(Some("127.0.0.1".to_string()))
        .with_user_agent(Some("repo-test".to_string()))
}

async fn insert_audit_user(db: &Database) {
    // audit_logs.user_id has an FK to user_auth(user_id); seed a matching row.
    sqlx::query("INSERT INTO user_auth (user_id, failed_attempts, password_change_required, created_at, updated_at) VALUES (?, 0, 0, ?, ?)")
            .bind("tester")
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(db.pool())
            .await
            .unwrap();
}

async fn rebuild_workspaces_table(db: &Database, ddl: &str) {
    sqlx::query("DROP TABLE IF EXISTS workspaces")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query(AssertSqlSafe(ddl.to_owned()))
        .execute(db.pool())
        .await
        .unwrap();
}
