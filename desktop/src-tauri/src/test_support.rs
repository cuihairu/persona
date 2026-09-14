//! Shared test fixtures for command-layer tests.
//!
//! Lives behind `#[cfg(test)]` (`mod test_support;` inside the test tree),
//! so it is never compiled into release builds. Each fixture owns a
//! `TempDir` — drop it and the on-disk database disappears.

#![cfg(test)]

use persona_core::models::{Identity, IdentityType};
use persona_core::storage::{Database, IdentityRepository, Repository};
use tempfile::TempDir;

/// What a fixture hands back to the test.
pub struct TestDb {
    /// Keep alive for the duration of the test; dropping removes the files.
    pub _dir: TempDir,
    pub db: Database,
    pub identity: Identity,
}

/// Migrated temp database plus a seeded "Wallet Tester" identity.
///
/// Generalizes the per-test setup previously inlined in commands.rs wallet
/// tests; new command tests should start from here instead of rebuilding
/// the boilerplate.
pub async fn test_db() -> TestDb {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Database::from_file(db_path.to_str().unwrap())
        .await
        .unwrap();
    db.migrate().await.unwrap();

    let identity_repo = IdentityRepository::new(db.clone());
    let identity = identity_repo
        .create(&Identity::new(
            "Wallet Tester".to_string(),
            IdentityType::Personal,
        ))
        .await
        .unwrap();

    TestDb {
        _dir: dir,
        db,
        identity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db_creates_migrated_database_with_identity() {
        let fixture = test_db().await;

        let identities = IdentityRepository::new(fixture.db.clone())
            .find_all()
            .await
            .unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].name, "Wallet Tester");
    }
}
