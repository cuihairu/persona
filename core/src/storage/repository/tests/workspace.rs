use super::*;

#[tokio::test]
async fn workspace_repository_legacy_schema_round_trip() {
    let db = test_db().await;
    // The shipped migrations ship the v2 layout; rebuild the pre-v2 table
    // (no path/settings columns) to exercise the legacy code paths.
    rebuild_workspaces_table(
        &db,
        r#"
            CREATE TABLE workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1
            )
            "#,
    )
    .await;
    let repo = WorkspaceRepository::new(db.clone());

    assert!(!repo.has_workspace_v2().await.unwrap());

    let mut ws = Workspace::new("/tmp/legacy-ws", "legacy".to_string());
    repo.create(&ws).await.unwrap();

    let by_id = repo.find_by_id(&ws.id).await.unwrap().unwrap();
    assert_eq!(by_id.name, "legacy");
    assert_eq!(by_id.path, std::path::PathBuf::from("."));

    let by_path = repo.find_by_path("legacy").await.unwrap().unwrap();
    assert_eq!(by_path.id, ws.id);
    assert!(repo.find_by_path("missing").await.unwrap().is_none());

    ws.name = "legacy renamed".to_string();
    ws.touch();
    repo.update(&ws).await.unwrap();
    assert_eq!(repo.find_all().await.unwrap()[0].name, "legacy renamed");

    assert!(repo.delete(&ws.id).await.unwrap());
    assert!(!repo.delete(&ws.id).await.unwrap());
}

#[tokio::test]
async fn workspace_repository_v2_schema_round_trip() {
    let db = test_db().await;
    // The shipped migrations already carry the v2 layout (path/settings).
    let repo = WorkspaceRepository::new(db);
    assert!(repo.has_workspace_v2().await.unwrap());

    let mut ws = Workspace::new("/tmp/v2-ws", "v2".to_string());
    ws.settings.session_timeout_seconds = 1234;
    repo.create(&ws).await.unwrap();

    let identity_id = Uuid::new_v4();
    ws.active_identity_id = Some(identity_id);
    ws.name = "v2 renamed".to_string();
    ws.touch();
    repo.update(&ws).await.unwrap();

    let by_id = repo.find_by_id(&ws.id).await.unwrap().unwrap();
    assert_eq!(by_id.name, "v2 renamed");
    assert_eq!(by_id.path, std::path::PathBuf::from("/tmp/v2-ws"));
    assert_eq!(by_id.active_identity_id, Some(identity_id));
    assert_eq!(by_id.settings.session_timeout_seconds, 1234);

    let by_path = repo.find_by_path("/tmp/v2-ws").await.unwrap().unwrap();
    assert_eq!(by_path.id, ws.id);
    assert_eq!(repo.find_all().await.unwrap().len(), 1);
}

#[tokio::test]
async fn workspace_create_persists_active_identity() {
    let db = test_db().await;
    let repo = WorkspaceRepository::new(db);

    let mut ws = Workspace::new("/tmp/v2-active", "active".to_string());
    ws.active_identity_id = Some(Uuid::new_v4());
    repo.create(&ws).await.unwrap();

    let fetched = repo.find_by_id(&ws.id).await.unwrap().unwrap();
    assert_eq!(fetched.active_identity_id, ws.active_identity_id);
}
