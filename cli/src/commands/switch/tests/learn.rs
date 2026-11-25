use super::{config_for, ensure_workspace_row, seeded_db, switch_args};
use crate::commands::switch::execute;
use crate::commands::switch::flow::execute_with_reason;
use crate::utils::prompt::scripted::ScriptedUi;
use persona_core::models::AuditAction;
use tempfile::TempDir;

/// Phase 2 learning records: with the toggle off (the default) → switch produces no learning
/// row; on → a record appears under the same directory hash; a learning failure does not
/// block the switch (degradation principle).
#[tokio::test]
async fn switch_records_learn_sample_only_when_enabled() {
    use persona_core::context::cwd_hash;
    use persona_core::storage::ContextLearnRepository;

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "bob"]).await;
    ensure_workspace_row(&db, &config).await;

    execute(switch_args(Some("alice"), true), &config)
        .await
        .expect("switch with learning off succeeds");
    {
        let learn = ContextLearnRepository::new(db.clone());
        assert!(!learn.learn_enabled().await.unwrap());
        assert_eq!(learn.record_count().await.unwrap(), 0, "off means no rows");
    }

    {
        let learn = ContextLearnRepository::new(db.clone());
        learn.set_learn_enabled(true).await.unwrap();
    }
    execute(switch_args(Some("bob"), true), &config)
        .await
        .expect("switch with learning on succeeds");
    let learn = ContextLearnRepository::new(db.clone());
    let hash = cwd_hash(&config.workspace.path);
    let counts = learn
        .counts_since(&hash, chrono::Utc::now() - chrono::Duration::days(30))
        .await
        .unwrap();
    assert_eq!(counts, vec![("bob".to_string(), 1)]);
    // already-active switch short-circuits before perform_switch → no row.
    execute(switch_args(Some("bob"), true), &config)
        .await
        .expect("already-active no-op");
    assert_eq!(learn.record_count().await.unwrap(), 1);
}

/// `persona use`: when the target is the current top suggestion the audit carries the
/// reason; when the target is not a candidate it is still an ordinary switch (no reason in
/// the audit); the learning row is stored as usual.
#[tokio::test]
async fn use_confirming_top_suggestion_audits_reason() {
    use persona_core::storage::{AuditLogRepository, ContextLearnRepository};
    use std::path::PathBuf;

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let db = seeded_db(&dir, &["alice", "clienta"]).await;
    ensure_workspace_row(&db, &config).await;
    {
        let learn = ContextLearnRepository::new(db.clone());
        learn.set_learn_enabled(true).await.unwrap();
    }

    // The in-repo mapping points this directory to clienta — persona use clienta is therefore a confirmation.
    let map_path = dir.path().join(".persona").join("context.toml");
    std::fs::create_dir_all(map_path.parent().unwrap()).unwrap();
    std::fs::write(
        &map_path,
        "[project.\"github.com/other/repo\"]\nidentity = \"clienta\"\n",
    )
    .unwrap();

    // The top suggestion is indeed clienta (it matches the use target → the audit carries the reason).
    let signals = persona_core::context::ContextSignals {
        cwd: config.workspace.path.clone(),
        repo: Some("github.com/other/repo".to_string()),
        host: None,
    };
    let paths = crate::commands::suggest::MapPaths {
        global: PathBuf::from("/nonexistent-global.toml"),
        repo_local: map_path.clone(),
    };
    let result = crate::commands::suggest::compute_suggestion(&config, &paths, &signals, None)
        .await
        .unwrap();
    assert_eq!(result.candidates[0].identity, "clienta");

    // execute_use goes through execute_with_reason → perform_switch.
    execute_with_reason(
        switch_args(Some("clienta"), true),
        &config,
        &ScriptedUi::new(),
        Some(("clienta".to_string(), result.candidates[0].reason.clone())),
    )
    .await
    .expect("use-confirm succeeds");

    let audits = AuditLogRepository::new(db.clone())
        .find_by_action(&AuditAction::WorkspaceEntered)
        .await
        .unwrap();
    assert_eq!(audits.len(), 1);
    assert!(
        audits[0]
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("confirmed context suggestion: repo github.com/other/repo"),
        "audit must carry the suggestion reason, got: {:?}",
        audits[0].error_message
    );

    // The target is not the top suggestion → an ordinary switch with no reason.
    execute_with_reason(
        switch_args(Some("alice"), true),
        &config,
        &ScriptedUi::new(),
        Some((
            "clienta".to_string(),
            "repo github.com/other/repo".to_string(),
        )),
    )
    .await
    .expect("non-matching suggestion still switches");
    let audits = AuditLogRepository::new(db.clone())
        .find_by_action(&AuditAction::WorkspaceEntered)
        .await
        .unwrap();
    assert_eq!(audits.len(), 2);
    assert!(
        audits[0].error_message.is_none(),
        "mismatched suggestion leaves no reason"
    );

    // Learning rows: both confirmations entered the same-directory learning table.
    let learn = ContextLearnRepository::new(db.clone());
    let counts = learn
        .counts_since(
            &persona_core::context::cwd_hash(&config.workspace.path),
            chrono::Utc::now() - chrono::Duration::days(30),
        )
        .await
        .unwrap();
    assert!(counts.iter().any(|(name, _)| name == "clienta"));
    assert!(counts.iter().any(|(name, _)| name == "alice"));
}
