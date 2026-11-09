use super::*;

#[tokio::test]
async fn test_change_history_surface() {
    let (_db, service) = unlocked_service().await;

    let entity_id = Uuid::new_v4();
    service
        .change_history_repo
        .record(&ChangeHistory::new(
            EntityType::Identity,
            entity_id,
            crate::models::ChangeType::Created,
        ))
        .await
        .unwrap();

    let history = service
        .get_entity_history(EntityType::Identity, &entity_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);

    let version = service
        .get_entity_version(EntityType::Identity, &entity_id, 1)
        .await
        .unwrap();
    assert!(version.is_some());
    assert!(service
        .get_entity_version(EntityType::Identity, &entity_id, 99)
        .await
        .unwrap()
        .is_none());

    let queried = service
        .query_change_history(
            &ChangeHistoryQuery::new()
                .entity_type(EntityType::Identity)
                .entity_id(entity_id),
        )
        .await
        .unwrap();
    assert_eq!(queried.len(), 1);

    let stats = service.get_change_history_stats().await.unwrap();
    assert!(stats.total_changes >= 1);

    // A cutoff in the future removes everything recorded so far.
    let removed = service
        .cleanup_old_history(chrono::Utc::now() + chrono::Duration::days(1))
        .await
        .unwrap();
    assert_eq!(removed, 1);
    assert!(service
        .get_entity_history(EntityType::Identity, &entity_id)
        .await
        .unwrap()
        .is_empty());
}
