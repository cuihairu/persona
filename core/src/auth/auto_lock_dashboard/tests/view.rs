use super::*;

#[tokio::test]
async fn test_default_view() {
    let session_manager = Arc::new(CachedAutoLockManager::new(
        crate::auth::EnhancedAutoLockConfig::default(),
    ));

    let dashboard = AutoLockDashboard::new(session_manager);
    let view = dashboard.create_default_view();

    assert_eq!(view.name, "Auto-Lock Overview");
    assert_eq!(view.components.len(), 4);
    assert_eq!(view.auto_refresh_interval_secs, 30);
}

#[tokio::test]
async fn test_dashboard_view_lookup() {
    let session_manager = Arc::new(CachedAutoLockManager::new(
        crate::auth::EnhancedAutoLockConfig::default(),
    ));
    let dashboard = AutoLockDashboard::new(session_manager);

    // The nil UUID resolves to the default view.
    let view = dashboard
        .get_dashboard_view(&Uuid::nil())
        .await
        .expect("nil UUID must yield the default view");
    assert_eq!(view.name, "Auto-Lock Overview");

    // Any other id has no persisted view yet.
    assert!(dashboard
        .get_dashboard_view(&Uuid::new_v4())
        .await
        .is_none());
}
