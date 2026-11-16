use super::*;

#[tokio::test]
async fn test_notification_settings() {
    let session_manager = Arc::new(CachedAutoLockManager::new(
        crate::auth::EnhancedAutoLockConfig::default(),
    ));

    let dashboard = AutoLockDashboard::new(session_manager);

    let settings = dashboard.get_notification_settings().await;
    assert!(settings.desktop_notifications);
    assert!(!settings.email_notifications);

    // Update settings
    let new_settings = NotificationSettings {
        desktop_notifications: false,
        email_notifications: true,
        webhook_notifications: false,
        thresholds: settings.thresholds.clone(),
        quiet_hours: None,
    };

    dashboard.update_notification_settings(new_settings).await;

    let updated_settings = dashboard.get_notification_settings().await;
    assert!(!updated_settings.desktop_notifications);
    assert!(updated_settings.email_notifications);
}
