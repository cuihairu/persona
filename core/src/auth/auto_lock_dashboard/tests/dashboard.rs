use super::*;

#[tokio::test]
async fn test_dashboard_creation() {
    let session_manager = Arc::new(CachedAutoLockManager::new(
        crate::auth::EnhancedAutoLockConfig::default(),
    ));

    let dashboard = AutoLockDashboard::new(session_manager);

    let metrics = dashboard.get_metrics().await;
    assert_eq!(metrics.active_sessions, 0); // No sessions initially

    let events = dashboard.get_active_events().await;
    assert!(events.is_empty()); // No events initially
}

#[tokio::test]
async fn test_initialize_registers_strategies_and_all_reports() {
    let session_manager = Arc::new(CachedAutoLockManager::new(
        crate::auth::EnhancedAutoLockConfig::default(),
    ));
    let dashboard = AutoLockDashboard::new(session_manager);

    dashboard.initialize().await.unwrap();

    // The security report counts the two default strategies.
    let report = dashboard.generate_report(ReportType::Security).await;
    assert!(matches!(
        report.content,
        ReportContent::Security {
            active_strategies: 2,
            ..
        }
    ));

    let summary = dashboard.generate_report(ReportType::Summary).await;
    assert!(matches!(summary.content, ReportContent::Summary { .. }));
    assert_eq!(summary.report_type, ReportType::Summary);

    let performance = dashboard.generate_report(ReportType::Performance).await;
    assert!(matches!(
        performance.content,
        ReportContent::Performance { .. }
    ));

    let compliance = dashboard.generate_report(ReportType::Compliance).await;
    assert!(matches!(
        compliance.content,
        ReportContent::Compliance { .. }
    ));
}

#[tokio::test]
async fn test_evaluate_security_strategies_triggers_and_sorts() {
    use crate::auth::security_strategies::{
        EventSeverity, RiskLevel, SecurityAction, SecurityCategory, SecurityCondition,
    };

    let session_manager = Arc::new(CachedAutoLockManager::new(
        crate::auth::EnhancedAutoLockConfig::default(),
    ));
    // No default strategies here: they carry empty condition lists and
    // would trigger on every context, muddying the assertions.
    let dashboard = AutoLockDashboard::new(session_manager);

    // A triggering strategy at medium risk that locks the session.
    let triggering = SecurityStrategy::new(
        "Office Lock".to_string(),
        SecurityCategory::LocationBased,
        RiskLevel::Medium,
    )
    .with_condition(SecurityCondition::LocationCondition {
        location: "Office".to_string(),
        trusted_locations: vec!["Office".to_string()],
    })
    .with_action(SecurityAction::LockSession {
        reason: "office policy".to_string(),
        duration_secs: None,
    })
    .with_action(SecurityAction::LogEvent {
        category: "policy".to_string(),
        details: HashMap::new(),
        severity: EventSeverity::Low,
    });

    // A triggering strategy at critical risk (should sort first).
    let critical = SecurityStrategy::new(
        "Critical Lock".to_string(),
        SecurityCategory::LocationBased,
        RiskLevel::Critical,
    )
    .with_condition(SecurityCondition::LocationCondition {
        location: "Headquarters".to_string(),
        trusted_locations: vec!["Office".to_string()],
    });

    // Strategies whose conditions never match for this context: a
    // location outside its trust list and an untrusted device.
    let dormant = SecurityStrategy::new(
        "Dormant".to_string(),
        SecurityCategory::LocationBased,
        RiskLevel::Critical,
    )
    .with_condition(SecurityCondition::LocationCondition {
        location: "Vault".to_string(),
        trusted_locations: vec!["Vault".to_string()],
    });
    let untrusted_device = SecurityStrategy::new(
        "BYOD Lock".to_string(),
        SecurityCategory::DeviceBased,
        RiskLevel::Critical,
    )
    .with_condition(SecurityCondition::DeviceCondition {
        device_id: "device789".to_string(),
        trusted: false,
        device_type: "laptop".to_string(),
    });

    dashboard.add_security_strategy(triggering).await;
    dashboard.add_security_strategy(critical).await;
    dashboard.add_security_strategy(dormant).await;
    dashboard.add_security_strategy(untrusted_device).await;

    let mut results = dashboard
        .evaluate_security_strategies(&sample_context("Office"))
        .await;
    assert_eq!(results.len(), 2, "only the two matching strategies fire");
    assert_eq!(
        results[0].0.name, "Critical Lock",
        "critical risk sorts first"
    );
    assert_eq!(results[1].0.name, "Office Lock");

    // The office strategy ran both of its actions.
    let (_, actions) = results.pop().expect("office strategy present");
    assert_eq!(actions.len(), 2);
    assert!(actions[0].contains("Session locked"));

    // A context outside every condition triggers nothing.
    let none = dashboard
        .evaluate_security_strategies(&sample_context("Cafe"))
        .await;
    assert!(none.is_empty(), "no strategy should fire, got {none:?}");
}

#[tokio::test]
async fn test_events_recorded_and_acknowledged() {
    let config = crate::auth::EnhancedAutoLockConfig {
        base: crate::auth::AutoLockConfig {
            inactivity_timeout_secs: 3600, // keep the idle arm quiet
            ..Default::default()
        },
        enable_warnings: false,
        ..Default::default()
    };
    let manager = Arc::new(CachedAutoLockManager::new(config));
    let dashboard = AutoLockDashboard::new(Arc::clone(&manager));

    dashboard.initialize_default_strategies().await.unwrap();
    dashboard.register_event_listeners().await.unwrap();

    // Fast monitoring loop plus an already-expired session.
    manager
        .start_background_monitoring_with_interval(Duration::from_millis(10))
        .await
        .unwrap();
    let session = crate::auth::Session::new("user123".to_string(), Duration::from_secs(0));
    manager.add_session(session).await.unwrap();

    // The dashboard's log fills with the add-session Activity event
    // first; keep polling until the background loop's Locked event lands.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let events = loop {
        let events = dashboard.get_active_events().await;
        if events
            .iter()
            .any(|e| matches!(e.event_type, AutoLockEvent::Locked { .. }))
        {
            break events;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "lock event was never recorded"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let record = events
        .iter()
        .find(|e| matches!(e.event_type, AutoLockEvent::Locked { .. }))
        .expect("locked event present");
    assert!(matches!(record.event_type, AutoLockEvent::Locked { .. }));
    assert!(!record.acknowledged);

    // Acknowledging works exactly once per id, and unknown ids fail.
    assert!(dashboard.acknowledge_event(&record.id).await);
    assert!(!dashboard.acknowledge_event(&Uuid::new_v4()).await);

    manager.stop_background_monitoring().await;
}

#[tokio::test]
async fn test_metrics_reflect_session_activity() {
    let session_manager = Arc::new(CachedAutoLockManager::new(
        crate::auth::EnhancedAutoLockConfig::default(),
    ));
    let dashboard = AutoLockDashboard::new(session_manager.clone());

    let session = crate::auth::Session::new("user123".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    session_manager.add_session(session).await.unwrap();

    // A single valid lookup: one hit, no misses.
    assert!(session_manager.is_session_valid(&session_id).await);

    let metrics = dashboard.get_metrics().await;
    assert_eq!(metrics.active_sessions, 1);
    assert_eq!(metrics.performance.cache_hit_ratio, 1.0);
    assert!(metrics.performance.memory_usage_mb >= 0.0);
    // All-hits lookups are fast: the health score takes the top branch.
    assert_eq!(metrics.system_health.health_score, 90);
    assert_eq!(
        metrics.system_health.auto_lock_service_status,
        ServiceStatus::Healthy
    );
}
