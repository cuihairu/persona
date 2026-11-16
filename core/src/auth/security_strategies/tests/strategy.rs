use super::*;

#[test]
fn test_security_strategy_creation() {
    let strategy = SecurityStrategy::new(
        "After Hours Lock".to_string(),
        SecurityCategory::TimeBased,
        RiskLevel::High,
    )
    .with_condition(SecurityCondition::TimeCondition {
        time_rule: TimeRule::IsRestrictedHours,
    })
    .with_action(SecurityAction::LockSession {
        reason: "Access outside business hours".to_string(),
        duration_secs: None,
    });

    assert_eq!(strategy.name, "After Hours Lock");
    assert_eq!(strategy.category, SecurityCategory::TimeBased);
    assert_eq!(strategy.risk_level, RiskLevel::High);
    assert_eq!(strategy.conditions.len(), 1);
    assert_eq!(strategy.actions.len(), 1);
}

#[test]
fn test_risk_level_ordering() {
    assert!(RiskLevel::Critical > RiskLevel::High);
    assert!(RiskLevel::High > RiskLevel::Medium);
    assert!(RiskLevel::Medium > RiskLevel::Low);
    assert!(RiskLevel::Low > RiskLevel::Minimal);
}

#[test]
fn test_security_context() {
    let context = SecurityContext {
        user_id: "user123".to_string(),
        session_id: "session456".to_string(),
        location: "Office".to_string(),
        device_id: "device789".to_string(),
        network: "Corporate LAN".to_string(),
        current_time: chrono::Utc::now(),
        session_duration_secs: 3600,
        daily_usage_secs: 7200,
        inactivity_duration_secs: 300,
        risk_score: 0.2,
        session_locked: false,
        session_timeout_extended_by: 0,
        reauth_required: false,
        reauth_method: None,
        notifications: Vec::new(),
        security_events: Vec::new(),
        restricted_features: Vec::new(),
    };

    assert_eq!(context.user_id, "user123");
    assert_eq!(context.session_duration_secs, 3600);
    assert_eq!(context.risk_score, 0.2);
    assert!(!context.session_locked);
}

#[test]
fn test_disabled_strategy_and_priority_builder() {
    let context = context_at("Office");
    let always_matching = SecurityCondition::DeviceCondition {
        device_id: "device789".to_string(),
        trusted: true,
        device_type: "laptop".to_string(),
    };

    let strategy = SecurityStrategy::new(
        "Disabled".to_string(),
        SecurityCategory::Custom,
        RiskLevel::Low,
    )
    .with_condition(always_matching)
    .with_priority(80)
    .with_enabled(false);

    assert_eq!(strategy.priority, 80);
    assert!(!strategy.enabled);
    assert!(
        !strategy.should_trigger(&context),
        "disabled never triggers"
    );

    // Re-enabling lets the same condition fire again.
    let strategy = strategy.with_enabled(true);
    assert!(strategy.should_trigger(&context));
}
