use super::*;

#[test]
fn test_execute_all_action_kinds_mutates_context() {
    let strategy = SecurityStrategy::new(
        "Kitchen Sink".to_string(),
        SecurityCategory::Custom,
        RiskLevel::Medium,
    )
    .with_action(SecurityAction::LockSession {
        reason: "policy".to_string(),
        duration_secs: None,
    })
    .with_action(SecurityAction::ExtendTimeout {
        extension_secs: 300,
        reason: "long task".to_string(),
    })
    .with_action(SecurityAction::RequireReauth {
        method: AuthMethod::TwoFactor,
        message: "verify".to_string(),
    })
    .with_action(SecurityAction::Notify {
        recipients: vec!["admin".to_string()],
        message: "suspicious activity".to_string(),
        severity: NotificationSeverity::Warning,
    })
    .with_action(SecurityAction::LogEvent {
        category: "audit".to_string(),
        details: HashMap::new(),
        severity: EventSeverity::Low,
    })
    .with_action(SecurityAction::RestrictFunctionality {
        restricted_features: vec!["export".to_string(), "sharing".to_string()],
        reason: "least privilege".to_string(),
    })
    .with_action(SecurityAction::CustomAction {
        name: "rotate-keys".to_string(),
        parameters: HashMap::new(),
    });

    let mut context = context_at("Office");
    let results = strategy.execute_actions(&mut context);

    assert_eq!(results.len(), 7);
    assert_eq!(results[0], "Session locked: policy");
    assert_eq!(results[1], "Timeout extended by 300s: long task");
    assert_eq!(
        results[2],
        "Re-authentication required (two_factor): verify"
    );
    assert_eq!(results[3], "Notification sent: suspicious activity");
    assert_eq!(results[4], "Security event logged: audit");
    assert_eq!(
        results[5],
        "Functionality restricted: least privilege - export, sharing"
    );
    assert_eq!(results[6], "Custom action executed: rotate-keys");

    // Every action left its mark on the context.
    assert!(context.session_locked);
    assert_eq!(context.session_timeout_extended_by, 300);
    assert!(context.reauth_required);
    assert_eq!(context.reauth_method, Some(AuthMethod::TwoFactor));
    assert_eq!(context.notifications.len(), 1);
    assert_eq!(
        context.notifications[0],
        (
            "suspicious activity".to_string(),
            NotificationSeverity::Warning
        )
    );
    assert_eq!(context.security_events.len(), 1);
    assert_eq!(context.restricted_features, ["export", "sharing"]);
}

#[test]
fn test_auth_method_display() {
    assert_eq!(AuthMethod::Password.to_string(), "password");
    assert_eq!(AuthMethod::Biometric.to_string(), "biometric");
    assert_eq!(AuthMethod::TwoFactor.to_string(), "two_factor");
    assert_eq!(AuthMethod::SecurityKey.to_string(), "security_key");
    assert_eq!(AuthMethod::SmartCard.to_string(), "smart_card");
    assert_eq!(
        AuthMethod::Custom("yubikey-otp".to_string()).to_string(),
        "custom:yubikey-otp"
    );
}
