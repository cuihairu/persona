use super::*;

#[test]
fn test_composite_conditions() {
    let strategy = SecurityStrategy::new(
        "High Risk Location Lock".to_string(),
        SecurityCategory::LocationBased,
        RiskLevel::Critical,
    )
    .with_condition(SecurityCondition::CompositeCondition {
        operator: LogicalOperator::And,
        conditions: vec![
            SecurityCondition::LocationCondition {
                location: "Unknown".to_string(),
                trusted_locations: vec!["Office".to_string(), "Home".to_string()],
            },
            SecurityCondition::NetworkCondition {
                network: "Public WiFi".to_string(),
                connection_type: "WiFi".to_string(),
                is_vpn: false,
                is_encrypted: false,
            },
        ],
    });

    assert_eq!(strategy.conditions.len(), 1);
    if let SecurityCondition::CompositeCondition { conditions, .. } = &strategy.conditions[0] {
        assert_eq!(conditions.len(), 2);
    }
}

#[test]
fn test_time_rules_evaluate_against_context() {
    let context = context_at("Office");

    // Numeric rules compare against the context fields (strict >).
    assert!(triggers(
        SecurityCondition::TimeCondition {
            time_rule: TimeRule::SessionDurationExceeds { limit_secs: 1800 },
        },
        &context,
    ));
    assert!(!triggers(
        SecurityCondition::TimeCondition {
            time_rule: TimeRule::SessionDurationExceeds { limit_secs: 3600 },
        },
        &context,
    ));
    assert!(triggers(
        SecurityCondition::TimeCondition {
            time_rule: TimeRule::DailyUsageExceeds { limit_secs: 3600 },
        },
        &context,
    ));
    assert!(!triggers(
        SecurityCondition::TimeCondition {
            time_rule: TimeRule::DailyUsageExceeds { limit_secs: 7200 },
        },
        &context,
    ));
    assert!(triggers(
        SecurityCondition::TimeCondition {
            time_rule: TimeRule::InactivityExceeds {
                threshold_secs: 120
            },
        },
        &context,
    ));
    assert!(!triggers(
        SecurityCondition::TimeCondition {
            time_rule: TimeRule::InactivityExceeds {
                threshold_secs: 300
            },
        },
        &context,
    ));

    // Calendar rules are placeholders that never fire yet.
    for rule in [
        TimeRule::IsRestrictedHours,
        TimeRule::IsWeekend,
        TimeRule::IsHoliday,
    ] {
        assert!(
            !triggers(
                SecurityCondition::TimeCondition { time_rule: rule },
                &context,
            ),
            "placeholder rule must not trigger"
        );
    }
}

#[test]
fn test_behavioral_condition_thresholds() {
    let context = context_at("Office");
    let behavioral =
        |risk: f64, anomaly: bool, deviation: f64| SecurityCondition::BehavioralCondition {
            risk_score: risk,
            anomaly_detected: anomaly,
            pattern_deviation: deviation,
        };

    // Default threshold is 0.5.
    assert!(triggers(behavioral(0.6, false, 0.0), &context));
    assert!(!triggers(behavioral(0.4, false, 0.4), &context));
    // An anomaly alone trips the condition regardless of score.
    assert!(triggers(behavioral(0.0, true, 0.0), &context));
    assert!(triggers(behavioral(0.0, false, 0.7), &context));

    // A configured threshold overrides the default.
    let mut strategy = SecurityStrategy::new(
        "Strict Behavior".to_string(),
        SecurityCategory::Behavioral,
        RiskLevel::High,
    )
    .with_condition(behavioral(0.6, false, 0.0));
    strategy.configuration.behavioral_settings = Some(BehavioralSettings {
        anomaly_detection: true,
        typing_analysis: false,
        mouse_pattern_analysis: false,
        access_pattern_analysis: true,
        risk_score_threshold: 0.9,
        learning_period_days: 14,
        baseline_update_frequency_hours: 24,
    });
    assert!(!strategy.should_trigger(&context));

    // ...but a detected anomaly still trips it.
    let mut strategy = strategy.clone();
    strategy.conditions = vec![behavioral(0.6, true, 0.0)];
    assert!(strategy.should_trigger(&context));
}

#[test]
fn test_device_and_network_conditions() {
    let context = context_at("Office");

    assert!(triggers(
        SecurityCondition::DeviceCondition {
            device_id: "device789".to_string(),
            trusted: true,
            device_type: "laptop".to_string(),
        },
        &context,
    ));
    assert!(!triggers(
        SecurityCondition::DeviceCondition {
            device_id: "device789".to_string(),
            trusted: false,
            device_type: "laptop".to_string(),
        },
        &context,
    ));

    assert!(triggers(
        SecurityCondition::NetworkCondition {
            network: "Corporate LAN".to_string(),
            connection_type: "wired".to_string(),
            is_vpn: false,
            is_encrypted: true,
        },
        &context,
    ));
    assert!(!triggers(
        SecurityCondition::NetworkCondition {
            network: "Public WiFi".to_string(),
            connection_type: "wifi".to_string(),
            is_vpn: false,
            is_encrypted: false,
        },
        &context,
    ));
}

#[test]
fn test_composite_or_not_and_custom_conditions() {
    let context = context_at("Office");
    // Matching depends on the context's location being trusted, so a
    // condition whose trust list excludes "Office" never fires.
    let office = SecurityCondition::LocationCondition {
        location: "Office".to_string(),
        trusted_locations: vec!["Office".to_string()],
    };
    let cafe = SecurityCondition::LocationCondition {
        location: "Cafe".to_string(),
        trusted_locations: vec!["Vault".to_string()],
    };

    // Or: at least one matching sub-condition.
    assert!(triggers(
        SecurityCondition::CompositeCondition {
            operator: LogicalOperator::Or,
            conditions: vec![cafe.clone(), office.clone()],
        },
        &context,
    ));
    assert!(!triggers(
        SecurityCondition::CompositeCondition {
            operator: LogicalOperator::Or,
            conditions: vec![cafe.clone()],
        },
        &context,
    ));

    // Not: negates the first sub-condition only.
    assert!(triggers(
        SecurityCondition::CompositeCondition {
            operator: LogicalOperator::Not,
            conditions: vec![cafe.clone()],
        },
        &context,
    ));
    assert!(!triggers(
        SecurityCondition::CompositeCondition {
            operator: LogicalOperator::Not,
            conditions: vec![office.clone()],
        },
        &context,
    ));
    // Not over an empty list is vacuously true.
    assert!(triggers(
        SecurityCondition::CompositeCondition {
            operator: LogicalOperator::Not,
            conditions: vec![],
        },
        &context,
    ));

    // Custom conditions need external evaluation and never fire.
    assert!(!triggers(
        SecurityCondition::CustomCondition {
            name: "external".to_string(),
            parameters: HashMap::new(),
        },
        &context,
    ));
}
