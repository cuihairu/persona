use super::*;

#[test]
fn test_default_policy_allows() {
    let mut enforcer = PolicyEnforcer::new(SigningPolicy::default());
    let cred_id = Uuid::new_v4();

    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));
}

#[test]
fn test_deny_all_lockdown() {
    let mut policy = SigningPolicy::default();
    policy.global.deny_all = true;

    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_global_require_confirm() {
    let mut policy = SigningPolicy::default();
    policy.global.require_confirm = true;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::RequireConfirm { .. }));
}

#[test]
fn test_key_specific_require_confirm() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();
    let key_policy = KeyPolicy {
        require_confirm: true,
        ..Default::default()
    };
    policy.key_policies.insert(cred_id.to_string(), key_policy);

    let mut enforcer = PolicyEnforcer::new(policy);
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::RequireConfirm { .. }));
}

#[test]
fn test_key_specific_require_biometric_takes_precedence_over_confirm() {
    let mut policy = SigningPolicy::default();
    policy.global.require_confirm = true;

    let cred_id = Uuid::new_v4();
    let key_policy = KeyPolicy {
        require_confirm: true,
        require_biometric: true,
        ..Default::default()
    };
    policy.key_policies.insert(cred_id.to_string(), key_policy);

    let mut enforcer = PolicyEnforcer::new(policy);
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(
        decision,
        SignatureDecision::RequireBiometric { .. }
    ));
}

#[test]
fn test_key_policy_denied_hosts_takes_precedence_over_allowed_hosts() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();

    let key_policy = KeyPolicy {
        allowed_hosts: vec!["github.com".to_string()],
        denied_hosts: vec!["github.com".to_string()],
        ..Default::default()
    };
    policy.key_policies.insert(cred_id.to_string(), key_policy);

    let mut enforcer = PolicyEnforcer::new(policy);
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_disabled_key_and_host_are_denied() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();
    policy.key_policies.insert(
        cred_id.to_string(),
        KeyPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut enforcer = PolicyEnforcer::new(policy);
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    match decision {
        SignatureDecision::Denied { reason } => assert!(reason.contains("Key is disabled")),
        other => panic!("expected Denied, got {:?}", other),
    }

    let mut policy = SigningPolicy::default();
    policy.host_policies.insert(
        "github.com".to_string(),
        HostPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    match decision {
        SignatureDecision::Denied { reason } => assert!(reason.contains("is disabled")),
        other => panic!("expected Denied, got {:?}", other),
    }
}

#[test]
fn test_invalid_time_range_allows_by_default() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();
    policy.key_policies.insert(
        cred_id.to_string(),
        KeyPolicy {
            allowed_time_range: Some("garbage".to_string()),
            ..Default::default()
        },
    );
    let mut enforcer = PolicyEnforcer::new(policy);
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));
}

#[test]
fn test_is_within_time_range_invalid_formats_allow() {
    let enforcer = PolicyEnforcer::new(SigningPolicy::default());
    // Malformed ranges (wrong arity, unparsable times) allow by default.
    assert!(enforcer.is_within_time_range("09:00"));
    assert!(enforcer.is_within_time_range(""));
    assert!(enforcer.is_within_time_range("25:00-99:00"));
    // An overnight range spanning the whole day (start > end with
    // now >= start || now <= end) is always satisfied.
    assert!(enforcer.is_within_time_range("12:00-11:59"));
}
