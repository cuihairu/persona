use super::*;

#[test]
fn test_key_policy_host_restrictions() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();

    let key_policy = KeyPolicy {
        allowed_hosts: vec!["github.com".to_string(), "gitlab.com".to_string()],
        ..Default::default()
    };
    policy.key_policies.insert(cred_id.to_string(), key_policy);

    let mut enforcer = PolicyEnforcer::new(policy);

    // Allowed host
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));

    // Denied host
    let decision = enforcer
        .check_signature(&cred_id, Some("evil.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_glob_patterns() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();

    let key_policy = KeyPolicy {
        allowed_hosts: vec!["*.github.com".to_string()],
        ..Default::default()
    };
    policy.key_policies.insert(cred_id.to_string(), key_policy);

    let mut enforcer = PolicyEnforcer::new(policy);

    // Should match pattern
    let decision = enforcer
        .check_signature(&cred_id, Some("api.github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));

    // Should not match
    let decision = enforcer
        .check_signature(&cred_id, Some("github.io"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_enforce_known_hosts_denies_when_host_missing_or_absent() {
    let _guard = env_lock();
    let (_dir, path) = write_known_hosts("github.com ssh-ed25519 AAAA\n");
    std::env::set_var("PERSONA_KNOWN_HOSTS_FILE", &path);

    let mut policy = SigningPolicy::default();
    policy.global.enforce_known_hosts = true;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));

    let decision = enforcer
        .check_signature(&cred_id, Some("evil.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));

    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));

    std::env::remove_var("PERSONA_KNOWN_HOSTS_FILE");
}

#[test]
fn test_confirm_on_unknown_host_requires_confirmation() {
    let _guard = env_lock();
    let (_dir, path) = write_known_hosts("github.com ssh-ed25519 AAAA\n");
    std::env::set_var("PERSONA_KNOWN_HOSTS_FILE", &path);

    let mut policy = SigningPolicy::default();
    policy.global.confirm_on_unknown_host = true;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    // Known host: allowed
    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));

    // Unknown host: require confirm
    let decision = enforcer
        .check_signature(&cred_id, Some("evil.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::RequireConfirm { .. }));

    // Unknown host (None): require confirm
    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::RequireConfirm { .. }));

    std::env::remove_var("PERSONA_KNOWN_HOSTS_FILE");
}

#[test]
fn test_host_policy_allowed_keys_and_hourly_limit() {
    let mut policy = SigningPolicy::default();
    let host = "prod-1.company.com";

    let allowed_key = Uuid::new_v4();
    let denied_key = Uuid::new_v4();

    let host_policy = HostPolicy {
        allowed_keys: vec![allowed_key.to_string()],
        max_connections_per_hour: 1,
        ..Default::default()
    };
    policy
        .host_policies
        .insert("prod-*.company.com".to_string(), host_policy);

    let mut enforcer = PolicyEnforcer::new(policy);

    // Denied key due to allowed_keys restriction
    let decision = enforcer.check_signature(&denied_key, Some(host)).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));

    // Allowed key first time
    let decision = enforcer.check_signature(&allowed_key, Some(host)).unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));
    enforcer.record_signature(&allowed_key, Some(host));

    // Second time should exceed host hourly limit
    let decision = enforcer.check_signature(&allowed_key, Some(host)).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_host_policy_require_confirm() {
    let mut policy = SigningPolicy::default();
    policy.host_policies.insert(
        "prod-*.corp".to_string(),
        HostPolicy {
            require_confirm: true,
            ..Default::default()
        },
    );
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    let decision = enforcer
        .check_signature(&cred_id, Some("prod-7.corp"))
        .unwrap();
    match decision {
        SignatureDecision::RequireConfirm { reason } => {
            assert!(reason.contains("requires confirmation"))
        }
        other => panic!("expected RequireConfirm, got {:?}", other),
    }

    // Exact-match host policy takes precedence over the pattern policy:
    // rebuild with both entries and confirm the exact one wins.
    let mut policy = SigningPolicy::default();
    policy.host_policies.insert(
        "prod-*.corp".to_string(),
        HostPolicy {
            require_confirm: true,
            ..Default::default()
        },
    );
    policy.host_policies.insert(
        "prod-7.corp".to_string(),
        HostPolicy {
            enabled: true,
            ..Default::default()
        },
    );
    let mut enforcer = PolicyEnforcer::new(policy);
    let decision = enforcer
        .check_signature(&cred_id, Some("prod-7.corp"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));
}

#[test]
fn test_host_policy_glob_patterns_match_and_miss() {
    let mut policy = SigningPolicy::default();
    policy.host_policies.insert(
        "*.internal".to_string(),
        HostPolicy {
            require_confirm: true,
            ..Default::default()
        },
    );
    policy.host_policies.insert(
        "*.github.com".to_string(),
        HostPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    // A non-matching pattern is skipped; the matching glob disables.
    match enforcer
        .check_signature(&cred_id, Some("api.github.com"))
        .unwrap()
    {
        SignatureDecision::Denied { reason } => {
            assert!(reason.contains("disabled"), "{reason}")
        }
        other => panic!("expected Denied, got {:?}", other),
    }
    // The other glob asks for confirmation.
    match enforcer
        .check_signature(&cred_id, Some("build.internal"))
        .unwrap()
    {
        SignatureDecision::RequireConfirm { reason } => {
            assert!(reason.contains("requires confirmation"), "{reason}")
        }
        other => panic!("expected RequireConfirm, got {:?}", other),
    }
    // No pattern matches: the default policy allows.
    match enforcer
        .check_signature(&cred_id, Some("example.org"))
        .unwrap()
    {
        SignatureDecision::Allowed => {}
        other => panic!("expected Allowed, got {:?}", other),
    }
}
