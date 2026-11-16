use super::*;

#[test]
fn test_from_file_loads_toml_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent-policy.toml");
    std::fs::write(
        &path,
        r#"
[global]
deny_all = true

[[key_policies.invalid-placeholder]]
"#,
    )
    .unwrap();

    // HashMap<String, KeyPolicy> cannot be expressed as [[...]] arrays;
    // use an inline table instead.
    std::fs::write(
        &path,
        r#"
[global]
deny_all = true

[key_policies.some-key]
require_biometric = true
max_uses_per_day = 3

[host_policies."*.example.com"]
enabled = false
"#,
    )
    .unwrap();

    let mut enforcer = PolicyEnforcer::from_file(&path).unwrap();
    let cred_id = Uuid::new_v4();
    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_from_file_missing_file_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("does-not-exist.toml");
    assert!(PolicyEnforcer::from_file(&path).is_err());
}

#[test]
fn test_from_env_reads_policy_file_first() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent-policy.toml");
    std::fs::write(&path, "[global]\ndeny_all = true\n").unwrap();
    std::env::set_var("PERSONA_AGENT_POLICY_FILE", &path);
    let mut enforcer = PolicyEnforcer::from_env();
    std::env::remove_var("PERSONA_AGENT_POLICY_FILE");

    let cred_id = Uuid::new_v4();
    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_from_env_parses_environment_toggles() {
    let _guard = env_lock();
    std::env::remove_var("PERSONA_AGENT_POLICY_FILE");
    std::env::set_var("PERSONA_AGENT_REQUIRE_CONFIRM", "true");
    std::env::set_var("PERSONA_AGENT_MIN_INTERVAL_MS", "60000");
    std::env::set_var("PERSONA_AGENT_ENFORCE_KNOWN_HOSTS", "0");
    std::env::set_var("PERSONA_AGENT_CONFIRM_ON_UNKNOWN", "1");

    let enforcer = PolicyEnforcer::from_env();
    assert!(enforcer.policy.global.require_confirm);
    assert_eq!(enforcer.policy.global.min_interval_ms, 60000);
    assert!(!enforcer.policy.global.enforce_known_hosts);
    assert!(enforcer.policy.global.confirm_on_unknown_host);

    std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");
    std::env::remove_var("PERSONA_AGENT_MIN_INTERVAL_MS");
    std::env::remove_var("PERSONA_AGENT_ENFORCE_KNOWN_HOSTS");
    std::env::remove_var("PERSONA_AGENT_CONFIRM_ON_UNKNOWN");
}

#[test]
fn test_from_env_falls_back_when_policy_file_is_invalid() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken-policy.toml");
    std::fs::write(&path, "this is = not valid toml [[[").unwrap();
    std::env::set_var("PERSONA_AGENT_POLICY_FILE", &path);

    // Unparseable file -> from_file fails -> fall through to env parsing.
    let enforcer = PolicyEnforcer::from_env();
    std::env::remove_var("PERSONA_AGENT_POLICY_FILE");

    assert!(!enforcer.policy.global.deny_all);
    assert!(!enforcer.policy.global.require_confirm);
}

#[test]
fn test_from_env_reads_env_vars_after_corrupt_policy_file() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken-policy.toml");
    std::fs::write(&path, "this is = not valid toml [[[").unwrap();
    std::env::set_var("PERSONA_AGENT_POLICY_FILE", &path);
    std::env::set_var("PERSONA_AGENT_REQUIRE_CONFIRM", "1");

    // The corrupt file is ignored and the env fallback is actually read.
    let mut enforcer = PolicyEnforcer::from_env();
    std::env::remove_var("PERSONA_AGENT_POLICY_FILE");
    std::env::remove_var("PERSONA_AGENT_REQUIRE_CONFIRM");

    match enforcer.check_signature(&Uuid::new_v4(), None).unwrap() {
        SignatureDecision::RequireConfirm { .. } => {}
        other => panic!("expected RequireConfirm, got {:?}", other),
    }
}
