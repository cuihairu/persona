use super::*;

#[test]
fn test_rate_limiting() {
    let mut policy = SigningPolicy::default();
    policy.global.min_interval_ms = 1000;

    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    // First signature should be allowed
    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));
    enforcer.record_signature(&cred_id, None);

    // Immediate second signature should be denied
    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_key_daily_limit_exceeded() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();

    let key_policy = KeyPolicy {
        max_uses_per_day: 1,
        ..Default::default()
    };
    policy.key_policies.insert(cred_id.to_string(), key_policy);

    let mut enforcer = PolicyEnforcer::new(policy);
    assert!(matches!(
        enforcer.check_signature(&cred_id, None).unwrap(),
        SignatureDecision::Allowed
    ));
    enforcer.record_signature(&cred_id, None);

    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_key_time_range_denies_outside_window() {
    let mut policy = SigningPolicy::default();
    let cred_id = Uuid::new_v4();

    let now = chrono::Local::now();
    let start = (now + chrono::Duration::hours(2))
        .time()
        .format("%H:%M")
        .to_string();
    let end = (now + chrono::Duration::hours(3))
        .time()
        .format("%H:%M")
        .to_string();

    let key_policy = KeyPolicy {
        allowed_time_range: Some(format!("{start}-{end}")),
        ..Default::default()
    };
    policy.key_policies.insert(cred_id.to_string(), key_policy);

    let mut enforcer = PolicyEnforcer::new(policy);
    let decision = enforcer.check_signature(&cred_id, None).unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_record_signature_tracks_key_and_host_usage() {
    let mut enforcer = PolicyEnforcer::new(SigningPolicy::default());
    let cred_id = Uuid::new_v4();

    enforcer.record_signature(&cred_id, Some("gitlab.com"));
    enforcer.record_signature(&cred_id, None);

    let key_usage = enforcer.state.key_usage.get(&cred_id).unwrap();
    assert_eq!(key_usage.daily_count, 2);
    assert_eq!(key_usage.total_count, 2);

    let host_usage = enforcer.state.host_usage.get("gitlab.com").unwrap();
    assert_eq!(host_usage.hourly_count, 1);
    assert_eq!(host_usage.total_count, 1);
    assert!(enforcer.state.last_sign.is_some());
    assert_eq!(enforcer.state.signature_timestamps.len(), 2);
}

#[test]
fn test_global_hourly_limit_denies_after_threshold() {
    let mut policy = SigningPolicy::default();
    policy.global.max_signatures_per_hour = 1;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Allowed));
    enforcer.record_signature(&cred_id, Some("github.com"));

    let decision = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(decision, SignatureDecision::Denied { .. }));
}

#[test]
fn test_min_interval_ms_denies_rapid_signatures() {
    let mut policy = SigningPolicy::default();
    policy.global.min_interval_ms = 60_000;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    let first = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(first, SignatureDecision::Allowed));
    enforcer.record_signature(&cred_id, Some("github.com"));

    let second = enforcer
        .check_signature(&cred_id, Some("github.com"))
        .unwrap();
    assert!(matches!(second, SignatureDecision::Denied { .. }));
}

#[test]
fn test_usage_state_counters_reset_after_their_windows() {
    let mut key_state = KeyUsageState {
        daily_count: 3,
        last_reset: Instant::now() - Duration::from_secs(86_460),
        total_count: 9,
    };
    key_state.reset_if_needed();
    assert_eq!(key_state.daily_count, 0);
    assert_eq!(key_state.total_count, 9);

    // Inside the window the counter is kept.
    let mut fresh = KeyUsageState {
        daily_count: 5,
        last_reset: Instant::now(),
        total_count: 5,
    };
    fresh.reset_if_needed();
    assert_eq!(fresh.daily_count, 5);

    let mut host_state = HostUsageState {
        hourly_count: 2,
        last_reset: Instant::now() - Duration::from_secs(3_660),
        total_count: 7,
    };
    host_state.reset_if_needed();
    assert_eq!(host_state.hourly_count, 0);
    assert_eq!(host_state.total_count, 7);
}

#[test]
fn test_min_interval_rate_limit_allows_the_first_signature() {
    let mut policy = SigningPolicy::default();
    policy.global.min_interval_ms = 60_000;
    let mut enforcer = PolicyEnforcer::new(policy);

    // A fresh state has no previous signature, so the interval does not
    // apply and the first request is allowed.
    match enforcer
        .check_signature(&Uuid::new_v4(), Some("github.com"))
        .unwrap()
    {
        SignatureDecision::Allowed => {}
        other => panic!("expected Allowed, got {:?}", other),
    }
}

// ---------------------------------------------------------------
// check/record atomicity (two-lock race) and rollback semantics
// ---------------------------------------------------------------

#[test]
fn test_concurrent_check_and_record_respects_hourly_limit() {
    // The daemon handles each connection on its own spawned task. With
    // the old split check_signature / record_signature (two separate
    // lock acquisitions) every task could pass the check before any of
    // them recorded, so the hourly limit was bypassed. The combined
    // call decides and books under one lock: at most
    // max_signatures_per_hour requests are admitted.
    let policy = SigningPolicy {
        global: GlobalPolicy {
            min_interval_ms: 0,
            max_signatures_per_hour: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let enforcer = Arc::new(StdMutex::new(PolicyEnforcer::new(policy)));
    let allowed = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let enforcer = Arc::clone(&enforcer);
            let allowed = Arc::clone(&allowed);
            std::thread::spawn(move || {
                let mut enforcer = enforcer.lock().unwrap();
                if matches!(
                    enforcer
                        .check_and_record_signature(&Uuid::new_v4(), None)
                        .unwrap(),
                    SignatureDecision::Allowed
                ) {
                    allowed.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(allowed.load(Ordering::SeqCst), 3);
    // every admitted request is booked exactly once
    assert_eq!(enforcer.lock().unwrap().state.signature_timestamps.len(), 3);
}

#[test]
fn test_denied_decision_does_not_consume_budget() {
    let mut policy = SigningPolicy::default();
    policy.global.deny_all = true;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    for _ in 0..3 {
        assert!(matches!(
            enforcer
                .check_and_record_signature(&cred_id, Some("github.com"))
                .unwrap(),
            SignatureDecision::Denied { .. }
        ));
    }
    // denied requests never reach signing, so they leave no trace in
    // the ledger (otherwise repeated denied requests could exhaust the
    // hourly budget without a single signature happening)
    assert!(enforcer.state.signature_timestamps.is_empty());
    assert!(enforcer.state.key_usage.is_empty());
    assert!(enforcer.state.host_usage.is_empty());
    assert!(enforcer.state.last_sign.is_none());
}

#[test]
fn test_rollback_restores_rate_limit_budget() {
    let mut policy = SigningPolicy::default();
    policy.global.min_interval_ms = 0;
    policy.global.max_signatures_per_hour = 1;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();

    // The only hourly slot is booked...
    assert!(matches!(
        enforcer.check_and_record_signature(&cred_id, None).unwrap(),
        SignatureDecision::Allowed
    ));
    // ...the approval gate refuses, the record is rolled back...
    enforcer.rollback_signature(&cred_id, None);
    assert!(enforcer.state.signature_timestamps.is_empty());
    assert_eq!(enforcer.state.key_usage[&cred_id].daily_count, 0);

    // ...and the next request is admitted again instead of denied.
    assert!(matches!(
        enforcer.check_and_record_signature(&cred_id, None).unwrap(),
        SignatureDecision::Allowed
    ));
}

#[test]
fn test_rollback_restores_min_interval_to_remaining_signature() {
    let mut policy = SigningPolicy::default();
    policy.global.min_interval_ms = 0;
    let mut enforcer = PolicyEnforcer::new(policy);
    let cred_id = Uuid::new_v4();
    let host = "github.com";

    // Two signatures go through, then the second one's gate refuses and
    // its record is rolled back. last_sign must fall back to the first
    // signature instead of being cleared...
    assert!(matches!(
        enforcer
            .check_and_record_signature(&cred_id, Some(host))
            .unwrap(),
        SignatureDecision::Allowed
    ));
    assert!(matches!(
        enforcer
            .check_and_record_signature(&cred_id, Some(host))
            .unwrap(),
        SignatureDecision::Allowed
    ));
    enforcer.rollback_signature(&cred_id, Some(host));
    assert_eq!(enforcer.state.signature_timestamps.len(), 1);
    assert_eq!(enforcer.state.host_usage[host].hourly_count, 1);
    assert!(enforcer.state.last_sign.is_some());

    // ...otherwise the min-interval gate would be disarmed and an
    // immediate request after the rollback would pass.
    enforcer.policy.global.min_interval_ms = 60_000;
    assert!(matches!(
        enforcer.check_signature(&cred_id, Some(host)).unwrap(),
        SignatureDecision::Denied { .. }
    ));
}
