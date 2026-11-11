use super::*;

#[tokio::test]
async fn sign_response_unknown_key_errors() {
    let agent = make_test_agent(vec![]);
    let (_, _) = make_ed25519_key("unused");
    // Blob for a key the agent does not hold.
    let seed = [3u8; 32];
    let (pub_line, blob) = openssh_pub_line(seed);
    let _ = pub_line;
    let payload = {
        let mut p = Vec::new();
        write_ssh_string(&mut p, &blob).unwrap();
        write_ssh_string(&mut p, b"data").unwrap();
        p.extend_from_slice(&0u32.to_be_bytes());
        p
    };
    let err = agent.sign_response(&payload).await.unwrap_err();
    assert!(err.to_string().contains("Key not found"));
}

#[tokio::test]
async fn sign_response_denied_by_deny_all_policy() {
    let _guard = env_lock();
    std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

    let mut policy = policy::SigningPolicy::default();
    policy.global.deny_all = true;
    let (key, _) = make_ed25519_key("denied");
    let agent = agent_with_policy(
        vec![key.clone()],
        policy,
        stub_biometric(true, StubOutcome::Succeed(true)),
    );

    let pkt = agent
        .sign_response(&sign_payload_for(&key, b"data"))
        .await
        .unwrap();
    assert_eq!(pkt[4], 5u8, "failure packet");
}

#[tokio::test]
async fn sign_response_biometric_branches() {
    let _guard = env_lock();
    std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

    for (name, outcome, expect_success) in [
        ("verified", StubOutcome::Succeed(true), true),
        ("rejected", StubOutcome::Succeed(false), false),
        (
            "error",
            StubOutcome::Fail("sensor unavailable".to_string()),
            false,
        ),
    ] {
        let mut policy = policy::SigningPolicy::default();
        let (key, verifying) = make_ed25519_key("biometric");
        policy.key_policies.insert(
            key.credential_id.to_string(),
            policy::KeyPolicy {
                require_biometric: true,
                ..Default::default()
            },
        );
        let agent = agent_with_policy(vec![key.clone()], policy, stub_biometric(true, outcome));

        let pkt = agent
            .sign_response(&sign_payload_for(&key, b"payload"))
            .await
            .unwrap();
        if expect_success {
            assert_eq!(pkt[4], 14u8, "{}: signature response", name);
            let mut slice: &[u8] = &pkt[5..];
            let sig_blob = read_ssh_string(&mut slice).unwrap();
            let mut s: &[u8] = &sig_blob;
            let _algo = read_ssh_string(&mut s).unwrap();
            let sig_bytes = read_ssh_string(&mut s).unwrap();
            let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
            verifying.verify_strict(b"payload", &sig).unwrap();
        } else {
            assert_eq!(pkt[4], 5u8, "{}: failure packet", name);
        }
    }
}

// ------------------------------------------------------------------
// handle_connection protocol branches
// ------------------------------------------------------------------

#[tokio::test]
async fn sign_response_biometric_unavailable_falls_back_to_approval() {
    let _guard = env_lock();
    std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

    // Approval allows: the signature still succeeds through the fallback.
    let (key, verifying) = make_ed25519_key("biometric-fallback");
    let allow = Arc::new(RecordingApproval {
        allow: true,
        prompts: StdMutex::new(Vec::new()),
    });
    let agent = agent_with(
        key.clone(),
        biometric_policy_for(&key),
        allow.clone(),
        stub_biometric(false, StubOutcome::Succeed(true)),
    );
    let pkt = agent
        .sign_response(&sign_payload_for(&key, b"fallback-allow"))
        .await
        .unwrap();
    let sig = extract_signature(&pkt);
    let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
    verifying.verify_strict(b"fallback-allow", &sig).unwrap();
    let prompts = allow.prompts.lock().unwrap();
    assert_eq!(prompts.len(), 1);
    assert!(prompts[0].contains("Biometric unavailable"));

    // Approval denies: the request is refused without a signature.
    let deny = Arc::new(RecordingApproval {
        allow: false,
        prompts: StdMutex::new(Vec::new()),
    });
    let agent = agent_with(
        key.clone(),
        biometric_policy_for(&key),
        deny.clone(),
        stub_biometric(false, StubOutcome::Succeed(true)),
    );
    let pkt = agent
        .sign_response(&sign_payload_for(&key, b"fallback-deny"))
        .await
        .unwrap();
    assert_eq!(pkt[4], 5u8, "denied fallback must fail");
    assert_eq!(deny.prompts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn sign_response_require_confirm_without_hostname_prompts_generically() {
    let _guard = env_lock();
    for var in [
        "PERSONA_AGENT_TARGET_HOST",
        "PERSONA_AGENT_TARGET_HOST_HINT",
        "PERSONA_AGENT_SSH_DEST",
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "PERSONA_AGENT_SSH_COMMAND",
        "SSH_ORIGINAL_COMMAND",
        "GIT_SSH_COMMAND",
    ] {
        std::env::remove_var(var);
    }

    let mut policy = policy::SigningPolicy::default();
    policy.global.require_confirm = true;
    let (key, _) = make_ed25519_key("confirm-no-host");
    let allow = Arc::new(RecordingApproval {
        allow: true,
        prompts: StdMutex::new(Vec::new()),
    });
    let agent = agent_with(
        key.clone(),
        policy,
        allow.clone(),
        stub_biometric(true, StubOutcome::Succeed(true)),
    );
    let pkt = agent
        .sign_response(&sign_payload_for(&key, b"no-host"))
        .await
        .unwrap();
    assert_eq!(pkt[4], 14u8);
    // Without any host hint the prompt is the generic form.
    let prompts = allow.prompts.lock().unwrap();
    assert_eq!(prompts[0], "Allow SSH signature? [y/N] ");
}
