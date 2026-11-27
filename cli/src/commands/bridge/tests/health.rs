use super::*;

/// Bridge protocol v8: `health_scan` over the public request path. Seeds
/// weak + reused logins through `save_credential`, then checks the bucketed
/// metadata-only report, the session gate, and the locked-vault refusal.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn health_scan_protocol_cases() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    // Read-only metadata command: must work WITHOUT a user gesture (same
    // class as get_suggestions).
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    let save = |name: &str, origin: &str, password: &str| {
        request(
            "save_credential",
            serde_json::json!({
                "origin": origin,
                "user_gesture": true,
                "username": "alice@example.com",
                "password": password,
                "name_hint": name
            }),
        )
    };

    // Two logins sharing a trivially weak password on a directory site
    // (github.com is in BUILTIN_2FA_SITES, so the no-TOTP rule has an
    // input); no TOTP-like credential exists in this vault.
    for name in ["Repo admin", "Repo forum"] {
        let resp = handle_request(
            &db_path,
            &state_dir,
            save(name, "https://github.com", "123456"),
        )
        .await
        .unwrap();
        assert!(resp.ok, "seed save must succeed: {:?}", resp.error);
    }
    // One strong, unique secret on another site — must stay unflagged.
    let resp = handle_request(
        &db_path,
        &state_dir,
        save(
            "Wiki admin",
            "https://wiki.example.org",
            "correct-horse-battery-staple-42!",
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "seed save (strong) must succeed: {:?}", resp.error);

    // ---- health_scan: bucketed report ----
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("health_scan", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert!(resp.ok, "health_scan must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "health_scan_response");
    let payload = resp.payload.unwrap();
    assert_eq!(payload["total_credentials"].as_u64(), Some(3));
    assert_eq!(payload["breach_status"].as_str(), Some("skipped"));

    let names_in = |key: &str| -> Vec<String> {
        payload[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_string())
            .collect()
    };

    // weak: both "123456" logins; the strong one is absent everywhere.
    let weak = names_in("weak");
    assert_eq!(weak.len(), 2, "weak bucket: {weak:?}");
    assert!(weak.contains(&"Repo admin".to_string()));
    assert!(weak.contains(&"Repo forum".to_string()));
    for entry in payload["weak"].as_array().unwrap() {
        assert!(
            entry["score"].as_u64().is_some(),
            "weak entries carry the score"
        );
    }

    // reused: both members of the shared-secret group.
    let reused = names_in("reused");
    assert_eq!(reused.len(), 2, "reused bucket: {reused:?}");
    for entry in payload["reused"].as_array().unwrap() {
        assert_eq!(entry["group_size"].as_u64(), Some(2));
    }

    // no_totp: directory sites with a login and no TOTP coverage.
    let no_totp = names_in("no_totp");
    assert_eq!(no_totp.len(), 2, "no_totp bucket: {no_totp:?}");

    // stale: fresh items only — nothing flagged.
    assert_eq!(names_in("stale").len(), 0);

    // severity counts sum to the flagged entries.
    let counts = payload["counts"].as_object().unwrap();
    let total: u64 = counts.values().map(|v| v.as_u64().unwrap()).sum();
    assert!(
        total >= 4,
        "counts cover weak+reused+no_totp hits: {counts:?}"
    );

    // ---- health_scan: locked vault refused ----
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    let err = handle_request(
        &db_path,
        &state_dir,
        request("health_scan", serde_json::json!({})),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().starts_with("locked"),
        "locked vault must refuse: {err}"
    );
}
