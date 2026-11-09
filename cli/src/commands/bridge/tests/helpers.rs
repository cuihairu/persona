use super::*;

#[test]
fn bridge_pure_helpers_cover_edge_cases() {
    // ok/err constructors.
    let ok_resp = ok(
        Some("r1".to_string()),
        "kind-x",
        serde_json::json!({"a": 1}),
    );
    assert!(ok_resp.ok);
    assert_eq!(ok_resp.kind, "kind-x");
    assert_eq!(ok_resp.request_id.as_deref(), Some("r1"));
    assert!(ok_resp.error.is_none());
    assert!(ok_resp.payload.is_some());
    let err_resp = err::<serde_json::Value>(None, "error", "boom".to_string());
    assert!(!err_resp.ok);
    assert_eq!(err_resp.kind, "error");
    assert!(err_resp.request_id.is_none());
    assert_eq!(err_resp.error.as_deref(), Some("boom"));
    assert!(err_resp.payload.is_none());

    // normalize_pairing_code trims, strips spaces, and uppercases.
    assert_eq!(normalize_pairing_code("  ab c-12 9 "), "ABC-129");
    assert_eq!(normalize_pairing_code("123-456"), "123-456");

    // state_path and now_ms.
    assert_eq!(
        state_path(Path::new("/tmp/s")),
        PathBuf::from("/tmp/s/state.json")
    );
    assert!(now_ms() > 1_600_000_000_000, "now_ms must be plausible");

    // default_true.
    assert!(default_true());

    // canonicalize_json_value is an identity on parsed JSON, including
    // nested objects, arrays, and scalars.
    let input = serde_json::json!({
        "b": 1,
        "a": [ { "d": 2, "c": 3 }, null, true, "x", 1.5 ],
        "nested": { "z": { "m": [] } }
    });
    assert_eq!(canonicalize_json_value(&input), input);

    // flat_persona_error strips the human prefix but keeps the wire code.
    let flat = flat_persona_error(PersonaError::InvalidInput(
        "invalid_request: missing user".to_string(),
    ));
    assert_eq!(flat.to_string(), "invalid_request: missing user");
    let flat_plain = flat_persona_error(PersonaError::NotFound("item".to_string()));
    assert_eq!(flat_plain.to_string(), "item");

    // compute_match_strength buckets.
    assert_eq!(
        compute_match_strength("github.com", "https://github.com/login"),
        100
    );
    assert_eq!(
        compute_match_strength("GitHub.COM", "https://github.com"),
        100
    );
    assert_eq!(
        compute_match_strength("api.github.com", "https://github.com"),
        90
    );
    assert_eq!(
        compute_match_strength("github.com", "https://api.github.com/x"),
        90
    );
    // Same registrable domain (TLD+1) but no subdomain relation.
    assert_eq!(
        compute_match_strength("a.b.example.com", "https://c.d.example.com/"),
        60
    );
    // Legacy contains fallback for non-URL credential values.
    assert_eq!(
        compute_match_strength("github.com", "not-a-url-but-mentions-github.com"),
        80
    );
    assert_eq!(
        compute_match_strength("github.com", "https://gitlab.com/x"),
        0
    );

    // validate_origin_binding requires TLD+1 or better (or no URL at all).
    assert!(validate_origin_binding("example.com", None));
    assert!(validate_origin_binding(
        "example.com",
        Some("https://example.com/login")
    ));
    assert!(validate_origin_binding(
        "a.example.com",
        Some("https://example.com")
    ));
    assert!(!validate_origin_binding(
        "evil.com",
        Some("https://example.com")
    ));

    // origin_to_host accepts origins, bare hosts, and ports, and rejects
    // schemes without a host part.
    assert_eq!(
        origin_to_host("https://Example.com/path?q=1").unwrap(),
        "example.com"
    );
    assert_eq!(origin_to_host("example.com").unwrap(), "example.com");
    assert_eq!(
        origin_to_host("http://localhost:8080").unwrap(),
        "localhost"
    );
    assert!(origin_to_host("mailto:user@example.com").is_err());
    assert!(origin_to_host("").is_err());
}

#[test]
fn gesture_required_env_parsing() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    assert!(gesture_required(), "default is on");

    for off in ["0", "false", "FALSE"] {
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", off);
        assert!(!gesture_required(), "{off} must disable the requirement");
    }
    for on in ["1", "yes", "true"] {
        std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", on);
        assert!(gesture_required(), "{on} must keep the requirement on");
    }

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
}

#[test]
fn compute_match_strength_contains_fallback() {
    // Unparseable credential URL falls back to the legacy contains
    // heuristic: 80 when the raw URL embeds the request host.
    assert_eq!(compute_match_strength("shop", "https://shop.example"), 80);
    // No relation at all scores zero.
    assert_eq!(
        compute_match_strength("elsewhere", "https://example.com"),
        0
    );
}

#[tokio::test]
async fn get_active_identity_id_survives_repository_error() {
    let (_dir, db_path, _state_dir, _identity_id) = seeded_bridge().await;

    // A broken workspaces table makes find_all fail; the helper must
    // swallow the error and report no active identity.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("DROP TABLE workspaces")
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    let db = open_db(&db_path).await.unwrap();
    assert_eq!(get_active_identity_id(&db).await, None);
}
