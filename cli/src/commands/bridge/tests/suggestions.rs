use super::*;

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_get_suggestions_filters_and_orders_items() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

    let exact = seed_password_credential(
        &db_path,
        identity_id,
        "Exact match",
        Some("https://example.com/login"),
        Some("alice@example.com"),
        "pw-exact",
    )
    .await;
    let _sub = seed_password_credential(
        &db_path,
        identity_id,
        "Subdomain match",
        Some("https://api.example.com/signin"),
        Some("bob@example.com"),
        "pw-sub",
    )
    .await;
    let _zero = seed_password_credential(
        &db_path,
        identity_id,
        "Unrelated site",
        Some("https://unrelated.org/x"),
        Some("eve@example.com"),
        "pw-zero",
    )
    .await;
    let _nourl = seed_password_credential(
        &db_path,
        identity_id,
        "No URL",
        None,
        Some("no-url@example.com"),
        "pw-nourl",
    )
    .await;
    let inactive = seed_password_credential(
        &db_path,
        identity_id,
        "Inactive entry",
        Some("https://example.com/inactive"),
        Some("inactive@example.com"),
        "pw-inactive",
    )
    .await;
    let _api = seed_api_key_credential(
        &db_path,
        identity_id,
        "API key",
        Some("https://example.com/api"),
    )
    .await;

    // Deactivate one credential directly in the store.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("UPDATE credentials SET is_active = 0 WHERE id = ?")
        .bind(inactive.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);

    // Bad payload -> context error.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("get_suggestions", serde_json::json!({})),
    )
    .await
    .expect_err("get_suggestions without origin must fail");
    assert!(
        err.to_string()
            .contains("invalid payload for get_suggestions"),
        "got: {err}"
    );

    // Unparseable origin -> error from origin_to_host.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_suggestions",
            serde_json::json!({ "origin": "not a url" }),
        ),
    )
    .await
    .expect_err("invalid origin must fail");

    assert!(!err.to_string().is_empty());

    // Only the exact (100) and subdomain (90) matches survive filtering,
    // ordered by descending match strength.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_suggestions",
            serde_json::json!({ "origin": "https://example.com" }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "suggestions must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "suggestions_response");
    assert_eq!(resp.request_id.as_deref(), Some("req-1"));
    let payload = resp.payload.unwrap();
    assert_eq!(payload["suggesting_for"], "example.com");
    let items = payload["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "expected exactly the two matching items");
    assert_eq!(items[0]["match_strength"], 100);
    assert_eq!(items[0]["item_id"], exact.to_string());
    assert_eq!(items[0]["credential_type"], "password");
    assert_eq!(items[0]["username_hint"], "alice@example.com");
    assert_eq!(items[1]["match_strength"], 90);

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_host_map_hit_and_credential_merge() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, work_id, os_id) = seeded_context_bridge().await;

    // Global map: host regex → OpenSource (deliberately NOT the active
    // identity, so the cross-identity merge is exercised; suggesting the
    // active identity would be a no-op dedupe). Regex keys must be
    // single-quoted TOML literal strings (a basic-string `\.` is illegal
    // and would silently void the whole table).
    std::fs::write(
        dir.path().join("global-context.toml"),
        "[host.'^github\\.com$']\nidentity = \"OpenSource\"\n",
    )
    .unwrap();

    seed_password_credential(
        &db_path,
        work_id,
        "Work GitHub",
        Some("https://github.com/login"),
        Some("work@corp.com"),
        "pw-work",
    )
    .await;
    seed_password_credential(
        &db_path,
        os_id,
        "OpenSource GitHub",
        Some("https://github.com/open"),
        Some("oss@example.com"),
        "pw-oss",
    )
    .await;

    let maps = context_maps_for(dir.path());
    let parsed = context_payload("https://github.com", None, None);
    let ctx = context_suggestion_for_bridge_with(&db_path, "github.com", &parsed, &maps)
        .await
        .expect("host map hit must produce a suggestion");
    assert_eq!(ctx.identity, "OpenSource");
    assert!((ctx.score - 0.8).abs() < f64::EPSILON);

    // The suggested identity's credential merges into the pool and
    // sorts ahead of the active identity's; every item carries its
    // owning identity name.
    let items = get_credential_suggestions(&db_path, "github.com", "login", Some(&ctx))
        .await
        .unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].title, "OpenSource GitHub");
    assert_eq!(items[0].identity.as_deref(), Some("OpenSource"));
    assert_eq!(items[1].title, "Work GitHub");
    assert_eq!(items[1].identity.as_deref(), Some("Work"));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_no_maps_returns_none() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, _work_id, _os_id) = seeded_context_bridge().await;

    // Empty temp dir: no map files anywhere → no candidate.
    let maps = context_maps_for(dir.path());
    let parsed = context_payload("https://github.com", None, None);
    assert!(
        context_suggestion_for_bridge_with(&db_path, "github.com", &parsed, &maps)
            .await
            .is_none()
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_broken_map_degrades_to_none() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, _work_id, _os_id) = seeded_context_bridge().await;

    // Malformed TOML: the layer degrades to no suggestion (design §10),
    // never an error.
    std::fs::write(
        dir.path().join("global-context.toml"),
        "[host.'^github\\.com$'\nidentity = \"Work\"\n",
    )
    .unwrap();
    let maps = context_maps_for(dir.path());
    let parsed = context_payload("https://github.com", None, None);
    assert!(
        context_suggestion_for_bridge_with(&db_path, "github.com", &parsed, &maps)
            .await
            .is_none()
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_env_override_wins_over_map() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, _work_id, _os_id) = seeded_context_bridge().await;

    std::fs::write(
        dir.path().join("global-context.toml"),
        "[host.'^github\\.com$']\nidentity = \"Work\"\n",
    )
    .unwrap();
    let _ovr = EnvRestore::set("PERSONA_CONTEXT_OVERRIDE", "OpenSource");

    let maps = context_maps_for(dir.path());
    let parsed = context_payload("https://github.com", None, None);
    let ctx = context_suggestion_for_bridge_with(&db_path, "github.com", &parsed, &maps)
        .await
        .expect("env override must produce a suggestion");
    assert_eq!(ctx.identity, "OpenSource");
    assert!(ctx.reason.contains("PERSONA_CONTEXT_OVERRIDE"));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_explicit_host_field_beats_origin_host() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, _work_id, _os_id) = seeded_context_bridge().await;

    // Map keys on gitlab.com; the origin host (github.com) would match
    // nothing — the explicit `host` signal must win.
    std::fs::write(
        dir.path().join("global-context.toml"),
        "[host.'^gitlab\\.com$']\nidentity = \"OpenSource\"\n",
    )
    .unwrap();
    let maps = context_maps_for(dir.path());
    let parsed = context_payload("https://github.com", Some("gitlab.com"), None);
    let ctx = context_suggestion_for_bridge_with(&db_path, "github.com", &parsed, &maps)
        .await
        .expect("explicit host signal must produce a suggestion");
    assert_eq!(ctx.identity, "OpenSource");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_cwd_repo_map_outranks_global_host_map() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, _work_id, _os_id) = seeded_context_bridge().await;

    // A real (fake) git dir: repo discovery reads .git/config's origin.
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::write(
        proj.join(".git").join("config"),
        "[remote \"origin\"]\nurl = git@github.com:acme/widgets.git\n",
    )
    .unwrap();

    // Global host map: github.com → Work (0.8). Repo-local project map:
    // the discovered repo → OpenSource (1.0, outranks the host hit).
    std::fs::write(
        dir.path().join("global-context.toml"),
        "[host.'^github\\.com$']\nidentity = \"Work\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("repo-context.toml"),
        "[project.\"github.com/acme/widgets\"]\nidentity = \"OpenSource\"\n",
    )
    .unwrap();

    let maps = context_maps_for(dir.path());
    let parsed = context_payload("https://github.com", None, Some(&proj.to_string_lossy()));
    let ctx = context_suggestion_for_bridge_with(&db_path, "github.com", &parsed, &maps)
        .await
        .expect("repo-local project map must produce a suggestion");
    assert_eq!(ctx.identity, "OpenSource");
    assert!(ctx.reason.contains("acme/widgets"));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_no_context_opt_out() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, _work_id, _os_id) = seeded_context_bridge().await;

    std::fs::write(
        dir.path().join("global-context.toml"),
        "[host.'^github\\.com$']\nidentity = \"Work\"\n",
    )
    .unwrap();
    let _no_ctx = EnvRestore::set("PERSONA_NO_CONTEXT", "1");

    let maps = context_maps_for(dir.path());
    let parsed = context_payload("https://github.com", None, None);
    assert!(
        context_suggestion_for_bridge_with(&db_path, "github.com", &parsed, &maps)
            .await
            .is_none(),
        "PERSONA_NO_CONTEXT must switch the whole layer off"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_context_suggestion_card_form_merges_suggested_identity_first() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, db_path, work_id, os_id) = seeded_context_bridge().await;

    std::fs::write(
        dir.path().join("global-context.toml"),
        "[host.'^shop\\.example$']\nidentity = \"OpenSource\"\n",
    )
    .unwrap();
    seed_bank_card_credential(&db_path, work_id, "Work Card", "1111").await;
    seed_bank_card_credential(&db_path, os_id, "OSS Card", "2222").await;

    let maps = context_maps_for(dir.path());
    let mut parsed = context_payload("https://shop.example", None, None);
    parsed.form_type = Some("card".to_string());
    let ctx = context_suggestion_for_bridge_with(&db_path, "shop.example", &parsed, &maps)
        .await
        .expect("host map hit must produce a suggestion");
    assert_eq!(ctx.identity, "OpenSource");

    let items = get_credential_suggestions(&db_path, "shop.example", "card", Some(&ctx))
        .await
        .unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].title, "OSS Card");
    assert_eq!(items[0].identity.as_deref(), Some("OpenSource"));
    assert_eq!(items[0].credential_type, "bank_card");
    assert_eq!(items[1].title, "Work Card");
    assert_eq!(items[1].identity.as_deref(), Some("Work"));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_get_suggestions_accepts_optional_signals_without_maps() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let exact = seed_password_credential(
        &db_path,
        identity_id,
        "Exact match",
        Some("https://example.com/login"),
        Some("alice@example.com"),
        "pw-exact",
    )
    .await;

    // The stage-4 optional signals are accepted; with no maps anywhere
    // the response keeps the v7 shape (context null) and items are
    // unchanged — now carrying the owning identity name.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_suggestions",
            serde_json::json!({
                "origin": "https://example.com",
                "host": "example.com",
                "cwd": "/tmp/persona-bridge-no-such-dir"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "suggestions must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    assert_eq!(payload["suggesting_for"], "example.com");
    assert!(
        payload["context"].is_null(),
        "no maps → context must be null, got: {}",
        payload["context"]
    );
    let items = payload["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["item_id"], exact.to_string());
    assert_eq!(items[0]["match_strength"], 100);
    assert_eq!(items[0]["identity"], "Bridge Identity");

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_get_suggestions_form_type_card_lists_bank_cards() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;
    let card_a = seed_bank_card_credential(&db_path, identity_id, "Personal card", "123").await;
    let card_b = seed_bank_card_credential(&db_path, identity_id, "Work card", "456").await;
    let _pw = seed_password_credential(
        &db_path,
        identity_id,
        "Shop login",
        Some("https://shop.example.com"),
        Some("alice@example.com"),
        "hunter2",
    )
    .await;

    // form_type=card: every active BankCard, no URL filtering, password
    // credentials excluded.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_suggestions",
            serde_json::json!({
                "origin": "https://checkout.anywhere.example",
                "form_type": "card"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "card suggestions must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "suggestions_response");
    let payload = resp.payload.unwrap();
    let items = payload["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "both active cards must be listed");
    assert_eq!(items[0]["credential_type"], "bank_card");
    assert_eq!(items[0]["match_strength"], 100);
    let listed: Vec<&str> = items
        .iter()
        .map(|i| i["item_id"].as_str().unwrap())
        .collect();
    assert!(listed.contains(&card_a.to_string().as_str()));
    assert!(listed.contains(&card_b.to_string().as_str()));

    // Default (no form_type) stays login-only: the password matches the
    // origin, the cards never appear.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "get_suggestions",
            serde_json::json!({ "origin": "https://shop.example.com" }),
        ),
    )
    .await
    .unwrap();
    let payload = resp.payload.unwrap();
    let items = payload["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "default must remain login-only");
    assert_eq!(items[0]["credential_type"], "password");

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
