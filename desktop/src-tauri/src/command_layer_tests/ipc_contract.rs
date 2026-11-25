//! Command-layer integration tests — `ipc_contract` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

/// Full audit of the IPC argument-key contract (regression pin, per the
/// 2026-09-28 audit findings).
///
/// Tauri 2's `#[command]` macro looks up invoke argument keys in camelCase
/// by default (the macro defaults to `ArgumentCase::Camel`, and
/// `v.get(key)` is an exact match with no case fallback), while the
/// frontend `desktop/src/utils/api.ts` always sends snake_case keys —
/// without `rename_all = "snake_case"` the runtime fails with
/// "missing required key xxxYyy" (observed by a user in the generator
/// panel: `invalid args 'includeLowercase' ... missing required key
/// includeLowercase`). Command-layer tests that call the Rust fn directly
/// never reach that layer, so this checks each command by source-level
/// assertions:
/// ① every command in the table must have `rename_all = "snake_case"` on
///    its `#[command]`;
/// ② every multi-word key sent by api.ts must have the same name as the
///    Rust formal parameter (spelling drift shows up here).
/// Single-word parameters (`request`/`id`/`query`, etc.) are equivalent
/// under both conventions and are not in this table.
/// The frontend side is pinned by the mock invoke assertions in
/// `desktop/src/utils/api.test.ts`; together both sides form the full
/// contract. If a new command takes a multi-word parameter: add the
/// attribute, then register it in this table.
#[test]
fn command_ipc_arg_keys_match_api_ts_snake_case() {
    // After the command-layer split (LAY-004) the source lives in the
    // per-family files under commands/; all families are concatenated at
    // compile time, and the contract assertion logic is unchanged.
    let source = concat!(
        include_str!("../commands/account.rs"),
        include_str!("../commands/attachments.rs"),
        include_str!("../commands/audit.rs"),
        include_str!("../commands/autolock.rs"),
        include_str!("../commands/backup.rs"),
        include_str!("../commands/biometric.rs"),
        include_str!("../commands/connect.rs"),
        include_str!("../commands/credentials.rs"),
        include_str!("../commands/health.rs"),
        include_str!("../commands/identity.rs"),
        include_str!("../commands/lifecycle.rs"),
        include_str!("../commands/passkey.rs"),
        include_str!("../commands/quickaccess.rs"),
        include_str!("../commands/reveal.rs"),
        include_str!("../commands/ssh.rs"),
        include_str!("../commands/sync.rs"),
        include_str!("../commands/travel.rs"),
        include_str!("../commands/wallet.rs"),
    );

    // (command name, multi-word snake_case keys sent by api.ts) — 2026-09-28 full audit
    const AUDITED: &[(&str, &[&str])] = &[
        (
            "generate_password_advanced",
            &[
                "length",
                "include_lowercase",
                "include_uppercase",
                "include_numbers",
                "include_symbols",
                "pronounceable",
                "count",
            ],
        ),
        ("attach_file_to_credential", &["credential_id", "file_path"]),
        ("audit_cleanup", &["retain_days"]),
        ("delete_attachment", &["attachment_id"]),
        ("delete_credential", &["credential_id"]),
        ("delete_identity", &["identity_id"]),
        ("export_identity", &["identity_id"]),
        ("fetch_credential_favicon", &["credential_id"]),
        ("generate_password", &["length", "include_symbols"]),
        ("get_credential_data", &["credential_id"]),
        ("get_credential_history", &["credential_id"]),
        ("get_credentials_for_identity", &["identity_id"]),
        ("get_totp_code", &["credential_id"]),
        ("list_attachments", &["credential_id"]),
        ("passkey_list", &["identity_id"]),
        ("passkey_list_by_rp", &["rp_id"]),
        ("restore_credential_version", &["credential_id"]),
        ("save_attachment_to_file", &["attachment_id", "output_path"]),
        ("set_active_identity", &["identity_id"]),
        (
            "set_feature_flags",
            &["ssh_agent", "wallet", "passkeys", "fetch_favicons"],
        ),
        (
            "set_sync_config",
            &["enabled", "server_url", "server_token"],
        ),
        ("toggle_credential_favorite", &["credential_id"]),
        ("wallet_add_address", &["wallet_id"]),
        ("wallet_delete", &["wallet_id"]),
        ("wallet_generate", &["identity_id"]),
        ("wallet_generate_mnemonic", &["word_count"]),
        ("wallet_validate_mnemonic", &["phrase"]),
        ("wallet_set_item_password", &["credential_id", "password"]),
        (
            "wallet_clear_item_password",
            &["credential_id", "item_password"],
        ),
        ("wallet_import", &["identity_id"]),
        ("wallet_list", &["identity_id"]),
        ("wallet_list_addresses", &["wallet_id"]),
        ("wallet_pending_transactions", &["wallet_id"]),
    ];

    let mut failures = Vec::new();
    // commands.rs contains Chinese comments, so window slices must land on
    // character boundaries
    let boundary_floor = |src: &str, mut idx: usize| -> usize {
        while idx > 0 && !src.is_char_boundary(idx) {
            idx -= 1;
        }
        idx
    };
    for (name, keys) in AUDITED {
        // Match with the trailing left paren for exactness (also handles
        // generic signatures like `<R: Runtime>(`), so that the
        // `wallet_generate` prefix does not hit longer same-prefix commands
        // like `wallet_generate_mnemonic`
        let marker = format!("pub async fn {name}(");
        let marker_generic = format!("pub async fn {name}<");
        let fn_start = match source
            .find(&marker)
            .or_else(|| source.find(&marker_generic))
        {
            Some(idx) => idx,
            None => {
                failures.push(format!("{name}: definition not found in commands.rs"));
                continue;
            }
        };
        // ① the attribute window must contain rename_all = "snake_case"
        let attrs_window = &source[boundary_floor(source, fn_start.saturating_sub(500))..fn_start];
        if !attrs_window.contains("#[command(rename_all = \"snake_case\")]") {
            failures.push(format!(
                "{name}: missing #[command(rename_all = \"snake_case\")] — invoke layer \
                 would look up camelCase keys and the frontend call fails at runtime"
            ));
        }
        // ② every sent key must be a formal parameter of the same name
        //    (probing for a concatenated `key:` to skip false matches on
        //    generic lines: a parameter line looks like `    key: Type,`)
        let sig = &source[fn_start..];
        let sig_end = sig.find(") ->").unwrap_or(sig.len());
        let params = &sig[..sig_end];
        for key in *keys {
            if !params.contains(&format!("\n    {key}:")) && !params.contains(&format!("({key}:")) {
                failures.push(format!(
                    "{name}: api.ts sends key `{key}` but no matching parameter in the signature"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "IPC arg-key contract violations:\n  - {}",
        failures.join("\n  - ")
    );
}
/// The IPC key contract for `generate_password_advanced` — at the runtime
/// level (the real invoke layer).
///
/// Calling the Rust fn directly never reaches argument-key resolution, and
/// `command_ipc_arg_keys_match_api_ts_snake_case` above only performs a
/// source-level audit; this test runs three paths for real via
/// `tauri::test::get_ipc_response` to pin down the runtime semantics of the
/// key contract:
/// ① api.ts's full snake_case key payload (words omitted) -> success,
///    returning 1 candidate;
/// ② a camelCase key payload (includeLowercase...) -> reports "missing
///    required key include_lowercase", proving the lookup key is
///    snake_case; if `rename_all` were removed, lookup would fall back to
///    camelCase and this payload would wrongly succeed, turning the
///    assertion red;
/// ③ one required key missing (no include_symbols) -> likewise reports a
///    missing key — missing keys are fail-closed, never silently defaulted.
/// The frontend side that sends the keys is pinned by the mock invoke
/// assertions in `desktop/src/utils/api.test.ts`.
#[test]
fn generate_password_advanced_ipc_arg_contract() {
    let app = tauri::test::mock_builder()
        .invoke_handler(tauri::generate_handler![
            crate::commands::generate_password_advanced
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();

    let invoke = |payload: serde_json::Value| {
        tauri::test::get_ipc_response(
            &webview,
            tauri::webview::InvokeRequest {
                cmd: "generate_password_advanced".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: if cfg!(any(windows, target_os = "android")) {
                    "http://tauri.localhost"
                } else {
                    "tauri://localhost"
                }
                .parse()
                .unwrap(),
                body: payload.into(),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_string(),
            },
        )
    };

    // ① snake_case full key set (words omitted = None) -> success
    let resp = invoke(serde_json::json!({
        "length": 16,
        "include_lowercase": true,
        "include_uppercase": true,
        "include_numbers": true,
        "include_symbols": false,
        "pronounceable": false,
        "count": 1,
    }))
    .unwrap_or_else(|e| panic!("snake_case payload must succeed: {e}"));
    let body = resp
        .deserialize::<serde_json::Value>()
        .expect("valid json response");
    assert_eq!(body["success"], serde_json::json!(true), "{body}");
    let passwords = body["data"]["passwords"].as_array().expect("passwords");
    assert_eq!(passwords.len(), 1);

    // ② camelCase keys -> missing-key error, reporting the snake_case key
    // name (rename_all in effect)
    let err = invoke(serde_json::json!({
        "length": 16,
        "includeLowercase": true,
        "includeUppercase": true,
        "includeNumbers": true,
        "includeSymbols": false,
        "pronounceable": false,
        "count": 1,
    }))
    .expect_err("camelCase payload must fail while rename_all = snake_case");
    assert!(
        err.to_string()
            .contains("missing required key include_lowercase"),
        "{err}"
    );

    // ③ missing a required key -> fail-closed, no silent default
    let err = invoke(serde_json::json!({
        "length": 16,
        "include_lowercase": true,
        "include_uppercase": true,
        "include_numbers": true,
        "pronounceable": false,
        "count": 1,
    }))
    .expect_err("missing key must error, not silently default");
    assert!(
        err.to_string()
            .contains("missing required key include_symbols"),
        "{err}"
    );
}
