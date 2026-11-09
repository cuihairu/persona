//! Command-layer integration tests — `ipc_contract` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

/// 全量 IPC 参数键契约审计（回归钉，2026-09-28 审计结论）。
///
/// Tauri 2 的 `#[command]` 宏默认按 camelCase 查 invoke 参数键（宏默认
/// `ArgumentCase::Camel`，`v.get(key)` 精确匹配、无大小写回退），而前端
/// `desktop/src/utils/api.ts` 统一发 snake_case 键——缺
/// `rename_all = "snake_case"` 时运行时报
/// "missing required key xxxYyy"（用户在生成器面板实测：
/// `invalid args 'includeLowercase' ... missing required key includeLowercase`）。
/// 直调 Rust fn 的命令层测试走不到这一层，故按源级断言逐命令核对：
/// ① 表内每个命令的 `#[command]` 必须带 `rename_all = "snake_case"`；
/// ② api.ts 发送的每个多词键必须与 Rust 形参同名（拼写漂移会在此暴露）。
/// 单词参数（`request`/`id`/`query` 等）两种命名法等价，不在本表。
/// 前端侧发键由 `desktop/src/utils/api.test.ts` 的 mock invoke 断言钉住，
/// 两侧合起来构成完整契约。新命令若收多词参数：加上属性后在此表登记。
#[test]
fn command_ipc_arg_keys_match_api_ts_snake_case() {
    // 命令层拆分后（LAY-004）源码分散在 commands/ 各 family 文件；
    // 编译期拼接全部 family，契约断言逻辑不变。
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

    // (命令名, api.ts 发送的多词 snake_case 键)——2026-09-28 全量审计
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
    // commands.rs 含中文注释，窗口切片须落在字符边界上
    let boundary_floor = |src: &str, mut idx: usize| -> usize {
        while idx > 0 && !src.is_char_boundary(idx) {
            idx -= 1;
        }
        idx
    };
    for (name, keys) in AUDITED {
        // 带左括号精确匹配（兼容泛型签名 `<R: Runtime>(`），避免
        // `wallet_generate` 前缀命中 `wallet_generate_mnemonic` 这类
        // 更长的同前缀命令
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
        // ① 属性窗内必须有 rename_all = "snake_case"
        let attrs_window = &source[boundary_floor(source, fn_start.saturating_sub(500))..fn_start];
        if !attrs_window.contains("#[command(rename_all = \"snake_case\")]") {
            failures.push(format!(
                "{name}: missing #[command(rename_all = \"snake_case\")] — invoke layer \
                 would look up camelCase keys and the frontend call fails at runtime"
            ));
        }
        // ② 每个发送键必须是同名形参（拼接 `key:` 探测，跳过泛型行误配：
        //    形参行形如 `    key: Type,`）
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
/// `generate_password_advanced` 的 IPC 键契约——运行时级（真实 invoke 层）。
///
/// 直调 Rust fn 走不到参数键解析，上面的
/// `command_ipc_arg_keys_match_api_ts_snake_case` 只做源级审计；本测试用
/// `tauri::test::get_ipc_response` 实跑三条路径，钉死键契约的运行时语义：
/// ① api.ts 的 snake_case 全键载荷（words 省略）→ 成功，回 1 个候选；
/// ② camelCase 键载荷（includeLowercase…）→ 报 "missing required key
///    include_lowercase"——证明 lookup 键是 snake_case；若 `rename_all`
///    被删，lookup 回落 camelCase、该载荷会误成功，断言即翻红；
/// ③ 缺一个必需键（无 include_symbols）→ 同样报缺键——缺键 fail-closed，
///    不静默默认。前端发键侧由 `desktop/src/utils/api.test.ts` 的 mock
///    invoke 断言钉住。
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

    // ① snake_case 全键（words 省略 = None）→ 成功
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

    // ② camelCase 键 → 缺键报错，且报的是 snake_case 键名（rename_all 生效）
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

    // ③ 缺必需键 → fail-closed，不静默默认
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
