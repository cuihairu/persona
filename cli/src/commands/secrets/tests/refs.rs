use super::*;

// ---- 引用解析 ----

#[test]
fn parse_ref_rejects_bad_shapes() {
    for raw in ["no-slash", "a/b", "a/b/c/d", "/work/x", "work//password"] {
        let err = SecretRef::parse(raw).unwrap_err();
        assert!(format!("{err:#}").contains("IDENTITY/ITEM/FIELD"), "{err}");
    }
    let ok = SecretRef::parse(" work / deploy / api_key ").unwrap();
    assert_eq!(
        ok,
        SecretRef {
            identity: "work".into(),
            item: "deploy".into(),
            field: "api_key".into()
        }
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn resolve_outputs_metadata_and_variant_fields() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;

    execute_with(
        resolve_args(&[
            "work/login/password",
            "work/login/username",
            "work/login/name",
            "work/login/notes",
            "work/login/secret",
            "work/deploy/api_key",
            "work/deploy/secret",
            "work/github-2fa/secret_key",
            "work/server/private_key",
            "work/playbook/note",
        ]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn resolve_errors_are_precise() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;

    // 未知身份 / 未知条目 / 未知字段
    let err = execute_with(
        resolve_args(&["ghost/login/password"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("Identity 'ghost' not found"),
        "{err}"
    );

    let err = execute_with(
        resolve_args(&["work/none/password"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("Credential 'none' not found"),
        "{err}"
    );

    let err = execute_with(
        resolve_args(&["work/deploy/card_number"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("unknown field"), "{err}");
    assert!(format!("{err:#}").contains("api_secret"), "{err}");

    // 未设置的可选字段：报错不给空串
    let err = execute_with(
        resolve_args(&["work/deploy/api_secret"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("is not set"), "{err}");

    // 元数据缺省同理
    let err = execute_with(
        resolve_args(&["work/deploy/username"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("is not set"), "{err}");

    // secret 别名用在无主秘密类型 → 列出合法字段
    let err = execute_with(
        resolve_args(&["work/bank/secret"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("Credential 'bank' not found"),
        "{err}"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn ambiguous_item_names_are_rejected() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.authenticate_user("master-pin").await.unwrap();
    let identity = service.get_identity_by_name("work").await.unwrap().unwrap();
    service
        .create_credential(
            identity.id,
            "login".to_string(),
            CredentialType::Password,
            SecurityLevel::Low,
            &CredentialData::Password(PasswordCredentialData {
                password: "dup".to_string(),
                email: None,
                security_questions: vec![],
            }),
        )
        .await
        .unwrap();

    let err = execute_with(
        resolve_args(&["work/login/password"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("ambiguous"), "{err}");
}

#[test]
fn parse_env_assignments_validate_names() {
    let err = parse_env_assignments(&["JUST_A_REF".to_string()]).unwrap_err();
    assert!(format!("{err:#}").contains("NAME=REF"), "{err}");
    let err = parse_env_assignments(&["1BAD=x/y/z".to_string()]).unwrap_err();
    assert!(
        format!("{err:#}").contains("must not start with a digit"),
        "{err}"
    );
    let err = parse_env_assignments(&["BAD-NAME=x/y/z".to_string()]).unwrap_err();
    assert!(
        format!("{err:#}").contains("invalid variable name"),
        "{err}"
    );
    let err = parse_env_assignments(&["OK=only-two".to_string()]).unwrap_err();
    assert!(format!("{err:#}").contains("IDENTITY/ITEM/FIELD"), "{err}");
}
