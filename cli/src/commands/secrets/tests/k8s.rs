use super::*;

// ---- k8s ----

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn k8s_renders_base64_manifest() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;

    // 捕获 stdout：println!/print! 直接写进程 stdout，测试里用
    // resolve_ref + 序列化层验证（渲染路径与输出路径解耦），这里只
    // 验证命令本身成功且引用错误会失败。
    execute_with(
        k8s_args(&["password=work/login/password"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap();

    let err = execute_with(
        k8s_args(&["password=work/ghost/password"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("not found"), "{err}");
}

#[test]
fn k8s_manifest_shape_is_valid() {
    // 结构层断言：base64 + 字段名 + 可选段省略
    let manifest = K8sSecretManifest {
        apiVersion: "v1",
        kind: "Secret",
        secret_type: "Opaque",
        metadata: K8sObjectMeta {
            name: "app-secret".to_string(),
            namespace: None,
            labels: None,
            annotations: None,
        },
        data: BTreeMap::from([(
            "password".to_string(),
            base64::engine::general_purpose::STANDARD.encode("p@ss"),
        )]),
    };
    let yaml = serde_yaml::to_string(&manifest).unwrap();
    assert!(yaml.contains("apiVersion: v1"), "{yaml}");
    assert!(yaml.contains("kind: Secret"), "{yaml}");
    assert!(yaml.contains("type: Opaque"), "{yaml}");
    assert!(yaml.contains("password: cEBzcw=="), "{yaml}");
    assert!(!yaml.contains("namespace"), "{yaml}");
}

#[test]
fn k8s_key_validation_rejects_bad_input() {
    let err = parse_kv_pairs(&["bad key=v".to_string()], "labels").unwrap_err();
    assert!(format!("{err:#}").contains("invalid key"), "{err}");
    assert!(valid_key("app.kubernetes.io/managed-by", true));
    assert!(!valid_key("", true));
    assert!(!valid_key("has space", false));
}

// ---- external ----

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn external_resolves_query_map() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;
    let service = open_unlocked(&config, &ScriptedUi::new()).await.unwrap();

    let out = resolve_external_map(
        &service,
        r#"{"api_key": "work/deploy/api_key", "title": "work/login/name"}"#,
    )
    .await
    .unwrap();
    assert_eq!(out["api_key"], "sk-123");
    assert_eq!(out["title"], "login");

    let err = resolve_external_map(&service, r#"{"x": "work/ghost/password"}"#)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("not found"), "{err}");

    let err = resolve_external_map(&service, "[1,2]").await.unwrap_err();
    assert!(format!("{err:#}").contains("JSON object"), "{err}");

    let err = resolve_external_map(&service, r#"{"x": 3}"#)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("must be a string REF"), "{err}");
}

#[tokio::test]
async fn k8s_input_validation_bails_before_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);

    let err = k8s_validation_run(&config, "bad name", None, &["k=work/x/y"], &[])
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("not a valid Kubernetes object name"),
        "{err}"
    );

    let err = k8s_validation_run(&config, "app", Some("bad ns"), &["k=work/x/y"], &[])
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("not a valid namespace name"),
        "{err}"
    );

    let err = k8s_validation_run(&config, "app", None, &[], &[])
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("at least one --key"), "{err}");

    let err = k8s_validation_run(&config, "app", None, &["bad key=work/x/y"], &[])
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("has an invalid key"), "{err}");

    let err = k8s_validation_run(&config, "app", None, &["noequals"], &[])
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("must be KEY=REF"), "{err}");

    let err = k8s_validation_run(&config, "app", None, &["k=work/x/y"], &["bad label=v"])
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("invalid key"), "{err}");
}
