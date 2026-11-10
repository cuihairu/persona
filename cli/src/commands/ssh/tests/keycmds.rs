use super::*;

// ------------------------------------------------------------------
// generate / list / list-all / export-pub.
// ------------------------------------------------------------------

#[tokio::test]
async fn generate_list_and_list_all_flows() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    // With no keys anywhere yet, list-all reports the empty state.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(ssh_args(SshSubcommand::ListAll), &config, &ui)
        .await
        .expect("list-all on a keyless workspace works");
    assert!(ui.exhausted());

    // Unknown key types are refused before anything is unlocked
    // (rsa/ecdsa 生成已支持，dsa 之类仍是快失败).
    let ui = ScriptedUi::new();
    let err = execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            name: None,
            key_type: "dsa".to_string(),
            comment: None,
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("dsa must be refused");
    assert!(err.to_string().contains("Unsupported SSH key type: dsa"));
    assert!(ui.exhausted());

    // Generating with an explicit label and favorite flag.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            name: Some("work-key".to_string()),
            key_type: "ed25519".to_string(),
            comment: None,
            favorite: true,
        }),
        &config,
        &ui,
    )
    .await
    .expect("generate with a label works");
    assert!(ui.exhausted());

    // Generating with the default label.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            name: None,
            key_type: "ed25519".to_string(),
            comment: None,
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect("generate with the default label works");
    assert!(ui.exhausted());

    // Generating against an unknown identity fails during resolution.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "ghost".to_string(),
            name: None,
            key_type: "ed25519".to_string(),
            comment: None,
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("unknown identity must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));
    assert!(ui.exhausted());

    // List reports alice's keys…
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::List {
            identity: "alice".to_string(),
        }),
        &config,
        &ui,
    )
    .await
    .expect("list works");
    assert!(ui.exhausted());

    // …and the empty state for bob.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::List {
            identity: "bob".to_string(),
        }),
        &config,
        &ui,
    )
    .await
    .expect("empty list works");
    assert!(ui.exhausted());

    // List-all spans identities.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(ssh_args(SshSubcommand::ListAll), &config, &ui)
        .await
        .expect("list-all works");
    assert!(ui.exhausted());
}

#[tokio::test]
async fn export_pubkey_branches() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            name: Some("pubkey-src".to_string()),
            key_type: "ed25519".to_string(),
            comment: None,
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect("generate works");

    // A non-SSH credential to exercise the type guard.
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert!(matches!(
            service.authenticate_user("master-pin").await.unwrap(),
            AuthResult::Success
        ));
        let identity = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        service
            .create_credential(
                identity.id,
                "token".to_string(),
                CredentialType::ApiKey,
                SecurityLevel::Medium,
                &CredentialData::ApiKey(ApiKeyData {
                    api_key: "k".to_string(),
                    api_secret: None,
                    token: None,
                    permissions: Vec::new(),
                    expires_at: None,
                }),
            )
            .await
            .unwrap();
    }

    let creds = alice_credentials(&config, "master-pin").await;
    let ssh_id = creds
        .iter()
        .find(|(_, t)| matches!(t, CredentialType::SshKey))
        .expect("ssh key present")
        .0;
    let api_id = creds
        .iter()
        .find(|(_, t)| matches!(t, CredentialType::ApiKey))
        .expect("api key present")
        .0;

    // The happy path prints the OpenSSH line.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::ExportPub { id: ssh_id }),
        &config,
        &ui,
    )
    .await
    .expect("export pubkey works");
    assert!(ui.exhausted());

    // A non-SSH credential is refused.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::ExportPub { id: api_id }),
        &config,
        &ui,
    )
    .await
    .expect_err("non-ssh credential must fail");
    assert!(err.to_string().contains("Credential is not an SSH key"));
    assert!(ui.exhausted());

    // An unknown id is refused.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::ExportPub { id: Uuid::new_v4() }),
        &config,
        &ui,
    )
    .await
    .expect_err("unknown credential must fail");
    assert!(err.to_string().contains("Credential not found"));
    assert!(ui.exhausted());
}

// ------------------------------------------------------------------
// import: base64/hex seeds and rejections.
// ------------------------------------------------------------------

#[tokio::test]
async fn import_seed_variants_and_rejections() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;
    let seed = [9u8; 32];

    // base64 seed with an explicit label.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Import {
            identity: "alice".to_string(),
            name: Some("imported-b64".to_string()),
            seed_base64: Some(BASE64.encode(seed)),
            seed_hex: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect("base64 import works");
    assert!(ui.exhausted());

    // hex seed (outer whitespace tolerated, default label).
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Import {
            identity: "alice".to_string(),
            name: None,
            seed_base64: None,
            seed_hex: Some(format!(" {} ", hex::encode(seed))),
        }),
        &config,
        &ui,
    )
    .await
    .expect("hex import works");
    assert!(ui.exhausted());

    // Neither seed source.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Import {
            identity: "alice".to_string(),
            name: None,
            seed_base64: None,
            seed_hex: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("missing seed must fail");
    assert!(err
        .to_string()
        .contains("Provide --seed-base64 or --seed-hex"));
    assert!(ui.exhausted());

    // A seed of the wrong length.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Import {
            identity: "alice".to_string(),
            name: None,
            seed_base64: Some(BASE64.encode([7u8; 16])),
            seed_hex: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("short seed must fail");
    assert!(err.to_string().contains("Seed must be 32 bytes"));

    // Undecodable base64.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Import {
            identity: "alice".to_string(),
            name: None,
            seed_base64: Some("!!not-base64!!".to_string()),
            seed_hex: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("bad base64 must fail");
    assert!(err.to_string().contains("Invalid base64 seed"));

    // Undecodable hex.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Import {
            identity: "alice".to_string(),
            name: None,
            seed_base64: None,
            seed_hex: Some("zz-nothex".to_string()),
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("bad hex must fail");
    assert!(err.to_string().contains("Invalid hex seed"));

    // Unknown identity.
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Import {
            identity: "ghost".to_string(),
            name: None,
            seed_base64: Some(BASE64.encode(seed)),
            seed_hex: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("unknown identity must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));
}

// ------------------------------------------------------------------
// import-file: OpenSSH 私钥文件导入（seed 导入之外的文件通道）
// ------------------------------------------------------------------

fn write_key_file(dir: &TempDir, name: &str, pem: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, pem).unwrap();
    path
}

fn openssh_pem(algorithm: ssh_key::Algorithm) -> (String, String) {
    let key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        algorithm,
    )
    .unwrap();
    (
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
        key.public_key().to_openssh().unwrap(),
    )
}

#[tokio::test]
async fn import_file_plain_and_stored_shape() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    let (pem, pub_line) = openssh_pem(ssh_key::Algorithm::Rsa { hash: None });
    let key_path = write_key_file(&dir, "id_rsa", &pem);

    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file: key_path.to_string_lossy().to_string(),
            name: Some("rsa-import".to_string()),
            passphrase: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect("plain rsa file import works");
    assert!(ui.exhausted());

    // 库内形状：私钥 = 解锁后的 PEM（可再解析、非密文），类型/公钥一致
    let creds = alice_credentials(&config, "master-pin").await;
    let ssh_id = creds
        .iter()
        .find(|(_, t)| matches!(t, CredentialType::SshKey))
        .expect("ssh credential present")
        .0;
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.authenticate_user("master-pin").await.unwrap();
    let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&ssh_id).await.unwrap()
    else {
        panic!("ssh key data readable");
    };
    assert_eq!(ssh.key_type, "rsa");
    assert_eq!(ssh.public_key, pub_line);
    assert!(ssh
        .private_key
        .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    let reparsed = ssh_key::private::PrivateKey::from_openssh(&ssh.private_key).unwrap();
    assert!(!reparsed.key_data().is_encrypted());

    // 名字回退：comment 非空且无 --name 时用 comment；这里给了 --name
    // 走 label——再导一把不带 --name 的 ed25519 验证 comment/file 回退。
    // （这把的公钥行在 set_comment 之后才取，解构出的第一个直接丢弃）
    let (pem, _) = openssh_pem(ssh_key::Algorithm::Ed25519);
    let mut key = ssh_key::private::PrivateKey::from_openssh(&pem).unwrap();
    key.set_comment("cui@laptop");
    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
    let pub_line = key.public_key().to_openssh().unwrap();
    let key_path = write_key_file(&dir, "id_ed25519_test", &pem);

    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file: key_path.to_string_lossy().to_string(),
            name: None,
            passphrase: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect("comment fallback works");
    let creds = alice_credentials(&config, "master-pin").await;
    assert_eq!(
        creds
            .iter()
            .filter(|(_, t)| matches!(t, CredentialType::SshKey))
            .count(),
        2
    );
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.authenticate_user("master-pin").await.unwrap();
    let identity = service
        .get_identity_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let named = service
        .get_credentials_for_identity(&identity.id)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.name == "cui@laptop")
        .expect("entry named after the key comment");
    let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&named.id).await.unwrap()
    else {
        panic!("ssh key data readable");
    };
    assert_eq!(ssh.public_key, pub_line);
    assert_eq!(ssh.key_type, "ed25519");
}

#[tokio::test]
async fn import_file_encrypted_passphrase_paths() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    let key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    // encrypt 返回新的加密实例（不改动原值），必须接住再序列化
    let key = key
        .encrypt(&mut rand_core::UnwrapErr(rand::rngs::SysRng), "hunter2")
        .unwrap();
    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
    let key_path = write_key_file(&dir, "id_encrypted", &pem);
    let file = key_path.to_string_lossy().to_string();

    // 受保护但没给 --passphrase → ScriptedUi 补问口令后解锁成功
    let ui = ScriptedUi::new().password("hunter2").password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file: file.clone(),
            name: None,
            passphrase: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect("interactive passphrase unlock works");
    assert!(ui.exhausted());

    // --passphrase 直给也通
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file: file.clone(),
            name: None,
            passphrase: Some("hunter2".to_string()),
        }),
        &config,
        &ui,
    )
    .await
    .expect("flagged passphrase unlock works");

    // 错误口令 → 明确报错（不静默吞）
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file,
            name: None,
            passphrase: Some("wrong".to_string()),
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("wrong passphrase must fail");
    assert!(err.to_string().contains("incorrect"), "{err}");
}

#[tokio::test]
async fn import_file_rejects_garbage_and_missing_files() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    // 不存在的文件
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file: dir.path().join("nope").to_string_lossy().to_string(),
            name: None,
            passphrase: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("missing file must fail");
    assert!(err.to_string().contains("Cannot read key file"));

    // 垃圾内容 / 公钥行当私钥 → 解析层拒绝
    let garbage = write_key_file(&dir, "garbage", "not a key at all");
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file: garbage.to_string_lossy().to_string(),
            name: None,
            passphrase: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("garbage file must fail");
    assert!(
        err.to_string()
            .contains("Unrecognized private key file format"),
        "{err}"
    );

    let (_, pub_line) = openssh_pem(ssh_key::Algorithm::Ed25519);
    let pub_file = write_key_file(&dir, "id_ed25519.pub", &pub_line);
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::ImportFile {
            identity: "alice".to_string(),
            file: pub_file.to_string_lossy().to_string(),
            name: None,
            passphrase: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("public key file must fail");
    assert!(
        err.to_string()
            .contains("Unrecognized private key file format"),
        "{err}"
    );
}

// ------------------------------------------------------------------
// generate: 页面内/CLI 生成新密钥对（rsa 走 core 测试，这里不跑 4096 位）
// ------------------------------------------------------------------

#[tokio::test]
async fn generate_stores_keypair_and_applies_name_fallback() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    // 一把带 comment 不带 --name：条目名回退 comment
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            key_type: "ed25519".to_string(),
            comment: Some("gen-test".to_string()),
            name: None,
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect("ed25519 generate works");

    let creds = alice_credentials(&config, "master-pin").await;
    let (ssh_id, _) = creds
        .iter()
        .find(|(_, t)| matches!(t, CredentialType::SshKey))
        .expect("generated ssh credential present")
        .clone();
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.authenticate_user("master-pin").await.unwrap();
    let cred = service.get_credential(&ssh_id).await.unwrap().unwrap();
    assert_eq!(cred.name, "gen-test", "名字回退 comment");

    let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&ssh_id).await.unwrap()
    else {
        panic!("ssh key data readable");
    };
    assert_eq!(ssh.key_type, "ed25519");
    assert_eq!(ssh.passphrase, None);
    // ed25519 生成走库内既有约定：BASE64 seed（非 PEM；agent 双格式加载
    // seed 优先），公钥行以重建 verifying key 为独立裁判
    let seed = BASE64.decode(&ssh.private_key).unwrap();
    assert_eq!(seed.len(), 32, "ed25519 私钥 = 32B seed");
    use ed25519_dalek::SigningKey;
    let seed_bytes: [u8; 32] = seed.as_slice().try_into().unwrap();
    let expected_pub = SigningKey::from_bytes(&seed_bytes).verifying_key();
    let parsed_pub = ssh_key::PublicKey::from_openssh(&ssh.public_key).unwrap();
    assert_eq!(
        parsed_pub.key_data().ed25519().unwrap().0,
        *expected_pub.as_bytes(),
        "公钥行与 seed 重建的公钥一致"
    );
    assert!(ssh.public_key.ends_with("gen-test"), "comment 进公钥行");

    // 二把带 --name + ecdsa：label 优先
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            key_type: "ecdsa".to_string(),
            comment: Some("ignored-comment".to_string()),
            name: Some("my-ecdsa".to_string()),
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect("ecdsa generate works");
    let creds = alice_credentials(&config, "master-pin").await;
    let ecdsa_id = creds
        .iter()
        .find(|(id, _)| *id != ssh_id)
        .map(|(id, _)| *id)
        .expect("second credential present");
    let cred = service.get_credential(&ecdsa_id).await.unwrap().unwrap();
    assert_eq!(cred.name, "my-ecdsa", "--name 优先于 comment");
}

#[tokio::test]
async fn generate_rejects_unknown_key_type() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            key_type: "dsa".to_string(),
            comment: None,
            name: None,
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("unknown type must fail");
    assert!(
        err.to_string().contains("Unsupported SSH key type: dsa"),
        "{err}"
    );
}
