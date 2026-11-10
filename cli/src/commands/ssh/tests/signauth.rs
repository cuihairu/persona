use super::super::host::{authorized_keys_plan, bare_public_line, sh_quote};
use super::*;

// ------------------------------------------------------------------
// gpg-sign: SSHSIG signing for git commits.
// ------------------------------------------------------------------

/// 真 ssh-keygen 参照向量（与 core/src/crypto/sshsig.rs 同一份：ed25519
/// 确定性签名 ⇒ 我们输出正确 ⇔ 与 `ssh-keygen -Y sign` 逐字节一致）。
const REF_SEED: [u8; 32] = [
    0x59, 0xd9, 0x98, 0xd6, 0xdb, 0x19, 0xcc, 0x8f, 0x7f, 0xe2, 0x45, 0xfa, 0x8a, 0x04, 0xe6, 0x10,
    0xd8, 0x84, 0x5d, 0xff, 0x80, 0xdb, 0xec, 0x8d, 0xfc, 0x88, 0x15, 0xe1, 0x8e, 0xa0, 0x83, 0x8d,
];
const REF_PUBLIC_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaLEB5wGG3c9s7atvxL3FnUPZ+Gwqp/YOsLfQqzJeNg";
const REF_MESSAGE: &[u8] = b"hello persona\nsecond line\n";
const REF_ARMOR: &str = concat!(
    "-----BEGIN SSH SIGNATURE-----\n",
    "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJosQHnAYbdz2ztq2/EvcWdQ9n4\n",
    "bCqn9g6wt9CrMl42AAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\n",
    "AAAAQJt/PJ1nuI6ToAzsanR3MLYqM2qiVC5IWESIGbXh6o4hiHoB8ng7N1/2nUDiqAq55b\n",
    "nM36bAlsZrid+A5TX5agU=\n",
    "-----END SSH SIGNATURE-----\n",
);

/// 把参照 seed 导入 alice 名下，返回新凭据 id。
async fn import_reference_key(config: &CliConfig, identity: &str) -> Uuid {
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Import {
            identity: identity.to_string(),
            name: Some("signing-key".to_string()),
            seed_base64: Some(BASE64.encode(REF_SEED)),
            seed_hex: None,
        }),
        config,
        &ui,
    )
    .await
    .expect("reference seed imports");
    alice_credentials(config, "master-pin")
        .await
        .into_iter()
        .find(|(_, t)| matches!(t, CredentialType::SshKey))
        .map(|(id, _)| id)
        .expect("imported ssh key is in the vault")
}

async fn gpg_sign_via_dispatch(
    config: &CliConfig,
    key: Option<String>,
    file: &std::path::Path,
    output: Option<String>,
) -> anyhow::Result<()> {
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::GpgSign {
            mode: "sign".to_string(),
            namespace: "git".to_string(),
            key,
            file: file.to_string_lossy().into_owned(),
            output,
        }),
        config,
        &ui,
    )
    .await
}

#[tokio::test]
async fn gpg_sign_output_is_byte_identical_to_ssh_keygen() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    let msg = dir.path().join("commit-msg");
    std::fs::write(&msg, REF_MESSAGE).unwrap();

    // 默认 -f（保险库唯一 key）+ 默认输出 <file>.sig —— 与 git 调用形状一致
    let cred = import_reference_key(&config, "alice").await;
    gpg_sign_via_dispatch(&config, None, &msg, None)
        .await
        .expect("signing with the only vault key works");
    let sig = std::fs::read(dir.path().join("commit-msg.sig")).unwrap();
    assert_eq!(
        String::from_utf8(sig).unwrap(),
        REF_ARMOR,
        "must match ssh-keygen -Y sign byte-for-byte"
    );

    // keyspec = 凭据 UUID → 同样逐字节
    gpg_sign_via_dispatch(
        &config,
        Some(cred.to_string()),
        &msg,
        Some(
            dir.path()
                .join("by-uuid.sig")
                .to_string_lossy()
                .into_owned(),
        ),
    )
    .await
    .expect("signing by credential uuid works");

    // keyspec = 公钥行字面量 / .pub 文件路径
    let pub_file = dir.path().join("ref.pub");
    std::fs::write(&pub_file, format!("{REF_PUBLIC_LINE} comment\n")).unwrap();
    for spec in [
        REF_PUBLIC_LINE.to_string(),
        format!("persona:ssh:{cred}"),
        pub_file.to_string_lossy().into_owned(),
    ] {
        gpg_sign_via_dispatch(
            &config,
            Some(spec),
            &msg,
            Some(
                dir.path()
                    .join("by-line.sig")
                    .to_string_lossy()
                    .into_owned(),
            ),
        )
        .await
        .expect("keyspec resolves to the reference key");
    }
    // 非默认 namespace 的产物应当能被 core 的 verify 验过
    let ns_msg = dir.path().join("ns-file");
    std::fs::write(&ns_msg, b"payload").unwrap();
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::GpgSign {
            mode: "sign".to_string(),
            namespace: "file".to_string(),
            key: Some(cred.to_string()),
            file: ns_msg.to_string_lossy().into_owned(),
            output: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect("non-git namespace signs");
    let blob = persona_core::crypto::sshsig::disarmor(
        &std::fs::read_to_string(dir.path().join("ns-file.sig")).unwrap(),
    )
    .unwrap();
    persona_core::crypto::sshsig::verify(&blob, "file", b"payload")
        .expect("namespace-bound signature verifies");
}

#[tokio::test]
async fn gpg_sign_rejects_bad_mode_keyspec_and_inputs() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;
    import_reference_key(&config, "alice").await;
    let msg = dir.path().join("commit-msg");
    std::fs::write(&msg, REF_MESSAGE).unwrap();

    // -Y 只支持 sign（git 不会传别的，但保持与 ssh-keygen 的差异明确）
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::GpgSign {
            mode: "verify".to_string(),
            namespace: "git".to_string(),
            key: None,
            file: msg.to_string_lossy().into_owned(),
            output: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("non-sign mode must fail");
    assert!(err.to_string().contains("Only `-Y sign`"));

    // 待签文件不存在
    let err = gpg_sign_via_dispatch(&config, None, &dir.path().join("missing"), None)
        .await
        .expect_err("missing file must fail");
    assert!(err.to_string().contains("Cannot read"));

    // 保险库里有两把 key 且未给 -f
    import_reference_key(&config, "bob").await;
    let err = gpg_sign_via_dispatch(&config, None, &msg, None)
        .await
        .expect_err("ambiguous vault must fail");
    assert!(err.to_string().contains("pick one with -f"), "{err}");

    // 未知的凭据 UUID
    let err = gpg_sign_via_dispatch(&config, Some(Uuid::new_v4().to_string()), &msg, None)
        .await
        .expect_err("unknown uuid must fail");
    assert!(err.to_string().contains("not an SSH key"), "{err}");

    // 非 ssh-ed25519 的公钥行
    let err = gpg_sign_via_dispatch(
        &config,
        Some("ssh-rsa AAAAB3NzaC1yc2E".to_string()),
        &msg,
        None,
    )
    .await
    .expect_err("rsa keyspec must fail");
    assert!(err
        .to_string()
        .contains("neither a credential UUID, nor a readable key file"));

    // 匹配不到任何 vault key 的 ed25519 公钥行
    let err = gpg_sign_via_dispatch(
        &config,
        Some(format!("ssh-ed25519 {}", BASE64.encode([3u8; 51]))),
        &msg,
        None,
    )
    .await
    .expect_err("foreign key must fail");
    assert!(
        err.to_string().contains("No vault SSH key matches"),
        "{err}"
    );

    // 空保险库（所有 identity 的 key 全删）且未给 -f
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.authenticate_user("master-pin").await.unwrap();
    for identity in service.get_identities().await.unwrap() {
        for cred in service
            .get_credentials_for_identity(&identity.id)
            .await
            .unwrap()
        {
            if matches!(cred.credential_type, CredentialType::SshKey) {
                service.delete_credential(&cred.id).await.unwrap();
            }
        }
    }
    let err = gpg_sign_via_dispatch(&config, None, &msg, None)
        .await
        .expect_err("empty vault must fail");
    assert!(
        err.to_string().contains("No SSH keys in the vault"),
        "{err}"
    );
}

#[tokio::test]
async fn gpg_sign_writes_an_ssh_sign_audit_row() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;
    let cred = import_reference_key(&config, "alice").await;
    let msg = dir.path().join("commit-msg");
    std::fs::write(&msg, REF_MESSAGE).unwrap();

    gpg_sign_via_dispatch(&config, Some(cred.to_string()), &msg, None)
        .await
        .expect("signing works");

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let repo = persona_core::storage::AuditLogRepository::new(db);
    // 审计是 inline await 的，直接查即可
    let rows = repo
        .find_by_action(&persona_core::models::AuditAction::Custom(
            "ssh_sign".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one ssh_sign row expected");
    let row = &rows[0];
    assert_eq!(row.credential_id, Some(cred));
    assert_eq!(
        row.metadata.get("via").map(String::as_str),
        Some("gpg-sign")
    );
    assert_eq!(
        row.metadata.get("namespace").map(String::as_str),
        Some("git")
    );
    assert_eq!(
        row.metadata.get("data_sha256").map(String::as_str),
        Some(persona_core::crypto::hashing::Sha256Hasher::hash_hex(REF_MESSAGE).as_str())
    );
}

#[test]
fn authorize_plan_builders_bare_lines_and_quoting() {
    let path = "\"$HOME/.ssh/authorized_keys\"";
    let line = "ssh-ed25519 AAAA";
    let add = authorized_keys_plan("add", path, line).unwrap();
    assert!(add.contains("mkdir -p \"$HOME/.ssh\""));
    assert!(add.contains("chmod 700 \"$HOME/.ssh\""));
    assert!(add.contains("chmod 600 \"$HOME/.ssh/authorized_keys\""));
    assert!(
        add.contains("if grep -qxF 'ssh-ed25519 AAAA'"),
        "idempotent add via grep -qxF: {add}"
    );
    assert!(add.contains("printf '%s\\n' 'ssh-ed25519 AAAA' >>"));

    let remove = authorized_keys_plan("remove", path, "BBBB").unwrap();
    assert!(remove.contains("awk '$2 != \"BBBB\"'"));
    assert!(remove.contains(".persona-tmp"), "tmp rewrite, not mv");

    // blob 会内嵌 awk 双引号程序体——非 base64 字符集必须拒绝
    assert!(authorized_keys_plan("remove", path, "BB;BB").is_err());

    let list = authorized_keys_plan("list", path, "BBBB").unwrap();
    assert!(list.contains("cat \"$HOME/.ssh/authorized_keys\""));
    assert!(list.contains("test -f"));

    // 自定义路径按不可信内容单引号转义
    let custom = sh_quote("/srv/keys/a b'c");
    assert_eq!(custom, "'/srv/keys/a b'\\''c'");
    let add_custom = authorized_keys_plan("add", &custom, line).unwrap();
    assert!(add_custom.contains("touch '/srv/keys/a b'\\''c'"));

    // bare 行：去注释/选项，只留 algo + blob；畸形输入原样兜底
    assert_eq!(
        bare_public_line("ssh-ed25519 AAAA some comment"),
        "ssh-ed25519 AAAA"
    );
    assert_eq!(bare_public_line("ssh-ed25519 AAAA"), "ssh-ed25519 AAAA");
    assert_eq!(bare_public_line("garbage"), "garbage");
}

/// 假 ssh：把「最后一个参数」（远端脚本）放到沙箱 HOME 里执行——测试
/// 跑的就是 `authorized_keys_plan` 生成的脚本本身。
#[cfg(unix)]
fn plant_fake_ssh(dir: &TempDir, home: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let stub = dir.path().join("fake-ssh");
    let script = format!(
        "#!/bin/sh\nfor last in \"$@\"; do :; done\nHOME='{}' exec sh -c \"$last\"\n",
        home.display()
    );
    std::fs::write(&stub, &script).unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    stub
}

#[cfg(unix)]
#[tokio::test]
async fn authorize_round_trip_through_fake_ssh() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;
    let cred = import_reference_key(&config, "alice").await;
    let remote_home = TempDir::new().unwrap();
    let stub = plant_fake_ssh(&dir, remote_home.path());
    let _state = sandbox_agent_state_dir(&dir);
    let _ssh = EnvVarGuard::set("PERSONA_SSH_BINARY", &stub);

    async fn run_authorize(
        config: &CliConfig,
        ui: &ScriptedUi,
        remove: bool,
        list: bool,
        dry_run: bool,
        id: Option<Uuid>,
    ) -> anyhow::Result<()> {
        execute_with(
            ssh_args(SshSubcommand::Authorize {
                identity: "alice".to_string(),
                host: "server.example".to_string(),
                id,
                remove,
                list,
                dry_run,
                port: None,
                remote_path: None,
            }),
            config,
            ui,
        )
        .await
    }

    let akey = remote_home.path().join(".ssh/authorized_keys");

    // add → 行写入且与参照公钥完全一致（整形换行）
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, false, false, false, None)
        .await
        .expect("add works");
    assert_eq!(
        std::fs::read_to_string(&akey).unwrap().trim(),
        REF_PUBLIC_LINE
    );

    // 幂等：再 add 一次仍是同一行、没有重复
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, false, false, false, None)
        .await
        .expect("re-add works");
    assert_eq!(std::fs::read_to_string(&akey).unwrap().lines().count(), 1);

    // list 只读不写
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, false, true, false, None)
        .await
        .expect("list works");
    assert_eq!(std::fs::read_to_string(&akey).unwrap().lines().count(), 1);

    // remove → 行被删；再 remove 幂等（test -f + awk 空重写）
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, true, false, false, Some(cred))
        .await
        .expect("remove works");
    assert!(std::fs::read_to_string(&akey).unwrap().trim().is_empty());
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, true, false, false, None)
        .await
        .expect("re-remove works");

    // 审计行（handler 内 inline await，无需轮询）
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let repo = persona_core::storage::AuditLogRepository::new(db);
    let rows = repo
        .find_by_action(&persona_core::models::AuditAction::Custom(
            "ssh_authorize".to_string(),
        ))
        .await
        .unwrap();
    // add ×2 + list + remove ×2 共 5 行
    assert!(
        rows.len() >= 5,
        "every authorize action audited: {}",
        rows.len()
    );
    for row in &rows {
        assert_eq!(row.credential_id, Some(cred));
        assert_eq!(
            row.metadata.get("host").map(String::as_str),
            Some("server.example")
        );
    }
}

#[tokio::test]
async fn authorize_rejections_and_dry_run() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    async fn run_authorize(
        config: &CliConfig,
        ui: &ScriptedUi,
        identity: &str,
        id: Option<Uuid>,
    ) -> anyhow::Result<()> {
        execute_with(
            ssh_args(SshSubcommand::Authorize {
                identity: identity.to_string(),
                host: "server.example".to_string(),
                id,
                remove: false,
                list: false,
                dry_run: false,
                port: None,
                remote_path: None,
            }),
            config,
            ui,
        )
        .await
    }

    // 身份名下没有任何 SSH key
    let ui = ScriptedUi::new().password("master-pin");
    let err = run_authorize(&config, &ui, "bob", None)
        .await
        .expect_err("keyless identity must fail");
    assert!(err.to_string().contains("has no SSH keys"), "{err}");

    // 两把 key 且未给 --id
    let key_a = import_reference_key(&config, "alice").await;
    import_reference_key(&config, "alice").await;
    let ui = ScriptedUi::new().password("master-pin");
    let err = run_authorize(&config, &ui, "alice", None)
        .await
        .expect_err("ambiguous identity must fail");
    assert!(err.to_string().contains("pick one with --id"), "{err}");

    // 未知 --id
    let ui = ScriptedUi::new().password("master-pin");
    let err = run_authorize(&config, &ui, "alice", Some(Uuid::new_v4()))
        .await
        .expect_err("unknown id must fail");
    assert!(
        err.to_string().contains("is not an SSH key of identity"),
        "{err}"
    );

    // dry-run：ssh 二进制指向不存在也不报错（不 spawn），真实跑才报
    let _ssh = EnvVarGuard::set("PERSONA_SSH_BINARY", dir.path().join("no-such-ssh"));
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Authorize {
            identity: "alice".to_string(),
            host: "server.example".to_string(),
            id: Some(key_a),
            remove: false,
            list: false,
            dry_run: true,
            port: None,
            remote_path: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect("dry-run must not spawn");
    let ui = ScriptedUi::new().password("master-pin");
    let err = execute_with(
        ssh_args(SshSubcommand::Authorize {
            identity: "alice".to_string(),
            host: "server.example".to_string(),
            id: Some(key_a),
            remove: false,
            list: false,
            dry_run: false,
            port: None,
            remote_path: None,
        }),
        &config,
        &ui,
    )
    .await
    .expect_err("missing ssh binary must fail");
    assert!(err.to_string().contains("Failed to run ssh"), "{err}");
}
