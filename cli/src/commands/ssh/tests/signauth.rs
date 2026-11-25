use super::super::host::{authorized_keys_plan, bare_public_line, sh_quote};
use super::*;

// ------------------------------------------------------------------
// gpg-sign: SSHSIG signing for git commits.
// ------------------------------------------------------------------

/// Real ssh-keygen reference vector (the same one as core/src/crypto/sshsig.rs:
/// ed25519 signatures are deterministic, so our output is correct iff it is
/// byte-for-byte identical to `ssh-keygen -Y sign`).
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

/// Import the reference seed under the given identity and return the new credential id.
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

    // Default -f (the only key in the vault) + default output <file>.sig — the shape git calls it with
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

    // keyspec = credential UUID -> likewise byte-for-byte
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

    // keyspec = public key line literal / .pub file path
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
    // Output for a non-default namespace should pass core's verify
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

    // -Y only supports sign (git never passes anything else, but keep the divergence from ssh-keygen explicit)
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

    // File to sign does not exist
    let err = gpg_sign_via_dispatch(&config, None, &dir.path().join("missing"), None)
        .await
        .expect_err("missing file must fail");
    assert!(err.to_string().contains("Cannot read"));

    // Two keys in the vault and no -f given
    import_reference_key(&config, "bob").await;
    let err = gpg_sign_via_dispatch(&config, None, &msg, None)
        .await
        .expect_err("ambiguous vault must fail");
    assert!(err.to_string().contains("pick one with -f"), "{err}");

    // Unknown credential UUID
    let err = gpg_sign_via_dispatch(&config, Some(Uuid::new_v4().to_string()), &msg, None)
        .await
        .expect_err("unknown uuid must fail");
    assert!(err.to_string().contains("not an SSH key"), "{err}");

    // Public key line that is not ssh-ed25519
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

    // ed25519 public key line matching no vault key
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

    // Empty vault (every identity's keys deleted) and no -f given
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
    // The audit write is awaited inline, so the rows can be queried directly
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

    // The blob ends up embedded in an awk program body wrapped in double quotes — non-base64 characters must be refused
    assert!(authorized_keys_plan("remove", path, "BB;BB").is_err());

    let list = authorized_keys_plan("list", path, "BBBB").unwrap();
    assert!(list.contains("cat \"$HOME/.ssh/authorized_keys\""));
    assert!(list.contains("test -f"));

    // Custom paths are single-quote escaped as untrusted content
    let custom = sh_quote("/srv/keys/a b'c");
    assert_eq!(custom, "'/srv/keys/a b'\\''c'");
    let add_custom = authorized_keys_plan("add", &custom, line).unwrap();
    assert!(add_custom.contains("touch '/srv/keys/a b'\\''c'"));

    // Bare line: comments/options stripped, keeping only algo + blob; malformed input falls back verbatim
    assert_eq!(
        bare_public_line("ssh-ed25519 AAAA some comment"),
        "ssh-ed25519 AAAA"
    );
    assert_eq!(bare_public_line("ssh-ed25519 AAAA"), "ssh-ed25519 AAAA");
    assert_eq!(bare_public_line("garbage"), "garbage");
}

/// Fake ssh: executes the "last argument" (the remote script) inside the sandbox
/// HOME — the tests run exactly the script that `authorized_keys_plan` generates.
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

    // add -> the line is written and matches the reference public key exactly (with tidied line endings)
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, false, false, false, None)
        .await
        .expect("add works");
    assert_eq!(
        std::fs::read_to_string(&akey).unwrap().trim(),
        REF_PUBLIC_LINE
    );

    // Idempotent: adding once more leaves the same single line, with no duplicates
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, false, false, false, None)
        .await
        .expect("re-add works");
    assert_eq!(std::fs::read_to_string(&akey).unwrap().lines().count(), 1);

    // list is read-only, it never writes
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, false, true, false, None)
        .await
        .expect("list works");
    assert_eq!(std::fs::read_to_string(&akey).unwrap().lines().count(), 1);

    // remove -> the line is deleted; a second remove is idempotent (test -f + awk rewriting an empty file)
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, true, false, false, Some(cred))
        .await
        .expect("remove works");
    assert!(std::fs::read_to_string(&akey).unwrap().trim().is_empty());
    let ui = ScriptedUi::new().password("master-pin");
    run_authorize(&config, &ui, true, false, false, None)
        .await
        .expect("re-remove works");

    // Audit rows (awaited inline inside the handler, so no polling is needed)
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
    // add x2 + list + remove x2 = 5 rows in total
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

    // No SSH keys under the identity
    let ui = ScriptedUi::new().password("master-pin");
    let err = run_authorize(&config, &ui, "bob", None)
        .await
        .expect_err("keyless identity must fail");
    assert!(err.to_string().contains("has no SSH keys"), "{err}");

    // Two keys and no --id given
    let key_a = import_reference_key(&config, "alice").await;
    import_reference_key(&config, "alice").await;
    let ui = ScriptedUi::new().password("master-pin");
    let err = run_authorize(&config, &ui, "alice", None)
        .await
        .expect_err("ambiguous identity must fail");
    assert!(err.to_string().contains("pick one with --id"), "{err}");

    // Unknown --id
    let ui = ScriptedUi::new().password("master-pin");
    let err = run_authorize(&config, &ui, "alice", Some(Uuid::new_v4()))
        .await
        .expect_err("unknown id must fail");
    assert!(
        err.to_string().contains("is not an SSH key of identity"),
        "{err}"
    );

    // dry-run: even a nonexistent ssh binary does not error (nothing gets spawned); a real run would
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
