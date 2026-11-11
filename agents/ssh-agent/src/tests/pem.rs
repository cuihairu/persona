use super::*;

#[tokio::test]
async fn pem_rsa_credential_loads_and_signs_rsa_sha2() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Rsa { hash: None },
    )
    .unwrap();
    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
    let pub_line = key.public_key().to_openssh().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    std::env::set_var("PERSONA_DB_PATH", dir.path().join("audit.db"));
    seed_vault_with_ssh_credentials(
        &db_path,
        vec![("rsa-pem", pem_credential_data(&pem, &pub_line, "rsa"))],
    )
    .await;

    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    assert_eq!(agent.keys.len(), 1, "imported RSA PEM loads");
    let loaded = agent.keys[0].clone();
    assert_eq!(
        public_key_algorithm(&loaded.public_blob).as_deref(),
        Some("ssh-rsa")
    );

    // flags=0 → rsa-sha2-512（SHA-1 的 ssh-rsa 不再产出）
    // 独立裁判：从 PEM 的 n/e 重建 rsa 公钥验签
    let kp = key.key_data().rsa().unwrap();
    let to_big = |m: &ssh_key::Mpint| rsa::BigUint::from_bytes_be(m.as_positive_bytes().unwrap());
    let rsa_public =
        rsa::RsaPublicKey::new(to_big(kp.public().n()), to_big(kp.public().e())).unwrap();

    let pkt = agent
        .sign_response(&sign_payload_for(&loaded, b"rsa-data"))
        .await
        .unwrap();
    let (algo, sig_bytes) = parse_signature_blob(&pkt);
    assert_eq!(algo, "rsa-sha2-512");
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    let verifying = VerifyingKey::<rsa::sha2::Sha512>::new(rsa_public.clone());
    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
    verifying.verify(b"rsa-data", &sig).unwrap();

    // flags=2 (SSH_AGENT_RSA_SHA2_256) → rsa-sha2-256
    let mut payload = Vec::new();
    write_ssh_string(&mut payload, &loaded.public_blob).unwrap();
    write_ssh_string(&mut payload, b"rsa-data").unwrap();
    payload.extend_from_slice(&2u32.to_be_bytes());
    let pkt = agent.sign_response(&payload).await.unwrap();
    let (algo, sig_bytes) = parse_signature_blob(&pkt);
    assert_eq!(algo, "rsa-sha2-256");
    let verifying = VerifyingKey::<rsa::sha2::Sha256>::new(rsa_public);
    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
    verifying.verify(b"rsa-data", &sig).unwrap();

    std::env::remove_var("PERSONA_DB_PATH");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn pem_ecdsa_credential_loads_and_signs_nistp256() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
    let pub_line = key.public_key().to_openssh().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    std::env::set_var("PERSONA_DB_PATH", dir.path().join("audit.db"));
    seed_vault_with_ssh_credentials(
        &db_path,
        vec![("ecdsa-pem", pem_credential_data(&pem, &pub_line, "ecdsa"))],
    )
    .await;

    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    assert_eq!(agent.keys.len(), 1, "imported ECDSA PEM loads");
    let loaded = agent.keys[0].clone();
    assert_eq!(
        public_key_algorithm(&loaded.public_blob).as_deref(),
        Some("ecdsa-sha2-nistp256")
    );

    let pkt = agent
        .sign_response(&sign_payload_for(&loaded, b"ecdsa-data"))
        .await
        .unwrap();
    let (algo, sig_bytes) = parse_signature_blob(&pkt);
    assert_eq!(algo, "ecdsa-sha2-nistp256");

    // 签名是 mpint r || mpint s（RFC 5656 线格式，不是 DER）
    let mut s: &[u8] = &sig_bytes;
    let r = read_ssh_string(&mut s).unwrap();
    let sig_s = read_ssh_string(&mut s).unwrap();
    assert!(s.is_empty());
    use p256::ecdsa::signature::Verifier;
    use p256::FieldBytes;
    // mpint 带符号：标量高位为 1 时线格式补 0x00（恰好覆盖这条随机路径），
    // 重构 32B 标量前先剥掉补位
    let strip_sign_pad = |mut v: Vec<u8>| -> Vec<u8> {
        while v.len() > 32 {
            v.remove(0);
        }
        v
    };
    let sig = p256::ecdsa::Signature::from_scalars(
        FieldBytes::try_from(strip_sign_pad(r).as_slice()).unwrap(),
        FieldBytes::try_from(strip_sign_pad(sig_s).as_slice()).unwrap(),
    )
    .unwrap();
    let private_bytes = key.key_data().ecdsa().unwrap().private_key_bytes();
    let signing =
        p256::ecdsa::SigningKey::from_bytes(&FieldBytes::try_from(private_bytes).unwrap()).unwrap();
    let verifying = p256::ecdsa::VerifyingKey::from(&signing);
    verifying.verify(b"ecdsa-data", &sig).unwrap();

    std::env::remove_var("PERSONA_DB_PATH");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn pem_ed25519_credential_normalizes_to_seed_signing() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
    let pub_line = key.public_key().to_openssh().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    std::env::set_var("PERSONA_DB_PATH", dir.path().join("audit.db"));
    seed_vault_with_ssh_credentials(
        &db_path,
        vec![("ed-pem", pem_credential_data(&pem, &pub_line, "ed25519"))],
    )
    .await;

    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    assert_eq!(agent.keys.len(), 1, "imported ed25519 PEM loads");
    let loaded = agent.keys[0].clone();
    assert_eq!(
        loaded.signing_key.algorithm_name(),
        "ssh-ed25519",
        "PEM ed25519 normalizes to the seed path"
    );

    let pkt = agent
        .sign_response(&sign_payload_for(&loaded, b"ed-data"))
        .await
        .unwrap();
    let (algo, sig_bytes) = parse_signature_blob(&pkt);
    assert_eq!(algo, "ssh-ed25519");
    // 独立裁判：从 PEM 里的 seed 重建 verifying key 验签
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    verifying.verify_strict(b"ed-data", &sig).unwrap();

    std::env::remove_var("PERSONA_DB_PATH");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn encrypted_pem_credential_is_skipped() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    // encrypt 返回加密后的新实例——必须接住，原实例仍是明文
    let key = key
        .encrypt(&mut rand_core::UnwrapErr(rand::rngs::SysRng), "hunter2")
        .unwrap();
    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    seed_vault_with_ssh_credentials(
        &db_path,
        vec![("locked", pem_credential_data(&pem, "garbage", "ed25519"))],
    )
    .await;

    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    assert!(agent.keys.is_empty(), "still-encrypted PEM must not load");
}

#[tokio::test]
async fn mismatched_public_line_is_rebuilt_from_private() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    // ed25519 私钥 + 一把真实但不同的 rsa 公钥行 → 算法不匹配，重建
    let key = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
    let other_rsa = ssh_key::private::PrivateKey::random(
        &mut rand_core::UnwrapErr(rand::rngs::SysRng),
        ssh_key::Algorithm::Rsa { hash: None },
    )
    .unwrap();
    let wrong_pub_line = other_rsa.public_key().to_openssh().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    seed_vault_with_ssh_credentials(
        &db_path,
        vec![(
            "mismatch",
            pem_credential_data(&pem, &wrong_pub_line, "ed25519"),
        )],
    )
    .await;

    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    assert_eq!(agent.keys.len(), 1);
    assert_eq!(
        public_key_algorithm(&agent.keys[0].public_blob).as_deref(),
        Some("ssh-ed25519"),
        "blob rebuilt from the private key, not the mismatched rsa line"
    );
}
