use super::*;

#[test]
fn decrypt_private_key_rejects_unknown_version() {
    let encrypted = encrypt_private_key(&[7u8; 32], "pw").unwrap();
    let mut future = encrypted.clone();
    future.version = 2;
    let err = decrypt_private_key(&future, "pw").expect_err("unknown version must be rejected");
    assert!(err
        .to_string()
        .contains("Unsupported encryption version: 2"));
}

#[test]
fn decrypt_mnemonic_rejects_unknown_version() {
    let encrypted = encrypt_mnemonic("test phrase", "pw").unwrap();
    let mut future = encrypted.clone();
    future.version = 99;
    let err = decrypt_mnemonic(&future, "pw").expect_err("unknown version must be rejected");
    assert!(err
        .to_string()
        .contains("Unsupported encryption version: 99"));
}

#[test]
fn decrypt_mnemonic_rejects_non_utf8_payload() {
    let password = "pw";
    // Hand-build an EncryptedMnemonic whose plaintext is not valid UTF-8.
    let encrypted = encrypt_data(&[0xFF, 0xFE, 0xC0], password.as_bytes()).unwrap();
    let forged = EncryptedMnemonic {
        version: 1,
        encrypted_phrase: encrypted.ciphertext,
        salt: encrypted.salt,
        nonce: encrypted.nonce,
    };
    let err = decrypt_mnemonic(&forged, password).expect_err("non-UTF-8 mnemonic must be rejected");
    assert!(err.to_string().contains("Invalid UTF-8"));
}

#[test]
fn decrypt_private_key_rejects_wrong_password() {
    let encrypted = encrypt_private_key(&[3u8; 32], "correct").unwrap();
    let err = decrypt_private_key(&encrypted, "wrong").expect_err("wrong password must fail");
    assert!(err.to_string().contains("Failed to decrypt private key"));
}

#[test]
fn decrypt_mnemonic_rejects_wrong_password() {
    let encrypted = encrypt_mnemonic("phrase", "correct").unwrap();
    let err = decrypt_mnemonic(&encrypted, "wrong").expect_err("wrong password must fail");
    assert!(err.to_string().contains("Failed to decrypt mnemonic"));
}

#[test]
fn mnemonic_encryption_roundtrip_with_special_chars() {
    let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    // Non-ASCII exercises the UTF-8 path end to end.
    let unicode_phrase = "成功 ハэлло wörld";
    let password = "pw-😀";
    for phrase in [phrase, unicode_phrase] {
        let encrypted = encrypt_mnemonic(phrase, password).unwrap();
        assert_eq!(encrypted.version, 1);
        assert_eq!(decrypt_mnemonic(&encrypted, password).unwrap(), phrase);
    }
}

#[test]
fn import_from_keystore_rejects_malformed_json() {
    let err = import_from_keystore("not json at all", "pw")
        .expect_err("malformed keystore JSON must be rejected");
    assert!(err.to_string().contains("Invalid keystore format"));
}

#[test]
fn import_from_keystore_rejects_wrong_version() {
    let keystore = KeystoreV3 {
        version: 1,
        id: Uuid::new_v4().to_string(),
        address: None,
        crypto: KeystoreCrypto {
            cipher: "aes-128-ctr".to_string(),
            ciphertext: "aa".to_string(),
            cipherparams: CipherParams {
                iv: "bb".to_string(),
            },
            kdf: "scrypt".to_string(),
            kdfparams: KdfParams::Scrypt {
                dklen: 32,
                n: 16384,
                p: 1,
                r: 8,
                salt: "cc".to_string(),
            },
            mac: "dd".to_string(),
        },
    };
    let json = serde_json::to_string(&keystore).unwrap();
    let err = import_from_keystore(&json, "pw").expect_err("non-v3 keystore must be rejected");
    assert!(err.to_string().contains("Unsupported keystore version: 1"));
}

/// The canonical scrypt vector from go-ethereum's own testdata
/// (`accounts/keystore/testdata/v3_test_vector.json`, the
/// "wikipage_test_vector_scrypt" entry). Conformance is self-contained:
/// a wrong MAC formula fails the MAC check; wrong AES/CTR composition
/// yields a key whose address cannot match the spec's published address.
#[test]
fn import_from_keystore_spec_vector() {
    let keystore_json = r#"{
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
                "kdf": "scrypt",
                "kdfparams": {"dklen": 32, "n": 262144, "r": 1, "p": 8, "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},
                "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
            },
            "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version": 3
        }"#;
    let secret = import_from_keystore(keystore_json, "testpassword")
        .expect("canonical spec vector must decrypt");
    assert_eq!(
        hex::encode(&secret),
        "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
    );

    // secp256k1 address of the recovered key must equal the spec's
    // published address: keccak256(pubkey_xy)[12..].
    let signing_key = k256::ecdsa::SigningKey::from_slice(&secret)
        .expect("recovered key is a valid secp256k1 key");
    let uncompressed = signing_key
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let hash = sha3::Keccak256::digest(&uncompressed[1..]);
    let address = hex::encode(&hash[12..]);
    assert_eq!(address, "008aeeda4d805471df9b2a5b0f38a0c3bcba786b");

    // Wrong password must fail at the MAC, not produce garbage.
    let err = import_from_keystore(keystore_json, "wrongpassword")
        .expect_err("wrong password must not decrypt");
    assert!(err.to_string().contains("MAC mismatch"));
}

/// scrypt KDF layer cross-checked against OpenSSL (python hashlib.scrypt):
/// password "test", salt aa×16, n=16 r=1 p=1 dklen=32.
#[test]
fn keystore_scrypt_derivation_matches_openssl() {
    let crypto = KeystoreCrypto {
        cipher: "aes-128-ctr".to_string(),
        ciphertext: "00".to_string(),
        cipherparams: CipherParams {
            iv: "00".repeat(16),
        },
        kdf: "scrypt".to_string(),
        kdfparams: KdfParams::Scrypt {
            dklen: 32,
            n: 16,
            r: 1,
            p: 1,
            salt: "aa".repeat(16),
        },
        mac: "00".to_string(),
    };
    let dk = derive_keystore_key(&crypto, "test").unwrap();
    assert_eq!(
        hex::encode(dk),
        "977a0f4a5c2267090ead966af8edd176a319dec3607cfcbb0b2436687408ffea"
    );
}

/// pbkdf2 KDF layer cross-checked against OpenSSL (python
/// hashlib.pbkdf2_hmac): password "test", salt bb×8, c=1000, sha256.
#[test]
fn keystore_pbkdf2_derivation_matches_openssl() {
    let crypto = KeystoreCrypto {
        cipher: "aes-128-ctr".to_string(),
        ciphertext: "00".to_string(),
        cipherparams: CipherParams {
            iv: "00".repeat(16),
        },
        kdf: "pbkdf2".to_string(),
        kdfparams: KdfParams::Pbkdf2 {
            dklen: 32,
            c: 1000,
            prf: "hmac-sha256".to_string(),
            salt: "bb".repeat(8),
        },
        mac: "00".to_string(),
    };
    let dk = derive_keystore_key(&crypto, "test").unwrap();
    assert_eq!(
        hex::encode(dk),
        "78862acd1a1b83cc9120c3214f52ae2e04c19918ebd6f6019231ac41189efb35"
    );
}

#[test]
fn pbkdf2_keystore_roundtrip() {
    let secret = [0x5Au8; 32];
    let json = build_pbkdf2_keystore_json(&secret, "roundtrip-pass", 1000);
    let recovered = import_from_keystore(&json, "roundtrip-pass").unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn keystore_scrypt_export_roundtrip() {
    let secret = [0xC0u8; 32];
    let json = export_to_keystore_with_params(
        &secret,
        "export-pass",
        Some("008aeeda4d805471d9ce51f053c6c1265d6a6ad9".to_string()),
        ScryptExportParams {
            log_n: 4,
            r: 1,
            p: 1,
        },
    )
    .unwrap();
    let parsed: KeystoreV3 = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.version, 3);
    assert_eq!(
        parsed.address.as_deref(),
        Some("008aeeda4d805471d9ce51f053c6c1265d6a6ad9")
    );
    let recovered = import_from_keystore(&json, "export-pass").unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn keystore_tampered_ciphertext_fails_mac() {
    let secret = [0x11u8; 32];
    let json = build_pbkdf2_keystore_json(&secret, "mac-pass", 1000);
    let mut keystore: KeystoreV3 = serde_json::from_str(&json).unwrap();
    // Flip one bit of the ciphertext.
    let mut ct = hex::decode(&keystore.crypto.ciphertext).unwrap();
    ct[0] ^= 0x01;
    keystore.crypto.ciphertext = hex::encode(ct);
    let err = import_from_keystore(&serde_json::to_string(&keystore).unwrap(), "mac-pass")
        .expect_err("tampered ciphertext must fail the MAC");
    assert!(err.to_string().contains("MAC mismatch"));
}

#[test]
fn keystore_rejects_unsupported_kdf_cipher_and_prf() {
    let secret = [0x22u8; 32];
    let json = build_pbkdf2_keystore_json(&secret, "fmt-pass", 100);
    let bad_kdf = json.replace("\"pbkdf2\"", "\"bcrypt\"");
    let err =
        import_from_keystore(&bad_kdf, "fmt-pass").expect_err("unsupported kdf must be rejected");
    assert!(err.to_string().contains("Unsupported keystore kdf"));

    let bad_cipher = json.replace("aes-128-ctr", "aes-256-cbc");
    let err = import_from_keystore(&bad_cipher, "fmt-pass")
        .expect_err("unsupported cipher must be rejected");
    assert!(err.to_string().contains("Unsupported keystore cipher"));

    let bad_prf = json.replace("hmac-sha256", "hmac-sha512");
    let err =
        import_from_keystore(&bad_prf, "fmt-pass").expect_err("unsupported prf must be rejected");
    assert!(err.to_string().contains("Unsupported pbkdf2 prf"));
}

#[test]
fn keystore_rejects_oversized_scrypt_work_factor() {
    let crypto = KeystoreCrypto {
        cipher: "aes-128-ctr".to_string(),
        ciphertext: "00".to_string(),
        cipherparams: CipherParams {
            iv: "00".repeat(16),
        },
        kdf: "scrypt".to_string(),
        // 128 * r * n = 128 * 8 * 2^24 = 4 GiB > 256 MiB cap.
        kdfparams: KdfParams::Scrypt {
            dklen: 32,
            n: 16_777_216,
            r: 8,
            p: 1,
            salt: "aa".repeat(16),
        },
        mac: "00".to_string(),
    };
    let keystore = KeystoreV3 {
        version: 3,
        id: Uuid::new_v4().to_string(),
        address: None,
        crypto,
    };
    let json = serde_json::to_string(&keystore).unwrap();
    let err = import_from_keystore(&json, "pw")
        .expect_err("oversized scrypt must be rejected before any work");
    assert!(err.to_string().contains("work factor too high"));
}

/// n and r both set to u32::MAX: 128*r*n overflows u64 (panics in debug,
/// wraps in release). checked_mul must turn that into a "work factor too
/// high" error rather than a crash.
#[test]
fn keystore_rejects_overflowing_scrypt_work_factor() {
    let crypto = KeystoreCrypto {
        cipher: "aes-128-ctr".to_string(),
        ciphertext: "00".to_string(),
        cipherparams: CipherParams {
            iv: "00".repeat(16),
        },
        kdf: "scrypt".to_string(),
        kdfparams: KdfParams::Scrypt {
            dklen: 32,
            n: u32::MAX,
            r: u32::MAX,
            p: 1,
            salt: "aa".repeat(16),
        },
        mac: "00".to_string(),
    };
    let keystore = KeystoreV3 {
        version: 3,
        id: Uuid::new_v4().to_string(),
        address: None,
        crypto,
    };
    let json = serde_json::to_string(&keystore).unwrap();
    let err = import_from_keystore(&json, "pw")
        .expect_err("overflowing scrypt must be rejected before any work");
    assert!(
        err.to_string().contains("work factor too high"),
        "unexpected error: {err}"
    );
}

/// An unbounded pbkdf2 iteration count lets a hostile keystore hang the import
/// (c is a u32; 4 billion HMAC rounds take hours on real hardware). Reject it
/// before deriving anything.
#[test]
fn keystore_rejects_oversized_pbkdf2_iterations() {
    let json = build_pbkdf2_keystore_json(&[0x33u8; 32], "pw", 100)
        .replace("\"c\":100", "\"c\":4000000000");
    let err = import_from_keystore(&json, "pw")
        .expect_err("oversized pbkdf2 iteration count must be rejected before any work");
    assert!(
        err.to_string().contains("work factor too high"),
        "unexpected error: {err}"
    );
}

/// An unbounded dklen lets a hostile keystore force a 4 GiB (u32::MAX)
/// allocation for the derived-key buffer out of a single u32 field — a memory
/// DoS. Both the scrypt and pbkdf2 KDF arms must reject it.
#[test]
fn keystore_rejects_oversized_dklen_before_allocating() {
    let base = build_pbkdf2_keystore_json(&[0x44u8; 32], "pw", 100);
    let json = base.replace("\"dklen\":32", "\"dklen\":4000000000");
    let err = import_from_keystore(&json, "pw")
        .expect_err("oversized pbkdf2 dklen must be rejected before allocating");
    assert!(err.to_string().contains("dklen"), "unexpected error: {err}");

    let crypto = KeystoreCrypto {
        cipher: "aes-128-ctr".to_string(),
        ciphertext: "00".to_string(),
        cipherparams: CipherParams {
            iv: "00".repeat(16),
        },
        kdf: "scrypt".to_string(),
        kdfparams: KdfParams::Scrypt {
            dklen: 4_000_000_000,
            n: 1024,
            r: 8,
            p: 1,
            salt: "aa".repeat(16),
        },
        mac: "00".to_string(),
    };
    let keystore = KeystoreV3 {
        version: 3,
        id: Uuid::new_v4().to_string(),
        address: None,
        crypto,
    };
    let json = serde_json::to_string(&keystore).unwrap();
    let err = import_from_keystore(&json, "pw")
        .expect_err("oversized scrypt dklen must be rejected before allocating");
    assert!(err.to_string().contains("dklen"), "unexpected error: {err}");
}

/// Deterministic mutation harness: starting from a valid keystore with a small
/// work factor, it applies byte flips, truncations and field-level tampering and
/// asserts the parser is total — every mutation yields Ok or Err, never a panic.
/// Fills the keystore mutation-harness gap tracked in ROADMAP.
#[test]
fn keystore_mutation_harness_is_total() {
    let base = build_pbkdf2_keystore_json(&[0x55u8; 32], "harness-pass", 100);
    // The baseline itself must be decryptable, or the harness anchor is void.
    assert!(import_from_keystore(&base, "harness-pass").is_ok());

    let mut cases: Vec<(String, String)> = Vec::new();
    let bytes = base.as_bytes();
    // Byte flips: sample the whole string at a fixed stride, writing three
    // replacement values at each position.
    for pos in (0..bytes.len()).step_by(7) {
        for val in [0x00u8, 0xFF, 0x22] {
            let mut mutated = base.clone().into_bytes();
            mutated[pos] = val;
            cases.push((
                format!("flip@{pos}=0x{val:02X}"),
                String::from_utf8_lossy(&mutated).into_owned(),
            ));
        }
    }
    // Truncations: anchor lengths from the empty string up to nearly the full length.
    for len in [0usize, 1, 2, 5, 10, 50, 100, base.len() / 2, base.len() - 1] {
        cases.push((
            format!("truncate@{len}"),
            base[..len.min(base.len())].to_string(),
        ));
    }
    // Field-level tampering: type confusion, unknown algorithms, out-of-range
    // parameters, and bad hex.
    for (label, mutation) in [
        (
            "version-string",
            base.replace("\"version\":3", "\"version\":\"3\""),
        ),
        (
            "version-zero",
            base.replace("\"version\":3", "\"version\":0"),
        ),
        ("cipher-unknown", base.replace("aes-128-ctr", "aes-256-gcm")),
        ("kdf-unknown", base.replace("\"pbkdf2\"", "\"argon2id\"")),
        ("prf-unknown", base.replace("hmac-sha256", "hmac-sha1")),
        ("c-negative", base.replace("\"c\":100", "\"c\":-1")),
        ("c-huge", base.replace("\"c\":100", "\"c\":4000000000")),
        (
            "dklen-huge",
            base.replace("\"dklen\":32", "\"dklen\":4000000000"),
        ),
        ("dklen-zero", base.replace("\"dklen\":32", "\"dklen\":0")),
        (
            "iv-short",
            base.replace("43434343434343434343434343434343", "4343"),
        ),
        (
            "iv-odd-hex",
            base.replace(
                "43434343434343434343434343434343",
                "4343434343434343434343434343434g",
            ),
        ),
        ("mac-empty", {
            // Mutating mac through serde is safer: it targets the `"mac":"..."` value span
            // directly.
            let mut keystore: serde_json::Value = serde_json::from_str(&base).unwrap();
            keystore["crypto"]["mac"] = serde_json::json!("");
            keystore.to_string()
        }),
        ("salt-nonhex", {
            let mut keystore: serde_json::Value = serde_json::from_str(&base).unwrap();
            keystore["crypto"]["kdfparams"]["salt"] = serde_json::json!("zz-not-hex");
            keystore.to_string()
        }),
        ("ciphertext-array", {
            let mut keystore: serde_json::Value = serde_json::from_str(&base).unwrap();
            keystore["crypto"]["ciphertext"] = serde_json::json!([1, 2, 3]);
            keystore.to_string()
        }),
    ] {
        cases.push((label.to_string(), mutation));
    }

    for (label, mutated) in cases {
        let result = std::panic::catch_unwind(|| import_from_keystore(&mutated, "harness-pass"));
        match result {
            Ok(Ok(_)) | Ok(Err(_)) => {} // total: both outcomes are legal
            Err(_) => panic!("keystore mutation harness panicked on case: {label}"),
        }
    }
}

#[test]
fn master_key_encryption_rejects_wrong_password() {
    let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words12).unwrap();
    let master_key = MasterKey::from_mnemonic(&mnemonic, "").unwrap();
    let encrypted = encrypt_master_key(&master_key, "right").unwrap();
    assert!(decrypt_master_key(&encrypted, "wrong").is_err());
    assert!(decrypt_master_key(&encrypted, "right").is_ok());
}
