use super::*;

#[tokio::test]
async fn scan_health_flags_expiring_software_license() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Watchtower Licenses".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let make_license = |valid_until: Option<String>| {
        CredentialData::SoftwareLicense(crate::models::credential::SoftwareLicenseData {
            license_key: "LICENSE-1".to_string(),
            version: None,
            publisher: None,
            purchase_date: None,
            order_number: None,
            support_email: None,
            download_url: None,
            seats: None,
            valid_until,
        })
    };

    // One expiring soon (ISO text) and one far from expiry (dotted text); also keep a free-text
    // entry whose expiry date cannot be parsed — it must be silently skipped, not errored.
    let soon = (chrono::Utc::now() + chrono::Duration::days(10))
        .format("%Y-%m-%d")
        .to_string();
    let far = (chrono::Utc::now() + chrono::Duration::days(400))
        .format("%d.%m.%Y")
        .to_string();
    service
        .create_credential(
            identity.id,
            "JetBrains".to_string(),
            CredentialType::SoftwareLicense,
            SecurityLevel::Medium,
            &make_license(Some(soon)),
        )
        .await
        .unwrap();
    service
        .create_credential(
            identity.id,
            "Perpetual Tool".to_string(),
            CredentialType::SoftwareLicense,
            SecurityLevel::Medium,
            &make_license(Some(far)),
        )
        .await
        .unwrap();
    service
        .create_credential(
            identity.id,
            "Lifetime Deal".to_string(),
            CredentialType::SoftwareLicense,
            SecurityLevel::Medium,
            &make_license(Some("lifetime".to_string())),
        )
        .await
        .unwrap();

    let report = service
        .scan_health(HealthScanConfig::default())
        .await
        .unwrap();
    let expiring: Vec<&HealthIssue> = report
        .issues
        .iter()
        .filter(|i| matches!(i.kind, HealthIssueKind::ExpiringSoon { .. }))
        .collect();
    assert_eq!(expiring.len(), 1, "only the soon license is flagged");
    assert_eq!(expiring[0].credential_name, "JetBrains");
}

/// Blanket coverage of the scan rule surface: ApiKey/BankCard expired and near-expiry, unparseable
/// expiry silently skipped, the weak-password reuse group (ServerConfig.password and
/// SshKey.passphrase sharing a source), inactive skipped, and a decryption-failed credential
/// skipped without interrupting the whole scan.
#[tokio::test]
async fn scan_health_covers_expiry_rules_and_skips_inactive_undecryptable() {
    let (db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Watchtower Mixed".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    let make_api_key = |expires_at: Option<chrono::DateTime<chrono::Utc>>| {
        CredentialData::ApiKey(crate::models::credential::ApiKeyData {
            api_key: "KEY".to_string(),
            api_secret: None,
            token: None,
            permissions: vec![],
            expires_at,
        })
    };
    let make_bank_card = |expiry_date: &str| {
        CredentialData::BankCard(crate::models::credential::BankCardData {
            card_number: "4111 1111 1111 1111".to_string(),
            cardholder_name: "Test User".to_string(),
            expiry_date: expiry_date.to_string(),
            cvv: "123".to_string(),
            bank_name: "Test Bank".to_string(),
            card_type: "visa".to_string(),
        })
    };

    service
        .create_credential(
            identity.id,
            "Old Key".to_string(),
            CredentialType::ApiKey,
            SecurityLevel::High,
            &make_api_key(Some(chrono::Utc::now() - chrono::Duration::days(1))),
        )
        .await
        .unwrap();
    service
        .create_credential(
            identity.id,
            "New Key".to_string(),
            CredentialType::ApiKey,
            SecurityLevel::High,
            &make_api_key(Some(chrono::Utc::now() + chrono::Duration::days(5))),
        )
        .await
        .unwrap();
    // BankCard: one expired (01/20) and one unparseable (data quality, silently skipped)
    service
        .create_credential(
            identity.id,
            "Dead Card".to_string(),
            CredentialType::BankCard,
            SecurityLevel::High,
            &make_bank_card("01/20"),
        )
        .await
        .unwrap();
    service
        .create_credential(
            identity.id,
            "Weird Card".to_string(),
            CredentialType::BankCard,
            SecurityLevel::High,
            &make_bank_card("lifetime"),
        )
        .await
        .unwrap();
    // Weak-password reuse group: ServerConfig.password and SshKey.passphrase share the same value
    service
        .create_credential(
            identity.id,
            "Box".to_string(),
            CredentialType::ServerConfig,
            SecurityLevel::High,
            &CredentialData::ServerConfig(crate::models::credential::ServerConfigData {
                hostname: "box.local".to_string(),
                ip_address: None,
                port: 22,
                protocol: "ssh".to_string(),
                username: "root".to_string(),
                password: Some("123".to_string()),
                ssh_key_id: None,
                additional_config: Default::default(),
            }),
        )
        .await
        .unwrap();
    service
        .create_credential(
            identity.id,
            "Deploy Key".to_string(),
            CredentialType::SshKey,
            SecurityLevel::Critical,
            &CredentialData::SshKey(crate::models::credential::SshKeyData {
                private_key: "-----BEGIN".to_string(),
                public_key: "ssh-ed25519 AAA".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: Some("123".to_string()),
            }),
        )
        .await
        .unwrap();

    // inactive: counted in total_credentials but produces no issue
    let disabled =
        seed_credential(&service, identity.id, "Disabled", CredentialType::Password).await;
    let updated = sqlx::query("UPDATE credentials SET is_active = 0 WHERE id = ?")
        .bind(disabled.id.to_string()) // sqlite stores TEXT; a Uuid bind would not match
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 1);
    // Decryption failure: encrypted_data swapped for garbage bytes -> warn + skip, and the scan continues
    let broken = seed_credential(&service, identity.id, "Broken", CredentialType::Password).await;
    let updated = sqlx::query("UPDATE credentials SET encrypted_data = ? WHERE id = ?")
        .bind(vec![0u8, 1, 2, 3])
        .bind(broken.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 1);

    let report = service
        .scan_health(HealthScanConfig::default())
        .await
        .unwrap();

    assert_eq!(report.total_credentials, 8);
    let kinds_of = |name: &str| -> Vec<&HealthIssueKind> {
        report
            .issues
            .iter()
            .filter(|i| i.credential_name == name)
            .map(|i| &i.kind)
            .collect()
    };
    assert!(matches!(
        kinds_of("Old Key")[..],
        [HealthIssueKind::Expired]
    ));
    assert!(matches!(
        kinds_of("New Key")[..],
        [HealthIssueKind::ExpiringSoon { .. }]
    ));
    assert!(matches!(
        kinds_of("Dead Card")[..],
        [HealthIssueKind::Expired]
    ));
    assert!(
        kinds_of("Weird Card").is_empty(),
        "unparseable expiry is skipped, not an error"
    );
    for name in ["Box", "Deploy Key"] {
        let kinds = kinds_of(name);
        assert_eq!(kinds.len(), 2, "{name} must be weak and reused: {kinds:?}");
        assert!(kinds
            .iter()
            .any(|k| matches!(k, HealthIssueKind::WeakPassword { .. })));
        assert!(kinds
            .iter()
            .any(|k| matches!(k, HealthIssueKind::ReusedPassword { group_size: 2 })));
    }
    assert!(kinds_of("Disabled").is_empty(), "inactive is skipped");
    assert!(kinds_of("Broken").is_empty(), "undecryptable is skipped");
}

#[tokio::test]
async fn scan_health_breach_rule_reports_and_tolerates_checker_failure() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Watchtower Breach".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let make_login = |password: &str| {
        CredentialData::Password(PasswordCredentialData {
            password: password.to_string(),
            email: None,
            security_questions: vec![],
        })
    };
    for (name, password) in [
        ("Pwned One", "pwned-everywhere"),
        ("Pwned Two", "pwned-everywhere"),
        ("Clean One", "unique-clean-secret"),
    ] {
        service
            .create_credential(
                identity.id,
                name.to_string(),
                CredentialType::Password,
                SecurityLevel::Medium,
                &make_login(password),
            )
            .await
            .unwrap();
    }

    let pwned_digest = crate::breach::sha1_hex_upper("pwned-everywhere");
    let checker = FixedBreaches {
        counts: [(pwned_digest.clone(), 3u64)].into_iter().collect(),
    };
    let report = service
        .scan_health_with(
            HealthScanConfig::default(),
            Some(&checker as &dyn BreachChecker),
        )
        .await
        .unwrap();
    let breached: Vec<_> = report
        .issues
        .iter()
        .filter(|i| matches!(i.kind, HealthIssueKind::BreachedPassword { count: 3 }))
        .collect();
    assert_eq!(breached.len(), 2, "both holders of the pwned secret");
    assert!(breached
        .iter()
        .all(|i| i.credential_name.starts_with("Pwned")));

    // Checker failure: the full report still returns, just without breach-type issues
    let report = service
        .scan_health_with(
            HealthScanConfig::default(),
            Some(&DownChecker as &dyn BreachChecker),
        )
        .await
        .unwrap();
    assert!(report
        .issues
        .iter()
        .all(|i| !matches!(i.kind, HealthIssueKind::BreachedPassword { .. })));
}

/// The stale rule: credentials whose updated_at is earlier than stale_after_days report
/// StaleUnchanged, with the day count rounded down to whole days.
#[tokio::test]
async fn scan_health_flags_stale_credentials_with_day_count() {
    let (db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Watchtower Stale".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let stale = seed_credential(&service, identity.id, "Mossy", CredentialType::Password).await;
    let fresh = seed_credential(&service, identity.id, "Fresh", CredentialType::Password).await;
    let old = (chrono::Utc::now() - chrono::Duration::days(400)).to_rfc3339();
    let updated = sqlx::query("UPDATE credentials SET updated_at = ? WHERE id = ?")
        .bind(&old)
        .bind(stale.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 1);

    let report = service
        .scan_health(HealthScanConfig::default())
        .await
        .unwrap();
    let stale_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| matches!(i.kind, HealthIssueKind::StaleUnchanged { .. }))
        .collect();
    assert_eq!(stale_issues.len(), 1);
    assert_eq!(stale_issues[0].credential_name, "Mossy");
    assert!(matches!(
        stale_issues[0].kind,
        HealthIssueKind::StaleUnchanged { days: 400 }
    ));
    let _ = fresh; // a fresh credential is not reported stale (implied: only one entry was filtered above)
}

#[tokio::test]
async fn scan_health_flags_two_factor_available_until_covered() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Watchtower 2FA".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // A GitHub login (directory site, no TOTP) -> should be suggested; an internal site is not in the directory -> no suggestion.
    let mut github =
        seed_credential(&service, identity.id, "GitHub", CredentialType::Password).await;
    github.url = Some("https://github.com".to_string());
    service.update_credential(&github).await.unwrap();
    let mut intranet =
        seed_credential(&service, identity.id, "Intranet", CredentialType::Password).await;
    intranet.url = Some("https://internal.corp.local".to_string());
    service.update_credential(&intranet).await.unwrap();

    let report = service
        .scan_health(HealthScanConfig::default())
        .await
        .unwrap();
    let two_fa: Vec<&HealthIssue> = report
        .issues
        .iter()
        .filter(|i| matches!(i.kind, HealthIssueKind::TwoFactorAvailable { .. }))
        .collect();
    assert_eq!(two_fa.len(), 1);
    assert_eq!(two_fa[0].credential_name, "GitHub");
    match &two_fa[0].kind {
        HealthIssueKind::TwoFactorAvailable { site } => assert_eq!(site, "github.com"),
        other => panic!("wrong kind: {other:?}"),
    }

    // After a TOTP is stored for GitHub and the scan reruns: the suggestion disappears (same-site override).
    service
        .create_credential(
            identity.id,
            "GitHub TOTP".to_string(),
            CredentialType::TwoFactor,
            SecurityLevel::High,
            &CredentialData::TwoFactor(crate::models::credential::TwoFactorData {
                secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                issuer: "GitHub".to_string(),
                account_name: "alice".to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                hotp: None,
                initial_counter: None,
                period: 30,
            }),
        )
        .await
        .unwrap();
    // create_credential has no url parameter: set the url via the same update path the historical tests use
    let mut totp = service
        .get_credentials_for_identity(&identity.id)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.name == "GitHub TOTP")
        .expect("seeded TOTP credential");
    totp.url = Some("https://github.com".to_string());
    service.update_credential(&totp).await.unwrap();

    let report = service
        .scan_health(HealthScanConfig::default())
        .await
        .unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|i| matches!(i.kind, HealthIssueKind::TwoFactorAvailable { .. })),
        "covering TOTP must quiet the 2FA-available issue"
    );
}
