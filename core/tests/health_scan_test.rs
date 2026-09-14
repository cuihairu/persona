//! Integration tests for `PersonaService::scan_health` (Watchtower rules).

use persona_core::*;
use std::collections::HashSet;
use tempfile::tempdir;
use uuid::Uuid;

// A genuinely weak sample (zxcvbn score 1) that is not a substring of any
// report field name, so the JSON-leak assertion below stays meaningful.
const WEAK_UNIQUE: &str = "hunter2";
const REUSED: &str = "Rhinestone-Kestrel-Overpass-71!";
const STRONG: &str = "correct horse battery staple Zx9!";

// Seed helpers as free async fns (not closures): an async closure returning
// `service.create_credential(...)` would smuggle a reference to the
// `CredentialData` temporary out of the closure body (E0515).
async fn seed_password(
    service: &PersonaService,
    identity_id: Uuid,
    name: &str,
    password: &str,
) -> Result<Credential> {
    service
        .create_credential(
            identity_id,
            name.to_string(),
            CredentialType::Password,
            SecurityLevel::Medium,
            &CredentialData::Password(PasswordCredentialData {
                password: password.to_string(),
                email: None,
                security_questions: vec![],
            }),
        )
        .await
}

async fn seed_api_key(
    service: &PersonaService,
    identity_id: Uuid,
    name: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Credential> {
    service
        .create_credential(
            identity_id,
            name.to_string(),
            CredentialType::ApiKey,
            SecurityLevel::High,
            &CredentialData::ApiKey(ApiKeyData {
                api_key: format!("k-{}", Uuid::new_v4()),
                api_secret: None,
                token: None,
                permissions: vec![],
                expires_at,
            }),
        )
        .await
}

/// Seed a vault with credentials covering every rule, scan it, and assert
/// the report (and its JSON form) leaks no secret material.
#[tokio::test]
async fn scan_health_reports_all_issue_kinds() -> Result<()> {
    let temp_dir = tempdir()?;
    let db = Database::from_file(temp_dir.path().join("health.db")).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db).await?;
    service.initialize_user("master_pw_123").await?;
    let identity = service
        .create_identity("Health".to_string(), IdentityType::Personal)
        .await?;

    let c1_weak = seed_password(&service, identity.id, "Weak Site", WEAK_UNIQUE).await?;
    let _c2 = seed_password(&service, identity.id, "Reused A", REUSED).await?;
    let _c3 = seed_password(&service, identity.id, "Reused B", REUSED).await?;
    let _c4 = seed_password(&service, identity.id, "Strong Site", STRONG).await?;

    // ServerConfig joins the weak/reuse group via its optional password field.
    let c7_server = service
        .create_credential(
            identity.id,
            "Server with reused pw".to_string(),
            CredentialType::ServerConfig,
            SecurityLevel::High,
            &CredentialData::ServerConfig(ServerConfigData {
                hostname: "srv.example.com".to_string(),
                ip_address: None,
                port: 22,
                protocol: "ssh".to_string(),
                username: "root".to_string(),
                password: Some(WEAK_UNIQUE.to_string()),
                ssh_key_id: None,
                additional_config: Default::default(),
            }),
        )
        .await?;

    let now = chrono::Utc::now();
    let _c5 = seed_api_key(
        &service,
        identity.id,
        "Expired token",
        Some(now - chrono::Duration::days(1)),
    )
    .await?;
    let _c6 = seed_api_key(
        &service,
        identity.id,
        "Soon token",
        Some(now + chrono::Duration::days(10)),
    )
    .await?;

    let _c8 = service
        .create_credential(
            identity.id,
            "Old card".to_string(),
            CredentialType::BankCard,
            SecurityLevel::Medium,
            &CredentialData::BankCard(BankCardData {
                card_number: "4111111111111111".to_string(),
                cardholder_name: "Test".to_string(),
                expiry_date: "01/20".to_string(), // long past
                cvv: "123".to_string(),
                bank_name: "Test Bank".to_string(),
                card_type: "visa".to_string(),
            }),
        )
        .await?;

    let report = service
        .scan_health(HealthScanConfig {
            stale_after_days: -1, // force-flag staleness deterministically
            ..HealthScanConfig::default()
        })
        .await?;

    assert_eq!(report.total_credentials, 8);

    let kinds = |pred: &dyn Fn(&HealthIssueKind) -> bool| {
        report
            .issues
            .iter()
            .filter(|i| pred(&i.kind))
            .collect::<Vec<_>>()
    };

    // Weak password (score below 3): exactly the two WEAK_UNIQUE holders —
    // the standalone Password entry and the ServerConfig optional password.
    let weak_ids = kinds(&|k| matches!(k, HealthIssueKind::WeakPassword { .. }))
        .iter()
        .map(|i| i.credential_id)
        .collect::<HashSet<_>>();
    assert_eq!(
        weak_ids,
        HashSet::from([c1_weak.id, c7_server.id]),
        "exactly the WEAK_UNIQUE holders must be flagged weak"
    );

    // Two reuse groups: {weak site, server} and {reused a, reused b}
    let reused = kinds(&|k| matches!(k, HealthIssueKind::ReusedPassword { group_size: 2 }));
    assert_eq!(
        reused.len(),
        4,
        "two groups of two = four flagged credentials"
    );

    // Expiry: one expired ApiKey + one expired card + one expiring soon
    assert_eq!(kinds(&|k| matches!(k, HealthIssueKind::Expired)).len(), 2);
    assert_eq!(
        kinds(&|k| matches!(k, HealthIssueKind::ExpiringSoon { .. })).len(),
        1
    );

    // Staleness was force-enabled for every credential
    assert_eq!(
        kinds(&|k| matches!(k, HealthIssueKind::StaleUnchanged { .. })).len(),
        8
    );

    // Report JSON must not contain any scanned secret material
    let json = serde_json::to_string(&report)?;
    assert!(!json.contains(WEAK_UNIQUE));
    assert!(!json.contains(REUSED));
    assert!(!json.contains(STRONG));

    // Exactly one aggregate audit entry for the scan
    let audits = service
        .query_audit_logs(AuditLogQuery {
            action: Some(AuditAction::SecurityScanPerformed),
            ..Default::default()
        })
        .await?;
    assert_eq!(audits.len(), 1);
    assert_eq!(
        audits[0].metadata.get("total_credentials"),
        Some(&"8".to_string())
    );

    Ok(())
}

/// A locked vault must refuse to scan.
#[tokio::test]
async fn scan_health_requires_unlocked_service() -> Result<()> {
    let temp_dir = tempdir()?;
    let db = Database::from_file(temp_dir.path().join("locked.db")).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db).await?;
    service.initialize_user("master_pw_123").await?;
    service.lock();

    let result = service.scan_health(HealthScanConfig::default()).await;
    assert!(result.is_err(), "locked service must not scan");

    Ok(())
}
