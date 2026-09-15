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
    // No checker was supplied: the breach rule records a skip.
    assert_eq!(
        audits[0].metadata.get("breach_status"),
        Some(&"skipped".to_string())
    );
    assert_eq!(
        audits[0].metadata.get("breach_checked"),
        Some(&"0".to_string())
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

// -------------------------------------------------------------------------
// Breach rule (scan_health_with)
// -------------------------------------------------------------------------

use std::collections::HashMap;

/// In-memory BreachChecker: digests it was seeded with report their counts,
/// everything else reports 0. `fail: true` simulates an unreachable corpus.
struct StubChecker {
    counts: HashMap<String, u64>,
    fail: bool,
}

#[async_trait::async_trait]
impl persona_core::BreachChecker for StubChecker {
    async fn breach_counts(
        &self,
        sha1_hex: &[String],
    ) -> persona_core::Result<HashMap<String, u64>> {
        if self.fail {
            anyhow::bail!("corpus unreachable");
        }
        Ok(sha1_hex
            .iter()
            .map(|d| (d.clone(), self.counts.get(d).copied().unwrap_or(0)))
            .collect())
    }
}

/// A checker hit flags the credential (High severity) and the audit entry
/// records the completed lookup — digests only, no secret material.
#[tokio::test]
async fn scan_health_with_checker_flags_breached_passwords() -> Result<()> {
    let temp_dir = tempdir()?;
    let db = Database::from_file(temp_dir.path().join("breach.db")).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db).await?;
    service.initialize_user("master_pw_123").await?;
    let identity = service
        .create_identity("Breach".to_string(), IdentityType::Personal)
        .await?;

    let breached = seed_password(&service, identity.id, "Breached Site", WEAK_UNIQUE).await?;
    let _clean = seed_password(&service, identity.id, "Clean Site", STRONG).await?;

    let checker = StubChecker {
        counts: HashMap::from([(persona_core::sha1_hex_upper(WEAK_UNIQUE), 37_584)]),
        fail: false,
    };
    let report = service
        .scan_health_with(HealthScanConfig::default(), Some(&checker))
        .await?;

    let breach_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| matches!(i.kind, HealthIssueKind::BreachedPassword { .. }))
        .collect();
    assert_eq!(breach_issues.len(), 1, "exactly the breached credential");
    assert_eq!(breach_issues[0].credential_id, breached.id);
    assert_eq!(breach_issues[0].severity, HealthSeverity::High);
    assert!(
        matches!(
            &breach_issues[0].kind,
            HealthIssueKind::BreachedPassword { count: 37_584 }
        ),
        "count must carry through: {:?}",
        breach_issues[0].kind
    );
    // The clean strong secret must not be flagged by the breach rule.
    assert!(!report
        .issues
        .iter()
        .any(|i| i.credential_name == "Clean Site"
            && matches!(i.kind, HealthIssueKind::BreachedPassword { .. })));

    let audits = service
        .query_audit_logs(AuditLogQuery {
            action: Some(AuditAction::SecurityScanPerformed),
            ..Default::default()
        })
        .await?;
    assert_eq!(audits.len(), 1);
    assert_eq!(
        audits[0].metadata.get("breach_status"),
        Some(&"completed".to_string())
    );
    assert_eq!(
        audits[0].metadata.get("breach_checked"),
        Some(&"2".to_string()),
        "one digest per distinct secret"
    );
    // Report JSON carries counts as numbers, never the secret itself.
    let json = serde_json::to_string(&report)?;
    assert!(!json.contains(WEAK_UNIQUE));
    assert!(json.contains("37584"));

    Ok(())
}

/// A failing checker downgrades to a warning: the offline rules still report
/// and the audit entry records the outage.
#[tokio::test]
async fn scan_health_survives_breach_checker_failure() -> Result<()> {
    let temp_dir = tempdir()?;
    let db = Database::from_file(temp_dir.path().join("breach-fail.db")).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db).await?;
    service.initialize_user("master_pw_123").await?;
    let identity = service
        .create_identity("Breach".to_string(), IdentityType::Personal)
        .await?;

    // Fresh + strong: the offline rules stay quiet for this credential.
    let _clean = seed_password(&service, identity.id, "Clean Site", STRONG).await?;

    let checker = StubChecker {
        counts: HashMap::new(),
        fail: true,
    };
    let report = service
        .scan_health_with(HealthScanConfig::default(), Some(&checker))
        .await
        .expect("checker failure must not fail the scan");

    assert!(!report
        .issues
        .iter()
        .any(|i| matches!(i.kind, HealthIssueKind::BreachedPassword { .. })));

    let audits = service
        .query_audit_logs(AuditLogQuery {
            action: Some(AuditAction::SecurityScanPerformed),
            ..Default::default()
        })
        .await?;
    assert_eq!(audits.len(), 1);
    assert_eq!(
        audits[0].metadata.get("breach_status"),
        Some(&"unavailable".to_string())
    );
    assert_eq!(
        audits[0].metadata.get("breach_checked"),
        Some(&"0".to_string())
    );

    Ok(())
}

/// Inactive credentials are skipped entirely (even a weak secret stays
/// unreported), and a credential whose payload no longer decrypts is
/// skipped without aborting the scan.
#[tokio::test]
async fn scan_health_skips_inactive_and_undecryptable_credentials() -> Result<()> {
    let temp_dir = tempdir()?;
    let db = Database::from_file(temp_dir.path().join("edges.db")).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db.clone()).await?;
    service.initialize_user("master_pw_123").await?;

    let identity = service
        .create_identity("Edge Identity".to_string(), IdentityType::Personal)
        .await?;
    let healthy = seed_password(&service, identity.id, "Healthy Site", STRONG).await?;
    let inactive = seed_password(&service, identity.id, "Retired Site", WEAK_UNIQUE).await?;
    let corrupted = seed_password(&service, identity.id, "Corrupted Site", STRONG).await?;

    let repo = CredentialRepository::new(db.clone());
    // Retire one credential: its weak secret must never reach the report.
    let mut retired = repo.find_by_id(&inactive.id).await?.expect("seeded");
    retired.is_active = false;
    repo.update(&retired).await?;

    // Corrupt another one's ciphertext: decryption fails, scan survives.
    let mut broken = repo.find_by_id(&corrupted.id).await?.expect("seeded");
    broken.encrypted_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    repo.update(&broken).await?;

    let report = service.scan_health(HealthScanConfig::default()).await?;

    let issue_ids: HashSet<Uuid> = report.issues.iter().map(|i| i.credential_id).collect();
    assert!(
        !issue_ids.contains(&inactive.id),
        "inactive credential must be skipped even with a weak secret"
    );
    assert!(
        !issue_ids.contains(&corrupted.id),
        "undecryptable credential must be skipped, not reported or fatal"
    );
    assert!(
        !issue_ids.contains(&healthy.id),
        "strong active credential must stay clean"
    );
    // The scan itself still recorded its aggregate audit entry.
    let audits = service
        .query_audit_logs(AuditLogQuery {
            action: Some(AuditAction::SecurityScanPerformed),
            ..Default::default()
        })
        .await?;
    assert_eq!(audits.len(), 1);
    // Only the healthy credential produced rules output.
    assert_eq!(
        audits[0].metadata.get("issue_count"),
        Some(&"0".to_string())
    );

    Ok(())
}

/// Secret-strength rules also apply to SSH-key passphrases, and an expiry
/// date far beyond the warning window raises no issue.
#[tokio::test]
async fn scan_health_covers_sshkey_passphrase_and_far_future_expiry() -> Result<()> {
    let temp_dir = tempdir()?;
    let db = Database::from_file(temp_dir.path().join("edges2.db")).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db.clone()).await?;
    service.initialize_user("master_pw_123").await?;

    let identity = service
        .create_identity("Edge Identity 2".to_string(), IdentityType::Personal)
        .await?;

    // Weak passphrase on an SSH key joins the strength rules.
    service
        .create_credential(
            identity.id,
            "Key with weak passphrase".to_string(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(SshKeyData {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAAATEST".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: Some(WEAK_UNIQUE.to_string()),
            }),
        )
        .await?;

    // API key expiring well past the warning window: Some(expires_at) but no
    // issue (as opposed to the already-covered expired/soon-expiring cases).
    seed_api_key(
        &service,
        identity.id,
        "Far future token",
        Some(chrono::Utc::now() + chrono::Duration::days(400)),
    )
    .await?;

    let report = service.scan_health(HealthScanConfig::default()).await?;

    let weak_ssh = report
        .issues
        .iter()
        .find(|i| matches!(i.kind, HealthIssueKind::WeakPassword { .. }))
        .expect("weak SSH passphrase must be reported");
    assert!(weak_ssh.credential_name.contains("weak passphrase"));

    assert!(
        !report
            .issues
            .iter()
            .any(|i| matches!(i.kind, HealthIssueKind::ExpiringSoon { .. })),
        "an expiry 400 days out is not 'expiring soon'"
    );

    Ok(())
}
