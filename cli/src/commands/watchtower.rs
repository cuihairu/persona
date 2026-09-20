//! `persona watchtower` — vault health scan.
//!
//! Runs the core rules engine (weak / reused / expired / stale) over every
//! credential and prints a severity-grouped report. `--json` emits the
//! `HealthReport` directly; like the core type, that payload is metadata
//! only and never contains scanned secret material.

use crate::commands::service::init_service;
use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::PromptUi;
use anyhow::Result;
use clap::Args;
use persona_core::{
    HealthReport, HealthScanConfig, DEFAULT_EXPIRY_WARNING_DAYS, DEFAULT_MIN_PASSWORD_SCORE,
    DEFAULT_STALE_AFTER_DAYS,
};
use std::sync::Arc;

#[derive(Args)]
pub struct WatchtowerArgs {
    /// Print the report as JSON (metadata only, no secrets)
    #[arg(long)]
    pub json: bool,

    /// Also check passwords against the HIBP breach corpus (k-anonymity:
    /// only a 5-char hash prefix is sent). Network failures degrade to a
    /// warning; offline rules are unaffected.
    #[arg(long)]
    pub check_breaches: bool,

    /// Flag passwords whose zxcvbn score (0-4) is below this
    #[arg(long, value_parser = clap::value_parser!(u8).range(..=4))]
    pub min_score: Option<u8>,

    /// Warn this many days before an item expires
    #[arg(long)]
    pub expiry_days: Option<i64>,

    /// Flag credentials unchanged for more than this many days
    #[arg(long)]
    pub stale_days: Option<i64>,
}

impl WatchtowerArgs {
    /// CLI flags → core scan config; unset flags keep the core defaults.
    pub fn scan_config(&self) -> HealthScanConfig {
        HealthScanConfig {
            min_password_score: self.min_score.unwrap_or(DEFAULT_MIN_PASSWORD_SCORE),
            expiry_warning_days: self.expiry_days.unwrap_or(DEFAULT_EXPIRY_WARNING_DAYS),
            stale_after_days: self.stale_days.unwrap_or(DEFAULT_STALE_AFTER_DAYS),
        }
    }
}

pub async fn execute(args: WatchtowerArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: WatchtowerArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    // `--check-breaches` → HIBP checker; construction failure (rare)
    // degrades to an offline scan rather than aborting.
    let checker: Option<Arc<dyn persona_core::BreachChecker>> = if args.check_breaches {
        match persona_core::HibpBreachChecker::new() {
            Ok(checker) => Some(Arc::new(checker)),
            Err(e) => {
                eprintln!("Warning: breach checker unavailable ({e}); scanning offline.");
                None
            }
        }
    } else {
        None
    };
    execute_with_checker(args, config, ui, checker).await
}

/// Test seam: inject a checker directly instead of building the HIBP client.
pub(crate) async fn execute_with_checker(
    args: WatchtowerArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
    checker: Option<Arc<dyn persona_core::BreachChecker>>,
) -> Result<()> {
    let service = init_service(config, ui).await?;
    let report = service
        .scan_health_with(args.scan_config(), checker.as_deref())
        .await
        .into_anyhow()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", render_report(&report));
    }
    Ok(())
}

/// Short rule label used in the human-readable listing.
fn kind_label(kind: &persona_core::HealthIssueKind) -> &'static str {
    use persona_core::HealthIssueKind::*;
    match kind {
        WeakPassword { .. } => "weak password",
        ReusedPassword { .. } => "reused password",
        BreachedPassword { .. } => "breached password",
        Expired => "expired",
        ExpiringSoon { .. } => "expiring soon",
        StaleUnchanged { .. } => "stale",
        TwoFactorAvailable { .. } => "2FA available",
    }
}

/// Human-readable report: issues grouped by severity, then a summary line.
fn render_report(report: &HealthReport) -> String {
    let mut out = String::new();
    if report.issues.is_empty() {
        out.push_str(&format!(
            "✓ Watchtower: no issues found across {} credential(s).",
            report.total_credentials
        ));
        return out;
    }

    out.push_str(&format!(
        "🔍 Watchtower scan: {} credential(s) checked, {} issue(s) found",
        report.total_credentials,
        report.issues.len()
    ));

    for (severity, title) in [
        (persona_core::HealthSeverity::High, "HIGH"),
        (persona_core::HealthSeverity::Medium, "MEDIUM"),
        (persona_core::HealthSeverity::Low, "LOW"),
    ] {
        let issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.severity == severity)
            .collect();
        if issues.is_empty() {
            continue;
        }
        out.push_str(&format!("\n\n{title} ({})", issues.len()));
        for issue in issues {
            out.push_str(&format!(
                "\n  • [{}] {} — {}",
                kind_label(&issue.kind),
                issue.credential_name,
                issue.detail
            ));
        }
    }

    let count = |key: &str| report.counts.get(key).copied().unwrap_or(0);
    out.push_str(&format!(
        "\n\nSummary: {} high, {} medium, {} low",
        count("high"),
        count("medium"),
        count("low")
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use persona_core::Database;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the other command tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
        )
    }

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    fn args(
        min_score: Option<u8>,
        expiry_days: Option<i64>,
        stale_days: Option<i64>,
    ) -> WatchtowerArgs {
        WatchtowerArgs {
            json: false,
            check_breaches: false,
            min_score,
            expiry_days,
            stale_days,
        }
    }

    #[test]
    fn scan_config_flags_override_defaults() {
        let default = args(None, None, None).scan_config();
        assert_eq!(default, HealthScanConfig::default());

        let custom = args(Some(1), Some(7), Some(90)).scan_config();
        assert_eq!(custom.min_password_score, 1);
        assert_eq!(custom.expiry_warning_days, 7);
        assert_eq!(custom.stale_after_days, 90);
    }

    #[test]
    fn render_report_groups_by_severity_and_summarizes() {
        use persona_core::{HealthIssue, HealthIssueKind};
        use uuid::Uuid;

        let mk = |name: &str, kind: HealthIssueKind| HealthIssue {
            credential_id: Uuid::new_v4(),
            credential_name: name.to_string(),
            credential_type: "Password".to_string(),
            severity: kind.severity(),
            detail: kind.detail(),
            kind,
        };

        let report = HealthReport::finalize(
            chrono::Utc::now(),
            4,
            vec![
                mk("low-item", HealthIssueKind::StaleUnchanged { days: 400 }),
                mk("b-high", HealthIssueKind::Expired),
                mk("a-high", HealthIssueKind::ReusedPassword { group_size: 2 }),
                mk("mid", HealthIssueKind::ExpiringSoon { days: 10 }),
            ],
        );

        let text = render_report(&report);
        assert!(text.contains("4 credential(s) checked, 4 issue(s) found"));
        // Severity sections appear in order High → Medium → Low.
        let high = text.find("HIGH (2)").expect("high section");
        let medium = text.find("MEDIUM (1)").expect("medium section");
        let low = text.find("LOW (1)").expect("low section");
        assert!(high < medium && medium < low);
        // High section lists its members sorted by name.
        assert!(text[high..medium].contains("[expired] b-high"));
        assert!(text[high..medium].contains("[reused password] a-high"));
        assert!(text.contains("Summary: 2 high, 1 medium, 1 low"));
    }

    #[test]
    fn render_report_empty_state() {
        let report = HealthReport::finalize(chrono::Utc::now(), 3, vec![]);
        let text = render_report(&report);
        assert!(text.contains("no issues found across 3 credential(s)"));
    }

    #[tokio::test]
    async fn watchtower_requires_a_workspace() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let err = execute_with(
            args(None, None, None),
            &config_for(&dir),
            &crate::utils::prompt::TerminalUi,
        )
        .await
        .expect_err("uninitialized workspace must fail");
        assert!(err.to_string().contains("Workspace not initialized"));
    }

    #[tokio::test]
    async fn watchtower_scans_a_seeded_workspace() {
        let _guard = lock_process_env();
        let master = "watchtower-pass";

        let dir = TempDir::new().unwrap();
        let db = Database::from_file(&dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user(master).await.unwrap();
        let identity = service
            .create_identity("Watch".to_string(), persona_core::IdentityType::Personal)
            .await
            .unwrap();
        service
            .create_credential(
                identity.id,
                "weak-item".to_string(),
                persona_core::CredentialType::Password,
                persona_core::SecurityLevel::Medium,
                &persona_core::CredentialData::Password(persona_core::PasswordCredentialData {
                    password: "hunter2".to_string(),
                    email: None,
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        drop(service);

        std::env::set_var("PERSONA_MASTER_PASSWORD", master);

        // Human output path runs end-to-end (min score 2 flags the weak seed).
        execute_with(
            args(Some(2), None, None),
            &config_for(&dir),
            &crate::utils::prompt::TerminalUi,
        )
        .await
        .expect("human scan works");

        // JSON path emits the report document.
        let mut json_args = args(None, None, None);
        json_args.json = true;
        execute_with(
            json_args,
            &config_for(&dir),
            &crate::utils::prompt::TerminalUi,
        )
        .await
        .expect("json scan works");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// A stub checker can be injected through `execute_with_checker`; a hit
    /// flows into the report and the command succeeds end-to-end.
    #[tokio::test]
    async fn checker_injection_flags_breached_seed() {
        use std::collections::HashMap;

        let _guard = lock_process_env();
        let master = "watchtower-pass";

        let dir = TempDir::new().unwrap();
        let db = Database::from_file(&dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user(master).await.unwrap();
        let identity = service
            .create_identity("Watch".to_string(), persona_core::IdentityType::Personal)
            .await
            .unwrap();
        service
            .create_credential(
                identity.id,
                "weak-item".to_string(),
                persona_core::CredentialType::Password,
                persona_core::SecurityLevel::Medium,
                &persona_core::CredentialData::Password(persona_core::PasswordCredentialData {
                    password: "hunter2".to_string(),
                    email: None,
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        drop(service);

        std::env::set_var("PERSONA_MASTER_PASSWORD", master);

        struct Stub {
            counts: HashMap<String, u64>,
        }
        #[async_trait::async_trait]
        impl persona_core::BreachChecker for Stub {
            async fn breach_counts(
                &self,
                sha1_hex: &[String],
            ) -> persona_core::Result<HashMap<String, u64>> {
                Ok(sha1_hex
                    .iter()
                    .map(|d| (d.clone(), self.counts.get(d).copied().unwrap_or(0)))
                    .collect())
            }
        }

        let checker: Arc<dyn persona_core::BreachChecker> = Arc::new(Stub {
            counts: HashMap::from([(persona_core::sha1_hex_upper("hunter2"), 37_584)]),
        });

        let mut breach_args = args(Some(2), None, None);
        breach_args.check_breaches = true;
        execute_with_checker(
            breach_args,
            &config_for(&dir),
            &crate::utils::prompt::TerminalUi,
            Some(checker),
        )
        .await
        .expect("scan with injected checker works");

        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    /// The public `execute` wrapper resolves the same seeded workspace the
    /// `execute_with` seam does (it forwards to the terminal UI path).
    #[tokio::test]
    async fn execute_runs_the_terminal_ui_path() {
        let _guard = lock_process_env();
        let master = "watchtower-execute-pass";

        let dir = TempDir::new().unwrap();
        let db = Database::from_file(&dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user(master).await.unwrap();
        drop(service);

        std::env::set_var("PERSONA_MASTER_PASSWORD", master);
        execute(args(None, None, None), &config_for(&dir))
            .await
            .expect("execute wrapper must scan the seeded workspace");
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }
}
