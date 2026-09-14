//! Vault health checks (Watchtower-style rules engine).
//!
//! Pure evaluation rules plus the report types shared by the CLI
//! (`persona watchtower`) and the desktop `health_scan` command.
//!
//! Reports carry **metadata only** — credential names, issue kinds and
//! counts — never the passwords or secrets that were scanned. The decrypted
//! material lives inside [`super::service::PersonaService::scan_health`]'s
//! stack frame for the duration of the scan and is dropped with it.

use chrono::{DateTime, Duration as ChronoDuration, Months, Utc};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

/// How weak a password must be before it is flagged.
pub const DEFAULT_MIN_PASSWORD_SCORE: u8 = 3;
/// Warn this many days before an expiry is reached.
pub const DEFAULT_EXPIRY_WARNING_DAYS: i64 = 30;
/// Flag credentials untouched for this long.
pub const DEFAULT_STALE_AFTER_DAYS: i64 = 365;

/// Tunables for a health scan; all fields have conservative defaults.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HealthScanConfig {
    /// zxcvbn score (0-4) below which a password is weak. Default 3.
    pub min_password_score: u8,
    /// Warn this many days before an item expires. Default 30.
    pub expiry_warning_days: i64,
    /// Flag credentials whose `updated_at` is older than this many days.
    /// Default 365.
    pub stale_after_days: i64,
}

impl Default for HealthScanConfig {
    fn default() -> Self {
        Self {
            min_password_score: DEFAULT_MIN_PASSWORD_SCORE,
            expiry_warning_days: DEFAULT_EXPIRY_WARNING_DAYS,
            stale_after_days: DEFAULT_STALE_AFTER_DAYS,
        }
    }
}

/// Severity of a health issue, ordered High > Medium > Low for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthSeverity {
    Low,
    Medium,
    High,
}

/// The kind of problem found. Payloads are metadata only.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HealthIssueKind {
    /// zxcvbn score below the configured threshold
    WeakPassword { score: u8 },
    /// The same plaintext secret is shared by `group_size` credentials
    ReusedPassword { group_size: usize },
    /// An expiry date has already passed
    Expired,
    /// An expiry date falls inside the warning window
    ExpiringSoon { days: i64 },
    /// Not modified for longer than the stale threshold
    StaleUnchanged { days: i64 },
}

impl HealthIssueKind {
    /// Severity used for grouping/sorting in reports.
    pub fn severity(&self) -> HealthSeverity {
        match self {
            // Reuse and expiry are the highest-impact, exploitable classes.
            HealthIssueKind::ReusedPassword { .. } | HealthIssueKind::Expired => {
                HealthSeverity::High
            }
            HealthIssueKind::WeakPassword { score } => {
                if *score <= 1 {
                    HealthSeverity::High
                } else {
                    HealthSeverity::Medium
                }
            }
            HealthIssueKind::ExpiringSoon { .. } => HealthSeverity::Medium,
            HealthIssueKind::StaleUnchanged { .. } => HealthSeverity::Low,
        }
    }

    /// Fixed-template description. Never embeds scanned secret material.
    pub fn detail(&self) -> String {
        match self {
            HealthIssueKind::WeakPassword { score } => format!(
                "Password strength score is {score} (below threshold). Consider rotating it."
            ),
            HealthIssueKind::ReusedPassword { group_size } => format!(
                "This secret is reused by {group_size} credentials. A breach of one exposes all."
            ),
            HealthIssueKind::Expired => {
                "This item has expired and should be replaced or removed.".to_string()
            }
            HealthIssueKind::ExpiringSoon { days } => {
                format!("This item expires in {days} day(s). Plan a rotation.")
            }
            HealthIssueKind::StaleUnchanged { days } => {
                format!("Unchanged for {days} day(s). Verify it is still needed and current.")
            }
        }
    }
}

/// One finding, tied to a credential but carrying no secret material.
#[derive(Debug, Clone, Serialize)]
pub struct HealthIssue {
    pub credential_id: Uuid,
    pub credential_name: String,
    pub credential_type: String,
    pub severity: HealthSeverity,
    #[serde(flatten)]
    pub kind: HealthIssueKind,
    pub detail: String,
}

/// Aggregate result of a scan: metadata only, safe to persist/export.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub scanned_at: DateTime<Utc>,
    pub total_credentials: usize,
    /// Issues sorted High → Low, then by credential name.
    pub issues: Vec<HealthIssue>,
    /// issue counts keyed by severity ("high"/"medium"/"low")
    pub counts: HashMap<String, usize>,
}

impl HealthReport {
    /// Sort issues by severity and build the severity counts.
    pub fn finalize(
        scanned_at: DateTime<Utc>,
        total_credentials: usize,
        mut issues: Vec<HealthIssue>,
    ) -> Self {
        issues.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.credential_name.cmp(&b.credential_name))
        });
        let mut counts: HashMap<String, usize> = HashMap::new();
        for issue in &issues {
            let key = (match issue.severity {
                HealthSeverity::High => "high",
                HealthSeverity::Medium => "medium",
                HealthSeverity::Low => "low",
            })
            .to_string();
            *counts.entry(key).or_insert(0) += 1;
        }
        Self {
            scanned_at,
            total_credentials,
            issues,
            counts,
        }
    }
}

/// Password strength via zxcvbn (Dropbox estimator, pure Rust).
///
/// Returns `(score, suggestions)`. zxcvbn itself treats empty input as
/// score 0; suggestions contain no password material — they are generic
/// advice strings.
pub fn evaluate_password_strength(password: &str) -> (u8, Vec<String>) {
    let estimate = zxcvbn::zxcvbn(password, &[]);
    let suggestions = estimate
        .feedback()
        .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    (u8::from(estimate.score()), suggestions)
}

/// Group credentials whose secret material is identical.
///
/// Input maps password → credential ids; only groups of size > 1 are
/// returned (a password used once is not an issue).
pub fn find_reused_groups(by_password: &HashMap<String, Vec<Uuid>>) -> Vec<Vec<Uuid>> {
    let mut groups: Vec<Vec<Uuid>> = by_password
        .values()
        .filter(|ids| ids.len() > 1)
        .cloned()
        .collect();
    groups.sort();
    groups
}

/// Expiry check for `DateTime`-typed fields (ApiKey).
///
/// Returns `Expired` when past, `ExpiringSoon` inside the warning window.
pub fn check_expiry(
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    warning_days: i64,
) -> Option<HealthIssueKind> {
    if expires_at <= now {
        Some(HealthIssueKind::Expired)
    } else {
        let days_left = (expires_at - now).num_days();
        if days_left <= warning_days {
            Some(HealthIssueKind::ExpiringSoon {
                days: days_left.max(0),
            })
        } else {
            None
        }
    }
}

/// Bank-card expiry check. `expiry_date` is "MM/YY"; the two-digit year is
/// interpreted as 2000+YY (standard for payment cards). Malformed input is
/// silently skipped — a parse failure is a data-quality issue, not a
/// security finding.
pub fn check_bank_card_expiry(
    expiry_date: &str,
    now: DateTime<Utc>,
    warning_days: i64,
) -> Option<HealthIssueKind> {
    let (month, year) = expiry_date.split_once('/')?;
    let month: u32 = month.trim().parse().ok()?;
    let year: i32 = year.trim().parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    // Cards are valid through the last day of the expiry month.
    let first_of_next = chrono::NaiveDate::from_ymd_opt(2000 + year, month, 1)?
        .checked_add_months(Months::new(1))?;
    let expires_at = first_of_next.and_hms_opt(0, 0, 0)?.and_utc() - ChronoDuration::seconds(1);
    check_expiry(expires_at, now, warning_days)
}

/// Staleness check on `updated_at`.
pub fn check_stale(
    updated_at: DateTime<Utc>,
    now: DateTime<Utc>,
    stale_after_days: i64,
) -> Option<HealthIssueKind> {
    let days = (now - updated_at).num_days();
    if days > stale_after_days {
        Some(HealthIssueKind::StaleUnchanged { days })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    fn days_ago(days: i64) -> DateTime<Utc> {
        Utc::now() - ChronoDuration::days(days)
    }

    fn days_ahead(days: i64) -> DateTime<Utc> {
        Utc::now() + ChronoDuration::days(days)
    }

    // ---- evaluate_password_strength ----

    #[test]
    fn weak_and_strong_passwords_score_differently() {
        let (weak, _) = evaluate_password_strength("password");
        let (strong, _) = evaluate_password_strength("correct horse battery staple Zx9!");
        assert!(weak < 3, "trivial password must be weak, got {weak}");
        assert!(
            strong >= 3,
            "long mixed password must be strong, got {strong}"
        );
    }

    #[test]
    fn empty_password_scores_zero() {
        let (score, suggestions) = evaluate_password_strength("");
        assert_eq!(score, 0);
        assert!(!suggestions.is_empty());
    }

    #[test]
    fn strong_password_has_no_weakness_detail_leaking_secret() {
        // detail() is a fixed template: it must not contain the scanned value.
        let kind = HealthIssueKind::WeakPassword { score: 1 };
        assert!(!kind.detail().contains("hunter2"));
    }

    // ---- find_reused_groups ----

    #[test]
    fn reused_groups_returned_only_when_size_gt_one() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let mut by_password = HashMap::new();
        by_password.insert("shared".to_string(), vec![a, b]);
        by_password.insert("unique".to_string(), vec![c]);

        let groups = find_reused_groups(&by_password);
        assert_eq!(groups, vec![vec![a, b]]);
    }

    #[test]
    fn empty_reuse_map_has_no_groups() {
        assert!(find_reused_groups(&HashMap::new()).is_empty());
    }

    // ---- check_expiry ----

    #[test]
    fn past_expiry_is_expired() {
        let now = Utc::now();
        assert_eq!(
            check_expiry(days_ago(1), now, 30),
            Some(HealthIssueKind::Expired)
        );
    }

    #[test]
    fn inside_warning_window_is_expiring_soon() {
        let now = Utc::now();
        assert_eq!(
            check_expiry(days_ahead(10), now, 30),
            Some(HealthIssueKind::ExpiringSoon { days: 10 })
        );
    }

    #[test]
    fn far_future_expiry_is_clean() {
        assert_eq!(check_expiry(days_ahead(90), Utc::now(), 30), None);
    }

    #[test]
    fn expiry_boundary_day_is_expiring_soon() {
        let now = Utc::now();
        assert_eq!(
            check_expiry(days_ahead(30), now, 30),
            Some(HealthIssueKind::ExpiringSoon { days: 30 })
        );
    }

    // ---- check_bank_card_expiry ----

    #[test]
    fn past_bank_card_expiry_is_expired() {
        // Dec 2030 already passed relative to the test's frozen-ish "now"? No —
        // use a past month computed from now so the test never ages out.
        let now = Utc::now();
        let past = now - Months::new(14);
        let s = format!("{:02}/{:02}", past.month(), past.year() % 100);
        assert_eq!(
            check_bank_card_expiry(&s, now, 30),
            Some(HealthIssueKind::Expired)
        );
    }

    #[test]
    fn bank_card_expiry_parses_end_of_month() {
        // "12/99" → valid through 2099-12-31 → far future → clean.
        assert_eq!(check_bank_card_expiry("12/99", Utc::now(), 30), None);
    }

    #[test]
    fn malformed_bank_card_expiry_is_skipped() {
        let now = Utc::now();
        for bad in ["", "13/30", "00/30", "12/ab", "12", "1229"] {
            assert_eq!(
                check_bank_card_expiry(bad, now, 30),
                None,
                "{bad} must be skipped, not reported"
            );
        }
    }

    // ---- check_stale ----

    #[test]
    fn old_credentials_are_stale() {
        let now = Utc::now();
        match check_stale(days_ago(400), now, 365) {
            Some(HealthIssueKind::StaleUnchanged { days }) => {
                // num_days truncates toward zero and the two `now` calls are
                // not identical, so only bound it.
                assert!((398..=400).contains(&days), "unexpected day count {days}");
            }
            other => panic!("expected stale, got {other:?}"),
        }
    }

    #[test]
    fn fresh_credentials_are_not_stale() {
        assert_eq!(check_stale(days_ago(10), Utc::now(), 365), None);
    }

    #[test]
    fn exactly_at_threshold_is_not_stale() {
        // "older than stale_after_days" is strict: == threshold is clean.
        let now = Utc::now();
        assert_eq!(check_stale(days_ago(365), now, 365), None);
    }

    // ---- report assembly ----

    #[test]
    fn report_sorts_by_severity_and_counts() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let id_c = Uuid::new_v4();
        let mk = |id: Uuid, name: &str, kind: HealthIssueKind| HealthIssue {
            credential_id: id,
            credential_name: name.to_string(),
            credential_type: "Password".to_string(),
            severity: kind.severity(),
            detail: kind.detail(),
            kind,
        };

        let report = HealthReport::finalize(
            Utc::now(),
            3,
            vec![
                mk(id_a, "stale", HealthIssueKind::StaleUnchanged { days: 400 }),
                mk(
                    id_b,
                    "b-reuse",
                    HealthIssueKind::ReusedPassword { group_size: 3 },
                ),
                mk(id_c, "a-weak", HealthIssueKind::WeakPassword { score: 2 }),
            ],
        );

        assert_eq!(report.total_credentials, 3);
        assert_eq!(report.counts.get("high"), Some(&1));
        assert_eq!(report.counts.get("medium"), Some(&1));
        assert_eq!(report.counts.get("low"), Some(&1));
        assert_eq!(
            report.issues[0].severity,
            HealthSeverity::High,
            "high severity must sort first"
        );
        assert_eq!(report.issues[2].severity, HealthSeverity::Low);
    }
}
