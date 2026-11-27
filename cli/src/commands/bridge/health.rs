use super::*;

/// Body of `health_scan` (bridge protocol v8): run the core Watchtower
/// rules over the unlocked vault and return bucketed, metadata-only
/// findings. The decrypted secret material never leaves the scan frame —
/// the report carries names, ids and issue facts, the same contract the
/// CLI `persona watchtower` and desktop `health_scan` surfaces use.
/// Session-authenticated but not gesture-gated (read-only, no secret in
/// the reply), like `get_suggestions`.
pub(super) async fn run_health_scan(
    db_path: &Path,
    request_id: Option<String>,
) -> Result<BridgeResponse<serde_json::Value>> {
    let (service, _active_identity_id) = open_unlocked_service(db_path).await?;
    let report = service
        .scan_health(persona_core::HealthScanConfig::default())
        .await?;

    let mut weak = Vec::new();
    let mut reused = Vec::new();
    let mut no_totp = Vec::new();
    let mut stale = Vec::new();
    for issue in &report.issues {
        let entry = HealthScanIssue {
            item_id: issue.credential_id.to_string(),
            name: issue.credential_name.clone(),
            severity: match issue.severity {
                persona_core::health::HealthSeverity::High => "high",
                persona_core::health::HealthSeverity::Medium => "medium",
                persona_core::health::HealthSeverity::Low => "low",
            }
            .to_string(),
            detail: issue.detail.clone(),
            score: match issue.kind {
                persona_core::health::HealthIssueKind::WeakPassword { score } => Some(score),
                _ => None,
            },
            group_size: match issue.kind {
                persona_core::health::HealthIssueKind::ReusedPassword { group_size } => {
                    Some(group_size)
                }
                _ => None,
            },
            site: match &issue.kind {
                persona_core::health::HealthIssueKind::TwoFactorAvailable { site } => {
                    Some(site.clone())
                }
                _ => None,
            },
            days: match issue.kind {
                persona_core::health::HealthIssueKind::StaleUnchanged { days } => Some(days),
                _ => None,
            },
        };
        match issue.kind {
            persona_core::health::HealthIssueKind::WeakPassword { .. } => weak.push(entry),
            persona_core::health::HealthIssueKind::ReusedPassword { .. } => reused.push(entry),
            persona_core::health::HealthIssueKind::TwoFactorAvailable { .. } => no_totp.push(entry),
            persona_core::health::HealthIssueKind::StaleUnchanged { .. } => stale.push(entry),
            // Expiries and breach hits stay visible in counts but have no
            // dedicated bucket yet; the extension renders the four core
            // Watchtower faces (weak/reused/no-2FA/stale).
            _ => {}
        }
    }

    let payload = HealthScanResponse {
        scanned_at: report.scanned_at.to_rfc3339(),
        total_credentials: report.total_credentials,
        weak,
        reused,
        no_totp,
        stale,
        counts: report.counts.clone(),
        breach_status: "skipped".to_string(),
    };
    debug!(
        total = payload.total_credentials,
        weak = payload.weak.len(),
        reused = payload.reused.len(),
        no_totp = payload.no_totp.len(),
        stale = payload.stale.len(),
        "vault health scan served over the bridge"
    );
    Ok(ok(
        request_id,
        "health_scan_response",
        serde_json::to_value(payload)?,
    ))
}
