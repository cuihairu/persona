use super::*;

/// Optional request fields -> core scan configuration; fields left
/// unspecified fall back to the core defaults.
/// Kept as a pure function so it can be tested without a running service.
pub(crate) fn build_health_scan_config(
    request: &HealthScanRequest,
) -> persona_core::HealthScanConfig {
    persona_core::HealthScanConfig {
        min_password_score: request
            .min_password_score
            .unwrap_or(persona_core::DEFAULT_MIN_PASSWORD_SCORE),
        expiry_warning_days: request
            .expiry_warning_days
            .unwrap_or(persona_core::DEFAULT_EXPIRY_WARNING_DAYS),
        stale_after_days: request
            .stale_after_days
            .unwrap_or(persona_core::DEFAULT_STALE_AFTER_DAYS),
    }
}

/// Run the Watchtower health scan (weak / reused / expired / stale).
///
/// The report is metadata only — credential names and issue kinds, never
/// the decrypted secrets — and the scan writes one aggregate audit entry.
#[command]
pub async fn health_scan(
    request: Option<HealthScanRequest>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<HealthReport>, String> {
    let request = request.unwrap_or_default();
    let config = build_health_scan_config(&request);

    // check_breaches -> the HIBP k-anonymity checker; if construction fails
    // (rare), degrade to an offline-only scan instead of erroring, and network
    // failures inside scan_health_with only raise a warning.
    let checker: Option<std::sync::Arc<dyn persona_core::BreachChecker>> =
        if request.check_breaches.unwrap_or(false) {
            match persona_core::HibpBreachChecker::new() {
                Ok(checker) => Some(std::sync::Arc::new(checker)),
                Err(e) => {
                    tracing::warn!("health scan: breach checker unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

    let service_guard = state.service.lock().await;
    match service_guard.as_ref() {
        Some(service) => match service.scan_health_with(config, checker.as_deref()).await {
            Ok(report) => Ok(ApiResponse::success(report)),
            Err(e) => {
                let (code, msg) = map_persona_error(&e);
                match code {
                    Some(code) => Ok(ApiResponse::error_with_code(code, msg)),
                    None => Ok(ApiResponse::error(format!("Health scan failed: {}", msg))),
                }
            }
        },
        None => Ok(ApiResponse::error("Service not initialized".to_string())),
    }
}
