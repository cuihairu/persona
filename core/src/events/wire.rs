//! Wire shapes: the client-side mirror of the server Events API plus pre-send validation.
//!
//! [`limits`] stays in item-by-item sync with the validation ceilings in
//! `server/src/api/events.rs` (the server is authoritative; core cannot
//! depend on server in reverse, so the link is anchored only by comments —
//! a change over there must land in both places).

use crate::models::AuditLog;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

/// Mirror of the server's validation ceilings (in bytes, consistent with the server's `str::len()`).
pub mod limits {
    /// The server's per-batch cap (server/src/api/events.rs `MAX_BATCH_SIZE`);
    /// `EmitterConfig::batch_size` must not exceed this value.
    pub const MAX_BATCH_SIZE: usize = 500;
    pub const MAX_ACTION_LEN: usize = 128;
    /// Shared by id / resource_id / user_id / session_id.
    pub const MAX_ID_LEN: usize = 256;
    pub const MAX_IP_LEN: usize = 64;
    pub const MAX_UA_LEN: usize = 512;
    pub const MAX_ERROR_LEN: usize = 1024;
    pub const MAX_METADATA_ENTRIES: usize = 32;
    pub const MAX_METADATA_KEY_LEN: usize = 64;
    pub const MAX_METADATA_VALUE_LEN: usize = 512;
}

/// Client-side mirror of the server `IngestEvent`. `id` is the idempotency key
/// (the AuditLog UUID), which the server deduplicates on; every Option field
/// is skipped during serialization to save bandwidth and match server semantics.
#[derive(Debug, Clone, Serialize)]
pub struct WireEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub action: String,
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
    pub timestamp: DateTime<Utc>,
}

/// A pre-validation failure reason for a single event (`field` is a static field name, aligned with the server's ErrorItem).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireIssue {
    pub field: &'static str,
    pub issue: String,
}

impl WireIssue {
    fn new(field: &'static str, issue: impl Into<String>) -> Self {
        Self {
            field,
            issue: issue.into(),
        }
    }
}

/// `AuditLog` → wire. Each entry is pre-validated against the server ceilings by
/// **byte** length — the server validates all-or-nothing, so one poison pill
/// sinks the whole batch; all reasons for an invalid entry are returned and the
/// caller discards it with a warning. Lengths are always `str::len()` (bytes),
/// matching the server's convention.
///
/// action/resource_type use `Display` rather than serde: `AuditAction`'s serde
/// representation is externally-tagged (`Custom` serializes to a
/// `{"custom":"x"}` object), while the server expects a plain string.
pub fn to_wire(log: &AuditLog) -> Result<WireEvent, Vec<WireIssue>> {
    let mut issues = Vec::new();

    let action = log.action.to_string();
    if action.is_empty() {
        issues.push(WireIssue::new("action", "must not be empty"));
    } else if action.len() > limits::MAX_ACTION_LEN {
        issues.push(WireIssue::new(
            "action",
            format!("exceeds {} bytes", limits::MAX_ACTION_LEN),
        ));
    }

    check_opt_len(
        &mut issues,
        "resource_id",
        log.resource_id.as_deref(),
        limits::MAX_ID_LEN,
    );
    check_opt_len(
        &mut issues,
        "user_id",
        log.user_id.as_deref(),
        limits::MAX_ID_LEN,
    );
    check_opt_len(
        &mut issues,
        "session_id",
        log.session_id.as_deref(),
        limits::MAX_ID_LEN,
    );
    check_opt_len(
        &mut issues,
        "ip_address",
        log.ip_address.as_deref(),
        limits::MAX_IP_LEN,
    );
    check_opt_len(
        &mut issues,
        "user_agent",
        log.user_agent.as_deref(),
        limits::MAX_UA_LEN,
    );
    check_opt_len(
        &mut issues,
        "error_message",
        log.error_message.as_deref(),
        limits::MAX_ERROR_LEN,
    );

    if log.metadata.len() > limits::MAX_METADATA_ENTRIES {
        issues.push(WireIssue::new(
            "metadata",
            format!("exceeds {} entries", limits::MAX_METADATA_ENTRIES),
        ));
    }
    if log
        .metadata
        .keys()
        .any(|key| key.len() > limits::MAX_METADATA_KEY_LEN)
    {
        issues.push(WireIssue::new(
            "metadata",
            format!("key exceeds {} bytes", limits::MAX_METADATA_KEY_LEN),
        ));
    }
    if log
        .metadata
        .values()
        .any(|value| value.len() > limits::MAX_METADATA_VALUE_LEN)
    {
        issues.push(WireIssue::new(
            "metadata",
            format!("value exceeds {} bytes", limits::MAX_METADATA_VALUE_LEN),
        ));
    }

    if !issues.is_empty() {
        return Err(issues);
    }

    Ok(WireEvent {
        id: Some(log.id.to_string()),
        action,
        resource_type: log.resource_type.to_string(),
        resource_id: log.resource_id.clone(),
        user_id: log.user_id.clone(),
        identity_id: log.identity_id,
        credential_id: log.credential_id,
        session_id: log.session_id.clone(),
        ip_address: log.ip_address.clone(),
        user_agent: log.user_agent.clone(),
        success: log.success,
        error_message: log.error_message.clone(),
        metadata: (!log.metadata.is_empty()).then(|| log.metadata.clone()),
        timestamp: log.timestamp,
    })
}

/// Batch conversion: returns (valid batch, list of (input index, reasons)), preserving order.
pub fn build_batch(logs: &[AuditLog]) -> (Vec<WireEvent>, Vec<(usize, Vec<WireIssue>)>) {
    let mut events = Vec::with_capacity(logs.len());
    let mut rejected = Vec::new();
    for (index, log) in logs.iter().enumerate() {
        match to_wire(log) {
            Ok(event) => events.push(event),
            Err(issues) => rejected.push((index, issues)),
        }
    }
    (events, rejected)
}

fn check_opt_len(
    issues: &mut Vec<WireIssue>,
    field: &'static str,
    value: Option<&str>,
    max: usize,
) {
    if let Some(value) = value {
        if value.len() > max {
            issues.push(WireIssue::new(field, format!("exceeds {max} bytes")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuditAction, ResourceType};

    fn sample_log() -> AuditLog {
        AuditLog::new(AuditAction::Login, ResourceType::User, true)
    }

    #[test]
    fn named_action_becomes_snake_case_string() {
        let log = sample_log();
        let event = to_wire(&log).unwrap();
        assert_eq!(event.action, "login");
        assert_eq!(event.resource_type, "user");
        assert!(event.success);
        // id is the idempotency key: the AuditLog UUID string
        assert_eq!(event.id.as_deref(), Some(log.id.to_string().as_str()));
    }

    #[test]
    fn custom_action_passes_through_verbatim() {
        let log = AuditLog::new(
            AuditAction::Custom("totally_new".into()),
            ResourceType::User,
            true,
        );
        assert_eq!(to_wire(&log).unwrap().action, "totally_new");
    }

    #[test]
    fn empty_optionals_are_absent_from_json() {
        let event = to_wire(&sample_log()).unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.get("user_id").is_none());
        assert!(json.get("metadata").is_none());
        assert!(json.get("error_message").is_none());
        assert!(json.get("timestamp").is_some());
    }

    #[test]
    fn full_fields_round_trip_into_json() {
        let log = sample_log()
            .with_user_id(Some("u1".into()))
            .with_identity_id(Some(uuid::Uuid::new_v4()))
            .with_credential_id(Some(uuid::Uuid::new_v4()))
            .with_session_id(Some("s1".into()))
            .with_resource_id(Some("r1".into()))
            .with_ip_address(Some("127.0.0.1".into()))
            .with_user_agent(Some("ua".into()))
            .with_error_message(Some("boom".into()))
            .with_metadata("k".into(), "v".into());
        let json = serde_json::to_value(to_wire(&log).unwrap()).unwrap();
        assert_eq!(json["user_id"], "u1");
        assert_eq!(json["metadata"]["k"], "v");
        assert_eq!(json["ip_address"], "127.0.0.1");
        assert_eq!(json["error_message"], "boom");
        assert!(json["identity_id"].is_string());
    }

    #[test]
    fn each_limit_rejects_oversized_value_in_bytes() {
        // Byte-based validation: 43 CJK characters = 129 bytes > 128, though the
        // character count of 43 is ≤ 128 — validating by character count would let
        // this poison pill through.
        let cjk129: String = "审".repeat(43);
        assert_eq!(cjk129.len(), 129);

        let cases: Vec<AuditLog> = vec![
            sample_log().with_error_message(Some("x".repeat(1025))),
            sample_log().with_user_id(Some("x".repeat(257))),
            sample_log().with_session_id(Some("x".repeat(257))),
            sample_log().with_resource_id(Some("x".repeat(257))),
            sample_log().with_ip_address(Some("x".repeat(65))),
            sample_log().with_user_agent(Some("x".repeat(513))),
            sample_log().with_metadata_map(HashMap::from([(cjk129, "v".into())])),
            sample_log().with_metadata_map(HashMap::from([("k".into(), "x".repeat(513))])),
        ];
        for log in cases {
            let issues = to_wire(&log).unwrap_err();
            assert!(!issues.is_empty());
        }

        // metadata entry-count ceiling
        let map: HashMap<String, String> = (0..33).map(|i| (format!("k{i}"), "v".into())).collect();
        assert!(!to_wire(&sample_log().with_metadata_map(map)).is_ok());
    }

    #[test]
    fn boundary_values_are_accepted() {
        let log = sample_log()
            .with_error_message(Some("x".repeat(1024)))
            .with_user_id(Some("x".repeat(256)))
            .with_ip_address(Some("x".repeat(64)))
            .with_metadata_map(HashMap::from([("x".repeat(64), "x".repeat(512))]));
        assert!(to_wire(&log).is_ok());
    }

    #[test]
    fn build_batch_splits_valid_and_rejected() {
        let logs = vec![
            sample_log(),
            AuditLog::new(
                AuditAction::Custom("x".repeat(129)),
                ResourceType::User,
                true,
            ),
            sample_log().with_user_id(Some("ok".into())),
        ];
        let (events, rejected) = build_batch(&logs);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].user_id, None);
        assert_eq!(events[1].user_id.as_deref(), Some("ok"));
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].0, 1);
        assert_eq!(rejected[0].1[0].field, "action");
    }
}
