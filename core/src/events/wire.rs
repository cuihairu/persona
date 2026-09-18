//! wire 形状：server Events API 的客户端镜像与发送前预校验。
//!
//! [`limits`] 与 `server/src/api/events.rs` 的校验上限逐项保持同步
//! （server 是权威；core 不能反向依赖 server，只能注释锚定——那边
//! 改了必须两边一起改）。

use crate::models::AuditLog;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

/// server 校验上限镜像（字节口径，与 server 端 `str::len()` 一致）。
pub mod limits {
    /// server 单批上限（server/src/api/events.rs `MAX_BATCH_SIZE`）；
    /// `EmitterConfig::batch_size` 不得超过此值。
    pub const MAX_BATCH_SIZE: usize = 500;
    pub const MAX_ACTION_LEN: usize = 128;
    /// id / resource_id / user_id / session_id 共用。
    pub const MAX_ID_LEN: usize = 256;
    pub const MAX_IP_LEN: usize = 64;
    pub const MAX_UA_LEN: usize = 512;
    pub const MAX_ERROR_LEN: usize = 1024;
    pub const MAX_METADATA_ENTRIES: usize = 32;
    pub const MAX_METADATA_KEY_LEN: usize = 64;
    pub const MAX_METADATA_VALUE_LEN: usize = 512;
}

/// server `IngestEvent` 的客户端镜像。`id` 是幂等键（AuditLog 的 UUID），
/// server 据此去重；Option 字段全部跳过序列化，省带宽并对齐 server 语义。
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

/// 单条事件的预校验失败原因（`field` 为静态字段名，对齐 server ErrorItem）。
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

/// `AuditLog` → wire。逐条按 server 上限做**字节**长度预校验——server 是
/// 全有或全无校验，一条毒丸会拖垮整批；不合法返回全部原因，调用方丢弃
/// 并 warn。长度一律 `str::len()`（字节），与 server 口径一致。
///
/// action/resource_type 用 `Display` 而非 serde：`AuditAction` 的 serde 是
/// externally-tagged（`Custom` 序列化为 `{"custom":"x"}` 对象），server
/// 期望纯字符串。
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

/// 批量转换：返回（合法批, (输入下标, 原因) 列表），顺序保持。
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
        // id 是幂等键：AuditLog 的 UUID 字符串
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
        // 按字节校验：43 个 CJK 字符 = 129 字节 > 128，字符数 43 却 ≤ 128——
        // 若按字符数校验此用例会放行毒丸。
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

        // metadata 条数上限
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
