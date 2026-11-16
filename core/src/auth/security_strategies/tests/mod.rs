use super::*;
use std::collections::HashMap;

fn context_at(location: &str) -> SecurityContext {
    SecurityContext {
        user_id: "user123".to_string(),
        session_id: "session456".to_string(),
        location: location.to_string(),
        device_id: "device789".to_string(),
        network: "Corporate LAN".to_string(),
        current_time: chrono::Utc::now(),
        session_duration_secs: 3600,
        daily_usage_secs: 7200,
        inactivity_duration_secs: 300,
        risk_score: 0.2,
        session_locked: false,
        session_timeout_extended_by: 0,
        reauth_required: false,
        reauth_method: None,
        notifications: Vec::new(),
        security_events: Vec::new(),
        restricted_features: Vec::new(),
    }
}

fn triggers(condition: SecurityCondition, context: &SecurityContext) -> bool {
    SecurityStrategy::new(
        "probe".to_string(),
        SecurityCategory::Custom,
        RiskLevel::Low,
    )
    .with_condition(condition)
    .should_trigger(context)
}

mod actions;
mod conditions;
mod strategy;
