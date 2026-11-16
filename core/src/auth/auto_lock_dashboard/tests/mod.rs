use super::*;
use crate::auth::auto_lock::AutoLockEvent;
use crate::auth::auto_lock_cached::CachedAutoLockManager;
use crate::auth::security_strategies::{SecurityContext, SecurityStrategy};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn sample_context(location: &str) -> SecurityContext {
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

mod dashboard;
mod model;
mod view;
