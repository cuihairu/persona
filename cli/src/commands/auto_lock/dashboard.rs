//! 统计与状态看板：策略级统计、系统级统计与当前会话状态展示。

use anyhow::{anyhow, Result};
use persona_core::auth::session::{AutoLockConfig, SessionManager};
use persona_core::storage::AutoLockPolicyRepository;

use crate::utils::core_ext::CoreResultExt;

use super::display::OutputFormatter;

pub(super) async fn stats(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    policy_id: Option<uuid::Uuid>,
) -> Result<()> {
    if let Some(id) = policy_id {
        if let Some(stats) = repo.get_statistics(&id).await.into_anyhow()? {
            let policy = repo
                .find_by_id(&id)
                .await
                .into_anyhow()?
                .ok_or_else(|| anyhow!("Policy {} not found", id))?;
            formatter.print_info(&format!("Statistics for policy '{}':", policy.name));
            formatter.print_info(&format!("  Active Sessions: {}", stats.active_sessions));
            formatter.print_info(&format!("  Assigned Users: {}", stats.assigned_users));
            formatter.print_info(&format!(
                "  Avg Session Duration: {}s",
                stats.avg_session_duration_secs
            ));
            formatter.print_info(&format!(
                "  Recent Lock Events (24h): {}",
                stats.recent_lock_events
            ));
            formatter.print_info(&format!(
                "  Compliance Score: {}/100",
                stats.compliance_score
            ));
        } else {
            formatter.print_info("No statistics available for this policy");
        }
    } else {
        // System-wide statistics
        let session_manager = SessionManager::new();
        let active_sessions = session_manager.active_count().await;
        let all_policies = repo.find_all().await.into_anyhow()?;
        let active_policies = repo.find_active().await.into_anyhow()?;

        formatter.print_info("📊 Auto-Lock System Statistics:");
        formatter.print_info(&format!("  Total Policies: {}", all_policies.len()));
        formatter.print_info(&format!("  Active Policies: {}", active_policies.len()));
        formatter.print_info(&format!("  Active Sessions: {}", active_sessions));

        // Calculate security level distribution
        let mut level_counts = std::collections::HashMap::new();
        for policy in &all_policies {
            let count = level_counts.entry(policy.security_level).or_insert(0);
            *count += 1;
        }

        formatter.print_info("🔐 Security Level Distribution:");
        for (level, count) in level_counts {
            formatter.print_info(&format!("  {:?}: {} policies", level, count));
        }

        // Show default policy if exists
        if let Some(default_policy) = repo.get_default_policy().await.into_anyhow()? {
            formatter.print_info(&format!(
                "  Default Policy: {} ({})",
                default_policy.name, default_policy.security_level
            ));
        } else {
            formatter.print_warning("  No default policy set");
        }
    }
    Ok(())
}

pub(super) async fn status(formatter: &OutputFormatter, user_id: Option<String>) -> Result<()> {
    let session_manager = SessionManager::new();

    // Get active sessions count
    let active_sessions = session_manager.active_count().await;

    formatter.print_info("🔒 Auto-Lock Session Status");
    formatter.print_info(&format!("  Active Sessions: {}", active_sessions));

    if let Some(uid) = user_id {
        formatter.print_info(&format!("  Showing status for user: {}", uid));
        // In a real implementation, you'd find sessions for the specific user
        // For now, we show global status
    } else {
        formatter.print_info("  Showing global session status");
    }

    // Show auto-lock configuration
    let config = AutoLockConfig::default();
    formatter.print_info("🔧 Current Auto-Lock Configuration:");
    formatter.print_info(&format!(
        "  Inactivity Timeout: {}s",
        config.inactivity_timeout_secs
    ));
    formatter.print_info(&format!(
        "  Absolute Timeout: {}s",
        config.absolute_timeout_secs
    ));
    formatter.print_info(&format!(
        "  Sensitive Op Timeout: {}s",
        config.sensitive_operation_timeout_secs
    ));
    formatter.print_info(&format!(
        "  Require Re-auth for Sensitive Ops: {}",
        config.require_reauth_sensitive
    ));
    Ok(())
}
