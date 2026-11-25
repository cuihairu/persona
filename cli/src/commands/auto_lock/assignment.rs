//! User assignment: assign a policy to a user, unassign it, and query a user's current policy.

use anyhow::{anyhow, bail, Result};
use persona_core::storage::AutoLockPolicyRepository;

use crate::utils::core_ext::CoreResultExt;

use super::display::OutputFormatter;

pub(super) async fn assign(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    user_id: String,
    policy_identifier: String,
) -> Result<()> {
    let user_uuid = if let Ok(uuid) = uuid::Uuid::parse_str(&user_id) {
        uuid
    } else {
        bail!("User ID must be a valid UUID");
    };

    let policy = if let Ok(uuid) = uuid::Uuid::parse_str(&policy_identifier) {
        repo.find_by_id(&uuid).await.into_anyhow()?
    } else {
        let policies = repo
            .find_by_name_like(&policy_identifier)
            .await
            .into_anyhow()?;
        policies.into_iter().find(|p| p.name == policy_identifier)
    };

    let policy = policy.ok_or_else(|| anyhow!("Policy '{}' not found", policy_identifier))?;

    repo.assign_to_user(&policy.id, &user_uuid)
        .await
        .into_anyhow()?;
    formatter.print_success(&format!(
        "Assigned policy '{}' to user {}",
        policy.name, user_id
    ));
    Ok(())
}

pub(super) async fn unassign(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    user_id: String,
) -> Result<()> {
    let user_uuid = if let Ok(uuid) = uuid::Uuid::parse_str(&user_id) {
        uuid
    } else {
        bail!("User ID must be a valid UUID");
    };

    repo.remove_user_assignment(&user_uuid)
        .await
        .into_anyhow()?;
    formatter.print_success(&format!("Removed policy assignment from user {}", user_id));
    Ok(())
}

pub(super) async fn user_policy(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    user_id: String,
) -> Result<()> {
    let user_uuid = if let Ok(uuid) = uuid::Uuid::parse_str(&user_id) {
        uuid
    } else {
        bail!("User ID must be a valid UUID");
    };

    if let Some(policy) = repo.get_user_policy(&user_uuid).await.into_anyhow()? {
        formatter.print_info(&format!("User {} assigned to policy:", user_id));
        formatter.print_info(&format!("  Name: {}", policy.name));
        formatter.print_info(&format!("  Security Level: {:?}", policy.security_level));
        formatter.print_info(&format!(
            "  Inactivity Timeout: {}s",
            policy.inactivity_timeout_secs
        ));
    } else {
        formatter.print_info(&format!(
            "User {} has no specific policy assignment",
            user_id
        ));
        if let Some(default_policy) = repo.get_default_policy().await.into_anyhow()? {
            formatter.print_info("User will use default policy:");
            formatter.print_info(&format!("  Name: {}", default_policy.name));
            formatter.print_info(&format!(
                "  Security Level: {:?}",
                default_policy.security_level
            ));
        }
    }
    Ok(())
}
