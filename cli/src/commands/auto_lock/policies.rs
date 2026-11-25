//! Policy CRUD: list/detail/create/update/delete/set default. Table rendering lives here with the list.

use anyhow::{anyhow, bail, Result};
use persona_core::models::auto_lock_policy::{
    AutoLockPolicy, AutoLockSecurityLevel, PolicyConfiguration,
};
use persona_core::storage::AutoLockPolicyRepository;
use tabled::{settings::Style, Table, Tabled};

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::PromptUi;

use super::display::{parse_use_case_label, OutputFormatter};

/// Table display for AutoLockPolicy
#[derive(Tabled)]
struct PolicyTable {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Security")]
    security: String,
    #[tabled(rename = "Inactivity")]
    inactivity: String,
    #[tabled(rename = "Max Sessions")]
    max_sessions: String,
    #[tabled(rename = "Active")]
    active: String,
    #[tabled(rename = "Default")]
    default: String,
}

pub(super) async fn list(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    active: bool,
    security_level: Option<AutoLockSecurityLevel>,
    search: Option<String>,
) -> Result<()> {
    let policies = if let Some(level) = security_level {
        repo.find_by_security_level(&level).await.into_anyhow()?
    } else if let Some(pattern) = search {
        repo.find_by_name_like(&pattern).await.into_anyhow()?
    } else if active {
        repo.find_active().await.into_anyhow()?
    } else {
        repo.find_all().await.into_anyhow()?
    };

    if policies.is_empty() {
        formatter.print_info("No auto-lock policies found.");
        return Ok(());
    }

    let table_data: Vec<PolicyTable> = policies
        .iter()
        .map(|p| PolicyTable {
            id: p.id.to_string().chars().take(8).collect(),
            name: p.name.clone(),
            security: format!("{:?}", p.security_level).to_lowercase(),
            inactivity: format!("{}s", p.inactivity_timeout_secs),
            max_sessions: p.max_concurrent_sessions.to_string(),
            active: if p.is_active { "✓" } else { "✗" }.to_string(),
            default: if p.is_default { "★" } else { "" }.to_string(),
        })
        .collect();

    let table = Table::new(&table_data).with(Style::modern()).to_string();
    formatter.print_output(&table);
    Ok(())
}

pub(super) async fn show(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    policy_identifier: String,
) -> Result<()> {
    let policy = if let Ok(uuid) = uuid::Uuid::parse_str(&policy_identifier) {
        repo.find_by_id(&uuid).await.into_anyhow()?
    } else {
        let policies = repo
            .find_by_name_like(&policy_identifier)
            .await
            .into_anyhow()?;
        policies.into_iter().find(|p| p.name == policy_identifier)
    };

    match policy {
        Some(p) => {
            formatter.print_info(&format!("Auto-Lock Policy: {}", p.name));
            formatter.print_info(&format!("ID: {}", p.id));
            formatter.print_info(&format!("Description: {:?}", p.description));
            formatter.print_info(&format!("Security Level: {:?}", p.security_level));
            formatter.print_info(&format!(
                "Inactivity Timeout: {} seconds",
                p.inactivity_timeout_secs
            ));
            formatter.print_info(&format!(
                "Absolute Timeout: {} seconds",
                p.absolute_timeout_secs
            ));
            formatter.print_info(&format!(
                "Sensitive Operation Timeout: {} seconds",
                p.sensitive_operation_timeout_secs
            ));
            formatter.print_info(&format!(
                "Max Concurrent Sessions: {}",
                p.max_concurrent_sessions
            ));
            formatter.print_info(&format!("Warnings Enabled: {}", p.enable_warnings));
            formatter.print_info(&format!("Warning Time: {} seconds", p.warning_time_secs));
            formatter.print_info(&format!("Force Lock Sensitive: {}", p.force_lock_sensitive));
            formatter.print_info(&format!("Security Score: {}/100", p.security_score()));
            formatter.print_info(&format!("Active: {}", p.is_active));
            formatter.print_info(&format!(
                "Created: {}",
                p.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
        None => bail!("Policy '{}' not found", policy_identifier),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn create(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    name: String,
    description: Option<String>,
    security_level: AutoLockSecurityLevel,
    inactivity_timeout: Option<u64>,
    absolute_timeout: Option<u64>,
    sensitive_timeout: Option<u64>,
    max_sessions: Option<usize>,
    warnings: bool,
    warning_time: Option<u64>,
    force_sensitive: bool,
    use_case: Option<String>,
) -> Result<()> {
    let policy = if let Some(use_case) = use_case {
        let parsed = parse_use_case_label(&use_case)?;
        let mut p = AutoLockPolicy::recommended_for_use_case(parsed);
        p.name = name;
        p.description = description;
        p
    } else {
        let config = PolicyConfiguration {
            name,
            description,
            security_level,
            inactivity_timeout_secs: inactivity_timeout.unwrap_or(900),
            absolute_timeout_secs: absolute_timeout.unwrap_or(3600),
            sensitive_operation_timeout_secs: sensitive_timeout.unwrap_or(300),
            max_concurrent_sessions: max_sessions.unwrap_or(5),
            enable_warnings: warnings,
            warning_time_secs: warning_time.unwrap_or(60),
            force_lock_sensitive: force_sensitive,
            activity_grace_period_secs: 5,
            background_check_interval_secs: 30,
            is_active: true,
        };

        AutoLockPolicy::new_full(config)
    };

    // Validate policy
    policy
        .validate()
        .map_err(|e| anyhow!("Invalid policy configuration: {}", e))?;

    let created = repo.create(&policy).await.into_anyhow()?;
    formatter.print_success(&format!(
        "Created policy '{}' with ID: {}",
        created.name, created.id
    ));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn update(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    policy_id: uuid::Uuid,
    name: Option<String>,
    description: Option<String>,
    security_level: Option<AutoLockSecurityLevel>,
    inactivity_timeout: Option<u64>,
    absolute_timeout: Option<u64>,
    sensitive_timeout: Option<u64>,
    max_sessions: Option<usize>,
    warnings: Option<bool>,
    warning_time: Option<u64>,
    force_sensitive: Option<bool>,
) -> Result<()> {
    let mut policy = repo
        .find_by_id(&policy_id)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Policy with ID '{}' not found", policy_id))?;

    // Create configuration for updates
    let mut config = PolicyConfiguration {
        name: policy.name.clone(),
        description: policy.description.clone(),
        security_level: policy.security_level,
        inactivity_timeout_secs: policy.inactivity_timeout_secs,
        absolute_timeout_secs: policy.absolute_timeout_secs,
        sensitive_operation_timeout_secs: policy.sensitive_operation_timeout_secs,
        max_concurrent_sessions: policy.max_concurrent_sessions,
        enable_warnings: policy.enable_warnings,
        warning_time_secs: policy.warning_time_secs,
        force_lock_sensitive: policy.force_lock_sensitive,
        activity_grace_period_secs: policy.activity_grace_period_secs,
        background_check_interval_secs: policy.background_check_interval_secs,
        is_active: policy.is_active,
    };

    // Apply updates
    if let Some(n) = name {
        config.name = n;
    }
    if let Some(d) = description {
        config.description = Some(d);
    }
    if let Some(sl) = security_level {
        config.security_level = sl;
    }
    if let Some(t) = inactivity_timeout {
        config.inactivity_timeout_secs = t;
    }
    if let Some(t) = absolute_timeout {
        config.absolute_timeout_secs = t;
    }
    if let Some(t) = sensitive_timeout {
        config.sensitive_operation_timeout_secs = t;
    }
    if let Some(m) = max_sessions {
        config.max_concurrent_sessions = m;
    }
    if let Some(w) = warnings {
        config.enable_warnings = w;
    }
    if let Some(t) = warning_time {
        config.warning_time_secs = t;
    }
    if let Some(f) = force_sensitive {
        config.force_lock_sensitive = f;
    }

    policy.update(config);

    // Validate updated policy
    policy
        .validate()
        .map_err(|e| anyhow!("Invalid policy configuration: {}", e))?;

    let updated = repo.update(&policy).await.into_anyhow()?;
    formatter.print_success(&format!("Updated policy '{}'", updated.name));
    Ok(())
}

pub(super) async fn delete(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    ui: &dyn PromptUi,
    config: &CliConfig,
    policy_id: uuid::Uuid,
    force: bool,
) -> Result<()> {
    let policy = repo
        .find_by_id(&policy_id)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Policy with ID '{}' not found", policy_id))?;

    if !force {
        // Check if it's a system policy
        if policy.metadata.is_system_policy {
            bail!("Cannot delete system policy. Use --force to override.");
        }

        // Scripts and CI never get a confirmation prompt: the row is
        // kept and the operator is told how to proceed.
        if !config.ui.interactive {
            formatter.print_warning(&format!("This will delete policy '{}'.", policy.name));
            formatter.print_warning("Non-interactive mode: re-run with --force to delete.");
            return Ok(());
        }

        if !ui.confirm(
            &format!("Delete policy '{}'? This cannot be undone.", policy.name),
            false,
        )? {
            formatter.print_warning("Deletion cancelled.");
            return Ok(());
        }
    }

    let deleted = repo.delete(&policy_id).await.into_anyhow()?;
    if deleted {
        formatter.print_success(&format!("Deleted policy '{}'", policy.name));
    } else {
        formatter.print_error("Failed to delete policy");
    }
    Ok(())
}

pub(super) async fn set_default(
    repo: &AutoLockPolicyRepository,
    formatter: &OutputFormatter,
    policy_id: uuid::Uuid,
) -> Result<()> {
    repo.set_as_default(&policy_id).await.into_anyhow()?;
    formatter.print_success(&format!("Set policy {} as default", policy_id));
    Ok(())
}
