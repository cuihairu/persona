use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    auth::session::{SessionManager, AutoLockConfig},
    models::auto_lock_policy::{
        AutoLockPolicy, AutoLockSecurityLevel, AutoLockUseCase, PolicyConfiguration,
    },
    storage::{AutoLockPolicyRepository, Database},
};
use std::sync::Arc;
use tabled::{settings::Style, Table, Tabled};

#[derive(Args)]
pub struct AutoLockArgs {
    #[command(subcommand)]
    pub command: AutoLockCommand,
}

#[derive(Subcommand)]
pub enum AutoLockCommand {
    /// List all auto-lock policies
    List {
        /// Show only active policies
        #[arg(long, short)]
        active: bool,

        /// Filter by security level
        #[arg(long, short)]
        security_level: Option<AutoLockSecurityLevel>,

        /// Search policies by name
        #[arg(long, short)]
        search: Option<String>,
    },
    /// Show details of a specific policy
    Show {
        /// Policy ID or name
        policy_identifier: String,
    },
    /// Create a new auto-lock policy
    Create {
        /// Policy name
        #[arg(long, short)]
        name: String,

        /// Policy description
        #[arg(long, short)]
        description: Option<String>,

        /// Security level (low, medium, high, maximum)
        #[arg(long, short)]
        security_level: AutoLockSecurityLevel,

        /// Inactivity timeout in seconds
        #[arg(long, short)]
        inactivity_timeout: Option<u64>,

        /// Absolute session timeout in seconds
        #[arg(long, short)]
        absolute_timeout: Option<u64>,

        /// Sensitive operation timeout in seconds
        #[arg(long, short)]
        sensitive_timeout: Option<u64>,

        /// Maximum concurrent sessions
        #[arg(long)]
        max_sessions: Option<usize>,

        /// Enable lock warnings
        #[arg(long)]
        warnings: bool,

        /// Warning time before lock in seconds
        #[arg(long)]
        warning_time: Option<u64>,

        /// Force lock on sensitive operations
        #[arg(long)]
        force_sensitive: bool,

        /// Create from predefined use case (personal|corporate|public|developer|high-security)
        #[arg(long, short)]
        use_case: Option<String>,
    },
    /// Update an existing auto-lock policy
    Update {
        /// Policy ID
        policy_id: uuid::Uuid,

        /// New policy name
        #[arg(long, short)]
        name: Option<String>,

        /// New policy description
        #[arg(long, short)]
        description: Option<String>,

        /// New security level
        #[arg(long, short)]
        security_level: Option<AutoLockSecurityLevel>,

        /// New inactivity timeout in seconds
        #[arg(long, short)]
        inactivity_timeout: Option<u64>,

        /// New absolute session timeout in seconds
        #[arg(long, short)]
        absolute_timeout: Option<u64>,

        /// New sensitive operation timeout in seconds
        #[arg(long, short)]
        sensitive_timeout: Option<u64>,

        /// New maximum concurrent sessions
        #[arg(long)]
        max_sessions: Option<usize>,

        /// Enable/disable warnings
        #[arg(long)]
        warnings: Option<bool>,

        /// New warning time in seconds
        #[arg(long)]
        warning_time: Option<u64>,

        /// Enable/disable force sensitive lock
        #[arg(long)]
        force_sensitive: Option<bool>,
    },
    /// Delete an auto-lock policy
    Delete {
        /// Policy ID
        policy_id: uuid::Uuid,

        /// Skip confirmation prompt
        #[arg(long, short)]
        force: bool,
    },
    /// Assign a policy to a user
    Assign {
        /// User ID (email or UUID)
        user_id: String,

        /// Policy ID or name
        policy_identifier: String,
    },
    /// Remove policy assignment from user
    Unassign {
        /// User ID (email or UUID)
        user_id: String,
    },
    /// Show policy assigned to a user
    UserPolicy {
        /// User ID (email or UUID)
        user_id: String,
    },
    /// Set a policy as the default
    SetDefault {
        /// Policy ID
        policy_id: uuid::Uuid,
    },
    /// Get current auto-lock statistics
    Stats {
        /// Policy ID to get statistics for specific policy
        #[arg(long, short)]
        policy_id: Option<uuid::Uuid>,
    },
    /// Show current session status
    Status {
        /// User ID (optional, defaults to current user)
        #[arg(long, short)]
        user_id: Option<String>,
    },
    /// Lock current session
    Lock {
        /// Session ID (optional, defaults to current session)
        #[arg(long, short)]
        session_id: Option<String>,
    },
    /// Unlock a session
    Unlock {
        /// Session ID
        session_id: String,
    },
}

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

pub async fn handle_auto_lock(args: AutoLockArgs, config: &CliConfig) -> Result<()> {
    let repo = init_repository(config).await?;
    let formatter = OutputFormatter::default();

    match args.command {
        AutoLockCommand::List {
            active,
            security_level,
            search,
        } => {
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
                    default: "".to_string(), // TODO: Check if it's default
                })
                .collect();

            let table = Table::new(&table_data).with(Style::modern()).to_string();
            formatter.print_output(&table);
        }

        AutoLockCommand::Show { policy_identifier } => {
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
                    formatter
                        .print_info(&format!("Force Lock Sensitive: {}", p.force_lock_sensitive));
                    formatter.print_info(&format!("Security Score: {}/100", p.security_score()));
                    formatter.print_info(&format!("Active: {}", p.is_active));
                    formatter.print_info(&format!(
                        "Created: {}",
                        p.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                    ));
                }
                None => bail!("Policy '{}' not found", policy_identifier),
            }
        }

        AutoLockCommand::Create {
            name,
            description,
            security_level,
            inactivity_timeout,
            absolute_timeout,
            sensitive_timeout,
            max_sessions,
            warnings,
            warning_time,
            force_sensitive,
            use_case,
        } => {
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
        }

        AutoLockCommand::Update {
            policy_id,
            name,
            description,
            security_level,
            inactivity_timeout,
            absolute_timeout,
            sensitive_timeout,
            max_sessions,
            warnings,
            warning_time,
            force_sensitive,
        } => {
            let mut policy = repo
                .find_by_id(&policy_id)
                .await
                .into_anyhow()?
                .ok_or_else(|| anyhow!("Policy with ID '{}' not found", policy_id))?;

            // Create configuration for updates
            let mut config = PolicyConfiguration {
                name: policy.name.clone(),
                description: policy.description.clone(),
                security_level: policy.security_level.clone(),
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
        }

        AutoLockCommand::Delete { policy_id, force } => {
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

                // TODO: Add confirmation prompt
                formatter.print_warning(&format!("This will delete policy '{}'.", policy.name));
                formatter.print_warning("Use --force to skip confirmation.");
                return Ok(());
            }

            let deleted = repo.delete(&policy_id).await.into_anyhow()?;
            if deleted {
                formatter.print_success(&format!("Deleted policy '{}'", policy.name));
            } else {
                formatter.print_error("Failed to delete policy");
            }
        }

        AutoLockCommand::Assign {
            user_id,
            policy_identifier,
        } => {
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

            let policy =
                policy.ok_or_else(|| anyhow!("Policy '{}' not found", policy_identifier))?;

            repo.assign_to_user(&policy.id, &user_uuid)
                .await
                .into_anyhow()?;
            formatter.print_success(&format!(
                "Assigned policy '{}' to user {}",
                policy.name, user_id
            ));
        }

        AutoLockCommand::Unassign { user_id } => {
            let user_uuid = if let Ok(uuid) = uuid::Uuid::parse_str(&user_id) {
                uuid
            } else {
                bail!("User ID must be a valid UUID");
            };

            repo.remove_user_assignment(&user_uuid)
                .await
                .into_anyhow()?;
            formatter.print_success(&format!("Removed policy assignment from user {}", user_id));
        }

        AutoLockCommand::UserPolicy { user_id } => {
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
        }

        AutoLockCommand::SetDefault { policy_id } => {
            repo.set_as_default(&policy_id).await.into_anyhow()?;
            formatter.print_success(&format!("Set policy {} as default", policy_id));
        }

        AutoLockCommand::Stats { policy_id } => {
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
                    formatter.print_info(&format!("  Default Policy: {} ({})", default_policy.name, default_policy.security_level));
                } else {
                    formatter.print_warning("  No default policy set");
                }
            }
        }

        AutoLockCommand::Status { user_id } => {
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
            formatter.print_info(&format!("  Inactivity Timeout: {}s", config.inactivity_timeout_secs));
            formatter.print_info(&format!("  Absolute Timeout: {}s", config.absolute_timeout_secs));
            formatter.print_info(&format!("  Sensitive Op Timeout: {}s", config.sensitive_operation_timeout_secs));
            formatter.print_info(&format!("  Require Re-auth for Sensitive Ops: {}", config.require_reauth_sensitive));
        }

        AutoLockCommand::Lock { session_id } => {
            let session_manager = SessionManager::new();

            if let Some(sid) = session_id {
                // Lock specific session
                match session_manager.lock_session(&sid).await {
                    Ok(()) => {
                        formatter.print_success(&format!("🔒 Session {} locked successfully", sid));
                    }
                    Err(e) => {
                        formatter.print_error(&format!("Failed to lock session {}: {}", sid, e));
                    }
                }
            } else {
                // In a real implementation, you'd lock the current user's session
                // For now, we show information about manual session locking
                formatter.print_info("🔒 Manual Session Lock");
                formatter.print_info("To lock a specific session, provide --session-id");
                formatter.print_info("Example: persona auto-lock lock --session-id <session-uuid>");
                formatter.print_info("Note: In a production setup, this would lock your current session");
            }
        }

        AutoLockCommand::Unlock { session_id } => {
            let session_manager = SessionManager::new();

            match session_manager.unlock_session(&session_id).await {
                Ok(()) => {
                    formatter.print_success(&format!("🔓 Session {} unlocked successfully", session_id));
                    formatter.print_info("Session timers have been reset and activity updated");
                }
                Err(e) => {
                    formatter.print_error(&format!("Failed to unlock session {}: {}", session_id, e));
                    formatter.print_info("Make sure the session ID is correct and exists");
                }
            }
        }
    }

    Ok(())
}

async fn init_repository(config: &CliConfig) -> Result<AutoLockPolicyRepository> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;
    Ok(AutoLockPolicyRepository::new(Arc::new(db)))
}

fn parse_use_case_label(label: &str) -> Result<AutoLockUseCase> {
    match label.to_lowercase().as_str() {
        "personal" | "personal-device" | "personal_device" => Ok(AutoLockUseCase::PersonalDevice),
        "corporate" | "desktop" | "corporate-desktop" | "corporate_desktop" => {
            Ok(AutoLockUseCase::CorporateDesktop)
        }
        "public" | "kiosk" | "public-kiosk" | "public_kiosk" => Ok(AutoLockUseCase::PublicKiosk),
        "developer" | "dev" | "developer-environment" | "developer_environment" => {
            Ok(AutoLockUseCase::DeveloperEnvironment)
        }
        "high" | "high-security" | "high_security" | "facility" => {
            Ok(AutoLockUseCase::HighSecurityFacility)
        }
        other => bail!("Unsupported use case '{}'", other),
    }
}

#[derive(Default)]
struct OutputFormatter;

impl OutputFormatter {
    fn print_info(&self, message: &str) {
        println!("{}", message.cyan());
    }

    fn print_output(&self, message: &str) {
        println!("{}", message);
    }

    fn print_success(&self, message: &str) {
        println!("{} {}", "✓".green().bold(), message);
    }

    fn print_warning(&self, message: &str) {
        println!("{} {}", "⚠".yellow().bold(), message);
    }

    fn print_error(&self, message: &str) {
        println!("{} {}", "✗".red().bold(), message.red());
    }
}
