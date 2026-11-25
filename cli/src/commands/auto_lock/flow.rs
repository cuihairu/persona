//! Command dispatch: destructures the arguments per subcommand and hands them to the domain functions; vault initialization is finalized here.

use anyhow::{Context, Result};
use persona_core::storage::{AutoLockPolicyRepository, Database};
use std::sync::Arc;

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::{PromptUi, TerminalUi};

use super::assignment;
use super::dashboard;
use super::display::OutputFormatter;
use super::policies;
use super::session;
use super::{AutoLockArgs, AutoLockCommand};

pub async fn handle_auto_lock(args: AutoLockArgs, config: &CliConfig) -> Result<()> {
    handle_auto_lock_with(args, config, &TerminalUi).await
}

pub(crate) async fn handle_auto_lock_with(
    args: AutoLockArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let repo = init_repository(config).await?;
    let formatter = OutputFormatter;

    match args.command {
        AutoLockCommand::List {
            active,
            security_level,
            search,
        } => policies::list(&repo, &formatter, active, security_level, search).await?,
        AutoLockCommand::Show { policy_identifier } => {
            policies::show(&repo, &formatter, policy_identifier).await?
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
            policies::create(
                &repo,
                &formatter,
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
            )
            .await?
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
            policies::update(
                &repo,
                &formatter,
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
            )
            .await?
        }
        AutoLockCommand::Delete { policy_id, force } => {
            policies::delete(&repo, &formatter, ui, config, policy_id, force).await?
        }
        AutoLockCommand::Assign {
            user_id,
            policy_identifier,
        } => assignment::assign(&repo, &formatter, user_id, policy_identifier).await?,
        AutoLockCommand::Unassign { user_id } => {
            assignment::unassign(&repo, &formatter, user_id).await?
        }
        AutoLockCommand::UserPolicy { user_id } => {
            assignment::user_policy(&repo, &formatter, user_id).await?
        }
        AutoLockCommand::SetDefault { policy_id } => {
            policies::set_default(&repo, &formatter, policy_id).await?
        }
        AutoLockCommand::Stats { policy_id } => {
            dashboard::stats(&repo, &formatter, policy_id).await?
        }
        AutoLockCommand::Status { user_id } => dashboard::status(&formatter, user_id).await?,
        AutoLockCommand::Lock { session_id } => session::lock(&formatter, session_id).await?,
        AutoLockCommand::Unlock { session_id } => session::unlock(&formatter, session_id).await?,
    }

    Ok(())
}

pub(super) async fn init_repository(config: &CliConfig) -> Result<AutoLockPolicyRepository> {
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
