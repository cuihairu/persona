use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use persona_core::{
    auth::AuthResult,
    storage::{CredentialRepository, IdentityRepository},
    Database,
};
use tokio::runtime::Builder;

mod app;
mod data;
#[cfg(test)]
mod tests;
mod view;

pub(crate) use app::{handle_key, AppState};
pub(crate) use data::DataProvider;
pub(crate) use view::render_ui;

#[derive(Args, Clone)]
pub struct TuiArgs {
    /// Preselect an identity by name
    #[arg(short, long)]
    pub identity: Option<String>,
}

pub async fn execute(args: TuiArgs, config: &CliConfig) -> Result<()> {
    let provider = init_data_provider(config, &TerminalUi).await?;
    let identity_hint = args.identity.clone();

    tokio::task::spawn_blocking(move || {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build TUI runtime")?;
        crate::commands::tui_runtime::run_tui(&runtime, provider, identity_hint)
    })
    .await??;

    Ok(())
}

async fn init_data_provider(config: &CliConfig, ui: &dyn PromptUi) -> Result<DataProvider> {
    let db_path = config.get_database_path();
    let db: persona_core::Database = Database::from_file::<std::path::PathBuf>(db_path.to_owned())
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    db.migrate()
        .await
        .context("Failed to run database migrations")?;

    let repo_db = db.clone();
    let mut service = crate::commands::service::new_service(db)
        .await
        .context("Failed to construct Persona service")?;

    if service
        .has_users()
        .await
        .context("Failed to check workspace users")?
    {
        let password = ui
            .password("Enter master password to unlock", false, None)
            .context("Failed to read password")?;

        match service
            .authenticate_user(&password)
            .await
            .context("Authentication failed")?
        {
            AuthResult::Success => Ok(DataProvider::Service(service)),
            other => Err(anyhow!("Authentication failed: {:?}", other)),
        }
    } else {
        Ok(DataProvider::Direct {
            identity_repo: IdentityRepository::new(repo_db.clone()),
            credential_repo: CredentialRepository::new(repo_db),
        })
    }
}
