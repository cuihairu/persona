use super::*;
use crate::config::CliConfig;
use crate::utils::prompt::scripted::ScriptedUi;
use anyhow::Result;
use tempfile::TempDir;

use super::display::parse_use_case_label;
use super::flow::{handle_auto_lock_with, init_repository};
use persona_core::models::auto_lock_policy::AutoLockUseCase;

mod assignment;
mod display;
mod flow;
mod policies;

fn config_for(dir: &TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    config
}

async fn handler(command: AutoLockCommand, dir: &TempDir) -> Result<()> {
    handle_auto_lock(AutoLockArgs { command }, &config_for(dir)).await
}
