use anyhow::{anyhow, bail, Context, Result};
use colored::*;
use std::path::PathBuf;
use tabled::{Table, Tabled};
use uuid::Uuid;

use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use persona_core::{
    custom_fields::new_custom_field,
    models::{
        ApiKeyData, Credential, CredentialData, CustomField, CustomFieldType, EntityType,
        IdentityData, PasswordCredentialData, SecureNoteData, SoftwareLicenseData,
    },
    Identity, PersonaService,
};

use crate::utils::prompt::{PromptUi, TerminalUi};

use super::service::init_service;

mod args;
mod attachments;
mod crud;
mod fields;
mod history;

pub use args::{AddArgs, CredentialArgs, CredentialCommand, CredentialTypeOption};

use attachments::{
    attach_file_command, list_attachments_command, remove_attachment_command,
    save_attachment_command,
};
use crud::{add_credential, list_credentials, remove_credential, show_credential};
use fields::{list_custom_fields_command, set_custom_fields_command};
use history::{restore_credential_version_command, show_credential_history};

pub async fn execute(args: CredentialArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: CredentialArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        CredentialCommand::Add(args) => add_credential(config, ui, *args).await?,
        CredentialCommand::List {
            identity,
            credential_type,
            favorite,
            format,
        } => list_credentials(config, ui, identity, credential_type, favorite, format).await?,
        CredentialCommand::Show { id, reveal } => show_credential(config, ui, id, reveal).await?,
        CredentialCommand::Remove { id, yes } => remove_credential(config, ui, id, yes).await?,
        CredentialCommand::History { id } => show_credential_history(config, ui, id).await?,
        CredentialCommand::Restore { id, version } => {
            restore_credential_version_command(config, ui, id, version).await?
        }
        CredentialCommand::Attach {
            id,
            file,
            no_encrypt,
        } => attach_file_command(config, ui, id, file, !no_encrypt).await?,
        CredentialCommand::Attachments { id } => list_attachments_command(config, ui, id).await?,
        CredentialCommand::SaveAttachment {
            attachment_id,
            output,
        } => save_attachment_command(config, ui, attachment_id, output).await?,
        CredentialCommand::RemoveAttachment { attachment_id, yes } => {
            remove_attachment_command(config, ui, attachment_id, yes).await?
        }
        CredentialCommand::Fields { id, reveal } => {
            list_custom_fields_command(config, ui, id, reveal).await?
        }
        CredentialCommand::SetFields { id, fields, clear } => {
            set_custom_fields_command(config, ui, id, fields, clear).await?
        }
    }
    Ok(())
}

async fn resolve_identity(service: &mut PersonaService, name: &str) -> Result<Identity> {
    service
        .get_identity_by_name(name)
        .await
        .into_anyhow()?
        .ok_or_else(|| anyhow!("Identity '{}' not found", name))
}

#[cfg(test)]
mod tests;
