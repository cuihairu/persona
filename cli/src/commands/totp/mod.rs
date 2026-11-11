use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use colored::*;
use persona_core::{
    crypto::game_token::{
        generate_code_now, generate_game_token_code_now, is_supported_provider,
        PROVIDER_STEAM_GUARD,
    },
    crypto::steam::decode_steam_secret,
    crypto::totp::{hotp_code, totp_now},
    import_mafile::parse_ma_file,
    models::{CredentialData, CredentialType, GameTokenData, SecurityLevel, TwoFactorData},
    PersonaService,
};
use rqrr::PreparedImage;
use uuid::Uuid;

use super::service::init_service;
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};

mod args;
mod codes;
mod parse;
mod setup;
mod steam;
mod template;

pub use args::{TotpArgs, TotpCommand};

use codes::generate_codes;
use setup::{setup_game_token, setup_steam_token, setup_totp};
use steam::import_steam_mafiles;

pub async fn execute(args: TotpArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: TotpArgs,
    config: &CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    match args.command {
        TotpCommand::Setup {
            identity,
            name,
            qr,
            otpauth,
            secret,
            issuer,
            account,
            url,
            digits,
            period,
            algorithm,
            hotp,
            counter,
        } => {
            setup_totp(
                config, ui, identity, name, qr, otpauth, secret, issuer, account, url, digits,
                period, algorithm, hotp, counter,
            )
            .await?
        }
        TotpCommand::SetupSteam {
            identity,
            name,
            secret,
            account,
            url,
        } => setup_steam_token(config, ui, identity, name, secret, account, url).await?,
        TotpCommand::SetupGameToken {
            identity,
            provider,
            name,
            secret,
            account,
            issuer,
            url,
        } => {
            setup_game_token(
                config, ui, identity, provider, name, secret, account, issuer, url,
            )
            .await?
        }
        TotpCommand::Code { id, watch, counter } => {
            generate_codes(config, ui, id, watch, counter).await?
        }
        TotpCommand::ImportSteam {
            identity,
            file,
            name,
            url,
            yes,
        } => import_steam_mafiles(config, ui, identity, file, name, url, yes).await?,
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

type Identity = persona_core::models::Identity;

#[cfg(test)]
mod tests;
