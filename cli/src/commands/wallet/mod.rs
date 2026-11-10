use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    crypto::{
        build_raw_transaction, change_mnemonic_password, change_wallet_password, sign_transaction,
        signing_key_for_address, verify_ethereum_transaction, verify_solana_transaction,
        EncryptedMnemonic, EncryptedWalletKey, WalletSigningKey,
    },
    models::wallet::{
        AddressType, BipVersion, BlockchainNetwork, CryptoWallet, SignedTransaction,
        TransactionRequest, WalletAddress, WalletSecurityLevel, WalletType,
    },
    storage::{CryptoWalletRepository, Database},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tabled::{settings::Style, Table, Tabled};

mod args;
mod commands;
mod format;
mod output;
mod psbt;

#[cfg(test)]
mod integration;
#[cfg(test)]
mod tests;

pub use args::{WalletArgs, WalletCommand};
pub use commands::handle_wallet;

use commands::find_wallet_by_identifier;
use format::{
    export_requires_password, format_address_type, format_wallet_type, parse_address_type,
    parse_network, parse_wallet_security_level, parse_wallet_type,
};
use output::OutputFormatter;
use psbt::{decode_psbt_input, run_export_psbt, run_sign_psbt};
