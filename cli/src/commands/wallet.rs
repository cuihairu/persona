use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    crypto::{
        build_raw_transaction, sign_transaction, signing_key_for_address,
        verify_ethereum_transaction, verify_solana_transaction,
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

#[derive(Args)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub command: WalletCommand,
}

#[derive(Subcommand)]
pub enum WalletCommand {
    /// List all crypto wallets
    List {
        /// Filter by network (bitcoin, ethereum, solana, etc.)
        #[arg(long)]
        network: Option<String>,

        /// Filter by security level (low, medium, high, maximum)
        #[arg(long)]
        security_level: Option<String>,

        /// Show only watch-only wallets
        #[arg(long)]
        watch_only: bool,

        /// Search wallets by name
        #[arg(long)]
        search: Option<String>,
    },
    /// Show details of a specific wallet
    Show {
        /// Wallet ID or name
        wallet_identifier: String,
    },
    /// Create a new crypto wallet
    Create {
        /// Wallet name
        #[arg(long)]
        name: String,

        /// Wallet description
        #[arg(long)]
        description: Option<String>,

        /// Blockchain network
        #[arg(long)]
        network: String,

        /// Wallet type (single, hd, multisig, hardware)
        #[arg(long)]
        wallet_type: String,

        /// BIP version for HD wallets (32, 44, 49, 84, 86)
        #[arg(long)]
        bip_version: Option<u32>,

        /// Address count for HD wallets
        #[arg(long)]
        address_count: Option<usize>,

        /// Create watch-only wallet (no private key)
        #[arg(long)]
        watch_only: bool,

        /// Extended public key (for watch-only wallets)
        #[arg(long)]
        xpub: Option<String>,

        /// Security level (low, medium, high, maximum)
        #[arg(long)]
        security_level: Option<String>,

        /// Import from mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,

        /// Import from private key (hex format)
        #[arg(long)]
        private_key: Option<String>,

        /// Derivation path (for HD wallets)
        #[arg(long)]
        derivation_path: Option<String>,
    },
    /// Create a watch-only wallet
    CreateWatchOnly {
        /// Wallet name
        #[arg(long)]
        name: String,

        /// Wallet description
        #[arg(long)]
        description: Option<String>,

        /// Blockchain network
        #[arg(long)]
        network: String,

        /// Extended public key (xpub/ypub/zpub)
        #[arg(long)]
        xpub: String,

        /// Address count to derive
        #[arg(long)]
        address_count: Option<usize>,
    },
    /// Generate a new wallet with fresh keys
    Generate {
        /// Wallet name
        #[arg(long)]
        name: String,

        /// Wallet description
        #[arg(long)]
        description: Option<String>,

        /// Blockchain network
        #[arg(long)]
        network: String,

        /// Generate HD wallet
        #[arg(long)]
        hd: bool,

        /// BIP version for HD wallet (default: 44)
        #[arg(long, default_value = "44")]
        bip_version: u32,

        /// Account index (default: 0)
        #[arg(long, default_value = "0")]
        account: u32,

        /// Address count to derive (default: 20)
        #[arg(long, default_value = "20")]
        address_count: usize,
    },
    /// Update wallet information
    Update {
        /// Wallet ID
        wallet_id: uuid::Uuid,

        /// New wallet name
        #[arg(long)]
        name: Option<String>,

        /// New wallet description
        #[arg(long)]
        description: Option<String>,

        /// New security level
        #[arg(long)]
        security_level: Option<String>,

        /// Add tag
        #[arg(long)]
        add_tag: Option<String>,

        /// Remove tag
        #[arg(long)]
        remove_tag: Option<String>,

        /// Set platform
        #[arg(long)]
        platform: Option<String>,

        /// Set purpose
        #[arg(long)]
        purpose: Option<String>,

        /// Add note
        #[arg(long)]
        note: Option<String>,
    },
    /// Delete a wallet
    Delete {
        /// Wallet ID
        wallet_id: uuid::Uuid,

        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Add address to wallet
    AddAddress {
        /// Wallet ID
        wallet_id: uuid::Uuid,

        /// Address string
        address: String,

        /// Address type (p2pkh, p2sh, p2wpkh, p2tr, ethereum, solana)
        #[arg(long)]
        address_type: String,

        /// Address index
        #[arg(long)]
        index: u32,

        /// Derivation path (for HD wallets)
        #[arg(long)]
        derivation_path: Option<String>,
    },
    /// List addresses in wallet
    ListAddresses {
        /// Wallet ID or name
        wallet_identifier: String,

        /// Show only used addresses
        #[arg(long)]
        used: bool,

        /// Show only unused addresses
        #[arg(long)]
        unused: bool,

        /// Limit number of addresses to show
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Mark address as used
    MarkUsed {
        /// Wallet ID or name
        wallet_identifier: String,

        /// Address string
        address: String,
    },
    /// Create and sign transaction
    CreateTransaction {
        /// Wallet ID or name
        wallet_identifier: String,

        /// To address
        #[arg(long)]
        to: String,

        /// Amount (in smallest unit - satoshis, wei, etc.)
        #[arg(long)]
        amount: String,

        /// Fee (in smallest unit)
        #[arg(long)]
        fee: String,

        /// Gas price (for EVM chains)
        #[arg(long)]
        gas_price: Option<String>,

        /// Gas limit (for EVM chains)
        #[arg(long)]
        gas_limit: Option<u64>,

        /// Nonce (for EVM chains)
        #[arg(long)]
        nonce: Option<u64>,

        /// Memo/note
        #[arg(long)]
        memo: Option<String>,

        /// Sign immediately (requires unlock)
        #[arg(long)]
        sign: bool,

        /// Broadcast immediately after signing
        #[arg(long)]
        broadcast: bool,

        /// Set transaction expiration (minutes)
        #[arg(long)]
        expires_in: Option<u64>,
    },
    /// List pending transactions
    ListTransactions {
        /// Wallet ID or name
        wallet_identifier: String,

        /// Show only pending transactions
        #[arg(long)]
        pending: bool,

        /// Show only signed transactions
        #[arg(long)]
        signed: bool,

        /// Show only broadcast transactions
        #[arg(long)]
        broadcast: bool,
    },
    /// Get wallet statistics
    Stats {
        /// Wallet ID or name (optional, shows overall stats if not provided)
        wallet_identifier: Option<String>,
    },
    /// Export wallet
    Export {
        /// Wallet ID or name
        wallet_identifier: String,

        /// Export format (json, mnemonic, private_key, wif, xpub)
        #[arg(long)]
        format: String,

        /// Include private keys (use with caution)
        #[arg(long)]
        include_private: bool,

        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
    /// Import wallet
    Import {
        /// Import format (json, mnemonic, private_key, keystore, wif)
        #[arg(long)]
        format: String,

        /// Import data (file path or direct input)
        data: String,

        /// Wallet name (overrides imported name)
        #[arg(long)]
        name: Option<String>,
    },
}

/// Table display for CryptoWallet
#[derive(Tabled)]
struct WalletTable {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Network")]
    network: String,
    #[tabled(rename = "Type")]
    wallet_type: String,
    #[tabled(rename = "Security")]
    security: String,
    #[tabled(rename = "Addresses")]
    address_count: String,
    #[tabled(rename = "Watch-Only")]
    watch_only: String,
}

/// Table display for WalletAddress
#[derive(Tabled)]
struct AddressTable {
    #[tabled(rename = "Index")]
    index: u32,
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Type")]
    address_type: String,
    #[tabled(rename = "Used")]
    used: String,
    #[tabled(rename = "Balance")]
    balance: String,
    #[tabled(rename = "Last Activity")]
    last_activity: String,
}

pub async fn handle_wallet(args: WalletArgs, config: &CliConfig) -> Result<()> {
    handle_wallet_with(args, config, &TerminalUi).await
}

/// Like [`handle_wallet`], but every interactive prompt is driven through
/// `ui` so tests can script the terminal (see [`crate::utils::prompt`]).
pub(crate) async fn handle_wallet_with(
    args: WalletArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    let repo = init_wallet_repository(config).await?;
    let formatter = OutputFormatter;

    match args.command {
        WalletCommand::List {
            network,
            security_level,
            watch_only,
            search,
        } => {
            let mut wallets = if let Some(level_str) = security_level {
                let level = parse_wallet_security_level(&level_str)?;
                repo.find_by_security_level(&level).await.into_anyhow()?
            } else if let Some(net_str) = network {
                let network = parse_network(&net_str)?;
                repo.find_by_network(&network).await.into_anyhow()?
            } else {
                repo.find_all().await.into_anyhow()?
            };

            if let Some(pattern) = search {
                let needle = pattern.to_lowercase();
                wallets.retain(|wallet| wallet.name.to_lowercase().contains(&needle));
            }

            if wallets.is_empty() {
                formatter.print_info("No wallets found.");
                return Ok(());
            }

            let filtered_wallets: Vec<_> = wallets
                .into_iter()
                .filter(|w| !watch_only || w.watch_only)
                .collect();

            if filtered_wallets.is_empty() {
                formatter.print_info("No wallets match the specified filters.");
                return Ok(());
            }

            let table_data: Vec<WalletTable> = filtered_wallets
                .iter()
                .map(|w| WalletTable {
                    id: w.id.to_string().chars().take(8).collect(),
                    name: w.name.clone(),
                    network: format!("{}", w.network),
                    wallet_type: format_wallet_type(&w.wallet_type),
                    security: format!("{}", w.security_level),
                    address_count: w.addresses.len().to_string(),
                    watch_only: if w.watch_only { "✓" } else { "✗" }.to_string(),
                })
                .collect();

            let table = Table::new(&table_data).with(Style::modern()).to_string();
            formatter.print_output(&table);
        }

        WalletCommand::Show { wallet_identifier } => {
            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;

            formatter.print_info(&format!("🔐 Crypto Wallet: {}", wallet.name));
            formatter.print_info(&format!("ID: {}", wallet.id));
            formatter.print_info(&format!("Network: {}", wallet.network));
            formatter.print_info(&format!(
                "Type: {}",
                format_wallet_type(&wallet.wallet_type)
            ));
            formatter.print_info(&format!("Security Level: {}", wallet.security_level));
            formatter.print_info(&format!(
                "Watch-Only: {}",
                if wallet.watch_only { "Yes" } else { "No" }
            ));

            if let Some(desc) = &wallet.description {
                formatter.print_info(&format!("Description: {}", desc));
            }

            if let Some(path) = &wallet.derivation_path {
                formatter.print_info(&format!("Derivation Path: {}", path));
            }

            if let Some(xpub) = &wallet.extended_public_key {
                formatter.print_info(&format!(
                    "Extended Public Key: {}...",
                    &xpub[..std::cmp::min(xpub.len(), 20)]
                ));
            }

            formatter.print_info(&format!("Address Count: {}", wallet.addresses.len()));
            formatter.print_info(&format!("Security Score: {}/100", wallet.security_score()));

            let unused_count = wallet.get_unused_addresses().len();
            formatter.print_info(&format!("Unused Addresses: {}", unused_count));

            formatter.print_info(&format!(
                "Created: {}",
                wallet.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            ));
            formatter.print_info(&format!(
                "Updated: {}",
                wallet.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
            ));

            // Show addresses
            if !wallet.addresses.is_empty() {
                formatter.print_info("\n📝 Addresses:");
                let address_data: Vec<AddressTable> = wallet
                    .addresses
                    .iter()
                    .take(10) // Limit to first 10 for readability
                    .map(|addr| AddressTable {
                        index: addr.index,
                        address: format!(
                            "{}...{}",
                            &addr.address[..std::cmp::min(addr.address.len(), 10)],
                            &addr.address
                                [std::cmp::max(addr.address.len().saturating_sub(10), 0)..]
                        ),
                        address_type: format_address_type(&addr.address_type),
                        used: if addr.used { "✓" } else { "✗" }.to_string(),
                        balance: addr
                            .balance
                            .clone()
                            .unwrap_or_else(|| "Unknown".to_string()),
                        last_activity: addr
                            .last_activity
                            .map(|dt| dt.format("%Y-%m-%d").to_string())
                            .unwrap_or_else(|| "Never".to_string()),
                    })
                    .collect();

                let address_table = Table::new(&address_data).with(Style::modern()).to_string();
                formatter.print_output(&address_table);

                if wallet.addresses.len() > 10 {
                    formatter.print_info(&format!(
                        "... and {} more addresses",
                        wallet.addresses.len() - 10
                    ));
                }
            }
        }

        WalletCommand::Create {
            name,
            description,
            network,
            wallet_type,
            bip_version,
            address_count,
            watch_only,
            xpub,
            security_level,
            mnemonic: _,
            private_key: _,
            derivation_path,
        } => {
            let network = parse_network(&network)?;
            let wallet_type = parse_wallet_type(&wallet_type, bip_version, address_count)?;
            let security_level = security_level
                .map(|s| parse_wallet_security_level(&s))
                .transpose()?
                .unwrap_or(WalletSecurityLevel::Medium);

            if watch_only {
                if xpub.is_none() {
                    bail!("Watch-only wallets require an extended public key (--xpub)");
                }

                let identity_id = resolve_default_identity_id(config).await?;
                let wallet =
                    CryptoWallet::new_watch_only(identity_id, name, network, xpub.unwrap());

                let created = repo.create(&wallet).await.into_anyhow()?;
                formatter.print_success(&format!(
                    "👁️ Created watch-only wallet '{}' with ID: {}",
                    created.name, created.id
                ));
            } else {
                let identity_id = resolve_default_identity_id(config).await?;
                // For now, create with placeholder encrypted key
                // In real implementation, this would involve key generation and encryption
                let mut wallet = CryptoWallet::new(
                    identity_id,
                    name,
                    network,
                    wallet_type,
                    vec![1, 2, 3, 4], // Placeholder encrypted private key
                );

                wallet.description = description;
                wallet.security_level = security_level;
                wallet.derivation_path = derivation_path;

                let created = repo.create(&wallet).await.into_anyhow()?;
                formatter.print_success(&format!(
                    "🔐 Created wallet '{}' with ID: {}",
                    created.name, created.id
                ));
                formatter.print_warning(
                    "⚠️  This is a demo implementation with placeholder encryption.",
                );
                formatter.print_info(
                    "In a production environment, private keys would be securely encrypted.",
                );
            }
        }

        WalletCommand::CreateWatchOnly {
            name,
            description,
            network,
            xpub,
            address_count: _,
        } => {
            let network = parse_network(&network)?;
            let identity_id = resolve_default_identity_id(config).await?;
            let mut wallet = CryptoWallet::new_watch_only(identity_id, name, network, xpub);

            wallet.description = description;

            let created = repo.create(&wallet).await.into_anyhow()?;
            formatter.print_success(&format!(
                "👁️ Created watch-only wallet '{}' with ID: {}",
                created.name, created.id
            ));
        }

        WalletCommand::Generate {
            name,
            description: _,
            network,
            hd,
            bip_version: _,
            account,
            address_count,
        } => {
            use persona_core::crypto::{import_from_mnemonic, MnemonicWordCount, SecureMnemonic};

            let network = parse_network(&network)?;
            let network_str = network.to_string();

            // Prompt for password
            let password =
                ui.password("🔐 Enter a password to encrypt your wallet:", false, None)?;

            if password.len() < 8 {
                bail!("Password must be at least 8 characters long");
            }

            // Generate mnemonic
            formatter.print_info("🎲 Generating new mnemonic phrase...");
            let mnemonic = SecureMnemonic::generate(MnemonicWordCount::Words24)
                .context("Failed to generate mnemonic")?;
            let mnemonic_phrase = mnemonic.phrase();

            // Show mnemonic to user (IMPORTANT: they must write this down!)
            formatter.print_warning("\n⚠️  IMPORTANT: Write down your recovery phrase!");
            formatter
                .print_warning("This is the ONLY way to recover your wallet if you lose access.\n");
            formatter.print_success(&format!("Recovery Phrase:\n{}\n", mnemonic_phrase));
            ui.input(
                "Press Enter after you've written it down securely...",
                None,
                true,
            )?;

            // Create wallet using import function
            let derivation_path = if hd {
                Some(CryptoWallet::recommended_derivation_path(&network, account))
            } else {
                None
            };

            let identity_id = resolve_default_identity_id(config).await?;
            let wallet = import_from_mnemonic(
                identity_id,
                name.clone(),
                &mnemonic_phrase,
                "", // No additional passphrase
                network,
                derivation_path.clone(),
                address_count,
                &password,
            )
            .context("Failed to create wallet from mnemonic")?;

            let created = repo.create(&wallet).await.into_anyhow()?;

            formatter.print_success(&format!(
                "🔐 Generated new wallet '{}' with ID: {}",
                created.name, created.id
            ));
            formatter.print_info(&format!("Network: {}", network_str));
            formatter.print_info(&format!("Addresses generated: {}", address_count));

            if let Some(path) = &created.derivation_path {
                formatter.print_info(&format!("Derivation Path: {}", path));
            }

            formatter.print_warning("\n⚠️  Security Reminder:");
            formatter.print_info("- Keep your recovery phrase safe and offline");
            formatter.print_info("- Never share your recovery phrase with anyone");
            formatter.print_info("- Your password is required to use this wallet");
        }

        WalletCommand::Update {
            wallet_id,
            name,
            description,
            security_level,
            add_tag,
            remove_tag,
            platform,
            purpose,
            note,
        } => {
            let mut wallet = repo
                .find_by_id(&wallet_id)
                .await
                .into_anyhow()?
                .ok_or_else(|| anyhow!("Wallet with ID {} not found", wallet_id))?;

            // Update fields
            if let Some(n) = name {
                wallet.name = n;
            }
            if let Some(d) = description {
                wallet.description = Some(d);
            }
            if let Some(level_str) = security_level {
                let level = parse_wallet_security_level(&level_str)?;
                wallet.security_level = level;
            }

            // Update metadata
            if let Some(tag) = add_tag {
                if !wallet.metadata.tags.contains(&tag) {
                    wallet.metadata.tags.push(tag);
                }
            }
            if let Some(tag) = remove_tag {
                wallet.metadata.tags.retain(|t| t != &tag);
            }
            if let Some(p) = platform {
                wallet.metadata.platform = Some(p);
            }
            if let Some(purp) = purpose {
                wallet.metadata.purpose = Some(purp);
            }
            if let Some(n) = note {
                wallet.metadata.notes = Some(n);
            }

            wallet.updated_at = chrono::Utc::now();

            let updated = repo.update(&wallet).await.into_anyhow()?;
            formatter.print_success(&format!("Updated wallet '{}'", updated.name));
        }

        WalletCommand::Delete { wallet_id, force } => {
            let wallet = repo
                .find_by_id(&wallet_id)
                .await
                .into_anyhow()?
                .ok_or_else(|| anyhow!("Wallet with ID {} not found", wallet_id))?;

            if !force {
                formatter.print_warning(&format!(
                    "This will permanently delete wallet '{}'",
                    wallet.name
                ));
                formatter
                    .print_warning("All associated addresses and transactions will be removed.");
                formatter.print_warning("Use --force to skip this confirmation.");
                return Ok(());
            }

            let deleted = repo.delete(&wallet_id).await.into_anyhow()?;
            if deleted {
                formatter.print_success(&format!("Deleted wallet '{}'", wallet.name));
            } else {
                formatter.print_error("Failed to delete wallet");
            }
        }

        WalletCommand::AddAddress {
            wallet_id,
            address,
            address_type,
            index,
            derivation_path,
        } => {
            let _wallet = repo
                .find_by_id(&wallet_id)
                .await
                .into_anyhow()?
                .ok_or_else(|| anyhow!("Wallet with ID {} not found", wallet_id))?;

            let addr_type = parse_address_type(&address_type)?;
            let wallet_address = WalletAddress {
                address: address.clone(),
                address_type: addr_type,
                derivation_path,
                index,
                used: false,
                balance: None,
                last_activity: None,
                metadata: std::collections::HashMap::new(),
                created_at: chrono::Utc::now(),
            };

            repo.add_address(&wallet_id, &wallet_address)
                .await
                .into_anyhow()?;
            formatter.print_success(&format!("Added address '{}' to wallet", address));
        }

        WalletCommand::ListAddresses {
            wallet_identifier,
            used,
            unused,
            limit,
        } => {
            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;

            let mut addresses: Vec<_> = wallet
                .addresses
                .iter()
                .filter(|addr| (!used || addr.used) && (!unused || !addr.used))
                .collect();

            if let Some(lim) = limit {
                addresses.truncate(lim);
            }

            if addresses.is_empty() {
                formatter.print_info("No addresses match the specified filters.");
                return Ok(());
            }

            let table_data: Vec<AddressTable> = addresses
                .iter()
                .map(|addr| AddressTable {
                    index: addr.index,
                    address: format!(
                        "{}...{}",
                        &addr.address[..std::cmp::min(addr.address.len(), 15)],
                        &addr.address[std::cmp::max(addr.address.len().saturating_sub(8), 0)..]
                    ),
                    address_type: format_address_type(&addr.address_type),
                    used: if addr.used { "✓" } else { "✗" }.to_string(),
                    balance: addr
                        .balance
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    last_activity: addr
                        .last_activity
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "Never".to_string()),
                })
                .collect();

            let table = Table::new(&table_data).with(Style::modern()).to_string();
            formatter.print_info(&format!("📝 Addresses for wallet '{}':", wallet.name));
            formatter.print_output(&table);

            if addresses.len() < wallet.addresses.len() {
                formatter.print_info(&format!(
                    "Showing {} of {} addresses",
                    addresses.len(),
                    wallet.addresses.len()
                ));
            }
        }

        WalletCommand::MarkUsed {
            wallet_identifier,
            address,
        } => {
            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;
            let updated = repo
                .update_address_usage(&wallet.id, &address, true)
                .await
                .into_anyhow()?;

            if updated {
                formatter.print_success(&format!("Marked address '{}' as used", address));
            } else {
                formatter.print_error(&format!("Address '{}' not found in wallet", address));
            }
        }

        WalletCommand::Stats { wallet_identifier } => {
            if let Some(identifier) = wallet_identifier {
                let wallet = find_wallet_by_identifier(&repo, &identifier).await?;
                let stats = repo.get_transaction_stats(&wallet.id).await.into_anyhow()?;

                formatter.print_info(&format!("📊 Statistics for wallet '{}':", wallet.name));
                formatter.print_info(&format!("Network: {}", wallet.network));
                formatter.print_info(&format!("Security Level: {}", wallet.security_level));
                formatter.print_info(&format!("Total Addresses: {}", wallet.addresses.len()));
                formatter.print_info(&format!(
                    "Unused Addresses: {}",
                    wallet.get_unused_addresses().len()
                ));
                formatter.print_info(&format!("Security Score: {}/100", wallet.security_score()));
                formatter.print_info(&format!("Total Transactions: {}", stats.total_transactions));
                formatter.print_info(&format!(
                    "Successful Transactions: {}",
                    stats.successful_transactions
                ));
                formatter.print_info(&format!(
                    "Failed Transactions: {}",
                    stats.failed_transactions
                ));
                formatter.print_info(&format!(
                    "Total Amount Sent: {} units",
                    stats.total_amount_sent
                ));
            } else {
                // System-wide statistics (simplified)
                formatter.print_info("📊 System Wallet Statistics:");
                formatter.print_info("Wallet feature is in development");
                formatter.print_info("Use 'persona wallet list' to see available wallets");
            }
        }

        WalletCommand::Export {
            wallet_identifier,
            format,
            include_private,
            output,
        } => {
            use persona_core::crypto::{
                export_mnemonic, export_private_key, export_to_json, export_to_wif, export_xpub,
                parse_export_format, ExportFormat,
            };

            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;
            let export_format = parse_export_format(&format)?;
            let requires_password = export_requires_password(export_format, include_private);

            // Get password if exporting private data
            let password = if requires_password {
                formatter.print_warning("⚠️  You are about to export private key data!");
                let pwd = ui.password("Enter wallet password:", false, None)?;
                Some(pwd)
            } else {
                None
            };

            let exported_data = match export_format {
                ExportFormat::Mnemonic => {
                    let pwd =
                        password.ok_or_else(|| anyhow!("Password required for mnemonic export"))?;
                    export_mnemonic(&wallet, &pwd).context("Failed to export mnemonic")?
                }
                ExportFormat::PrivateKey => {
                    let pwd = password
                        .ok_or_else(|| anyhow!("Password required for private key export"))?;
                    export_private_key(&wallet, &pwd).context("Failed to export private key")?
                }
                ExportFormat::Wif => {
                    let pwd =
                        password.ok_or_else(|| anyhow!("Password required for WIF export"))?;
                    export_to_wif(&wallet, &pwd).context("Failed to export WIF")?
                }
                ExportFormat::Xpub => export_xpub(&wallet).context("Failed to export xpub")?,
                ExportFormat::Json => export_to_json(&wallet, include_private, password.as_deref())
                    .context("Failed to export to JSON")?,
            };

            // Output to file or stdout
            if let Some(output_path) = output {
                std::fs::write(&output_path, exported_data.as_bytes())
                    .context("Failed to write export file")?;
                formatter.print_success(&format!("✅ Exported wallet to: {}", output_path));
            } else {
                formatter.print_success("Wallet Export:");
                println!("{}", exported_data);
            }

            if include_private {
                formatter.print_warning("\n⚠️  Security Warning:");
                formatter.print_info("- This export contains sensitive private data");
                formatter.print_info("- Store it securely and delete it when done");
                formatter.print_info("- Never share this data with anyone");
            }
        }

        WalletCommand::Import { format, data, name } => {
            use persona_core::crypto::{
                import_from_json, import_from_mnemonic, import_from_private_key, import_from_wif,
                parse_import_format, ImportFormat,
            };

            let import_format = parse_import_format(&format)?;

            let password = ui.password(
                "Enter a password to encrypt the imported wallet:",
                false,
                None,
            )?;

            if password.len() < 8 {
                bail!("Password must be at least 8 characters long");
            }

            // Read import data (from file or direct input)
            let import_data = if std::path::Path::new(&data).exists() {
                std::fs::read_to_string(&data).context("Failed to read import file")?
            } else {
                data.clone()
            };

            // Wallet rows carry a foreign key into `identities`, so the
            // imported wallet must belong to the workspace's default identity.
            let identity_id = resolve_default_identity_id(config).await?;

            let wallet = match import_format {
                ImportFormat::Mnemonic => {
                    let network_input =
                        ui.input("Enter network (bitcoin/ethereum/solana):", None, false)?;
                    let network = parse_network(network_input.trim())?;

                    let count_input = ui.input_with_default(
                        "Enter number of addresses to derive (default: 20):",
                        "20",
                    )?;
                    let address_count = count_input.trim().parse().unwrap_or(20);

                    let wallet_name = name.unwrap_or_else(|| "Imported Wallet".to_string());

                    import_from_mnemonic(
                        identity_id,
                        wallet_name,
                        import_data.trim(),
                        "",
                        network,
                        None,
                        address_count,
                        &password,
                    )
                    .context("Failed to import from mnemonic")?
                }
                ImportFormat::PrivateKey => {
                    let network_input =
                        ui.input("Enter network (bitcoin/ethereum/solana):", None, false)?;
                    let network = parse_network(network_input.trim())?;

                    let wallet_name = name.unwrap_or_else(|| "Imported Wallet".to_string());

                    import_from_private_key(
                        identity_id,
                        wallet_name,
                        import_data.trim(),
                        network,
                        &password,
                    )
                    .context("Failed to import from private key")?
                }
                ImportFormat::Wif => {
                    let wallet_name = name.unwrap_or_else(|| "Imported Wallet".to_string());

                    import_from_wif(identity_id, wallet_name, import_data.trim(), &password)
                        .context("Failed to import from WIF")?
                }
                ImportFormat::Json => {
                    import_from_json(identity_id, name, import_data.trim(), &password)
                        .context("Failed to import from JSON export")?
                }
                _ => {
                    bail!("Import format not yet fully implemented");
                }
            };

            let created = repo.create(&wallet).await.into_anyhow()?;
            formatter.print_success(&format!(
                "✅ Imported wallet '{}' with ID: {}",
                created.name, created.id
            ));
            formatter.print_info(&format!("Addresses: {}", created.addresses.len()));
        }

        WalletCommand::CreateTransaction {
            wallet_identifier,
            to,
            amount,
            fee,
            gas_price,
            gas_limit,
            nonce,
            memo,
            sign,
            broadcast: _,
            expires_in,
        } => {
            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;

            let transaction = TransactionRequest {
                id: uuid::Uuid::new_v4(),
                wallet_id: wallet.id,
                network: wallet.network.clone(),
                from_address: wallet
                    .addresses
                    .first()
                    .map(|a| a.address.clone())
                    .unwrap_or_default(),
                to_address: to,
                amount,
                fee,
                gas_price,
                gas_limit,
                nonce,
                memo,
                raw_transaction_data: None,
                required_signatures: 1,
                created_at: chrono::Utc::now(),
                expires_at: expires_in
                    .map(|mins| chrono::Utc::now() + chrono::Duration::minutes(mins as i64)),
                metadata: std::collections::HashMap::new(),
            };

            let created = repo
                .create_transaction_request(&transaction)
                .await
                .into_anyhow()?;
            formatter.print_success(&format!(
                "Created transaction request with ID: {}",
                created.id
            ));
            formatter.print_info(&format!("From: {}", created.from_address));
            formatter.print_info(&format!("To: {}", created.to_address));
            formatter.print_info(&format!("Amount: {} units", created.amount));
            formatter.print_info(&format!("Fee: {} units", created.fee));

            if !sign {
                return Ok(());
            }

            // Sign the created request with the wallet's first address key
            let password = if config.ui.interactive {
                ui.password("Enter wallet password to sign:", false, None)?
            } else {
                std::env::var("PERSONA_WALLET_PASSWORD")
                    .context("PERSONA_WALLET_PASSWORD must be set in non-interactive mode")?
            };

            let key = signing_key_for_address(&wallet, &password, &created.from_address)
                .context("Failed to derive signing key (wrong password?)")?;
            let signature =
                sign_transaction(&created, &key).context("Failed to sign transaction")?;

            // Verify locally before persisting anything
            match created.network {
                BlockchainNetwork::Ethereum
                | BlockchainNetwork::Polygon
                | BlockchainNetwork::Arbitrum
                | BlockchainNetwork::Optimism
                | BlockchainNetwork::BinanceSmartChain => {
                    anyhow::ensure!(
                        verify_ethereum_transaction(&created, &signature)?,
                        "Signature verification failed; refusing to store signed transaction"
                    );
                }
                BlockchainNetwork::Solana => {
                    let message = created
                        .raw_transaction_data
                        .clone()
                        .ok_or_else(|| anyhow!("Solana signing requires raw_transaction_data"))?;
                    anyhow::ensure!(
                        verify_solana_transaction(&signature, &message)?,
                        "Signature verification failed; refusing to store signed transaction"
                    );
                }
                _ => {}
            }

            // Bitcoin raw assembly needs the UTXO set; without 'inputs'
            // metadata only the audit signature is recorded.
            let (raw_bytes, tx_hash, raw_assembled) = match build_raw_transaction(&created, &key) {
                Ok(raw) => (raw.raw, raw.hash, true),
                Err(e) => {
                    formatter.print_warning(&format!(
                        "⚠️  Raw transaction not assembled: {e}. \
                         Only the audit signature will be stored."
                    ));
                    // The schema requires a non-empty `transaction_hash`; the
                    // audit-only record is identified by the digest of its
                    // signature instead of a chain transaction hash.
                    let audit_hash = format!(
                        "audit:{}",
                        hex::encode(Sha256::digest(&signature.signature))
                    );
                    (Vec::new(), audit_hash, false)
                }
            };

            let signed = SignedTransaction {
                id: uuid::Uuid::new_v4(),
                request: created.clone(),
                signatures: vec![signature],
                raw_signed_transaction: raw_bytes,
                transaction_hash: tx_hash.clone(),
                signed_at: chrono::Utc::now(),
                broadcast_status: persona_core::models::wallet::BroadcastStatus::NotBroadcast,
            };
            repo.create_signed_transaction(&signed)
                .await
                .into_anyhow()?;

            formatter.print_success("Transaction signed and stored");
            if raw_assembled {
                formatter.print_info(&format!("Transaction hash: {}", tx_hash));
                formatter.print_warning(
                    "⚠️  Broadcast it with your node/RPC provider; Persona does not broadcast.",
                );
            }
        }

        WalletCommand::ListTransactions {
            wallet_identifier,
            pending: _,
            signed: _,
            broadcast: _,
        } => {
            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;
            let transactions = repo.get_pending_requests(&wallet.id).await.into_anyhow()?;

            if transactions.is_empty() {
                formatter.print_info("No pending transactions found.");
                return Ok(());
            }

            formatter.print_info(&format!(
                "💳 Pending transactions for wallet '{}':",
                wallet.name
            ));
            for tx in &transactions {
                formatter.print_info(&format!("  ID: {}", tx.id));
                formatter.print_info(&format!("  To: {}", tx.to_address));
                formatter.print_info(&format!("  Amount: {} units", tx.amount));
                formatter.print_info(&format!("  Fee: {} units", tx.fee));
                formatter.print_info(&format!(
                    "  Created: {}",
                    tx.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                ));
                if let Some(memo) = &tx.memo {
                    formatter.print_info(&format!("  Memo: {}", memo));
                }
                formatter.print_info("");
            }
        }
    }

    Ok(())
}

// Helper functions

async fn init_wallet_repository(config: &CliConfig) -> Result<CryptoWalletRepository> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;
    Ok(CryptoWalletRepository::new(Arc::new(db)))
}

/// Resolve the identity a new wallet belongs to: the workspace's active
/// identity if set, otherwise the first identity in the database. Wallets
/// cannot be created without one (`identity_id` is a foreign key).
async fn resolve_default_identity_id(config: &CliConfig) -> Result<uuid::Uuid> {
    use persona_core::storage::{IdentityRepository, WorkspaceRepository};
    use persona_core::Repository;

    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path)
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    db.migrate()
        .await
        .into_anyhow()
        .context("Failed to run database migrations")?;

    let path_str = config.workspace.path.to_string_lossy().to_string();
    if let Some(active_id) = WorkspaceRepository::new(db.clone())
        .find_by_path(&path_str)
        .await
        .into_anyhow()?
        .and_then(|ws| ws.active_identity_id)
    {
        return Ok(active_id);
    }

    IdentityRepository::new(db)
        .find_all()
        .await
        .into_anyhow()?
        .into_iter()
        .next()
        .map(|identity| identity.id)
        .ok_or_else(|| anyhow!("No identity found. Create one with 'persona add' first"))
}

async fn find_wallet_by_identifier(
    repo: &CryptoWalletRepository,
    identifier: &str,
) -> Result<CryptoWallet> {
    let identifier = identifier.trim();
    if identifier.is_empty() {
        bail!("Wallet identifier cannot be empty");
    }

    if let Ok(uuid) = uuid::Uuid::parse_str(identifier) {
        return repo
            .find_by_id(&uuid)
            .await
            .into_anyhow()?
            .ok_or_else(|| anyhow!("Wallet with ID {} not found", uuid));
    }

    // Allow shortened IDs (CLI list shows first 8 chars).
    let looks_like_id_prefix = identifier.len() >= 8
        && identifier.len() <= 32
        && identifier.chars().all(|c| c.is_ascii_hexdigit());
    if looks_like_id_prefix {
        let matches = repo.find_by_id_prefix(identifier).await.into_anyhow()?;

        match matches.len() {
            0 => { /* fall through to name search */ }
            1 => return Ok(matches.into_iter().next().unwrap()),
            _ => {
                let listed = matches
                    .iter()
                    .take(10)
                    .map(|w| format!("- {} ({})", w.name, w.id))
                    .collect::<Vec<_>>()
                    .join("\n");
                bail!(
                    "Multiple wallets match ID prefix '{}':\n{}\nPlease use the full wallet ID.",
                    identifier,
                    listed
                );
            }
        }
    }

    // Case-insensitive exact name match.
    let exact = repo.find_by_name(identifier).await.into_anyhow()?;
    match exact.len() {
        0 => { /* fall through to fuzzy */ }
        1 => return Ok(exact.into_iter().next().unwrap()),
        _ => {
            let listed = exact
                .iter()
                .take(10)
                .map(|w| format!("- {} ({})", w.name, w.id))
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "Multiple wallets are named '{}':\n{}\nPlease use the wallet ID.",
                identifier,
                listed
            );
        }
    }

    // Fuzzy name search (substring).
    let matches = repo.find_by_name_like(identifier).await.into_anyhow()?;
    match matches.len() {
        0 => bail!("Wallet '{}' not found", identifier),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => {
            let listed = matches
                .iter()
                .take(10)
                .map(|w| format!("- {} ({})", w.name, w.id))
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "Multiple wallets match '{}':\n{}\nPlease use the wallet ID.",
                identifier,
                listed
            );
        }
    }
}

fn export_requires_password(
    format: persona_core::crypto::ExportFormat,
    include_private: bool,
) -> bool {
    matches!(
        format,
        persona_core::crypto::ExportFormat::Mnemonic
            | persona_core::crypto::ExportFormat::PrivateKey
            | persona_core::crypto::ExportFormat::Wif
    ) || include_private
}

fn parse_network(network_str: &str) -> Result<BlockchainNetwork> {
    match network_str.to_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(BlockchainNetwork::Bitcoin),
        "ethereum" | "eth" => Ok(BlockchainNetwork::Ethereum),
        "solana" | "sol" => Ok(BlockchainNetwork::Solana),
        "bitcoin-cash" | "bch" => Ok(BlockchainNetwork::BitcoinCash),
        "litecoin" | "ltc" => Ok(BlockchainNetwork::Litecoin),
        "dogecoin" | "doge" => Ok(BlockchainNetwork::Dogecoin),
        "polygon" | "matic" => Ok(BlockchainNetwork::Polygon),
        "arbitrum" | "arb" => Ok(BlockchainNetwork::Arbitrum),
        "optimism" | "op" => Ok(BlockchainNetwork::Optimism),
        "binance" | "bsc" | "bnb" => Ok(BlockchainNetwork::BinanceSmartChain),
        _ => bail!("Unsupported network: {}", network_str),
    }
}

fn parse_wallet_type(
    type_str: &str,
    bip_version: Option<u32>,
    address_count: Option<usize>,
) -> Result<WalletType> {
    match type_str.to_lowercase().as_str() {
        "single" | "single-address" => Ok(WalletType::SingleAddress),
        "hd" | "hierarchical" => {
            let bip_ver = match bip_version.unwrap_or(44) {
                32 => BipVersion::Bip32,
                44 => BipVersion::Bip44,
                49 => BipVersion::Bip49,
                84 => BipVersion::Bip84,
                86 => BipVersion::Bip86,
                _ => bail!("Unsupported BIP version: {}", bip_version.unwrap_or(44)),
            };

            Ok(WalletType::HierarchicalDeterministic {
                bip_version: bip_ver,
                address_count: address_count.unwrap_or(20),
                gap_limit: 20,
            })
        }
        "multisig" | "multi-signature" => Ok(WalletType::MultiSignature {
            required_signatures: 2,
            total_signers: 3,
            redeem_script: None,
        }),
        "hardware" | "hw" => Ok(WalletType::Hardware {
            device_type: "Generic".to_string(),
            device_fingerprint: None,
        }),
        _ => bail!("Unsupported wallet type: {}", type_str),
    }
}

fn parse_address_type(type_str: &str) -> Result<AddressType> {
    match type_str.to_lowercase().as_str() {
        "p2pkh" => Ok(AddressType::P2PKH),
        "p2sh" => Ok(AddressType::P2SH),
        "p2wpkh" => Ok(AddressType::P2WPKH),
        "p2tr" => Ok(AddressType::P2TR),
        "ethereum" | "eth" => Ok(AddressType::Ethereum),
        "solana" | "sol" => Ok(AddressType::Solana),
        _ => bail!("Unsupported address type: {}", type_str),
    }
}

fn format_wallet_type(wallet_type: &WalletType) -> String {
    match wallet_type {
        WalletType::SingleAddress => "Single".to_string(),
        WalletType::HierarchicalDeterministic {
            bip_version,
            address_count,
            ..
        } => {
            format!(
                "HD (BIP-{}{})",
                bip_version,
                if *address_count > 0 {
                    format!(", {} addrs", address_count)
                } else {
                    String::new()
                }
            )
        }
        WalletType::MultiSignature {
            required_signatures,
            total_signers,
            ..
        } => {
            format!("Multi-sig ({}/{})", required_signatures, total_signers)
        }
        WalletType::Hardware { device_type, .. } => {
            format!("Hardware ({})", device_type)
        }
    }
}

fn format_address_type(address_type: &AddressType) -> String {
    match address_type {
        AddressType::P2PKH => "P2PKH".to_string(),
        AddressType::P2SH => "P2SH".to_string(),
        AddressType::P2WPKH => "P2WPKH".to_string(),
        AddressType::P2TR => "P2TR".to_string(),
        AddressType::Ethereum => "ETH".to_string(),
        AddressType::Solana => "SOL".to_string(),
        AddressType::Custom(name) => name.clone(),
    }
}

fn parse_wallet_security_level(level_str: &str) -> Result<WalletSecurityLevel> {
    match level_str.to_lowercase().as_str() {
        "maximum" | "max" => Ok(WalletSecurityLevel::Maximum),
        "high" | "hi" => Ok(WalletSecurityLevel::High),
        "medium" | "med" | "mid" => Ok(WalletSecurityLevel::Medium),
        "low" | "lo" => Ok(WalletSecurityLevel::Low),
        _ => bail!(
            "Invalid security level: {}. Valid options: low, medium, high, maximum",
            level_str
        ),
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

#[cfg(test)]
mod tests {
    use super::export_requires_password;
    use persona_core::crypto::ExportFormat;

    #[test]
    fn parse_network_accepts_every_alias_case_insensitively() {
        let cases = [
            ("bitcoin", "BlockchainNetwork::Bitcoin"),
            ("btc", ""),
            ("ethereum", ""),
            ("eth", ""),
            ("solana", ""),
            ("sol", ""),
            ("bitcoin-cash", ""),
            ("bch", ""),
            ("litecoin", ""),
            ("ltc", ""),
            ("dogecoin", ""),
            ("doge", ""),
            ("polygon", ""),
            ("matic", ""),
            ("arbitrum", ""),
            ("arb", ""),
            ("optimism", ""),
            ("op", ""),
            ("binance", ""),
            ("bsc", ""),
            ("bnb", ""),
        ];
        for (input, _) in &cases {
            let parsed = super::parse_network(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            let reparsed = super::parse_network(&input.to_uppercase())
                .unwrap_or_else(|e| panic!("{input} upper: {e}"));
            assert_eq!(parsed, reparsed, "{input} must be case insensitive");
        }

        // Spot-check the canonical mappings.
        assert_eq!(
            super::parse_network("btc").unwrap(),
            persona_core::models::wallet::BlockchainNetwork::Bitcoin
        );
        assert_eq!(
            super::parse_network("MATIC").unwrap(),
            persona_core::models::wallet::BlockchainNetwork::Polygon
        );
        assert_eq!(
            super::parse_network("bnb").unwrap(),
            persona_core::models::wallet::BlockchainNetwork::BinanceSmartChain
        );
    }

    #[test]
    fn parse_network_rejects_unknown_names() {
        let err = super::parse_network("moon").expect_err("unknown network must fail");
        assert!(err.to_string().contains("Unsupported network: moon"));
        assert!(super::parse_network("").is_err());
    }

    #[test]
    fn parse_wallet_type_covers_every_variant() {
        use persona_core::models::wallet::{BipVersion, WalletType};

        assert_eq!(
            super::parse_wallet_type("single", None, None).unwrap(),
            WalletType::SingleAddress
        );
        assert_eq!(
            super::parse_wallet_type("Single-Address", None, None).unwrap(),
            WalletType::SingleAddress
        );
        assert_eq!(
            super::parse_wallet_type("multisig", None, None).unwrap(),
            WalletType::MultiSignature {
                required_signatures: 2,
                total_signers: 3,
                redeem_script: None,
            }
        );
        assert_eq!(
            super::parse_wallet_type("multi-signature", None, None).unwrap(),
            super::parse_wallet_type("multisig", None, None).unwrap()
        );
        assert_eq!(
            super::parse_wallet_type("hardware", None, None).unwrap(),
            WalletType::Hardware {
                device_type: "Generic".to_string(),
                device_fingerprint: None,
            }
        );
        assert_eq!(
            super::parse_wallet_type("HW", None, None).unwrap(),
            super::parse_wallet_type("hardware", None, None).unwrap()
        );

        // HD: every supported BIP version, plus defaults and custom counts.
        for (bip, expected) in [
            (Some(32), BipVersion::Bip32),
            (Some(44), BipVersion::Bip44),
            (Some(49), BipVersion::Bip49),
            (Some(84), BipVersion::Bip84),
            (Some(86), BipVersion::Bip86),
        ] {
            assert_eq!(
                super::parse_wallet_type("hd", bip, Some(7)).unwrap(),
                WalletType::HierarchicalDeterministic {
                    bip_version: expected,
                    address_count: 7,
                    gap_limit: 20,
                }
            );
        }
        assert_eq!(
            super::parse_wallet_type("hierarchical", None, None).unwrap(),
            WalletType::HierarchicalDeterministic {
                bip_version: BipVersion::Bip44,
                address_count: 20,
                gap_limit: 20,
            }
        );
    }

    #[test]
    fn parse_wallet_type_rejects_unknown_type_and_bip() {
        let err = super::parse_wallet_type("paper", None, None)
            .expect_err("unknown wallet type must fail");
        assert!(err.to_string().contains("Unsupported wallet type: paper"));

        let err = super::parse_wallet_type("hd", Some(33), None)
            .expect_err("unknown BIP version must fail");
        assert!(err.to_string().contains("Unsupported BIP version: 33"));
    }

    #[test]
    fn parse_address_type_accepts_known_and_rejects_unknown() {
        use persona_core::models::wallet::AddressType;

        assert_eq!(
            super::parse_address_type("P2PKH").unwrap(),
            AddressType::P2PKH
        );
        assert_eq!(
            super::parse_address_type("p2sh").unwrap(),
            AddressType::P2SH
        );
        assert_eq!(
            super::parse_address_type("p2wpkh").unwrap(),
            AddressType::P2WPKH
        );
        assert_eq!(
            super::parse_address_type("p2tr").unwrap(),
            AddressType::P2TR
        );
        assert_eq!(
            super::parse_address_type("ETH").unwrap(),
            AddressType::Ethereum
        );
        assert_eq!(
            super::parse_address_type("sol").unwrap(),
            AddressType::Solana
        );

        let err = super::parse_address_type("bech32").expect_err("unknown type must fail");
        assert!(err.to_string().contains("Unsupported address type: bech32"));
    }

    #[test]
    fn format_wallet_type_renders_every_variant() {
        use persona_core::models::wallet::{BipVersion, WalletType};

        assert_eq!(
            super::format_wallet_type(&WalletType::SingleAddress),
            "Single"
        );
        assert_eq!(
            super::format_wallet_type(&WalletType::HierarchicalDeterministic {
                bip_version: BipVersion::Bip44,
                address_count: 5,
                gap_limit: 20,
            }),
            "HD (BIP-44, 5 addrs)"
        );
        // Zero address count suppresses the suffix.
        assert_eq!(
            super::format_wallet_type(&WalletType::HierarchicalDeterministic {
                bip_version: BipVersion::Bip86,
                address_count: 0,
                gap_limit: 20,
            }),
            "HD (BIP-86)"
        );
        assert_eq!(
            super::format_wallet_type(&WalletType::MultiSignature {
                required_signatures: 2,
                total_signers: 3,
                redeem_script: None,
            }),
            "Multi-sig (2/3)"
        );
        assert_eq!(
            super::format_wallet_type(&WalletType::Hardware {
                device_type: "Ledger".to_string(),
                device_fingerprint: None,
            }),
            "Hardware (Ledger)"
        );
    }

    #[test]
    fn format_address_type_renders_every_variant_including_custom() {
        use persona_core::models::wallet::AddressType;

        assert_eq!(super::format_address_type(&AddressType::P2PKH), "P2PKH");
        assert_eq!(super::format_address_type(&AddressType::P2SH), "P2SH");
        assert_eq!(super::format_address_type(&AddressType::P2WPKH), "P2WPKH");
        assert_eq!(super::format_address_type(&AddressType::P2TR), "P2TR");
        assert_eq!(super::format_address_type(&AddressType::Ethereum), "ETH");
        assert_eq!(super::format_address_type(&AddressType::Solana), "SOL");
        assert_eq!(
            super::format_address_type(&AddressType::Custom("taproot-test".to_string())),
            "taproot-test"
        );
    }

    #[test]
    fn parse_wallet_security_level_accepts_aliases_and_rejects_unknown() {
        use persona_core::models::wallet::WalletSecurityLevel;

        assert_eq!(
            super::parse_wallet_security_level("maximum").unwrap(),
            WalletSecurityLevel::Maximum
        );
        assert_eq!(
            super::parse_wallet_security_level("MAX").unwrap(),
            WalletSecurityLevel::Maximum
        );
        assert_eq!(
            super::parse_wallet_security_level("High").unwrap(),
            WalletSecurityLevel::High
        );
        assert_eq!(
            super::parse_wallet_security_level("hi").unwrap(),
            WalletSecurityLevel::High
        );
        assert_eq!(
            super::parse_wallet_security_level("medium").unwrap(),
            WalletSecurityLevel::Medium
        );
        assert_eq!(
            super::parse_wallet_security_level("med").unwrap(),
            WalletSecurityLevel::Medium
        );
        assert_eq!(
            super::parse_wallet_security_level("mid").unwrap(),
            WalletSecurityLevel::Medium
        );
        assert_eq!(
            super::parse_wallet_security_level("low").unwrap(),
            WalletSecurityLevel::Low
        );
        assert_eq!(
            super::parse_wallet_security_level("LO").unwrap(),
            WalletSecurityLevel::Low
        );

        let err = super::parse_wallet_security_level("ultra").expect_err("unknown level must fail");
        assert!(err.to_string().contains("Invalid security level: ultra"));
        assert!(err.to_string().contains("low, medium, high, maximum"));
    }

    #[test]
    fn mnemonic_export_requires_password_without_include_private() {
        assert!(export_requires_password(ExportFormat::Mnemonic, false));
    }

    #[test]
    fn private_key_export_requires_password_without_include_private() {
        assert!(export_requires_password(ExportFormat::PrivateKey, false));
    }

    #[test]
    fn wif_export_requires_password_without_include_private() {
        assert!(export_requires_password(ExportFormat::Wif, false));
    }

    #[test]
    fn json_export_requires_password_only_when_private_data_is_requested() {
        assert!(!export_requires_password(ExportFormat::Json, false));
        assert!(export_requires_password(ExportFormat::Json, true));
    }

    #[test]
    fn xpub_export_does_not_require_password() {
        assert!(!export_requires_password(ExportFormat::Xpub, false));
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    use crate::config::CliConfig;
    use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
    use persona_core::models::wallet::BlockchainNetwork;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env mutations against the bridge, service and switch tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
        )
    }

    fn config_for(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// Wallet rows reference `identities(id)` via foreign key, so seed one.
    async fn seed_identity(dir: &TempDir, name: &str) {
        seed_identity_get_id(dir, name).await;
    }

    /// Same as [`seed_identity`] but returns the new identity's id.
    async fn seed_identity_get_id(dir: &TempDir, name: &str) -> uuid::Uuid {
        use persona_core::models::{Identity, IdentityType};
        use persona_core::storage::IdentityRepository;
        use persona_core::Repository;
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let identity = Identity::new(name.to_string(), IdentityType::Personal);
        let id = identity.id;
        IdentityRepository::new(db).create(&identity).await.unwrap();
        id
    }

    /// Insert a wallet directly, bypassing the command layer.
    async fn insert_wallet(config: &CliConfig, wallet: &CryptoWallet) {
        let repo = init_wallet_repository(config).await.unwrap();
        repo.create(wallet).await.unwrap();
    }

    fn generate_args(name: &str, network: &str, hd: bool, address_count: usize) -> WalletArgs {
        WalletArgs {
            command: WalletCommand::Generate {
                name: name.to_string(),
                description: None,
                network: network.to_string(),
                hd,
                bip_version: 44,
                account: 1,
                address_count,
            },
        }
    }

    fn import_args(format: &str, data: &str, name: Option<&str>) -> WalletArgs {
        WalletArgs {
            command: WalletCommand::Import {
                format: format.to_string(),
                data: data.to_string(),
                name: name.map(String::from),
            },
        }
    }

    fn export_args(
        identifier: &str,
        format: &str,
        include_private: bool,
        output: Option<&str>,
    ) -> WalletArgs {
        WalletArgs {
            command: WalletCommand::Export {
                wallet_identifier: identifier.to_string(),
                format: format.to_string(),
                include_private,
                output: output.map(String::from),
            },
        }
    }

    fn show_args(identifier: &str) -> WalletArgs {
        WalletArgs {
            command: WalletCommand::Show {
                wallet_identifier: identifier.to_string(),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tx_args(
        identifier: &str,
        to: &str,
        amount: &str,
        fee: &str,
        gas_price: Option<&str>,
        gas_limit: Option<u64>,
        nonce: Option<u64>,
        memo: Option<&str>,
        sign: bool,
    ) -> WalletArgs {
        WalletArgs {
            command: WalletCommand::CreateTransaction {
                wallet_identifier: identifier.to_string(),
                to: to.to_string(),
                amount: amount.to_string(),
                fee: fee.to_string(),
                gas_price: gas_price.map(String::from),
                gas_limit,
                nonce,
                memo: memo.map(String::from),
                sign,
                broadcast: false,
                expires_in: None,
            },
        }
    }

    fn list_tx_args(identifier: &str) -> WalletArgs {
        WalletArgs {
            command: WalletCommand::ListTransactions {
                wallet_identifier: identifier.to_string(),
                pending: false,
                signed: false,
                broadcast: false,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create_args(
        name: &str,
        network: &str,
        wallet_type: &str,
        watch_only: bool,
        xpub: Option<&str>,
        security_level: Option<&str>,
        description: Option<&str>,
    ) -> WalletArgs {
        WalletArgs {
            command: WalletCommand::Create {
                name: name.to_string(),
                description: description.map(String::from),
                network: network.to_string(),
                wallet_type: wallet_type.to_string(),
                bip_version: None,
                address_count: None,
                watch_only,
                xpub: xpub.map(String::from),
                security_level: security_level.map(String::from),
                mnemonic: None,
                private_key: None,
                derivation_path: None,
            },
        }
    }

    #[tokio::test]
    async fn wallet_create_list_show_update_stats_round_trip() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        // Empty list reports the hint.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::List {
                    network: None,
                    security_level: None,
                    watch_only: false,
                    search: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("empty list must succeed");

        // Watch-only Create without xpub is rejected.
        let err = handle_wallet_with(
            create_args("solo", "bitcoin", "single", true, None, None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("watch-only without xpub must fail");
        assert!(err.to_string().contains("require an extended public key"));

        // Create a normal wallet and a watch-only wallet.
        handle_wallet_with(
            create_args(
                "vault",
                "bitcoin",
                "single",
                false,
                None,
                Some("high"),
                Some("main savings"),
            ),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("create normal wallet");
        handle_wallet_with(
            create_args("watcher", "ethereum", "single", true, Some("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"), None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("create watch-only wallet");

        // List: default, filtered by network / level / search / watch_only.
        for list_args in [
            WalletCommand::List {
                network: None,
                security_level: None,
                watch_only: false,
                search: None,
            },
            WalletCommand::List {
                network: Some("bitcoin".into()),
                security_level: None,
                watch_only: false,
                search: None,
            },
            WalletCommand::List {
                network: None,
                security_level: Some("high".into()),
                watch_only: false,
                search: None,
            },
            WalletCommand::List {
                network: None,
                security_level: None,
                watch_only: false,
                search: Some("vau".into()),
            },
            WalletCommand::List {
                network: None,
                security_level: None,
                watch_only: true,
                search: None,
            },
            WalletCommand::List {
                network: Some("solana".into()),
                security_level: None,
                watch_only: false,
                search: None,
            },
            WalletCommand::List {
                network: None,
                security_level: Some("bogus".into()),
                watch_only: false,
                search: None,
            },
        ] {
            // The bogus security level must fail; the rest must succeed.
            let result = handle_wallet_with(
                WalletArgs { command: list_args },
                &config,
                &ScriptedUi::new(),
            )
            .await;
            match result {
                Ok(()) => {}
                Err(e) => assert!(
                    e.to_string().contains("Invalid security level"),
                    "unexpected error: {e}"
                ),
            }
        }

        // Show by name (normal) and by name (watch-only covers xpub rendering).
        handle_wallet_with(show_args("vault"), &config, &ScriptedUi::new())
            .await
            .expect("show by name");
        handle_wallet_with(show_args("watcher"), &config, &ScriptedUi::new())
            .await
            .expect("show watch-only");

        let err = handle_wallet_with(show_args("ghost"), &config, &ScriptedUi::new())
            .await
            .expect_err("unknown wallet must fail");
        assert!(err.to_string().to_lowercase().contains("not found"));

        // Empty identifier is rejected outright.
        let err = handle_wallet_with(show_args("   "), &config, &ScriptedUi::new())
            .await
            .expect_err("empty identifier must fail");
        assert!(err.to_string().contains("cannot be empty"));

        // Locate the wallet id through the repository for id-based commands.
        let repo = init_wallet_repository(&config).await.unwrap();
        let all = repo.find_all().await.into_anyhow().unwrap();
        let vault = all.iter().find(|w| w.name == "vault").unwrap().clone();
        drop(repo);

        // Update with an invalid security level fails.
        let err = handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Update {
                    wallet_id: vault.id,
                    name: None,
                    description: None,
                    security_level: Some("ultra".into()),
                    add_tag: None,
                    remove_tag: None,
                    platform: None,
                    purpose: None,
                    note: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("invalid update level must fail");
        assert!(err.to_string().contains("Invalid security level"));

        // Update every mutable field.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Update {
                    wallet_id: vault.id,
                    name: Some("vault2".into()),
                    description: Some("updated".into()),
                    security_level: Some("maximum".into()),
                    add_tag: Some("cold".into()),
                    remove_tag: Some("hot".into()),
                    platform: Some("ledger".into()),
                    purpose: Some("savings".into()),
                    note: Some("n".into()),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("update all fields");

        let ghost = uuid::Uuid::new_v4();
        let err = handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Update {
                    wallet_id: ghost,
                    name: None,
                    description: None,
                    security_level: None,
                    add_tag: None,
                    remove_tag: None,
                    platform: None,
                    purpose: None,
                    note: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("update missing wallet must fail");
        assert!(err.to_string().contains("not found"));

        // Stats for the wallet and system-wide.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Stats {
                    wallet_identifier: Some("vault2".into()),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("stats for wallet");
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Stats {
                    wallet_identifier: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("system stats");

        // Delete without force only warns.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Delete {
                    wallet_id: vault.id,
                    force: false,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("delete without force warns only");
        // Force delete works and a missing delete reports.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Delete {
                    wallet_id: vault.id,
                    force: true,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("force delete works");
        let err = handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Delete {
                    wallet_id: ghost,
                    force: true,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("delete missing wallet must fail");
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn wallet_addresses_mark_used_and_export_paths() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        handle_wallet_with(
            create_args("hot", "ethereum", "hd", false, None, None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("create hd wallet");

        let repo = init_wallet_repository(&config).await.unwrap();
        let all = repo.find_all().await.into_anyhow().unwrap();
        let hot = all.iter().find(|w| w.name == "hot").unwrap().clone();
        drop(repo);

        // Add an address; unknown wallet fails.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::AddAddress {
                    wallet_id: hot.id,
                    address: "0xabc123def4567890abcdef1234567890abcdef12".into(),
                    address_type: "ethereum".into(),
                    index: 0,
                    derivation_path: Some("m/44'/60'/0'/0/0".into()),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("add address");
        let err = handle_wallet_with(
            WalletArgs {
                command: WalletCommand::AddAddress {
                    wallet_id: uuid::Uuid::new_v4(),
                    address: "0xdeadbeef".into(),
                    address_type: "ethereum".into(),
                    index: 1,
                    derivation_path: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("add address to unknown wallet must fail");
        assert!(err.to_string().contains("not found"));

        // ListAddresses: all, unused-only, limit.
        for (used, unused, limit) in [
            (false, false, None),
            (false, true, None),
            (false, false, Some(1)),
        ] {
            handle_wallet_with(
                WalletArgs {
                    command: WalletCommand::ListAddresses {
                        wallet_identifier: "hot".into(),
                        used,
                        unused,
                        limit,
                    },
                },
                &config,
                &ScriptedUi::new(),
            )
            .await
            .expect("list addresses");
        }
        // Filter that matches nothing prints the hint.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::ListAddresses {
                    wallet_identifier: "hot".into(),
                    used: true,
                    unused: false,
                    limit: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("unused filter prints hint");

        // Mark used: success then unknown address error branch.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::MarkUsed {
                    wallet_identifier: "hot".into(),
                    address: "0xabc123def4567890abcdef1234567890abcdef12".into(),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("mark used");
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::MarkUsed {
                    wallet_identifier: "hot".into(),
                    address: "0xunknown00000000000000000000000000000000".into(),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("mark unknown address reports via formatter");

        // Now the used-only filter matches.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::ListAddresses {
                    wallet_identifier: "hot".into(),
                    used: true,
                    unused: false,
                    limit: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("used filter matches after mark");

        // CreateWatchOnly standalone command works.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::CreateWatchOnly {
                    name: "cold-watch".into(),
                    description: Some("watch".into()),
                    network: "bitcoin".into(),
                    xpub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDHsk3QtFKLNDbjKZ2vBKtK9BfOHmSib8aLerSzhVbfJogu6vndeXTZvoQDLasZJHnJQrAGNKG".into(),
                    address_count: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("create watch-only");

        // Export xpub to stdout and json (no private data) to a file.
        handle_wallet_with(
            export_args("cold-watch", "xpub", false, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("xpub export");
        let out_path = dir.path().join("wallet-export.json");
        handle_wallet_with(
            export_args(
                "cold-watch",
                "json",
                false,
                Some(&out_path.display().to_string()),
            ),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("json export to file");
        assert!(out_path.exists(), "export file written");

        // Unknown export format fails.
        let err = handle_wallet_with(
            export_args("hot", "yaml", false, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("unknown export format must fail");
        assert!(err.to_string().contains("Unknown export format"));

        // Invalid network is rejected during create.
        let err = handle_wallet_with(
            create_args("bad", "moon", "single", false, None, None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("invalid network must fail");
        assert!(err.to_string().contains("Unsupported network"));
    }

    #[tokio::test]
    async fn generate_scripts_password_and_press_enter_ack() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        // A too-short password bails before any key material exists.
        let ui = ScriptedUi::new().password("short");
        let err = handle_wallet_with(
            generate_args("never-created", "bitcoin", false, 1),
            &config,
            &ui,
        )
        .await
        .expect_err("short password must fail");
        assert!(err.to_string().contains("at least 8 characters"));
        assert!(ui.exhausted());

        // Happy path consumes the password and the "Press Enter" ack.
        let ui = ScriptedUi::new()
            .password("long-enough-passphrase")
            .input("");
        handle_wallet_with(generate_args("gen", "bitcoin", true, 12), &config, &ui)
            .await
            .expect("generate must succeed");
        assert!(ui.exhausted());

        let repo = init_wallet_repository(&config).await.unwrap();
        let all = repo.find_all().await.into_anyhow().unwrap();
        let gen = all.iter().find(|w| w.name == "gen").unwrap().clone();
        drop(repo);

        assert_eq!(gen.addresses.len(), 12);
        assert!(
            gen.encrypted_mnemonic.is_some(),
            "mnemonic stored encrypted"
        );
        assert_eq!(
            gen.derivation_path.as_deref(),
            Some("m/44'/0'/1'/0"),
            "hd generation uses the account-aware BIP-44 path"
        );

        // Showing a wallet with more than 10 addresses exercises the
        // "... and N more addresses" branch.
        handle_wallet_with(show_args("gen"), &config, &ScriptedUi::new())
            .await
            .expect("show generated wallet");
    }

    #[tokio::test]
    async fn import_flows_cover_every_format_and_error_path() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

        // Unknown format fails before any prompt is shown.
        let err = handle_wallet_with(
            import_args("yaml", "junk", None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("unknown import format must fail");
        assert!(err.to_string().contains("Unknown import format"));

        // Keystore parses but is not implemented; the password is asked first.
        let ui = ScriptedUi::new().password("import-pass-123");
        let err = handle_wallet_with(import_args("keystore", "{}", None), &config, &ui)
            .await
            .expect_err("keystore import must fail");
        assert!(err.to_string().contains("not yet fully implemented"));
        assert!(ui.exhausted());

        // Short password bails.
        let ui = ScriptedUi::new().password("short");
        let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
            .await
            .expect_err("short import password must fail");
        assert!(err.to_string().contains("at least 8 characters"));
        assert!(ui.exhausted());

        // Invalid network answer for the mnemonic flow.
        let ui = ScriptedUi::new().password("import-pass-123").input("moon");
        let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
            .await
            .expect_err("bad network answer must fail");
        assert!(err.to_string().contains("Unsupported network"));
        assert!(ui.exhausted());

        // Mnemonic import with scripted network and a custom address count.
        let ui = ScriptedUi::new()
            .password("import-pass-123")
            .input("ethereum")
            .input("3");
        handle_wallet_with(
            import_args("mnemonic", PHRASE, Some("imp-mnemonic")),
            &config,
            &ui,
        )
        .await
        .expect("mnemonic import");
        assert!(ui.exhausted());

        // Private-key import (hex) on bitcoin.
        let ui = ScriptedUi::new()
            .password("import-pass-123")
            .input("bitcoin");
        handle_wallet_with(
            import_args("private_key", &"11".repeat(32), Some("imp-key")),
            &config,
            &ui,
        )
        .await
        .expect("private key import");
        assert!(ui.exhausted());

        // WIF import asks no network question.
        let ui = ScriptedUi::new().password("import-pass-123");
        handle_wallet_with(import_args("wif", WIF, Some("imp-wif")), &config, &ui)
            .await
            .expect("wif import");
        assert!(ui.exhausted());

        // A `data` that points at a file is read from disk.
        let phrase_file = dir.path().join("phrase.txt");
        std::fs::write(&phrase_file, PHRASE).unwrap();
        let ui = ScriptedUi::new()
            .password("import-pass-123")
            .input("solana")
            .input("2");
        handle_wallet_with(
            import_args(
                "mnemonic",
                &phrase_file.display().to_string(),
                Some("imp-file"),
            ),
            &config,
            &ui,
        )
        .await
        .expect("file-based mnemonic import");
        assert!(ui.exhausted());

        // JSON export round-trip with a name override.
        let source = persona_core::crypto::import_from_mnemonic(
            uuid::Uuid::new_v4(),
            "json-src".to_string(),
            PHRASE,
            "",
            BlockchainNetwork::Bitcoin,
            None,
            2,
            "export-pass",
        )
        .unwrap();
        let json =
            persona_core::crypto::export_to_json(&source, true, Some("export-pass")).unwrap();
        let ui = ScriptedUi::new().password("import-pass-123");
        handle_wallet_with(import_args("json", &json, Some("renamed")), &config, &ui)
            .await
            .expect("json import");
        assert!(ui.exhausted());

        // Verify what landed in the database.
        let repo = init_wallet_repository(&config).await.unwrap();
        let all = repo.find_all().await.into_anyhow().unwrap();
        drop(repo);

        let mnemonic_wallet = all.iter().find(|w| w.name == "imp-mnemonic").unwrap();
        assert_eq!(mnemonic_wallet.addresses.len(), 3);
        assert_eq!(mnemonic_wallet.network, BlockchainNetwork::Ethereum);

        let key_wallet = all.iter().find(|w| w.name == "imp-key").unwrap();
        assert_eq!(key_wallet.addresses.len(), 1);
        assert!(key_wallet.addresses[0].address.starts_with("bc1q"));

        let wif_wallet = all.iter().find(|w| w.name == "imp-wif").unwrap();
        assert_eq!(wif_wallet.network, BlockchainNetwork::Bitcoin);
        assert_eq!(wif_wallet.addresses.len(), 1);

        let file_wallet = all.iter().find(|w| w.name == "imp-file").unwrap();
        assert_eq!(file_wallet.network, BlockchainNetwork::Solana);
        assert_eq!(file_wallet.addresses.len(), 2);

        let renamed = all.iter().find(|w| w.name == "renamed").unwrap();
        assert_eq!(renamed.addresses.len(), 2);
    }

    #[tokio::test]
    async fn export_private_flows_prompt_for_a_password() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let identity_id = seed_identity_get_id(&dir, "alice").await;

        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const ETH_KEY: &str = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";
        let password = "export-pass-123";

        let hd = persona_core::crypto::import_from_mnemonic(
            identity_id,
            "hd-export".to_string(),
            PHRASE,
            "",
            BlockchainNetwork::Ethereum,
            None,
            2,
            password,
        )
        .unwrap();
        insert_wallet(&config, &hd).await;

        let eth_single = persona_core::crypto::import_from_private_key(
            identity_id,
            "eth-single".to_string(),
            ETH_KEY,
            BlockchainNetwork::Ethereum,
            password,
        )
        .unwrap();
        insert_wallet(&config, &eth_single).await;

        let btc_single = persona_core::crypto::import_from_private_key(
            identity_id,
            "btc-single".to_string(),
            &"11".repeat(32),
            BlockchainNetwork::Bitcoin,
            password,
        )
        .unwrap();
        insert_wallet(&config, &btc_single).await;

        // Wrong password fails the mnemonic decryption.
        let ui = ScriptedUi::new().password("wrong-pass");
        let err = handle_wallet_with(
            export_args("hd-export", "mnemonic", false, None),
            &config,
            &ui,
        )
        .await
        .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Failed to export mnemonic"));
        assert!(ui.exhausted());

        // Correct password exports the phrase.
        let ui = ScriptedUi::new().password(password);
        handle_wallet_with(
            export_args("hd-export", "mnemonic", false, None),
            &config,
            &ui,
        )
        .await
        .expect("mnemonic export");
        assert!(ui.exhausted());

        // Private key export works for a single-key wallet.
        let ui = ScriptedUi::new().password(password);
        handle_wallet_with(
            export_args("eth-single", "private_key", false, None),
            &config,
            &ui,
        )
        .await
        .expect("private key export");
        assert!(ui.exhausted());

        // WIF export for the bitcoin single-address wallet.
        let ui = ScriptedUi::new().password(password);
        handle_wallet_with(export_args("btc-single", "wif", false, None), &config, &ui)
            .await
            .expect("wif export");
        assert!(ui.exhausted());

        // WIF is rejected for non-bitcoin wallets.
        let ui = ScriptedUi::new().password(password);
        let err = handle_wallet_with(export_args("eth-single", "wif", false, None), &config, &ui)
            .await
            .expect_err("wif export on ethereum must fail");
        assert!(format!("{:#}", err).contains("only supported for Bitcoin"));
        assert!(ui.exhausted());

        // JSON export with private data to a file (password branch + warning).
        let out_path = dir.path().join("private-export.json");
        let ui = ScriptedUi::new().password(password);
        handle_wallet_with(
            export_args(
                "hd-export",
                "json",
                true,
                Some(&out_path.display().to_string()),
            ),
            &config,
            &ui,
        )
        .await
        .expect("json private export");
        assert!(ui.exhausted());
        assert!(out_path.exists());
        let exported = std::fs::read_to_string(&out_path).unwrap();
        assert!(exported.contains(PHRASE), "mnemonic included in export");

        // A wallet without a stored mnemonic cannot export one.
        let ui = ScriptedUi::new().password(password);
        let err = handle_wallet_with(
            export_args("eth-single", "mnemonic", false, None),
            &config,
            &ui,
        )
        .await
        .expect_err("mnemonic export without mnemonic must fail");
        assert!(format!("{:#}", err).contains("Wallet has no mnemonic"));
        assert!(ui.exhausted());
    }

    #[tokio::test]
    async fn create_transaction_request_and_listing() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let identity_id = seed_identity_get_id(&dir, "alice").await;

        let eth_single = persona_core::crypto::import_from_private_key(
            identity_id,
            "tx-src".to_string(),
            "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
            BlockchainNetwork::Ethereum,
            "unused-here",
        )
        .unwrap();
        insert_wallet(&config, &eth_single).await;

        let fresh = persona_core::crypto::import_from_private_key(
            identity_id,
            "quiet-wallet".to_string(),
            "2222222222222222222222222222222222222222222222222222222222222222",
            BlockchainNetwork::Ethereum,
            "unused-here",
        )
        .unwrap();
        insert_wallet(&config, &fresh).await;

        // Create a request without signing (memo covers the listing line).
        handle_wallet_with(
            tx_args(
                "tx-src",
                "0x1111111111111111111111111111111111111111",
                "1000000000000000000",
                "21000",
                None,
                None,
                None,
                Some("run money"),
                false,
            ),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("create transaction request");

        // Listing shows the pending request for one wallet and the empty
        // hint for the other.
        handle_wallet_with(list_tx_args("tx-src"), &config, &ScriptedUi::new())
            .await
            .expect("list transactions");
        handle_wallet_with(list_tx_args("quiet-wallet"), &config, &ScriptedUi::new())
            .await
            .expect("empty transaction list");

        let repo = init_wallet_repository(&config).await.unwrap();
        let pending = repo
            .get_pending_requests(&eth_single.id)
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].memo.as_deref(), Some("run money"));
    }

    #[tokio::test]
    async fn create_transaction_sign_success_and_failure_paths() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let identity_id = seed_identity_get_id(&dir, "alice").await;
        let password = "sign-pass-123";

        let eth_single = persona_core::crypto::import_from_private_key(
            identity_id,
            "signer".to_string(),
            "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
            BlockchainNetwork::Ethereum,
            password,
        )
        .unwrap();
        insert_wallet(&config, &eth_single).await;

        let btc_single = persona_core::crypto::import_from_private_key(
            identity_id,
            "btc-signer".to_string(),
            &"11".repeat(32),
            BlockchainNetwork::Bitcoin,
            password,
        )
        .unwrap();
        insert_wallet(&config, &btc_single).await;

        let sol_hd = persona_core::crypto::import_from_mnemonic(
            identity_id,
            "sol-signer".to_string(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            BlockchainNetwork::Solana,
            None,
            1,
            "sol-pass-123",
        )
        .unwrap();
        insert_wallet(&config, &sol_hd).await;

        let watcher = CryptoWallet::new_watch_only(
            identity_id,
            "watch-signer".to_string(),
            BlockchainNetwork::Ethereum,
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYf1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs".to_string(),
        );
        insert_wallet(&config, &watcher).await;

        // Ethereum: full sign -> verify -> raw assembly -> stored.
        let ui = ScriptedUi::new().password(password);
        handle_wallet_with(
            tx_args(
                "signer",
                "0x1111111111111111111111111111111111111111",
                "1000000000000000000",
                "21000",
                Some("20000000000"),
                Some(21000),
                Some(0),
                None,
                true,
            ),
            &config,
            &ui,
        )
        .await
        .expect("ethereum sign must succeed");
        assert!(ui.exhausted());

        let repo = init_wallet_repository(&config).await.unwrap();
        let stats = repo
            .get_transaction_stats(&eth_single.id)
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(stats.total_transactions, 1);
        drop(repo);

        // Wrong password fails key derivation.
        let ui = ScriptedUi::new().password("wrong-pass");
        let err = handle_wallet_with(
            tx_args(
                "signer",
                "0x1111111111111111111111111111111111111111",
                "1",
                "1",
                Some("1"),
                Some(21000),
                Some(0),
                None,
                true,
            ),
            &config,
            &ui,
        )
        .await
        .expect_err("wrong password must fail");
        assert!(err.to_string().contains("Failed to derive signing key"));
        assert!(ui.exhausted());

        // Watch-only wallets cannot sign.
        let ui = ScriptedUi::new().password(password);
        let err = handle_wallet_with(
            tx_args(
                "watch-signer",
                "0x1111111111111111111111111111111111111111",
                "1",
                "1",
                Some("1"),
                Some(21000),
                Some(0),
                None,
                true,
            ),
            &config,
            &ui,
        )
        .await
        .expect_err("watch-only signing must fail");
        assert!(format!("{:#}", err).contains("Watch-only wallets cannot sign"));
        assert!(ui.exhausted());

        // Solana signing requires the serialized message in
        // `raw_transaction_data`, which the request does not carry -> the
        // signing itself fails before anything is stored.
        let ui = ScriptedUi::new().password("sol-pass-123");
        let err = handle_wallet_with(
            tx_args(
                "sol-signer",
                &sol_hd.addresses[0].address,
                "1",
                "1",
                None,
                None,
                None,
                None,
                true,
            ),
            &config,
            &ui,
        )
        .await
        .expect_err("solana sign without raw data must fail");
        assert!(err.to_string().contains("Failed to sign transaction"));
        assert!(format!("{:#}", err).contains("raw_transaction_data"));
        assert!(ui.exhausted());

        // Bitcoin without UTXO metadata stores only the audit signature.
        let ui = ScriptedUi::new().password(password);
        handle_wallet_with(
            tx_args(
                "btc-signer",
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "5000",
                "300",
                None,
                None,
                None,
                None,
                true,
            ),
            &config,
            &ui,
        )
        .await
        .expect("bitcoin audit sign must succeed");
        assert!(ui.exhausted());

        let repo = init_wallet_repository(&config).await.unwrap();
        let stats = repo
            .get_transaction_stats(&btc_single.id)
            .await
            .into_anyhow()
            .unwrap();
        assert_eq!(stats.total_transactions, 1);
    }

    #[tokio::test]
    async fn create_transaction_non_interactive_uses_env_password() {
        let _guard = lock_process_env();
        std::env::remove_var("PERSONA_WALLET_PASSWORD");

        let dir = TempDir::new().unwrap();
        let mut config = config_for(&dir);
        config.ui.interactive = false;
        let identity_id = seed_identity_get_id(&dir, "alice").await;
        let password = "env-pass-123";

        let eth_single = persona_core::crypto::import_from_private_key(
            identity_id,
            "env-signer".to_string(),
            "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
            BlockchainNetwork::Ethereum,
            password,
        )
        .unwrap();
        insert_wallet(&config, &eth_single).await;

        // Missing env var is rejected.
        let err = handle_wallet_with(
            tx_args(
                "env-signer",
                "0x1111111111111111111111111111111111111111",
                "1000000000000000000",
                "21000",
                Some("20000000000"),
                Some(21000),
                Some(0),
                None,
                true,
            ),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("missing env password must fail");
        assert!(err
            .to_string()
            .contains("PERSONA_WALLET_PASSWORD must be set"));

        // The env var supplies the password.
        std::env::set_var("PERSONA_WALLET_PASSWORD", password);
        handle_wallet_with(
            tx_args(
                "env-signer",
                "0x1111111111111111111111111111111111111111",
                "1000000000000000000",
                "21000",
                Some("20000000000"),
                Some(21000),
                Some(0),
                None,
                true,
            ),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("env-password sign must succeed");

        std::env::remove_var("PERSONA_WALLET_PASSWORD");
    }

    #[tokio::test]
    async fn find_wallet_by_identifier_resolution_paths() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let identity_id = seed_identity_get_id(&dir, "alice").await;

        let repo = init_wallet_repository(&config).await.unwrap();

        let mk_wallet = |name: &str, id: Option<uuid::Uuid>| {
            let mut wallet = CryptoWallet::new(
                identity_id,
                name.to_string(),
                BlockchainNetwork::Bitcoin,
                persona_core::models::wallet::WalletType::SingleAddress,
                vec![1, 2, 3, 4],
            );
            if let Some(id) = id {
                wallet.id = id;
            }
            wallet
        };

        // Two wallets whose ids share the "aaaaaaaa" prefix.
        repo.create(&mk_wallet(
            "alpha",
            Some(uuid::Uuid::parse_str("aaaaaaaa-0000-0000-0000-000000000001").unwrap()),
        ))
        .await
        .unwrap();
        repo.create(&mk_wallet(
            "gamma",
            Some(uuid::Uuid::parse_str("aaaaaaaa-0000-0000-0000-000000000002").unwrap()),
        ))
        .await
        .unwrap();

        // A wallet with a hex-like name exercises the prefix-to-name
        // fall-through, and twins exercise the name/fuzzy ambiguity errors.
        repo.create(&mk_wallet("deadbeef01", None)).await.unwrap();
        repo.create(&mk_wallet("twin", None)).await.unwrap();
        repo.create(&mk_wallet("twin", None)).await.unwrap();

        // A single, uniquely prefixed id is resolvable by its short form.
        let delta = repo.create(&mk_wallet("delta", None)).await.unwrap();
        drop(repo);

        // Ambiguous id prefix lists the candidates and bails.
        let err =
            find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "aaaaaaaa")
                .await
                .expect_err("ambiguous prefix must fail");
        let msg = err.to_string();
        assert!(msg.contains("Multiple wallets match ID prefix 'aaaaaaaa'"));
        assert!(msg.contains("alpha") && msg.contains("gamma"));

        // Full UUID resolves directly.
        let wallet = find_wallet_by_identifier(
            &init_wallet_repository(&config).await.unwrap(),
            "aaaaaaaa-0000-0000-0000-000000000001",
        )
        .await
        .unwrap();
        assert_eq!(wallet.name, "alpha");

        // Short unique prefix resolves.
        let prefix = delta.id.to_string()[..8].to_string();
        let wallet =
            find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), &prefix)
                .await
                .unwrap();
        assert_eq!(wallet.name, "delta");

        // A hex-looking name that matches no id falls through to the name.
        let wallet = find_wallet_by_identifier(
            &init_wallet_repository(&config).await.unwrap(),
            "deadbeef01",
        )
        .await
        .unwrap();
        assert_eq!(wallet.name, "deadbeef01");

        // Ambiguous exact names.
        let err =
            find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "twin")
                .await
                .expect_err("duplicate names must fail");
        assert!(err
            .to_string()
            .contains("Multiple wallets are named 'twin'"));

        // Fuzzy match: single and ambiguous.
        let wallet =
            find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "alph")
                .await
                .unwrap();
        assert_eq!(wallet.name, "alpha");
        let err = find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "twi")
            .await
            .expect_err("ambiguous fuzzy match must fail");
        assert!(err.to_string().contains("Multiple wallets match 'twi'"));

        // Unknown identifier fails.
        let err =
            find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "ghost")
                .await
                .expect_err("unknown identifier must fail");
        assert!(err.to_string().contains("Wallet 'ghost' not found"));
    }

    #[tokio::test]
    async fn create_rejects_unknown_wallet_type_bip_and_security_level() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        let err = handle_wallet_with(
            create_args("w1", "bitcoin", "paper", false, None, None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("unknown wallet type must fail");
        assert!(err.to_string().contains("Unsupported wallet type: paper"));

        let err = handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Create {
                    name: "w2".into(),
                    description: None,
                    network: "bitcoin".into(),
                    wallet_type: "hd".into(),
                    bip_version: Some(33),
                    address_count: None,
                    watch_only: false,
                    xpub: None,
                    security_level: None,
                    mnemonic: None,
                    private_key: None,
                    derivation_path: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("unknown BIP version must fail");
        assert!(err.to_string().contains("Unsupported BIP version: 33"));

        let err = handle_wallet_with(
            create_args("w3", "bitcoin", "single", false, None, Some("ultra"), None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("invalid security level must fail");
        assert!(err.to_string().contains("Invalid security level"));
    }

    #[tokio::test]
    async fn create_wallet_requires_a_seed_identity() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);

        let err = handle_wallet_with(
            create_args("orphan", "bitcoin", "single", false, None, None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect_err("creating without any identity must fail");
        assert!(err.to_string().contains("No identity found"));
    }

    #[tokio::test]
    async fn resolve_default_identity_prefers_the_active_workspace_identity() {
        use persona_core::models::Workspace;
        use persona_core::storage::WorkspaceRepository;
        use persona_core::Repository;

        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity_get_id(&dir, "first").await;
        let second = seed_identity_get_id(&dir, "second").await;

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut ws = Workspace::new(config.workspace.path.clone(), "ws".to_string());
        ws.switch_identity(second);
        WorkspaceRepository::new(db.clone())
            .create(&ws)
            .await
            .unwrap();
        drop(db);

        assert_eq!(resolve_default_identity_id(&config).await.unwrap(), second);
    }

    #[tokio::test]
    async fn resolve_default_identity_falls_back_to_the_first_identity() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        let only = seed_identity_get_id(&dir, "only").await;

        assert_eq!(resolve_default_identity_id(&config).await.unwrap(), only);
    }

    #[tokio::test]
    async fn resolve_default_identity_requires_an_identity() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);

        let err = resolve_default_identity_id(&config)
            .await
            .expect_err("no identity must fail");
        assert!(err.to_string().contains("No identity found"));
    }

    #[tokio::test]
    async fn terminal_entry_point_and_watch_only_filter_hint() {
        // The TerminalUi-backed entry point works on a fresh workspace: the
        // repository bootstraps an empty database and lists zero wallets.
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        handle_wallet(
            WalletArgs {
                command: WalletCommand::List {
                    network: None,
                    security_level: None,
                    watch_only: false,
                    search: None,
                },
            },
            &config,
        )
        .await
        .expect("empty workspace lists zero wallets");

        // A watch-only filter that hides every wallet prints the dedicated
        // hint instead of the table.
        seed_identity(&dir, "alice").await;
        handle_wallet_with(
            create_args("plain", "bitcoin", "single", false, None, None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("non-watch-only wallet created");
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::List {
                    network: None,
                    security_level: None,
                    watch_only: true,
                    search: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("watch-only filter with no matches succeeds");
    }

    #[tokio::test]
    async fn generate_without_hd_and_failing_ack_prompt() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        // hd=false passes no path, and the core import fills in the
        // account-0 recommended default.
        let ui = ScriptedUi::new()
            .password("long-enough-passphrase")
            .input("");
        handle_wallet_with(
            generate_args("plain-gen", "bitcoin", false, 2),
            &config,
            &ui,
        )
        .await
        .expect("non-HD generation must succeed");
        assert!(ui.exhausted());

        let repo = init_wallet_repository(&config).await.unwrap();
        let all = repo.find_all().await.into_anyhow().unwrap();
        let gen = all.iter().find(|w| w.name == "plain-gen").unwrap().clone();
        drop(repo);
        assert_eq!(gen.derivation_path.as_deref(), Some("m/44'/0'/0'/0"));

        // A failing "Press Enter" acknowledgement propagates.
        let inner = ScriptedUi::new().password("long-enough-passphrase");
        let ui = FailOn::new(&inner, PromptKind::Input);
        let err = handle_wallet_with(
            generate_args("never-created", "bitcoin", true, 1),
            &config,
            &ui,
        )
        .await
        .expect_err("failing acknowledgement must abort");
        assert!(err.to_string().contains("failing ui: input prompt"));
    }

    #[tokio::test]
    async fn update_with_sparse_fields_leaves_the_rest_untouched() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;
        handle_wallet_with(
            create_args(
                "sparse",
                "bitcoin",
                "single",
                false,
                None,
                Some("high"),
                Some("desc"),
            ),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("wallet created");

        let repo = init_wallet_repository(&config).await.unwrap();
        let all = repo.find_all().await.into_anyhow().unwrap();
        let wallet = all.iter().find(|w| w.name == "sparse").unwrap().clone();
        drop(repo);

        // Only name/description change; level and tag lists are skipped.
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::Update {
                    wallet_id: wallet.id,
                    name: Some("sparse2".into()),
                    description: Some("new desc".into()),
                    security_level: None,
                    add_tag: None,
                    remove_tag: None,
                    platform: None,
                    purpose: None,
                    note: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("sparse update succeeds");

        let repo = init_wallet_repository(&config).await.unwrap();
        let all = repo.find_all().await.into_anyhow().unwrap();
        let updated = all.iter().find(|w| w.name == "sparse2").unwrap().clone();
        drop(repo);
        assert_eq!(updated.security_level, wallet.security_level);
        assert_eq!(updated.metadata.tags, wallet.metadata.tags);
    }

    #[tokio::test]
    async fn list_addresses_limit_reports_the_shown_count() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        handle_wallet_with(
            create_args("limited", "ethereum", "hd", false, None, None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("hd wallet created");

        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::ListAddresses {
                    wallet_identifier: "limited".into(),
                    used: false,
                    unused: false,
                    limit: Some(1),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("limited listing succeeds");
    }

    #[tokio::test]
    async fn import_prompt_errors_propagate() {
        let dir = TempDir::new().unwrap();
        let config = config_for(&dir);
        seed_identity(&dir, "alice").await;

        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // A failing password prompt aborts the import immediately.
        let inner = ScriptedUi::new();
        let ui = FailOn::new(&inner, PromptKind::Password);
        let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
            .await
            .expect_err("failing password must abort");
        assert!(err.to_string().contains("failing ui: password prompt"));

        // A failing address-count prompt aborts after network selection.
        let inner = ScriptedUi::new()
            .password("import-pass-123")
            .input("bitcoin");
        let ui = FailOn::new(&inner, PromptKind::InputWithDefault);
        let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
            .await
            .expect_err("failing count prompt must abort");
        assert!(err.to_string().contains("failing ui: default input prompt"));
    }
}
