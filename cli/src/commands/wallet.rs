use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    models::wallet::{
        AddressType, BipVersion, BlockchainNetwork, CryptoWallet, TransactionRequest,
        WalletAddress, WalletMetadata, WalletSecurityLevel, WalletType,
    },
    storage::{CryptoWalletRepository, Database},
};
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
        #[arg(long, short)]
        network: Option<String>,

        /// Filter by security level (low, medium, high, maximum)
        #[arg(long, short)]
        security_level: Option<String>,

        /// Show only watch-only wallets
        #[arg(long)]
        watch_only: bool,

        /// Search wallets by name
        #[arg(long, short)]
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
        #[arg(long, short)]
        name: String,

        /// Wallet description
        #[arg(long, short)]
        description: Option<String>,

        /// Blockchain network
        #[arg(long, short)]
        network: String,

        /// Wallet type (single, hd, multisig, hardware)
        #[arg(long, short)]
        wallet_type: String,

        /// BIP version for HD wallets (32, 44, 49, 84, 86)
        #[arg(long)]
        bip_version: Option<u32>,

        /// Address count for HD wallets
        #[arg(long, short)]
        address_count: Option<usize>,

        /// Create watch-only wallet (no private key)
        #[arg(long)]
        watch_only: bool,

        /// Extended public key (for watch-only wallets)
        #[arg(long)]
        xpub: Option<String>,

        /// Security level (low, medium, high, maximum)
        #[arg(long, short)]
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
        #[arg(long, short)]
        name: String,

        /// Wallet description
        #[arg(long, short)]
        description: Option<String>,

        /// Blockchain network
        #[arg(long, short)]
        network: String,

        /// Extended public key (xpub/ypub/zpub)
        #[arg(long, short)]
        xpub: String,

        /// Address count to derive
        #[arg(long, short)]
        address_count: Option<usize>,
    },
    /// Generate a new wallet with fresh keys
    Generate {
        /// Wallet name
        #[arg(long, short)]
        name: String,

        /// Wallet description
        #[arg(long, short)]
        description: Option<String>,

        /// Blockchain network
        #[arg(long, short)]
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
        #[arg(long, short)]
        name: Option<String>,

        /// New wallet description
        #[arg(long, short)]
        description: Option<String>,

        /// New security level
        #[arg(long, short)]
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
        #[arg(long, short)]
        note: Option<String>,
    },
    /// Delete a wallet
    Delete {
        /// Wallet ID
        wallet_id: uuid::Uuid,

        /// Skip confirmation prompt
        #[arg(long, short)]
        force: bool,
    },
    /// Add address to wallet
    AddAddress {
        /// Wallet ID
        wallet_id: uuid::Uuid,

        /// Address string
        address: String,

        /// Address type (p2pkh, p2sh, p2wpkh, p2tr, ethereum, solana)
        #[arg(long, short)]
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
        #[arg(long, short)]
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

        /// Export format (json, mnemonic, private_key, xpub)
        #[arg(long, short)]
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
        /// Import format (json, mnemonic, private_key, xpub)
        #[arg(long, short)]
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
    let repo = init_wallet_repository(config).await?;
    let formatter = OutputFormatter::default();

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
                wallets = wallets
                    .into_iter()
                    .filter(|wallet| wallet.name.to_lowercase().contains(&needle))
                    .collect();
            }

            if wallets.is_empty() {
                formatter.print_info("No wallets found.");
                return Ok(());
            }

            let filtered_wallets: Vec<_> = wallets
                .into_iter()
                .filter(|w| {
                    let include = true;
                    let include = include && (!watch_only || w.watch_only);
                    include
                })
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
            let wallet = if let Ok(uuid) = uuid::Uuid::parse_str(&wallet_identifier) {
                repo.find_by_id(&uuid).await.into_anyhow()?
            } else {
                // Search by name (simplified - in real implementation would query by name)
                let all_wallets = repo
                    .find_by_network(&BlockchainNetwork::Bitcoin)
                    .await
                    .into_anyhow()?;
                all_wallets
                    .into_iter()
                    .find(|w| w.name == wallet_identifier)
            };

            match wallet {
                Some(wallet) => {
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
                    formatter
                        .print_info(&format!("Security Score: {}/100", wallet.security_score()));

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

                        let address_table =
                            Table::new(&address_data).with(Style::modern()).to_string();
                        formatter.print_output(&address_table);

                        if wallet.addresses.len() > 10 {
                            formatter.print_info(&format!(
                                "... and {} more addresses",
                                wallet.addresses.len() - 10
                            ));
                        }
                    }
                }
                None => bail!("Wallet '{}' not found", wallet_identifier),
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

                let wallet = CryptoWallet::new_watch_only(
                    uuid::Uuid::new_v4(), // Would get from current identity
                    name,
                    network,
                    xpub.unwrap(),
                );

                let created = repo.create(&wallet).await.into_anyhow()?;
                formatter.print_success(&format!(
                    "👁️ Created watch-only wallet '{}' with ID: {}",
                    created.name, created.id
                ));
            } else {
                // For now, create with placeholder encrypted key
                // In real implementation, this would involve key generation and encryption
                let mut wallet = CryptoWallet::new(
                    uuid::Uuid::new_v4(), // Would get from current identity
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
            address_count,
        } => {
            let network = parse_network(&network)?;
            let mut wallet = CryptoWallet::new_watch_only(
                uuid::Uuid::new_v4(), // Would get from current identity
                name,
                network,
                xpub,
            );

            wallet.description = description;

            let created = repo.create(&wallet).await.into_anyhow()?;
            formatter.print_success(&format!(
                "👁️ Created watch-only wallet '{}' with ID: {}",
                created.name, created.id
            ));
        }

        WalletCommand::Generate {
            name,
            description,
            network,
            hd,
            bip_version,
            account,
            address_count,
        } => {
            use persona_core::crypto::{
                import_from_mnemonic, MasterKey, MnemonicWordCount, SecureMnemonic,
            };

            let network = parse_network(&network)?;
            let network_str = network.to_string();

            // Prompt for password
            formatter.print_info("🔐 Enter a password to encrypt your wallet:");
            let password = rpassword::read_password().context("Failed to read password")?;

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
            formatter.print_warning("Press Enter after you've written it down securely...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            // Create wallet using import function
            let derivation_path = if hd {
                Some(CryptoWallet::recommended_derivation_path(&network, account))
            } else {
                None
            };

            let wallet = import_from_mnemonic(
                uuid::Uuid::new_v4(), // Would get from current identity
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
            let wallet = repo
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
                .filter(|addr| {
                    let include = true;
                    let include = include && (!used || addr.used);
                    let include = include && (!unused || !addr.used);
                    include
                })
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
                export_mnemonic, export_private_key, export_to_json, export_xpub,
                parse_export_format, ExportFormat,
            };

            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;
            let export_format = parse_export_format(&format)?;

            // Get password if exporting private data
            let password = if include_private {
                formatter.print_warning("⚠️  You are about to export private key data!");
                formatter.print_info("Enter wallet password:");
                let pwd = rpassword::read_password().context("Failed to read password")?;
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
                import_from_mnemonic, import_from_private_key, parse_import_format, ImportFormat,
            };

            let import_format = parse_import_format(&format)?;

            formatter.print_info("Enter a password to encrypt the imported wallet:");
            let password = rpassword::read_password().context("Failed to read password")?;

            if password.len() < 8 {
                bail!("Password must be at least 8 characters long");
            }

            // Read import data (from file or direct input)
            let import_data = if std::path::Path::new(&data).exists() {
                std::fs::read_to_string(&data).context("Failed to read import file")?
            } else {
                data.clone()
            };

            let wallet = match import_format {
                ImportFormat::Mnemonic => {
                    formatter.print_info("Enter network (bitcoin/ethereum/solana):");
                    let mut network_input = String::new();
                    std::io::stdin().read_line(&mut network_input)?;
                    let network = parse_network(network_input.trim())?;

                    formatter.print_info("Enter number of addresses to derive (default: 20):");
                    let mut count_input = String::new();
                    std::io::stdin().read_line(&mut count_input)?;
                    let address_count = count_input.trim().parse().unwrap_or(20);

                    let wallet_name = name.unwrap_or_else(|| "Imported Wallet".to_string());

                    import_from_mnemonic(
                        uuid::Uuid::new_v4(),
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
                    formatter.print_info("Enter network (bitcoin/ethereum/solana):");
                    let mut network_input = String::new();
                    std::io::stdin().read_line(&mut network_input)?;
                    let network = parse_network(network_input.trim())?;

                    let wallet_name = name.unwrap_or_else(|| "Imported Wallet".to_string());

                    import_from_private_key(
                        uuid::Uuid::new_v4(),
                        wallet_name,
                        import_data.trim(),
                        network,
                        &password,
                    )
                    .context("Failed to import from private key")?
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
            sign: _,
            broadcast: _,
            expires_in,
        } => {
            let wallet = find_wallet_by_identifier(&repo, &wallet_identifier).await?;

            let transaction = TransactionRequest {
                id: uuid::Uuid::new_v4(),
                wallet_id: wallet.id,
                network: wallet.network,
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

async fn find_wallet_by_identifier(
    repo: &CryptoWalletRepository,
    identifier: &str,
) -> Result<CryptoWallet> {
    if let Ok(uuid) = uuid::Uuid::parse_str(identifier) {
        repo.find_by_id(&uuid)
            .await
            .into_anyhow()?
            .ok_or_else(|| anyhow!("Wallet with ID {} not found", uuid))
    } else {
        // Search by name (simplified - in real implementation would have proper name search)
        bail!("Wallet lookup by name is not implemented in this demo. Please use wallet ID.");
    }
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
        _ => bail!("Invalid security level: {}. Valid options: low, medium, high, maximum", level_str),
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
