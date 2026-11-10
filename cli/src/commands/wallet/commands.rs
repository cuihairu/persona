use super::*;

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

        WalletCommand::Passwd { wallet_identifier } => {
            execute_passwd(&repo, &wallet_identifier, config, ui, &formatter).await?;
        }

        WalletCommand::ExportPsbt {
            wallet_identifier,
            to,
            amount,
            fee,
            inputs,
            change_address,
            confirm_poisoning_check,
        } => {
            let psbt = run_export_psbt(
                &repo,
                &wallet_identifier,
                &to,
                &amount,
                &fee,
                &inputs,
                change_address.as_deref(),
                confirm_poisoning_check,
            )
            .await?;
            formatter.print_info("Unsigned PSBT (base64, BIP-174):");
            println!("{}", BASE64.encode(&psbt));
        }

        WalletCommand::SignPsbt {
            wallet_identifier,
            psbt,
        } => {
            let signed = run_sign_psbt(&repo, &wallet_identifier, &psbt, config, ui).await?;
            formatter.print_info("Signed PSBT (base64):");
            println!("{}", BASE64.encode(&signed));
            formatter.print_info("Finalize with: persona wallet finalize-psbt <psbt>");
        }

        WalletCommand::FinalizePsbt { psbt } => {
            let bytes = decode_psbt_input(&psbt)?;
            let finalized = persona_core::crypto::finalize_bitcoin_psbt(&bytes)?;
            formatter.print_success(&format!("Finalized transaction {}", finalized.hash));
            formatter.print_info("Raw transaction (hex, not broadcast):");
            println!("{}", hex::encode(&finalized.raw));
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
                export_keystore, export_mnemonic, export_private_key, export_to_json,
                export_to_wif, export_xpub, parse_export_format, ExportFormat,
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
                ExportFormat::Keystore => {
                    let pwd =
                        password.ok_or_else(|| anyhow!("Password required for keystore export"))?;
                    export_keystore(&wallet, &pwd).context("Failed to export keystore")?
                }
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

            // Keystore JSON always wraps the private key, regardless of the
            // include_private flag.
            if include_private || matches!(export_format, ExportFormat::Keystore) {
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
                ImportFormat::Keystore => {
                    // Keystore JSON is defined over Ethereum-style secp256k1
                    // keys; the format itself carries no network hint.
                    let secret = persona_core::crypto::wallet_encryption::import_from_keystore(
                        import_data.trim(),
                        &password,
                    )
                    .context("Failed to import keystore")?;
                    let wallet_name = name.unwrap_or_else(|| "Imported Wallet".to_string());
                    import_from_private_key(
                        identity_id,
                        wallet_name,
                        &hex::encode(secret),
                        BlockchainNetwork::Ethereum,
                        &password,
                    )
                    .context("Failed to import from keystore")?
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
            confirm_poisoning_check,
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

            // 后端防投毒强制检查（WALLET_DESIGN.md §5 第 3 条）：to 地址模仿
            // 本钱包任一已知地址即拒绝签名，除非显式 --confirm-poisoning-check。
            // 放在口令 prompt 之前：被拦下时不必让用户先输口令。
            let known_addresses: Vec<String> =
                wallet.addresses.iter().map(|a| a.address.clone()).collect();
            persona_core::crypto::enforce_poisoning_check(
                &created.to_address,
                &known_addresses,
                confirm_poisoning_check,
            )
            .with_context(|| format!("Address-poisoning check refused '{}'", created.to_address))?;

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

/// `persona wallet passwd` — re-wrap a wallet's private key and mnemonic
/// under a new password (WALLET_DESIGN.md §3).
///
/// 解旧密与重包都在写回之前完成：任一步失败原钱包行保持不动，不会出现
/// 两份材料口令不一致的半写状态。旧口令的解析方式与签名一致
/// （`PERSONA_WALLET_PASSWORD` 环境变量优先，交互模式走 prompt）；新口令
/// 交互式输入（与 `persona passwd` 同规：无环境变量覆盖，陈旧的环境
/// 变量永远不能静默轮换口令）。
async fn execute_passwd(
    repo: &CryptoWalletRepository,
    wallet_identifier: &str,
    config: &CliConfig,
    ui: &dyn PromptUi,
    formatter: &OutputFormatter,
) -> Result<()> {
    let wallet = find_wallet_by_identifier(repo, wallet_identifier).await?;

    if wallet.watch_only {
        bail!("Watch-only wallets hold no key material to re-wrap");
    }

    let old_password = if config.ui.interactive {
        ui.password("Enter current wallet password:", false, None)?
    } else {
        std::env::var("PERSONA_WALLET_PASSWORD")
            .context("PERSONA_WALLET_PASSWORD must be set in non-interactive mode")?
    };

    if !config.ui.interactive {
        bail!("The new wallet password is interactive-only; re-run in an interactive terminal");
    }

    let new_password = ui.password(
        "Set a new wallet password",
        false,
        Some(("Confirm new wallet password", "Passwords don't match")),
    )?;
    if new_password == old_password {
        bail!("New password must be different from the current password");
    }
    if new_password.len() < 8 {
        bail!("New password must be at least 8 characters");
    }

    // 先全部解密（错旧口令在这里失败，不产生半写状态），再全部重包。
    let old_key: EncryptedWalletKey = serde_json::from_slice(&wallet.encrypted_private_key)
        .map_err(|e| anyhow!("Stored private key is not valid wallet encryption JSON: {e}"))?;
    let new_key = change_wallet_password(&old_key, &old_password, &new_password)
        .map_err(|e| anyhow!("Failed to re-wrap private key (wrong password?): {e}"))?;

    let new_mnemonic_bytes = if let Some(bytes) = &wallet.encrypted_mnemonic {
        let old_mnemonic: EncryptedMnemonic = serde_json::from_slice(bytes)
            .map_err(|e| anyhow!("Stored mnemonic is not valid wallet encryption JSON: {e}"))?;
        let new_mnemonic = change_mnemonic_password(&old_mnemonic, &old_password, &new_password)
            .map_err(|e| anyhow!("Failed to re-wrap mnemonic: {e}"))?;
        Some(serde_json::to_vec(&new_mnemonic)?)
    } else {
        None
    };

    let mut updated = wallet.clone();
    updated.encrypted_private_key = serde_json::to_vec(&new_key)?;
    updated.encrypted_mnemonic = new_mnemonic_bytes;
    updated.updated_at = chrono::Utc::now();
    repo.update(&updated).await.into_anyhow()?;

    formatter.print_success(&format!("Wallet password changed for '{}'", updated.name));
    Ok(())
}

pub(super) async fn init_wallet_repository(config: &CliConfig) -> Result<CryptoWalletRepository> {
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
pub(super) async fn resolve_default_identity_id(config: &CliConfig) -> Result<uuid::Uuid> {
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

pub(super) async fn find_wallet_by_identifier(
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
