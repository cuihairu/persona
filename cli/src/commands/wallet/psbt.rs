use super::*;

/// Decode a base64-encoded PSBT artifact (`wallet sign-psbt` / `finalize-psbt`).
pub(super) fn decode_psbt_input(psbt_b64: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(psbt_b64.trim())
        .context("Invalid base64 PSBT input")
}

/// `persona wallet export-psbt` — build the unsigned BIP-174 artifact for a
/// single-sig P2WPKH spend (WALLET_DESIGN.md §7). Needs no wallet password:
/// no key material is touched, so watch-only wallets can prepare it for an
/// airgapped signer. The address-poisoning check applies (the PSBT is a
/// spend authorization), same backend enforcement as the signing path.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_export_psbt(
    repo: &CryptoWalletRepository,
    wallet_identifier: &str,
    to: &str,
    amount: &str,
    fee: &str,
    inputs: &str,
    change_address: Option<&str>,
    confirmed_poisoning_check: bool,
) -> Result<Vec<u8>> {
    let wallet = find_wallet_by_identifier(repo, wallet_identifier).await?;
    if wallet.network != BlockchainNetwork::Bitcoin {
        bail!("PSBT export is only supported for Bitcoin wallets");
    }
    let from_address = wallet
        .addresses
        .first()
        .map(|a| a.address.clone())
        .ok_or_else(|| anyhow!("Wallet '{}' has no addresses", wallet.name))?;

    let known_addresses: Vec<String> = wallet.addresses.iter().map(|a| a.address.clone()).collect();
    persona_core::crypto::enforce_poisoning_check(to, &known_addresses, confirmed_poisoning_check)
        .with_context(|| format!("Address-poisoning check refused '{to}'"))?;

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("inputs".to_string(), inputs.to_string());
    if let Some(change) = change_address {
        metadata.insert("change_address".to_string(), change.to_string());
    }

    let request = TransactionRequest {
        id: uuid::Uuid::new_v4(),
        wallet_id: wallet.id,
        network: wallet.network.clone(),
        from_address,
        to_address: to.to_string(),
        amount: amount.to_string(),
        fee: fee.to_string(),
        gas_price: None,
        gas_limit: None,
        nonce: None,
        memo: None,
        raw_transaction_data: None,
        required_signatures: 1,
        created_at: chrono::Utc::now(),
        expires_at: None,
        metadata,
    };
    persona_core::crypto::export_bitcoin_psbt(&request).context("Failed to build PSBT")
}

/// `persona wallet sign-psbt` — sign every input owned by this wallet
/// (single-sig: one key must own all inputs), returning the signed PSBT.
pub(super) async fn run_sign_psbt(
    repo: &CryptoWalletRepository,
    wallet_identifier: &str,
    psbt_b64: &str,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<Vec<u8>> {
    let wallet = find_wallet_by_identifier(repo, wallet_identifier).await?;
    if wallet.watch_only {
        bail!(
            "Watch-only wallets hold no key material; \
             sign the PSBT on the key-holding wallet"
        );
    }
    if wallet.addresses.is_empty() {
        bail!("Wallet '{}' has no addresses", wallet.name);
    }

    let password = if config.ui.interactive {
        ui.password("Enter wallet password to sign the PSBT:", false, None)?
    } else {
        std::env::var("PERSONA_WALLET_PASSWORD")
            .context("PERSONA_WALLET_PASSWORD must be set in non-interactive mode")?
    };

    let psbt_bytes = decode_psbt_input(psbt_b64)?;

    // 单签口径：钱包的任一地址的钥必须持有全部输入。第一把钥失败（错
    // 口令派生不出任何钥）直接终止；其余钥逐把尝试，按 witness script
    // 归属校验（核心侧强制）。
    let first_address = &wallet.addresses[0].address;
    let first_key = signing_key_for_address(&wallet, &password, first_address)
        .map_err(|e| anyhow!("Failed to derive signing key (wrong password?): {e}"))?;
    let mut keys = vec![first_key];
    for address in wallet.addresses.iter().skip(1) {
        if let Ok(key) = signing_key_for_address(&wallet, &password, &address.address) {
            keys.push(key);
        }
    }

    let mut last_err = String::new();
    for key in &keys {
        let WalletSigningKey::Secp256k1(secp_key) = key else {
            continue;
        };
        match persona_core::crypto::sign_bitcoin_psbt(&psbt_bytes, secp_key) {
            Ok(signed) => return Ok(signed),
            Err(e) => last_err = e.to_string(),
        }
    }
    bail!("No wallet key owns all PSBT inputs ({last_err})")
}
