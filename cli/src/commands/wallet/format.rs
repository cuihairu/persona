use super::*;

pub(super) fn export_requires_password(
    format: persona_core::crypto::ExportFormat,
    include_private: bool,
) -> bool {
    matches!(
        format,
        persona_core::crypto::ExportFormat::Mnemonic
            | persona_core::crypto::ExportFormat::PrivateKey
            | persona_core::crypto::ExportFormat::Wif
            | persona_core::crypto::ExportFormat::Keystore
    ) || include_private
}

pub(super) fn parse_network(network_str: &str) -> Result<BlockchainNetwork> {
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

pub(super) fn parse_wallet_type(
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

pub(super) fn parse_address_type(type_str: &str) -> Result<AddressType> {
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

pub(super) fn format_wallet_type(wallet_type: &WalletType) -> String {
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

pub(super) fn format_address_type(address_type: &AddressType) -> String {
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

pub(super) fn parse_wallet_security_level(level_str: &str) -> Result<WalletSecurityLevel> {
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
