use super::*;

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
    /// Change a wallet's password (re-wraps private key and mnemonic)
    Passwd {
        /// Wallet ID or name
        wallet_identifier: String,
    },
    /// Export an unsigned Bitcoin PSBT (BIP-174) for offline signing
    ExportPsbt {
        /// Wallet ID or name
        wallet_identifier: String,

        /// Recipient address
        to: String,

        /// Amount in satoshis
        amount: String,

        /// Fee in satoshis
        fee: String,

        /// UTXOs to spend as a JSON array of {txid, vout, amount}
        #[arg(long)]
        inputs: String,

        /// Change address for the remainder (inputs - amount - fee)
        #[arg(long)]
        change_address: Option<String>,

        /// Confirm a recipient that mimics a known address (address-poisoning check)
        #[arg(long)]
        confirm_poisoning_check: bool,
    },
    /// Sign a Bitcoin PSBT's inputs with this wallet's key
    SignPsbt {
        /// Wallet ID or name
        wallet_identifier: String,

        /// Base64-encoded PSBT
        psbt: String,
    },
    /// Finalize a signed Bitcoin PSBT into the raw broadcastable transaction
    FinalizePsbt {
        /// Base64-encoded PSBT
        psbt: String,
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

        /// Explicitly acknowledge the address-poisoning check and sign anyway
        /// (only needed when the to-address mimics one of the wallet's own
        /// addresses — same first 6 and last 6 characters, different middle)
        #[arg(long)]
        confirm_poisoning_check: bool,

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

        /// Export format (json, mnemonic, private_key, wif, xpub, keystore)
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
