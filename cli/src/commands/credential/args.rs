use clap::{Args, Subcommand, ValueEnum};
use persona_core::models::{CredentialType, SecurityLevel};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Args, Clone, Debug)]
pub struct CredentialArgs {
    #[command(subcommand)]
    pub(crate) command: CredentialCommand,
}

/// `credential add` 的参数（字段多，收拢成单变体 struct，避免枚举变体大小失衡）
#[derive(Args, Clone, Debug)]
pub struct AddArgs {
    /// Identity name to attach the credential
    #[arg(short, long)]
    pub(crate) identity: String,
    /// Credential display name
    #[arg(short, long)]
    pub(crate) name: String,
    /// Credential type
    #[arg(long, default_value = "password")]
    pub(crate) credential_type: CredentialTypeOption,
    /// Security level (critical/high/medium/low)
    #[arg(long, default_value = "high")]
    pub(crate) security_level: SecurityLevelOption,
    /// Optional username / login
    #[arg(long)]
    pub(crate) username: Option<String>,
    /// Optional URL or service
    #[arg(long)]
    pub(crate) url: Option<String>,
    /// Prompt for password/secret in terminal
    #[arg(long)]
    pub(crate) prompt_secret: bool,
    /// Raw secret value (use only in CI)
    #[arg(long, conflicts_with = "prompt_secret")]
    pub(crate) secret: Option<String>,
    /// Note content for --credential-type note (prompts when omitted)
    #[arg(long)]
    pub(crate) note: Option<String>,
    /// Identity fields (--credential-type identity); first/last name prompt when omitted
    #[arg(long)]
    pub(crate) first_name: Option<String>,
    #[arg(long)]
    pub(crate) last_name: Option<String>,
    #[arg(long)]
    pub(crate) email: Option<String>,
    #[arg(long)]
    pub(crate) phone: Option<String>,
    #[arg(long)]
    pub(crate) birthday: Option<String>,
    #[arg(long)]
    pub(crate) address: Option<String>,
    #[arg(long)]
    pub(crate) id_number: Option<String>,
    #[arg(long)]
    pub(crate) passport_number: Option<String>,
    #[arg(long)]
    pub(crate) driver_license: Option<String>,
    #[arg(long)]
    pub(crate) tax_id: Option<String>,
    #[arg(long)]
    pub(crate) organization: Option<String>,
    #[arg(long)]
    pub(crate) job_title: Option<String>,
    /// License key (--credential-type software-license; prompts when omitted)
    #[arg(long)]
    pub(crate) license_key: Option<String>,
    #[arg(long)]
    pub(crate) version: Option<String>,
    #[arg(long)]
    pub(crate) publisher: Option<String>,
    #[arg(long)]
    pub(crate) purchase_date: Option<String>,
    #[arg(long)]
    pub(crate) order_number: Option<String>,
    #[arg(long)]
    pub(crate) support_email: Option<String>,
    #[arg(long)]
    pub(crate) download_url: Option<String>,
    #[arg(long)]
    pub(crate) seats: Option<u32>,
    #[arg(long)]
    pub(crate) valid_until: Option<String>,
    /// Mark as favorite
    #[arg(long)]
    pub(crate) favorite: bool,
}

#[derive(Subcommand, Clone, Debug)]
pub enum CredentialCommand {
    /// Create a new credential (password/API key/etc.)
    Add(Box<AddArgs>),
    /// List credentials with optional filters
    List {
        /// Identity name filter
        #[arg(short, long)]
        identity: Option<String>,
        /// Credential type filter
        #[arg(long)]
        credential_type: Option<String>,
        /// Show only favorites
        #[arg(long)]
        favorite: bool,
        /// Output as json/yaml
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Show decrypted credential details
    Show {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Include decrypted payload (will prompt for confirmation)
        #[arg(long)]
        reveal: bool,
    },
    /// Remove a credential
    Remove {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// Show change history for a credential (item history; metadata-only diffs)
    History {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
    },
    /// Restore a credential's metadata to an earlier item-history version
    Restore {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Target version number (see `persona credential history`)
        #[arg(long)]
        version: u32,
    },
    /// Attach a file to a credential (encrypted with the item's key)
    Attach {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Path of the file to attach
        #[arg(long)]
        file: PathBuf,
        /// Store the file without encryption
        #[arg(long)]
        no_encrypt: bool,
    },
    /// List attachments for a credential
    Attachments {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
    },
    /// Save an attachment to disk (decrypted)
    SaveAttachment {
        /// Attachment UUID (see `credential attachments`)
        #[arg(long)]
        attachment_id: Uuid,
        /// Output file path
        #[arg(long)]
        output: PathBuf,
    },
    /// Remove an attachment
    RemoveAttachment {
        /// Attachment UUID (see `credential attachments`)
        #[arg(long)]
        attachment_id: Uuid,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// List structured custom fields for a credential (concealed masked)
    Fields {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Show concealed values (confirmed before printing)
        #[arg(long)]
        reveal: bool,
    },
    /// Replace a credential's custom fields (whole-table replace)
    SetFields {
        /// Credential UUID
        #[arg(long)]
        id: Uuid,
        /// Field spec TYPE:SECTION:LABEL=VALUE (TYPE text|concealed|date;
        /// SECTION may be empty and must not contain ':'). Repeatable.
        #[arg(long = "field", value_name = "TYPE:SECTION:LABEL=VALUE")]
        fields: Vec<String>,
        /// Remove all custom fields (cannot be combined with --field)
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum CredentialTypeOption {
    Password,
    ApiKey,
    SshKey,
    CryptoWallet,
    BankCard,
    GameAccount,
    ServerConfig,
    Certificate,
    TwoFactor,
    Note,
    Identity,
    SoftwareLicense,
    Custom,
}

impl From<CredentialTypeOption> for CredentialType {
    fn from(value: CredentialTypeOption) -> Self {
        match value {
            CredentialTypeOption::Password => CredentialType::Password,
            CredentialTypeOption::ApiKey => CredentialType::ApiKey,
            CredentialTypeOption::SshKey => CredentialType::SshKey,
            CredentialTypeOption::CryptoWallet => CredentialType::CryptoWallet,
            CredentialTypeOption::BankCard => CredentialType::BankCard,
            CredentialTypeOption::GameAccount => CredentialType::GameAccount,
            CredentialTypeOption::ServerConfig => CredentialType::ServerConfig,
            CredentialTypeOption::Certificate => CredentialType::Certificate,
            CredentialTypeOption::TwoFactor => CredentialType::TwoFactor,
            CredentialTypeOption::Note => CredentialType::SecureNote,
            CredentialTypeOption::Identity => CredentialType::Identity,
            CredentialTypeOption::SoftwareLicense => CredentialType::SoftwareLicense,
            CredentialTypeOption::Custom => CredentialType::Custom("custom".into()),
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum SecurityLevelOption {
    Critical,
    High,
    Medium,
    Low,
}

impl From<SecurityLevelOption> for SecurityLevel {
    fn from(value: SecurityLevelOption) -> Self {
        match value {
            SecurityLevelOption::Critical => SecurityLevel::Critical,
            SecurityLevelOption::High => SecurityLevel::High,
            SecurityLevelOption::Medium => SecurityLevel::Medium,
            SecurityLevelOption::Low => SecurityLevel::Low,
        }
    }
}
