use clap::{Args, Subcommand};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct TotpArgs {
    #[command(subcommand)]
    pub(crate) command: TotpCommand,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TotpCommand {
    /// Set up a new TOTP credential from QR/otpauth URI/secret
    Setup {
        /// Identity name to store credential under
        #[arg(short, long)]
        identity: String,
        /// Credential display name (defaults to issuer/account)
        #[arg(short, long)]
        name: Option<String>,
        /// Path to QR code image (PNG/JPEG)
        #[arg(long)]
        qr: Option<PathBuf>,
        /// Raw otpauth URI (otpauth://totp/Issuer:Account?secret=...)
        #[arg(long)]
        otpauth: Option<String>,
        /// Base32 secret (fallback if no QR/otpauth provided)
        #[arg(long)]
        secret: Option<String>,
        /// Issuer override
        #[arg(long)]
        issuer: Option<String>,
        /// Account name override
        #[arg(long)]
        account: Option<String>,
        /// Associate this TOTP with a website origin (enables browser extension matching)
        ///
        /// Accepts full URL (https://github.com) or a bare host (github.com).
        #[arg(long)]
        url: Option<String>,
        /// Digits override
        #[arg(long)]
        digits: Option<u8>,
        /// Period override
        #[arg(long)]
        period: Option<u32>,
        /// Hash algorithm (SHA1/SHA256/SHA512)
        #[arg(long)]
        algorithm: Option<String>,
        /// HOTP (RFC 4226) counter-based entry instead of time-based TOTP.
        /// `otpauth://hotp/` URIs and QR codes set this automatically.
        #[arg(long)]
        hotp: bool,
        /// HOTP starting counter (default counter used when generating codes;
        /// `persona totp code --counter` overrides)
        #[arg(long)]
        counter: Option<u64>,
    },
    /// Set up a Steam Guard token from a base64 shared_secret
    SetupSteam {
        /// Identity name to store credential under
        #[arg(short, long)]
        identity: String,
        /// Credential display name (defaults to "Steam (account)")
        #[arg(short, long)]
        name: Option<String>,
        /// Steam shared_secret (standard base64, from the Steam authenticator export)
        #[arg(long)]
        secret: String,
        /// Steam account name the token belongs to
        #[arg(short, long)]
        account: String,
        /// Associate this token with a website origin (e.g. https://store.steampowered.com)
        #[arg(long)]
        url: Option<String>,
    },
    /// Record a game token entry (vendor-bound tokens are recorded, not generated)
    ///
    /// Vendor-bound providers (Tencent Game Security Center, NetEase Da Shen,
    /// miHoYo security token, ...) keep their seed server-side inside the
    /// vendor's app, so dynamic codes cannot be generated offline. This command
    /// stores a vault record; codes still come from the vendor's official app.
    SetupGameToken {
        /// Identity name to store credential under
        #[arg(short, long)]
        identity: String,
        /// Vendor provider slug, lowercase letters/digits/underscore
        /// (e.g. tencent_security, netease_dashen, mihoyo)
        #[arg(long)]
        provider: String,
        /// Credential display name (defaults to "issuer (account)")
        #[arg(short, long)]
        name: Option<String>,
        /// Shared secret if one is ever exported (base64; optional for
        /// vendor-bound providers, kept for future offline support)
        #[arg(long)]
        secret: Option<String>,
        /// Account the token protects
        #[arg(short, long)]
        account: String,
        /// Issuer override (defaults to the provider slug)
        #[arg(long)]
        issuer: Option<String>,
        /// Associate this token with a website origin (e.g. https://gamesafe.qq.com)
        #[arg(long)]
        url: Option<String>,
    },
    /// Generate a TOTP code for a stored credential
    Code {
        /// Credential UUID (must be TwoFactor)
        #[arg(long)]
        id: Uuid,
        /// Continuous watch output (refresh every period; TOTP entries only)
        #[arg(long)]
        watch: bool,
        /// HOTP counter (HOTP entries only; the stored starting counter is
        /// used when omitted)
        #[arg(long)]
        counter: Option<u64>,
    },
    /// Import Steam Desktop Authenticator (.maFile) exports
    ///
    /// Stores only the verifier fields (shared_secret, identity_secret,
    /// device_id, account_name). Session credentials (the `Session` object,
    /// `access_token`, ...) are never stored — they are listed before each
    /// import is confirmed.
    ImportSteam {
        /// Identity name to store credentials under
        #[arg(short, long)]
        identity: String,
        /// Path to a .maFile or a directory of .maFile exports
        #[arg(long)]
        file: PathBuf,
        /// Credential display name (single-file import only; defaults to
        /// "Steam (account)")
        #[arg(short, long)]
        name: Option<String>,
        /// Associate imported tokens with https://store.steampowered.com
        #[arg(long)]
        url: Option<String>,
        /// Import without the per-file confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}
