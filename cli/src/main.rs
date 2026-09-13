use anyhow::Result;
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::path::Path;

mod commands;
mod config;
mod utils;

use config::CliConfig;
use persona_core::RedactedLoggerBuilder;

#[derive(Parser)]
#[command(name = "persona")]
#[command(about = "Master your digital identity. Switch freely with one click.")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path
    // `-C` instead of the usual `-c`: subcommands like `credential`/`password`
    // own `-c` themselves, and a global `-c` would collide with them
    // (clap's debug asserts reject the definition and the short flag would be
    // silently shadowed at runtime).
    #[arg(short = 'C', long, global = true)]
    config: Option<std::path::PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new persona workspace
    Init(commands::init::InitArgs),

    /// Browser extension bridge (Chrome Native Messaging host)
    Bridge(commands::bridge::BridgeArgs),

    /// Add a new identity
    Add(commands::add::AddArgs),

    /// List all identities
    List(commands::list::ListArgs),

    /// Switch to a different identity
    Switch(commands::switch::SwitchArgs),

    /// Show identity details
    Show(commands::show::ShowArgs),

    /// Remove an identity
    Remove(commands::remove::RemoveArgs),

    /// Edit an identity
    Edit(commands::edit::EditArgs),

    /// Export identities
    Export(commands::export::ExportArgs),

    /// Import identities
    Import(commands::import::ImportArgs),

    /// Migrate database schema (e.g., Workspace v2)
    Migrate(commands::migrate::MigrateArgs),

    /// SSH key operations (developer features)
    Ssh(commands::ssh::SshArgs),

    /// Credential management (password/api key/etc.)
    Credential(commands::credential::CredentialArgs),

    /// Password generator utilities
    Password(commands::password::PasswordArgs),

    /// Interactive terminal UI
    Tui(commands::tui::TuiArgs),

    /// TOTP setup and code generation
    Totp(commands::totp::TotpArgs),

    /// Auto-lock policy management
    AutoLock(commands::auto_lock::AutoLockArgs),

    /// Crypto wallet management
    Wallet(commands::wallet::WalletArgs),

    /// Passkey (WebAuthn software authenticator) management
    Passkey(commands::passkey::PasskeyArgs),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = maybe_inject_bridge_subcommand(std::env::args_os().collect());
    let cli = Cli::parse_from(args);

    // Initialize logging
    init_logging(cli.verbose)?;

    // Load configuration.
    //
    // Workspace commands are intentionally "local by default": they require a
    // `config.toml` in the current working directory (or an explicit `--config`)
    // so tests and automation don't accidentally operate on a user's global
    // `~/.persona` workspace.
    let requires_workspace = command_requires_workspace(&cli.command);
    let config = if requires_workspace {
        let config_path = match cli.config.as_deref() {
            Some(p) => p.to_path_buf(),
            None => std::env::current_dir()?.join("config.toml"),
        };
        if !config_path.exists() {
            anyhow::bail!(
                "Workspace not initialized in this directory. Run `persona init` first (or pass --config)."
            );
        }
        let mut cfg = CliConfig::load_file(&config_path)?;
        cfg.apply_env_overrides();
        cfg
    } else {
        CliConfig::load(cli.config.as_deref())?
    };

    // Execute command
    match cli.command {
        Commands::Init(args) => commands::init::execute(args, &config).await,
        Commands::Bridge(args) => commands::bridge::execute(args).await,
        Commands::Add(args) => commands::add::execute(args, &config).await,
        Commands::List(args) => commands::list::execute(args, &config).await,
        Commands::Switch(args) => commands::switch::execute(args, &config).await,
        Commands::Show(args) => commands::show::execute(args, &config).await,
        Commands::Remove(args) => commands::remove::execute(args, &config).await,
        Commands::Edit(args) => commands::edit::execute(args, &config).await,
        Commands::Export(args) => commands::export::execute(args, &config).await,
        Commands::Import(args) => commands::import::execute(args, &config).await,
        Commands::Migrate(args) => commands::migrate::execute(args, &config).await,
        Commands::Ssh(args) => commands::ssh::execute(args, &config).await,
        Commands::Credential(args) => commands::credential::execute(args, &config).await,
        Commands::Password(args) => commands::password::execute(args, &config).await,
        Commands::Tui(args) => commands::tui::execute(args, &config).await,
        Commands::Totp(args) => commands::totp::execute(args, &config).await,
        Commands::AutoLock(args) => commands::auto_lock::handle_auto_lock(args, &config).await,
        Commands::Wallet(args) => commands::wallet::handle_wallet(args, &config).await,
        Commands::Passkey(args) => commands::passkey::handle_passkey(args, &config).await,
    }
}

fn maybe_inject_bridge_subcommand(mut args: Vec<OsString>) -> Vec<OsString> {
    if args.len() != 1 {
        return args;
    }

    let Some(exe) = args
        .first()
        .and_then(|s| s.to_str())
        .and_then(|p| Path::new(p).file_stem().and_then(|s| s.to_str()))
    else {
        return args;
    };

    // Native Messaging hosts are launched with no args; allow installing a copy of the
    // binary as `persona-bridge(.exe)` that defaults to `persona bridge`.
    if exe.eq_ignore_ascii_case("persona-bridge") {
        args.push(OsString::from("bridge"));
    }

    args
}

fn command_requires_workspace(cmd: &Commands) -> bool {
    !matches!(
        cmd,
        Commands::Init(_) | Commands::Bridge(_) | Commands::Password(_)
    )
}

/// Initialize logging based on verbosity level
fn init_logging(verbose: bool) -> Result<()> {
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    RedactedLoggerBuilder::new(level)
        .include_target(false)
        .init()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn bridge_injection_happens_only_for_bridge_named_single_arg() {
        // argv[0] == "persona-bridge" -> inject the bridge subcommand.
        let injected = maybe_inject_bridge_subcommand(args(&["persona-bridge"]));
        assert_eq!(injected, args(&["persona-bridge", "bridge"]));

        // An installed copy under a bin directory resolves via file_stem.
        let injected = maybe_inject_bridge_subcommand(args(&["/usr/local/bin/persona-bridge"]));
        assert_eq!(injected, args(&["/usr/local/bin/persona-bridge", "bridge"]));

        // Matching on the executable name ignores ASCII case.
        let injected = maybe_inject_bridge_subcommand(args(&["PERSONA-BRIDGE.EXE"]));
        assert_eq!(injected, args(&["PERSONA-BRIDGE.EXE", "bridge"]));

        // The regular binary and any multi-arg invocation stay untouched.
        let untouched = maybe_inject_bridge_subcommand(args(&["persona"]));
        assert_eq!(untouched, args(&["persona"]));

        let untouched = maybe_inject_bridge_subcommand(args(&["persona", "list"]));
        assert_eq!(untouched, args(&["persona", "list"]));
    }

    #[test]
    fn bridge_injection_ignores_non_utf8_and_pathless_names() {
        // An argv[0] that is not valid UTF-8 cannot be matched; args pass through.
        let untouched = maybe_inject_bridge_subcommand(args(&["persona-bridgé"]));
        assert_eq!(untouched, args(&["persona-bridgé"]));

        // A name without a recognizable file stem (e.g. trailing slash on the
        // root) also passes through untouched.
        let untouched = maybe_inject_bridge_subcommand(args(&["/"]));
        assert_eq!(untouched, args(&["/"]));
    }

    #[cfg(unix)]
    #[test]
    fn bridge_injection_ignores_non_utf8_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(vec![0xff, 0xfe, 0x2e]);
        let untouched = maybe_inject_bridge_subcommand(vec![raw]);
        assert_eq!(untouched.len(), 1);
    }

    #[test]
    fn workspace_commands_exclude_init_bridge_and_password() {
        // Build one instance per variant through the real clap parser so the
        // test keeps compiling when new subcommands are added.
        let cli = Cli::parse_from(args(&["persona", "init"]));
        assert!(!command_requires_workspace(&cli.command));

        let cli = Cli::parse_from(args(&["persona", "bridge"]));
        assert!(!command_requires_workspace(&cli.command));

        let cli = Cli::parse_from(args(&["persona", "password", "generate"]));
        assert!(!command_requires_workspace(&cli.command));

        // Everything else operates on an initialized workspace.
        let cli = Cli::parse_from(args(&["persona", "list"]));
        assert!(command_requires_workspace(&cli.command));

        let cli = Cli::parse_from(args(&["persona", "add", "work"]));
        assert!(command_requires_workspace(&cli.command));
    }

    #[test]
    fn cli_definition_is_well_formed() {
        // Exercises the derived clap metadata without spawning the binary.
        Cli::command().debug_assert();
    }

    #[test]
    fn init_logging_installs_subscriber_exactly_once() {
        // The global subscriber can only be installed once per process.
        // Either this test is the first (first call succeeds, second fails)
        // or another test installed one earlier (both calls fail) — in every
        // interleaving the second install must report an error.
        let _ = init_logging(true);
        assert!(init_logging(false).is_err());
    }
}
