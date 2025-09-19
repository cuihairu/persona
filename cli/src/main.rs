use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use tracing::{info, warn};

mod commands;
mod config;
mod utils;

use config::CliConfig;

#[derive(Parser)]
#[command(name = "persona")]
#[command(about = "A digital identity management CLI tool")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<std::path::PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new persona workspace
    Init(commands::init::InitArgs),
    
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose)?;

    // Load configuration
    let config = CliConfig::load(cli.config.as_deref())?;

    // Execute command
    match cli.command {
        Commands::Init(args) => commands::init::execute(args, &config).await,
        Commands::Add(args) => commands::add::execute(args, &config).await,
        Commands::List(args) => commands::list::execute(args, &config).await,
        Commands::Switch(args) => commands::switch::execute(args, &config).await,
        Commands::Show(args) => commands::show::execute(args, &config).await,
        Commands::Remove(args) => commands::remove::execute(args, &config).await,
        Commands::Edit(args) => commands::edit::execute(args, &config).await,
        Commands::Export(args) => commands::export::execute(args, &config).await,
        Commands::Import(args) => commands::import::execute(args, &config).await,
    }
}

/// Initialize logging based on verbosity level
fn init_logging(verbose: bool) -> Result<()> {
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    Ok()
}

fn print_banner() {
    println!("{}", "
    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗ █████╗ 
    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║██╔══██╗
    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║███████║
    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║██╔══██║
    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║██║  ██║
    ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
    ".cyan().bold());
    
    println!("{}", "Master your digital identity. Switch freely with one click.".italic());
    println!();
}