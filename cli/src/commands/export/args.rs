use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ExportArgs {
    /// Identity names to export (leave empty for all)
    pub(crate) names: Vec<String>,

    /// Output file path
    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    /// Export format (json, yaml, csv)
    #[arg(short, long, default_value = "json")]
    pub(crate) format: String,

    /// Include sensitive data
    #[arg(long)]
    pub(crate) include_sensitive: bool,

    /// Encrypt exported data
    #[arg(short, long)]
    pub(crate) encrypt: bool,

    /// Compression level (0-9, 0=no compression)
    #[arg(long, default_value = "6")]
    pub(crate) compression: u8,

    /// Interactive selection mode
    #[arg(short, long)]
    pub(crate) interactive: bool,
}
