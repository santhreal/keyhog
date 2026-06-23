use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct WatchArgs {
    /// Directory to watch recursively. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: PathBuf,
    /// Detector TOML directory. Falls back to embedded corpus if missing.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Override the Hyperscan compiled-database cache directory.
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,
    /// Quiet mode: only print findings (suppress "watching X" status).
    #[arg(long)]
    pub quiet: bool,
}
