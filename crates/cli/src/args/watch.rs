use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct WatchArgs {
    /// Director(ies) to watch recursively. Pass several to monitor multiple
    /// roots in one foreground watcher (`keyhog watch src/ config/`); nested or
    /// duplicate roots fold into their covering parent, mirroring `keyhog scan`.
    /// Each root must be a directory. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub paths: Vec<PathBuf>,
    /// Detector TOML directory. Falls back to embedded corpus if missing.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Override the Hyperscan compiled-database cache directory.
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,
    /// Select persisted autoroute (`auto`) or explicitly force one diagnostic
    /// backend (`gpu`, `simd`, or `cpu`). Without it (and without installer
    /// calibration for this binary) every change scan fails closed with an
    /// autoroute-calibration error, exactly as `keyhog scan` does.
    #[arg(
        long,
        value_name = "BACKEND",
        value_parser = clap::builder::PossibleValuesParser::new(
            keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
        )
    )]
    pub backend: Option<String>,
    /// Quiet mode: only print findings (suppress "watching X" status).
    #[arg(long)]
    pub quiet: bool,
}
