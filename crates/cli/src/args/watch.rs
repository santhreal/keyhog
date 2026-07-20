use std::path::PathBuf;

use clap::Parser;

/// Default consecutive engine-failure budget before watch exits (KH-1334 / KH-1462).
pub const DEFAULT_WATCH_MAX_CONSECUTIVE_SCAN_FAILURES: usize = 8;

#[derive(Parser)]
pub struct WatchArgs {
    /// Director(ies) to watch recursively. Pass several to monitor multiple
    /// roots in one foreground watcher (`keyhog watch src/ config/`); nested or
    /// duplicate roots fold into their covering parent, mirroring `keyhog scan`.
    /// Each root must be a directory. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub paths: Vec<PathBuf>,
    /// Detector TOML directory. When omitted, KeyHog discovers an installed
    /// corpus or uses the embedded corpus. An explicitly named missing path is
    /// an error.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    #[arg(skip)]
    pub(crate) detectors_cli_explicit: bool,
    /// Override the Hyperscan compiled-database cache directory.
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,
    /// Select persisted autoroute or explicitly force one diagnostic backend.
    /// Accepted values are listed below. Without valid installer calibration,
    /// each change scan warns and completes through scalar correctness recovery
    /// exactly as `keyhog scan` does.
    #[arg(
        long,
        value_name = "BACKEND",
        value_parser = clap::builder::PossibleValuesParser::new(
            keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
        )
    )]
    pub backend: Option<String>,
    /// Maximum bytes per changed file (same default as `keyhog scan`, 100 MiB).
    /// Pass `0` to use the built-in default. Oversized editor saves are skipped
    /// with a loud error rather than OOM-ing the single-threaded watcher (KH-1461).
    #[arg(long, value_name = "BYTES")]
    pub max_file_size: Option<u64>,
    /// Exit after this many consecutive per-file scan engine failures so a
    /// wedged scanner cannot silently drop secrets under editor saves
    /// (KH-1334 / KH-1462). Default 8.
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_WATCH_MAX_CONSECUTIVE_SCAN_FAILURES
    )]
    pub max_consecutive_failures: usize,
    /// Quiet mode: only print findings (suppress "watching X" status).
    #[arg(long)]
    pub quiet: bool,
}
