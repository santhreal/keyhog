use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct CalibrateArgs {
    /// Mark these detector IDs as confirmed true positives (α += 1 each).
    /// Use `--tp` repeatedly: `--tp aws-access-key --tp github-pat`.
    #[arg(long, value_name = "DETECTOR_ID")]
    pub tp: Vec<String>,
    /// Mark these detector IDs as confirmed false positives (β += 1 each).
    #[arg(long, value_name = "DETECTOR_ID")]
    pub fp: Vec<String>,
    /// Print every recorded counter and exit (no updates). Read-only: it cannot
    /// be combined with the `--tp`/`--fp` update flags (mixing "show me the
    /// state" with "mutate the state" is contradictory and silently ran the
    /// update before (clap now rejects it with exit 2)).
    #[arg(long, conflicts_with_all = ["tp", "fp"])]
    pub show: bool,
    /// Override the calibration cache path. Defaults to
    /// $XDG_CACHE_HOME/keyhog/calibration.json.
    #[arg(long, value_name = "PATH")]
    pub cache: Option<PathBuf>,
}
