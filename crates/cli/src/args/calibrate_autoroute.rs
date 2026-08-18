use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Scan policy whose workload ladder should be calibrated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AutorouteCalibrationPolicy {
    /// Calibrate the ordinary scan policy with no preset flag.
    Default,
    /// Calibrate the `--fast` scan preset.
    Fast,
    /// Calibrate the `--deep` scan preset.
    Deep,
    /// Calibrate the `--precision` scan preset.
    Precision,
    /// Calibrate the ordinary policy and every documented preset.
    All,
}

/// Run the full install-time autoroute calibration sweep in one command.
///
/// Generates the stdin + filesystem workload ladder a real scan can hit. Each
/// preset reuses one compiled production scanner while every representative
/// still runs through canonical source handling, all-backend parity checks,
/// workload-shaped cold-state measurement, and persisted route selection.
/// External source classes that need repositories, services, containers, or
/// remote endpoints remain installer-owned.
///
/// Overlapping route timings resolve deterministically to the lowest-complexity
/// non-inferior route. Unusable evidence or measured points that disagree about
/// the backend exit 2 without publication. An explicit `--backend` remains
/// diagnostic only.
#[derive(Parser)]
pub struct CalibrateAutorouteArgs {
    /// Override the persistent autoroute cache file every probe writes to.
    ///
    /// Must be a writable path. Calibration exists to PERSIST routing decisions,
    /// so `off` (which disables persistence) is rejected up front rather than
    /// failing every probe closed. Defaults to the same cache a normal scan
    /// reads, so a plain `keyhog calibrate-autoroute` primes exactly what later
    /// scans resolve against.
    #[arg(long, value_name = "PATH")]
    pub autoroute_cache: Option<String>,
    /// Bind persisted route evidence to this authenticated execution-pack generation.
    ///
    /// Calibration binds to the authenticated generation in the platform cache
    /// directory on its own, so an ordinary install needs no flag. Name a
    /// directory only to bind against a generation that lives elsewhere; it
    /// fails closed when the directory does not authenticate.
    #[arg(long, value_name = "DIR")]
    pub execution_packs: Option<PathBuf>,
    /// Internal receipt sink used by the all-policy parent transaction.
    #[arg(long, value_name = "PATH", hide = true)]
    pub measurement_receipts: Option<PathBuf>,

    /// Select which scan policy to calibrate.
    ///
    /// `all` preserves the install-time sweep. Select one policy when you need
    /// to repair or refresh only the configuration you run.
    #[arg(long, value_enum, default_value_t = AutorouteCalibrationPolicy::All)]
    pub policy: AutorouteCalibrationPolicy,

    /// Calibrate the compiled-in defaults instead of the repository config.
    ///
    /// Routing decisions are stored under the RESOLVED scan configuration, so
    /// calibration must resolve the same `.keyhog.toml` walk-up the scans that
    /// follow it resolve. Skipping the file writes every decision under a
    /// digest no scan in that repository requests, and the next `keyhog scan`
    /// fails closed with "none matching config digest".
    ///
    /// Pass this to prime a host baseline that is independent of whatever
    /// directory calibration ran in. Installers do exactly that, and an
    /// operator whose repository carries a `.keyhog.toml` reruns the bare
    /// command inside the repository.
    #[arg(long)]
    pub no_config: bool,

    /// Suppress the per-probe progress lines; print only the final summary.
    #[arg(long)]
    pub quiet: bool,
}
