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

    /// Select which scan policy to calibrate.
    ///
    /// `all` preserves the install-time sweep. Select one policy when you need
    /// to repair or refresh only the configuration you run.
    #[arg(long, value_enum, default_value_t = AutorouteCalibrationPolicy::All)]
    pub policy: AutorouteCalibrationPolicy,

    /// Suppress the per-probe progress lines; print only the final summary.
    #[arg(long)]
    pub quiet: bool,
}
