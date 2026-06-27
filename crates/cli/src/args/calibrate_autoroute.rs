use clap::Parser;

/// Run the full install-time autoroute calibration sweep in one command.
///
/// Generates the stdin + filesystem workload ladder a real scan can hit, then
/// runs `keyhog scan --autoroute-calibrate` once per (scan-policy preset ×
/// workload) so every bucket the auto router will look up is persisted before
/// the scan path goes live. This is the de-shelled core of what the installers
/// used to hand-roll in POSIX sh and PowerShell; the external source classes
/// (git / docker / web), which need environment orchestration this command
/// deliberately does not own, stay with the installer.
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

    /// Suppress the per-probe progress lines; print only the final summary.
    #[arg(long)]
    pub quiet: bool,
}
