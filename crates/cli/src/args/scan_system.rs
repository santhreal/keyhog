use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct ScanSystemArgs {
    /// Hard ceiling on total bytes scanned. Walker tracks running total
    /// and stops when the next file would push past this. Examples:
    ///   --space 50G   --space 1T   --space 500M
    /// Default 50 GiB; enough to cover most home directories without
    /// drowning the scan on a NAS-mount.
    #[arg(long, default_value = "50G", value_parser = parse_space_bytes)]
    pub space: u64,

    /// Include network-mounted filesystems (NFS, SMB, sshfs). Off by
    /// default; these are typically slow and contain other people's
    /// secrets the user hasn't authorized scanning.
    #[arg(long, default_value_t = false)]
    pub include_network: bool,

    /// Skip auto-discovery of `.git` directories. By default scan-system
    /// finds every git repo on every walked drive and runs --git-history
    /// on each, including bare repos and submodules. Disable to save time
    /// when you only care about working-tree state.
    #[arg(long, default_value_t = false)]
    pub no_git_history: bool,

    /// Honor `.gitignore` like `keyhog scan` does. Default OFF; system
    /// scans are paranoid because an attacker stashing a leaked key
    /// would `.gitignore` it. Set this to behave like a normal scan.
    #[arg(long, default_value_t = false)]
    pub respect_gitignore: bool,

    /// Output JSON path. Defaults to stderr (text format) if unset.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Detector directory (same as `keyhog scan --detectors`).
    #[arg(long, default_value = "detectors")]
    pub detectors: PathBuf,

    /// Override the Hyperscan compiled-database cache directory.
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Number of parallel scanning threads (default: number of CPU cores).
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_positive_thread_count)]
    pub threads: Option<usize>,

    /// Apply hardening protections (mlocked + coredump-blocked) and
    /// refuse the operations that weaken detection or expand attack
    /// surface. See `keyhog scan --lockdown` for the full list.
    #[arg(long, default_value_t = false)]
    pub lockdown: bool,
}

/// Parse human-readable byte sizes for `--space` (`50G`, `1T`, `500M`, `1024K`).
///
/// Thin `u64`-returning adapter over the single source of truth in
/// `crate::value_parsers::parse_byte_size` (overflow-checked, unit-required,
/// NaN/negative-guarded, with committed test fixtures). `ScanSystemArgs::space`
/// is a `u64`; the shared parser yields a sanity-capped `usize` (< usize::MAX/2),
/// so the widening cast is lossless on every supported platform.
#[doc(hidden)]
pub fn parse_space_bytes(s: &str) -> Result<u64, String> {
    crate::value_parsers::parse_byte_size(s).map(|bytes| bytes as u64)
}
