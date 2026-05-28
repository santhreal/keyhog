use clap::Parser;
use std::path::PathBuf;

/// Subcommand args for `keyhog daemon {start, stop, status}`.
#[derive(Parser)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub action: DaemonAction,
}

#[derive(clap::Subcommand)]
pub enum DaemonAction {
    /// Start a daemon process that holds a compiled scanner and
    /// serves scan requests over a Unix socket. Blocks until
    /// `daemon stop` is invoked.
    Start {
        /// Override the default socket path
        /// ($XDG_RUNTIME_DIR/keyhog.sock or ~/.cache/keyhog/server.sock).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Detector directory (same default as `keyhog scan --detectors`).
        #[arg(long, default_value = "detectors")]
        detectors: PathBuf,
    },
    /// Stop the running daemon by sending it a `Shutdown` over the socket.
    Stop {
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Print uptime, scans served, active scans, and detector count.
    Status {
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
}

#[derive(Parser)]
pub struct ScanSystemArgs {
    /// Hard ceiling on total bytes scanned. Walker tracks running total
    /// and stops when the next file would push past this. Examples:
    ///   --space 50G   --space 1T   --space 500M
    /// Default 50 GiB — enough to cover most home directories without
    /// drowning the scan on a NAS-mount.
    #[arg(long, default_value = "50G", value_parser = parse_byte_size)]
    pub space: u64,

    /// Include network-mounted filesystems (NFS, SMB, sshfs). Off by
    /// default — these are typically slow and contain other people's
    /// secrets the user hasn't authorized scanning.
    #[arg(long, default_value_t = false)]
    pub include_network: bool,

    /// Skip auto-discovery of `.git` directories. By default scan-system
    /// finds every git repo on every walked drive and runs --git-history
    /// on each, including bare repos and submodules. Disable to save time
    /// when you only care about working-tree state.
    #[arg(long, default_value_t = false)]
    pub no_git_history: bool,

    /// Honor `.gitignore` like `keyhog scan` does. Default OFF — system
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

    /// Apply hardening protections (mlocked + coredump-blocked) and
    /// refuse the operations that weaken detection or expand attack
    /// surface. See `keyhog scan --lockdown` for the full list.
    #[arg(long, default_value_t = false)]
    pub lockdown: bool,
}

/// Parse human-readable byte sizes: `50G`, `1T`, `500M`, `1024K`, `1234`.
fn parse_byte_size(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty size".into());
    }
    let (num_part, suffix) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(trimmed.len()),
    );
    let n: f64 = num_part.parse().map_err(|e| format!("bad number: {e}"))?;
    let multiplier: u64 = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" | "TIB" => 1024_u64.pow(4),
        other => return Err(format!("unknown size suffix: {other}")),
    };
    Ok((n * multiplier as f64) as u64)
}

#[derive(Parser)]
pub struct CompletionArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Parser)]
pub struct BackendArgs {
    /// Probe the workload size that would route to a different backend.
    /// E.g. `--probe-bytes $((256 * 1024 * 1024))` to confirm GPU is picked
    /// at the 256 MiB threshold.
    #[arg(long)]
    pub probe_bytes: Option<u64>,

    /// Pattern count to use for routing simulation. Defaults to the
    /// compiled embedded-corpus pattern count. Use this to test
    /// threshold behavior.
    #[arg(long)]
    pub patterns: Option<usize>,

    /// Run the GPU self-tests (MoE compute kernel + vyre literal-set
    /// dispatch). Prints PASS/FAIL with adapter info and exits with
    /// code 4 on failure so CI can gate a release on real GPU
    /// functionality. No-op on systems without a non-software adapter.
    #[arg(long)]
    pub self_test: bool,
}

#[derive(Parser)]
pub struct WatchArgs {
    /// Directory to watch recursively. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Detector TOML directory. Falls back to embedded corpus if missing.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Quiet mode — only print findings (suppress "watching X" status).
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Parser)]
pub struct CalibrateArgs {
    /// Mark these detector IDs as confirmed true positives (α += 1 each).
    /// Use `--tp` repeatedly: `--tp aws-access-key --tp github-pat`.
    #[arg(long, value_name = "DETECTOR_ID")]
    pub tp: Vec<String>,
    /// Mark these detector IDs as confirmed false positives (β += 1 each).
    #[arg(long, value_name = "DETECTOR_ID")]
    pub fp: Vec<String>,
    /// Print every recorded counter and exit (no updates).
    #[arg(long)]
    pub show: bool,
    /// Override the calibration cache path. Defaults to
    /// $XDG_CACHE_HOME/keyhog/calibration.json.
    #[arg(long, value_name = "PATH")]
    pub cache: Option<PathBuf>,
}

#[derive(Parser)]
pub struct DiffArgs {
    /// Baseline file A (the "before" / older state).
    pub before: PathBuf,
    /// Baseline file B (the "after" / newer state).
    pub after: PathBuf,
    /// Suppress the `UNCHANGED` section (default: shown).
    #[arg(long)]
    pub hide_unchanged: bool,
    /// Emit results as JSON instead of human-readable text. Useful for CI
    /// that wants to gate merges on regressions programmatically.
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct ExplainArgs {
    /// Detector ID to explain (e.g. `aws-access-key`, `github-pat`).
    /// Use `keyhog detectors` to list available IDs.
    pub detector_id: String,

    /// Detector TOML directory; falls back to the embedded corpus when
    /// missing. Same semantics as `keyhog detectors --detectors`.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
}
