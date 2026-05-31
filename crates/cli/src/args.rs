//! Command-line argument parsing for KeyHog.

mod scan;

pub use scan::ScanArgs;

use clap::{Parser, ValueEnum};
use keyhog_core::DedupScope;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keyhog",
    about = "KeyHog: The developer-first secret scanner.\nFind leaked credentials in your code before hackers do. Fast, accurate, and verifying.",
    after_help = "EXIT CODES:\n  0   Success (no secrets found)\n  1   Secrets found (unverified or verification skipped)\n  2   Runtime error (e.g., config error, unreadable path)\n  3   `detectors --audit` flagged a detector quality issue\n  4   `backend --self-test` failed (GPU/SIMD probe error)\n  10  Live credentials found (requires --verify)\n  11  Scanner thread panicked mid-scan (state is unreliable)",
    disable_version_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Print version, build information, and statistics
    #[arg(short = 'V', long)]
    pub version: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// 🔍 Scan files, directories, or repositories for secrets
    #[command(verbatim_doc_comment)]
    Scan(Box<ScanArgs>),

    /// 🪝 Manage git pre-commit hooks
    #[command(verbatim_doc_comment)]
    Hook {
        #[command(subcommand)]
        command: crate::subcommands::hook::HookCommand,
    },

    /// 📋 List all loaded secret detectors
    #[command(verbatim_doc_comment)]
    Detectors(DetectorArgs),

    /// 📖 Explain a detector: spec, regex, severity, rotation guide
    #[command(verbatim_doc_comment)]
    Explain(ExplainArgs),

    /// 🔀 Diff two baseline JSON files: show NEW / RESOLVED / UNCHANGED
    #[command(verbatim_doc_comment)]
    Diff(DiffArgs),

    /// 📊 Show or update per-detector Bayesian calibration counters
    #[command(verbatim_doc_comment)]
    Calibrate(CalibrateArgs),

    /// 👁  Watch a directory and scan files as they change (daemon mode)
    #[command(verbatim_doc_comment)]
    Watch(WatchArgs),

    /// 🔧 Print shell completion script (bash, zsh, fish, powershell, elvish)
    #[command(verbatim_doc_comment)]
    Completion(CompletionArgs),

    /// ⚙️  Inspect detected hardware + the auto-selected scan backend
    #[command(verbatim_doc_comment)]
    Backend(BackendArgs),

    /// 🩺 Health-check the install: host, PATH, detector corpus, scan self-test
    #[command(verbatim_doc_comment)]
    Doctor(DoctorArgs),

    /// ⬆️  Update keyhog to the latest release: verified download + self-replace
    #[command(verbatim_doc_comment)]
    Update(UpdateArgs),

    /// 🔧 Repair a broken install: reinstall a known-good binary, then verify
    #[command(verbatim_doc_comment)]
    Repair(RepairArgs),

    /// 🗑  Uninstall keyhog: remove the binary (dry run unless --yes)
    #[command(verbatim_doc_comment)]
    Uninstall(UninstallArgs),

    /// 🛰  Recursive system-wide scan: every mounted drive, every git history
    #[command(verbatim_doc_comment)]
    ScanSystem(ScanSystemArgs),

    /// 🔌 Manage the long-lived `keyhog daemon` (start, stop, status)
    #[command(verbatim_doc_comment)]
    Daemon(DaemonArgs),

    /// 🖥  Live TUI dashboard: scan a path with a real-time finding feed
    #[cfg(feature = "tui")]
    #[command(verbatim_doc_comment)]
    Tui(TuiArgs),
}

/// Arguments for the `keyhog tui` subcommand. Intentionally minimal: the
/// TUI is a demo / interactive surface, not a CI gate. Use `keyhog scan`
/// for headless / scriptable runs.
#[cfg(feature = "tui")]
#[derive(Parser)]
pub struct TuiArgs {
    /// Path to scan. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: PathBuf,

    /// Limit the number of files scanned. Useful for long demos where
    /// you want a fixed-duration loop. 0 = unlimited.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub max_files: usize,

    /// Cap the finding feed depth (recent N findings kept). Default 200.
    #[arg(long, value_name = "N", default_value_t = 200)]
    pub feed_depth: usize,

    /// Sleep N milliseconds between files. Slows the live feed so demo
    /// recordings actually capture findings streaming in. Default 0
    /// (scan as fast as possible). Use --throttle-ms 60 for a steady
    /// ~16 findings/sec feed on small corpora.
    #[arg(long, value_name = "MS", default_value_t = 0)]
    pub throttle_ms: u64,
}

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

    /// Compiled pattern count to use for the routing-simulation matrix.
    /// This is a what-if knob: it does not change the loaded corpus, only
    /// the pattern_count fed to the backend-routing thresholds so you can
    /// probe how a larger/smaller corpus would route. The default is a
    /// representative full-corpus figure; pass an explicit value to test a
    /// specific threshold boundary.
    #[arg(long, default_value_t = 1509)]
    pub patterns: usize,

    /// Run the GPU self-tests (MoE compute kernel + vyre literal-set
    /// dispatch). Prints PASS/FAIL with adapter info and exits with
    /// code 4 on failure so CI can gate a release on real GPU
    /// functionality. No-op on systems without a non-software adapter.
    #[arg(long)]
    pub self_test: bool,
}

/// Arguments for `keyhog doctor`. The health check is fully automatic; no
/// flags are needed today. The struct exists so the command can grow options
/// (e.g. `--json`) without a breaking signature change.
#[derive(Parser)]
pub struct DoctorArgs {}

/// Arguments for `keyhog update` (self-update from GitHub releases).
#[derive(Parser)]
pub struct UpdateArgs {
    /// Only check whether a newer release is available; do not install.
    /// Exits 10 when an update is available, 0 when already current.
    #[arg(long)]
    pub check: bool,

    /// Install a specific release tag instead of the latest (e.g. `v0.5.34`).
    /// Use this to pin a version or downgrade.
    #[arg(long)]
    pub version: Option<String>,

    /// Asset variant: `cuda` selects the CUDA-accelerated Linux build;
    /// otherwise the portable WGPU+SIMD build is installed (the default,
    /// which still uses the GPU via WGPU and runs everywhere).
    #[arg(long)]
    pub variant: Option<String>,
}

/// Arguments for `keyhog repair` (reinstall a known-good binary from releases).
#[derive(Parser)]
pub struct RepairArgs {
    /// Reinstall even if the scan-engine self-test currently passes.
    #[arg(long)]
    pub force: bool,

    /// Reinstall a specific release tag instead of the latest (e.g. `v0.5.34`).
    #[arg(long)]
    pub version: Option<String>,

    /// Asset variant: `cuda` for the CUDA Linux build; otherwise the portable
    /// WGPU+SIMD build (default).
    #[arg(long)]
    pub variant: Option<String>,
}

/// Arguments for `keyhog uninstall`.
#[derive(Parser)]
pub struct UninstallArgs {
    /// Actually remove the binary. Without this, uninstall is a safe dry run
    /// that only reports what would be removed.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Parser)]
pub struct WatchArgs {
    /// Directory to watch recursively. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Detector TOML directory. Falls back to embedded corpus if missing.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Quiet mode: only print findings (suppress "watching X" status).
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

#[derive(Parser)]
pub struct DetectorArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Filter detectors by substring match (case-insensitive) against id,
    /// name, service, and keywords. Useful for finding detectors in the
    /// 891-strong corpus (e.g. `keyhog detectors --search aws`).
    #[arg(short, long)]
    pub search: Option<String>,
    /// Print full detector spec (regex, prefixes, keywords) instead of
    /// the grouped service summary. Pairs naturally with `--search`.
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
    /// Audit detectors against the quality gate (`keyhog_core::validate_detector`).
    /// Prints every issue grouped by detector and exits non-zero (3) if any
    /// `Error`-severity issue was found. Warnings are reported but do not
    /// fail the run. Pairs with `--detectors <DIR>` for CI gating.
    #[arg(long, conflicts_with = "fix")]
    pub audit: bool,
    /// Apply safe automated fixes to the detector TOMLs in `--detectors`.
    /// Currently rewrites single-brace template references (`{name}`) to
    /// the double-brace form (`{{name}}`) within `[detector.verify*]`
    /// blocks: the one fix the interpolator's contract makes safe to
    /// perform mechanically. Other validator findings are left alone
    /// (they need human judgement). Use `--dry-run` to preview rewrites
    /// without touching the filesystem.
    #[arg(long, conflicts_with = "audit")]
    pub fix: bool,
    /// Show the rewrites `--fix` *would* make without writing them. No-op
    /// unless `--fix` is also set.
    #[arg(long, requires = "fix")]
    pub dry_run: bool,
    /// Emit the detector listing as a JSON array on stdout instead of the
    /// human-readable grouped summary. Pairs with `--search` for filtered
    /// programmatic discovery (CI gates, bench harnesses, IDE plugins).
    /// Mutually exclusive with `--audit` / `--fix` since those emit their
    /// own structured output formats. JSON shape mirrors the human surface:
    /// `[{ "id", "name", "service", "severity", "keywords": [..],
    /// "patterns": [{ "regex", "description", "group" }, ..],
    /// "companions": [{ "name", "regex", "within_lines", "required" }, ..],
    /// "verify": <bool> }, ..]`.
    #[arg(long, conflicts_with_all = ["audit", "fix"])]
    pub json: bool,
}

#[derive(Clone, ValueEnum)]
pub enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    pub fn to_severity(&self) -> keyhog_core::Severity {
        match self {
            Self::Info => keyhog_core::Severity::Info,
            Self::Low => keyhog_core::Severity::Low,
            Self::Medium => keyhog_core::Severity::Medium,
            Self::High => keyhog_core::Severity::High,
            Self::Critical => keyhog_core::Severity::Critical,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
    Csv,
    Html,
    Junit,
}

#[derive(Clone, ValueEnum, PartialEq)]
pub enum CliDedupScope {
    Credential,
    File,
    None,
}

impl CliDedupScope {
    pub fn to_core(&self) -> DedupScope {
        match self {
            Self::Credential => DedupScope::Credential,
            Self::File => DedupScope::File,
            Self::None => DedupScope::None,
        }
    }
}
