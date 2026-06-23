//! Command-line argument parsing for KeyHog.

mod limits;
mod maintenance;
mod scan;

pub use limits::SourceLimitArgs;
pub use maintenance::{
    BackendArgs, CompletionArgs, DoctorArgs, RepairArgs, UninstallArgs, UpdateArgs,
};
pub use scan::ScanArgs;

use clap::{Parser, ValueEnum};
use keyhog_core::DedupScope;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keyhog",
    about = "KeyHog: The developer-first secret scanner.\nFind leaked credentials in your code before hackers do. Fast, accurate, and verifying.",
    disable_version_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Print version, build information, and statistics
    #[arg(short = 'V', long)]
    pub version: bool,

    /// Include the hardware probe in version output. This initializes GPU/SIMD
    /// discovery, so it is explicit instead of controlled by ambient env.
    #[arg(long, requires = "version")]
    pub full: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Scan files, directories, or repositories for secrets
    #[command(verbatim_doc_comment)]
    Scan(Box<ScanArgs>),

    /// Print resolved scan configuration without scanning
    #[command(verbatim_doc_comment)]
    Config(Box<ConfigArgs>),

    /// Manage git pre-commit hooks
    #[command(verbatim_doc_comment)]
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },

    /// List all loaded secret detectors
    #[command(verbatim_doc_comment)]
    Detectors(DetectorArgs),

    /// Explain a detector: spec, regex, severity, rotation guide
    #[command(verbatim_doc_comment)]
    Explain(ExplainArgs),

    /// Diff two baseline JSON files: show NEW / RESOLVED / UNCHANGED
    #[command(verbatim_doc_comment)]
    Diff(DiffArgs),

    /// Show or update per-detector Bayesian calibration counters
    #[command(verbatim_doc_comment)]
    Calibrate(CalibrateArgs),

    /// Watch a directory and scan files as they change (daemon mode)
    #[command(verbatim_doc_comment)]
    Watch(WatchArgs),

    /// Print shell completion script (bash, zsh, fish, powershell, elvish)
    #[command(verbatim_doc_comment)]
    Completion(CompletionArgs),

    /// Inspect detected hardware + the auto-selected scan backend
    #[command(verbatim_doc_comment)]
    Backend(BackendArgs),

    /// Health-check the install: host, PATH, detector corpus, scan self-test
    #[command(verbatim_doc_comment)]
    Doctor(DoctorArgs),

    /// Update keyhog to the latest release: verified download + self-replace
    #[command(verbatim_doc_comment)]
    Update(UpdateArgs),

    /// Repair a broken install: reinstall a known-good binary, then verify
    #[command(verbatim_doc_comment)]
    Repair(RepairArgs),

    /// Uninstall keyhog: remove the binary (dry run unless --yes)
    #[command(verbatim_doc_comment)]
    Uninstall(UninstallArgs),

    /// 🛰  Recursive system-wide scan: every mounted drive, every git history
    #[command(verbatim_doc_comment)]
    ScanSystem(ScanSystemArgs),

    /// 🔌 Manage the long-lived `keyhog daemon` (start, stop, status)
    #[command(verbatim_doc_comment)]
    Daemon(DaemonArgs),
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum HookCommand {
    /// Install a git pre-commit hook in the current repository
    Install {
        /// Replace an existing non-KeyHog pre-commit hook.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Remove the KeyHog pre-commit hook from the current repository
    Uninstall,
}

#[derive(Parser)]
pub struct ConfigArgs {
    /// Print the resolved scan configuration and exit without scanning.
    ///
    /// Accepts the same config-affecting flags as `keyhog scan`, so operators
    /// can prove the compiled defaults, TOML config, and CLI overrides that
    /// would reach the scanner for the same scan invocation.
    #[arg(long, required = true)]
    pub effective: bool,

    #[command(flatten)]
    pub scan: ScanArgs,
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
        /// Override the Hyperscan compiled-database cache directory.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
        /// Force a daemon scan backend instead of using persisted autoroute.
        ///
        /// The default `auto` mode requires install-time calibration. Use an
        /// explicit backend for diagnostics and hermetic daemon tests.
        #[arg(long, value_name = "auto|simd|cpu|gpu|megascan")]
        backend: Option<String>,
        /// Max seconds a client connection may sit without completing one
        /// request frame before the daemon closes it and reclaims the slot.
        #[arg(
            long,
            default_value_t = 300,
            value_name = "SECS",
            value_parser = crate::value_parsers::parse_daemon_request_timeout_secs
        )]
        request_timeout_secs: u64,
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
    /// update before — clap now rejects it with exit 2).
    #[arg(long, conflicts_with_all = ["tp", "fp"])]
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
    /// Optional verb. `keyhog detectors` lists detectors by default, so the
    /// only accepted positional is the explicit `list` (a no-op alias kept for
    /// muscle-memory and for the historically-suggested
    /// `keyhog detectors list --detectors <DIR>` invocation). Any other token
    /// is rejected with a precise message rather than misparsed.
    #[arg(value_name = "VERB", value_parser = crate::value_parsers::parse_detectors_verb)]
    pub verb: Option<String>,
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Filter detectors by substring match (case-insensitive) against id,
    /// name, service, and keywords (e.g. `keyhog detectors --search aws`).
    ///
    /// The short `--help` line is intentionally count-free; the long `--help`
    /// (rendered via [`crate::args::command`]) injects the live embedded
    /// detector count so the cited corpus size can never drift from the
    /// detectors actually compiled into this binary.
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
    /// Output format for the detector listing. `text` (default) is the grouped,
    /// human-readable summary; `json` emits the structured array described under
    /// `--json`. This is the canonical flag — it matches `scan --format` so the
    /// two surfaces share one convention (CLI-01). Only `text`/`json` apply to a
    /// detector listing, so the format set is intentionally narrower than
    /// `scan`'s. Mutually exclusive with `--audit` / `--fix` (they emit their own
    /// structured formats) and with the legacy `--json` alias.
    #[arg(long, value_enum, conflicts_with_all = ["audit", "fix", "json"])]
    pub format: Option<DetectorFormat>,
    /// Emit the detector listing as a JSON array on stdout instead of the
    /// human-readable grouped summary. Pairs with `--search` for filtered
    /// programmatic discovery (CI gates, bench harnesses, IDE plugins).
    /// Mutually exclusive with `--audit` / `--fix` since those emit their
    /// own structured output formats. JSON shape mirrors the human surface:
    /// `[{ "id", "name", "service", "severity", "keywords": [..],
    /// "patterns": [{ "regex", "description", "group" }, ..],
    /// "companions": [{ "name", "regex", "within_lines", "required" }, ..],
    /// "verify": <bool> }, ..]`.
    ///
    /// Back-compat alias for `--format json`; prefer `--format` in new scripts.
    #[arg(long, conflicts_with_all = ["audit", "fix"])]
    pub json: bool,
}

/// Output formats valid for the `detectors` listing. Deliberately a narrow
/// pair (not the full [`OutputFormat`]): a detector listing has exactly one
/// structured form (JSON) and one human form (text); SARIF/JUnit/CSV/HTML are
/// findings-report shapes with no meaning here, so offering them would be an
/// incoherent surface. Shares the `--format` flag *name* with `scan` for
/// convention parity (CLI-01) without sharing the irrelevant variants.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DetectorFormat {
    Text,
    Json,
}

#[derive(Clone, Debug, ValueEnum)]
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

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
    Csv,
    GithubAnnotations,
    GitlabSast,
    Html,
    Junit,
}

#[derive(Clone, Debug, ValueEnum, PartialEq)]
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

/// Tri-state daemon routing policy for `scan --daemon[=auto|on|off]` (CLI-02).
///
/// Collapses what used to be a `--daemon` / `--no-daemon` boolean conflict pair
/// into a single flag with an explicit value, while preserving both legacy
/// spellings:
///   * `--daemon` (bare)  → [`Self::On`]   (back-compat: force the daemon route)
///   * `--daemon=auto`    → [`Self::Auto`] (the default when the flag is absent)
///   * `--daemon=off`     → [`Self::Off`]  (canonical form of `--no-daemon`)
///   * `--no-daemon`      → [`Self::Off`]  (retained compatibility alias)
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
pub enum DaemonMode {
    /// Use the daemon when a live socket is present, else scan in-process. This
    /// is the behavior when no `--daemon`/`--no-daemon` flag is given.
    Auto,
    /// Force the scan through a running `keyhog daemon`; fail if none is up.
    On,
    /// Force in-process scanning even when a daemon is running.
    Off,
}

/// Build the top-level clap [`clap::Command`] with the runtime-derived detector
/// count injected into the `detectors --search` long help.
///
/// The static `///` doc-comment on [`DetectorArgs::search`] is deliberately
/// count-free: clap doc-comments are compile-time string literals and cannot
/// embed the embedded-detector count without going stale (this is exactly the
/// drift AUD-coherence-1 documented — a hardcoded "894-strong" while the binary
/// loaded 899). Instead we render the long help here, at runtime, from
/// [`keyhog_core::embedded_detector_count`] — the *same* slice that backs
/// `keyhog detectors --json`. The cited corpus size therefore tracks the real
/// corpus exactly and can never undercount it.
///
/// Both `Cli::parse()`-equivalent paths and the `print_help` / completion paths
/// must route through this function so the dynamic help is always present.
pub fn command() -> clap::Command {
    use clap::CommandFactory;
    let count = keyhog_core::embedded_detector_count();
    let long_help = format!(
        "Filter detectors by substring match (case-insensitive) against id, \
         name, service, and keywords. Useful for finding detectors in the \
         {count}-strong corpus (e.g. `keyhog detectors --search aws`)."
    );
    Cli::command()
        .after_help(crate::exit_codes::HELP)
        .mut_subcommand("scan", |sub| sub.after_help(crate::exit_codes::HELP))
        .mut_subcommand("detectors", move |sub| {
            sub.mut_arg("search", move |arg| arg.long_help(long_help.clone()))
        })
}

/// Parse the CLI from `std::env::args_os`, using the dynamic [`command`] so the
/// rendered `--help` carries the live detector count and the full exit-code
/// contract. Mirrors `Cli::parse()` but with the runtime help wiring.
pub fn parse() -> Cli {
    use clap::FromArgMatches;
    let matches = command().get_matches();
    match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        // clap's own error rendering already exited for parse failures; this
        // branch only triggers on a derive/runtime mismatch, which is a bug.
        Err(err) => err.exit(),
    }
}
