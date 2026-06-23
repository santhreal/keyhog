//! Command-line argument parsing for KeyHog.

mod calibrate;
mod config;
mod daemon;
mod detectors;
mod diff;
mod explain;
mod hook;
mod limits;
mod maintenance;
mod scan;
mod scan_system;
mod watch;

pub use calibrate::CalibrateArgs;
pub use config::ConfigArgs;
pub use daemon::{DaemonAction, DaemonArgs};
pub use detectors::{DetectorArgs, DetectorFormat};
pub use diff::DiffArgs;
pub use explain::ExplainArgs;
pub use hook::HookCommand;
pub use limits::SourceLimitArgs;
pub use maintenance::{
    BackendArgs, CompletionArgs, DoctorArgs, RepairArgs, UninstallArgs, UpdateArgs,
};
pub use scan::{CliDedupScope, DaemonMode, OutputFormat, ScanArgs, SeverityFilter};
pub use scan_system::{parse_space_bytes, ScanSystemArgs};
pub use watch::WatchArgs;

use clap::Parser;

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
