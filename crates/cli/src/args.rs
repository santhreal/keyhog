//! Command-line argument parsing for KeyHog.

mod calibrate;
mod calibrate_autoroute;
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
pub use calibrate_autoroute::CalibrateAutorouteArgs;
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

use clap::{FromArgMatches, Parser};
use std::ffi::OsString;

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

    /// Prime autoroute: calibrate every scan-policy preset × workload bucket
    #[command(verbatim_doc_comment)]
    CalibrateAutoroute(CalibrateAutorouteArgs),

    /// Watch one or more directories and scan files as they change
    #[command(verbatim_doc_comment)]
    Watch(WatchArgs),

    /// Print shell completion script (bash, zsh, fish, powershell, elvish)
    #[command(verbatim_doc_comment)]
    Completion(CompletionArgs),

    /// Inspect hardware, diagnostic routing heuristics, or autoroute evidence
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
/// `keyhog detectors --format json`. The cited corpus size therefore tracks the real
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
        .after_help(crate::exit_codes::help())
        .mut_subcommand("scan", |sub| sub.after_help(crate::exit_codes::help()))
        .mut_subcommand("detectors", move |sub| {
            sub.mut_arg("search", move |arg| arg.long_help(long_help.clone()))
        })
}

/// Parse the CLI from `std::env::args_os`, using the dynamic [`command`] so the
/// rendered `--help` carries the live detector count and the full exit-code
/// contract. Mirrors `Cli::parse()` but with the runtime help wiring.
pub fn parse() -> Cli {
    let matches = command().get_matches();
    match cli_from_matches(&matches) {
        Ok(cli) => cli,
        // LAW10: clap has already rendered and exited for user parse errors; a
        // remaining `FromArgMatches` error means the derive shape and runtime
        // command builder disagree, so exiting with clap's diagnostic is loud.
        Err(err) => err.exit(),
    }
}

/// Parse a top-level CLI argument vector while preserving clap value-source
/// metadata used by the config merge. This is the production parse path with
/// explicit input, kept public so integration tests prove the same behavior the
/// binary uses instead of constructing partially marked `ScanArgs` by hand.
pub fn try_parse_from<I, T>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = command().try_get_matches_from(args)?;
    cli_from_matches(&matches)
}

fn cli_from_matches(matches: &clap::ArgMatches) -> Result<Cli, clap::Error> {
    let mut cli = Cli::from_arg_matches(matches)?;
    mark_scan_value_sources(&mut cli, matches);
    Ok(cli)
}

fn mark_scan_value_sources(cli: &mut Cli, matches: &clap::ArgMatches) {
    match (&mut cli.command, matches.subcommand()) {
        (Some(Command::Scan(args)), Some(("scan", subcommand_matches))) => {
            args.mark_cli_value_sources(subcommand_matches);
        }
        (Some(Command::Config(args)), Some(("config", subcommand_matches))) => {
            args.scan.mark_cli_value_sources(subcommand_matches);
        }
        _ => {}
    }
}
