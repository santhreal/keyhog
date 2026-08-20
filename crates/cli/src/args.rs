//! Command-line argument parsing for KeyHog.

mod action_report;
mod calibrate;
mod calibrate_autoroute;
mod config;
mod daemon;
mod detectors;
mod diff;
mod explain;
mod guard;
mod hook;
mod limits;
mod maintenance;
mod scan;
mod scan_system;
mod triage;
mod watch;

pub use action_report::{
    ActionReportArgs, ActionReportCommand, ActionReportFormat, ActionReportVerifyArgs,
};
pub use calibrate::CalibrateArgs;
pub use calibrate_autoroute::{AutorouteCalibrationPolicy, CalibrateAutorouteArgs};
pub use config::ConfigArgs;
pub use daemon::{DaemonAction, DaemonArgs};
pub use detectors::{DetectorArgs, DetectorFormat};
pub use diff::DiffArgs;
pub use explain::ExplainArgs;
pub use guard::{GuardAction, GuardArgs};
pub use hook::HookCommand;
pub use limits::SourceLimitArgs;
pub use maintenance::{
    BackendArgs, CompileExecutionPacksArgs, CompileGpuLiteralsArgs, CompletionArgs, DoctorArgs,
    InstallArgs, UninstallArgs,
};
pub use scan::{
    CliDedupScope, DaemonMode, DetectorMode, EvidencePolicy, OutputFormat, ScanArgs, SeverityFilter,
};
pub use scan_system::{parse_space_bytes, ScanSystemArgs};
pub use triage::TriageArgs;
pub use watch::WatchArgs;
pub use watch::DEFAULT_WATCH_MAX_CONSECUTIVE_SCAN_FAILURES;

use clap::{FromArgMatches, Parser};
use std::ffi::OsString;

/// Measure the production Bloom gate on a benchmark-owned corpus fixture.
#[derive(clap::Args, Debug)]
pub struct BloomDiagnosticArgs {
    /// JSON fixture naming the corpus and its exact negative input files
    #[arg(long, value_name = "PATH")]
    pub fixture: std::path::PathBuf,

    /// Root directory used to resolve fixture-relative corpus paths
    #[arg(long, value_name = "PATH")]
    pub corpus_root: std::path::PathBuf,
}

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
    #[arg(id = "build_version", short = 'V', long = "version")]
    pub build_version: bool,

    /// Include the hardware probe in version output. This initializes GPU/SIMD
    /// discovery, so it is explicit instead of controlled by ambient env.
    #[arg(long, requires = "build_version")]
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

    /// Verify a report against KeyHog's internal composite-Action receipt
    #[command(verbatim_doc_comment, hide = true)]
    ActionReport(ActionReportArgs),
    /// Compile and transactionally publish one host execution-pack generation
    #[command(verbatim_doc_comment, hide = true)]
    CompileExecutionPacks(CompileExecutionPacksArgs),

    /// Compile the shipped detector corpus into host GPU literal matcher artifacts
    #[command(verbatim_doc_comment, hide = true)]
    CompileGpuLiterals(CompileGpuLiteralsArgs),

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

    /// Diff baselines or artifacts: show NEW / REMOVED / UNCHANGED
    #[command(verbatim_doc_comment)]
    Diff(DiffArgs),

    /// Import redacted findings into scoped suppression and pattern feedback
    #[command(verbatim_doc_comment)]
    Triage(TriageArgs),

    /// Show or update per-detector Bayesian calibration counters
    #[command(verbatim_doc_comment)]
    Calibrate(CalibrateArgs),

    /// Prime autoroute: calibrate every scan-policy preset × workload bucket.
    ///
    /// Overlapping timings resolve to the lowest-complexity non-inferior route.
    /// Unusable or cross-point-inconsistent evidence exits 2 without publication.
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

    /// Measure Bloom rejection and prove enabled-versus-bypassed finding parity
    #[command(verbatim_doc_comment)]
    BloomDiagnostic(BloomDiagnosticArgs),

    /// Compile, authenticate, calibrate, and install execution packs for the local host
    #[command(verbatim_doc_comment)]
    Install(InstallArgs),

    /// Uninstall keyhog: remove the binary (dry run unless --yes)
    #[command(verbatim_doc_comment)]
    Uninstall(UninstallArgs),

    /// Recursive system-wide scan: every mounted drive, every git history
    #[command(verbatim_doc_comment)]
    ScanSystem(ScanSystemArgs),

    /// Manage the long-lived `keyhog daemon` (start, stop, status)
    #[command(verbatim_doc_comment)]
    Daemon(DaemonArgs),

    /// Manage the perpetual repository and filesystem guard
    #[command(verbatim_doc_comment)]
    Guard(GuardArgs),
}

/// Build the top-level clap [`clap::Command`] with the runtime-derived detector
/// count injected into the `detectors --search` long help.
///
/// The static `///` doc-comment on [`DetectorArgs::search`] is deliberately
/// count-free: clap doc-comments are compile-time string literals and cannot
/// embed the embedded-detector count without going stale (this is exactly the
/// drift AUD-coherence-1 documented, a hardcoded "894-strong" while the binary
/// loaded 899). Instead we render the long help here, at runtime, from
/// [`keyhog_core::embedded_detector_count`], the *same* slice that backs
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
    let _parse_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
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
    let _parse_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    let matches = command().try_get_matches_from(args)?;
    cli_from_matches(&matches)
}

fn cli_from_matches(matches: &clap::ArgMatches) -> Result<Cli, clap::Error> {
    let mut cli = Cli::from_arg_matches(matches)?;
    mark_cli_value_sources(&mut cli, matches);
    Ok(cli)
}

fn is_gpu_backend_str(backend: &str) -> bool {
    let b = backend.trim().to_ascii_lowercase();
    b == "gpu" || b.starts_with("gpu-") || b.starts_with("gpu_")
}

pub(crate) fn validate_backend_and_gpu_flags(
    backend: Option<&str>,
    no_gpu: bool,
    require_gpu: bool,
) -> Result<(), clap::Error> {
    if no_gpu && require_gpu {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "error: the argument '--no-gpu' cannot be used with '--require-gpu'\n",
        ));
    }
    if let Some(b) = backend {
        let is_gpu = is_gpu_backend_str(b);
        if no_gpu && is_gpu {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                format!("error: the argument '--no-gpu' cannot be used with '--backend {b}'\n"),
            ));
        }
        let b_normalized = b.trim().to_ascii_lowercase();
        if require_gpu && !is_gpu && b_normalized != "auto" {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                format!(
                    "error: the argument '--require-gpu' cannot be used with '--backend {b}'\n"
                ),
            ));
        }
        let b_lower = b.to_ascii_lowercase();
        if b_lower.starts_with("gpu-metal") && !cfg!(target_os = "macos") {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!(
                    "error: backend '{b}' is only supported on macOS (running on {})\n",
                    std::env::consts::OS
                ),
            ));
        }
        if b_lower.starts_with("gpu-cuda") && cfg!(target_os = "macos") {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("error: backend '{b}' is not supported on macOS\n"),
            ));
        }
    }
    Ok(())
}

fn validate_cli_args(cli: &Cli) -> Result<(), clap::Error> {
    match &cli.command {
        Some(Command::Scan(args)) => {
            validate_backend_and_gpu_flags(args.backend.as_deref(), args.no_gpu, args.require_gpu)?;
            if let Some(overlap) = args.window_overlap {
                if !(1024..=16 * 1024 * 1024).contains(&overlap) {
                    return Err(clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("error: --window-overlap must be between 1KB and 16MB (got {overlap} bytes)\n"),
                    ));
                }
            }
        }
        Some(Command::Config(args)) => {
            validate_backend_and_gpu_flags(
                args.scan.backend.as_deref(),
                args.scan.no_gpu,
                args.scan.require_gpu,
            )?;
            if let Some(overlap) = args.scan.window_overlap {
                if !(1024..=16 * 1024 * 1024).contains(&overlap) {
                    return Err(clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("error: --window-overlap must be between 1KB and 16MB (got {overlap} bytes)\n"),
                    ));
                }
            }
        }
        Some(Command::Watch(args)) => {
            validate_backend_and_gpu_flags(args.backend.as_deref(), false, false)?;
        }
        Some(Command::Backend(args)) => {
            validate_backend_and_gpu_flags(None, args.no_gpu, args.require_gpu)?;
        }
        _ => {}
    }
    Ok(())
}

fn mark_cli_value_sources(cli: &mut Cli, matches: &clap::ArgMatches) {
    use clap::parser::ValueSource;

    match (&mut cli.command, matches.subcommand()) {
        (Some(Command::Scan(args)), Some(("scan", subcommand_matches))) => {
            args.mark_cli_value_sources(subcommand_matches);
        }
        (Some(Command::Config(args)), Some(("config", subcommand_matches))) => {
            args.scan.mark_cli_value_sources(subcommand_matches);
        }
        (Some(Command::Detectors(args)), Some(("detectors", subcommand_matches))) => {
            args.detectors_cli_explicit =
                subcommand_matches.value_source("detectors") == Some(ValueSource::CommandLine);
        }
        (Some(Command::Explain(args)), Some(("explain", subcommand_matches))) => {
            args.detectors_cli_explicit =
                subcommand_matches.value_source("detectors") == Some(ValueSource::CommandLine);
        }
        (Some(Command::Watch(args)), Some(("watch", subcommand_matches))) => {
            args.detectors_cli_explicit =
                subcommand_matches.value_source("detectors") == Some(ValueSource::CommandLine);
        }
        (Some(Command::ScanSystem(args)), Some(("scan-system", subcommand_matches))) => {
            args.detectors_cli_explicit =
                subcommand_matches.value_source("detectors") == Some(ValueSource::CommandLine);
        }
        (Some(Command::Daemon(DaemonArgs { action })), Some(("daemon", daemon_matches))) => {
            if let (
                DaemonAction::Start {
                    detectors_cli_explicit,
                    ..
                },
                Some(("start", start_matches)),
            ) = (action, daemon_matches.subcommand())
            {
                *detectors_cli_explicit =
                    start_matches.value_source("detectors") == Some(ValueSource::CommandLine);
            }
        }
        _ => {}
    }
}
