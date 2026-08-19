//! KeyHog CLI: the user-facing binary that wires sources → scanner → verifier →
//! reporter together. This crate is the top of the dependency DAG (see
//! `docs/src/architecture.md`); it owns orchestration and I/O, never detection logic.
//!
//! # Module map (by responsibility)
//!
//! - **Entry**: `main.rs` (binary), this `lib.rs` (`cli_main()`: the scan
//!   lifecycle: parse → build config → drive sources → scan → report).
//! - **Argument surface**: [`args`] (clap definitions), [`value_parsers`]
//!   (typed flag parsing), [`path_validation`].
//! - **Subcommands**: [`subcommands`] (scan, triage, explain, detectors, diff,
//!   calibrate, completion, …); long-running modes in [`daemon`].
//! - **Scan orchestration**: [`orchestrator`] (fan-out, progress, deadlines),
//!   [`orchestrator_config`] (resolve `--fast`/`--deep`/`--precision`/flag
//!   overrides into one `ScannerConfig`), [`sources`] (CLI flags → input
//!   sources).
//! - **Output**: [`reporting`] (findings → text/JSON/SARIF), [`format`]
//!   (formatting helpers), and private terminal styling.
//! - **CI / baselines**: [`baseline`] (diff against a committed baseline),
//!   [`benchmark`].
//! - **Config & suppression**: [`config`] (`.keyhog.toml` discovery + merge),
//!   [`inline_suppression`], [`test_fixture_suppressions`].
//! - **Install / health**: [`installer`] (hook installer, `doctor`).

mod stable_hash;

use std::future::Future;
use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

pub(crate) static SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
/// Total source bytes consumed by the scanner. This is incremented at the
/// same production dispatch boundary as `SCANNED_CHUNKS`, so report metadata
/// cannot claim throughput from a separate approximation.
pub(crate) static SCANNED_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static TOTAL_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FINDINGS_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Chunks actually dispatched to GPU region presence (a subset of
/// [`SCANNED_CHUNKS`]; the remainder ran on the SIMD/CPU path). The orchestrator
/// bumps this in the coalesced GPU arm, the single place the GPU runs, so the
/// completion summary can state which backend selection used and why,
/// instead of the decision being buried at `tracing::debug!` (target
/// `keyhog::routing`). The optimized coalesced scan paths bypass `scan_inner`'s
/// per-chunk telemetry, so that snapshot under-counts on the production batch
/// path; this orchestrator-level counter is the authoritative routing signal.
pub(crate) static GPU_SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
/// Exact work replayed through the scalar recovery backend after an automatic GPU
/// route failed at runtime. These are successful coverage receipts, not source
/// errors: every counted chunk and byte completed through the recovery path.
pub(crate) static BACKEND_RECOVERY_EVENTS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static BACKEND_RECOVERED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static BACKEND_RECOVERED_BYTES: AtomicU64 = AtomicU64::new(0);
const MAX_BACKEND_RECOVERY_SUMMARY_ROWS: usize = 256;
const BACKEND_RECOVERY_OVERFLOW_REASON: &str =
    "additional distinct backend faults; inspect stderr and autoroute runtime health";
pub(crate) static BACKEND_RECOVERY_SUMMARIES: LazyLock<
    Mutex<Vec<keyhog_core::ScanBackendRecoverySummary>>,
> = LazyLock::new(|| Mutex::new(Vec::new()));
/// Number of source-read errors (a source yielded `Err` instead of a chunk).
/// Read at the end of `run()`: if a scan produced ZERO chunks AND a source
/// errored, the requested scan never actually ran (e.g. `--git-history` /
/// `--git-diff` on a non-repo, a bad ref, or an unreachable remote), so we
/// must NOT print "no findings, all clean" and exit 0, that would tell a CI
/// gate the tree is clean when nothing was scanned (KH-GAP-096). Same intent
/// as `SCANNER_PANICKED`, for the source-failure path.
pub(crate) static SOURCE_ERRORS: AtomicUsize = AtomicUsize::new(0);
/// Number of sources that failed *entirely*, produced ZERO chunks AND
/// errored. A source the user explicitly requested (e.g. `--github-org`,
/// `--git-diff`, `--url`) that yields nothing because the fetch failed means
/// that scan never ran, even if a co-requested filesystem source succeeded.
/// `run()` fails closed when this is non-zero and there are no findings, so a
/// failed remote scan is not masked by a clean local one (the more precise
/// successor to the `SOURCE_ERRORS && TOTAL_CHUNKS==0` global check). A
/// partial failure, a tree with some unreadable files that still produced
/// chunks (does NOT count: that source produced data).
pub(crate) static FAILED_SOURCES: AtomicUsize = AtomicUsize::new(0);
/// Number of times a requested incremental cache could not be persisted after
/// a scan. Findings are still reported, but a clean scan with a failed cache
/// write must not exit 0: the requested stateful speed path was not honored.
pub(crate) static INCREMENTAL_CACHE_ERRORS: AtomicUsize = AtomicUsize::new(0);
/// Number of times the autoroute decision cache could not be persisted after a
/// scan. Persisting a routing decision is NOT part of producing findings, so
/// this never discards them; it exists so `--autoroute-calibrate`, whose whole
/// requested operation was to persist that decision, cannot report success
/// when the write failed and leave every later automatic scan unroutable.
pub(crate) static AUTOROUTE_PERSIST_ERRORS: AtomicUsize = AtomicUsize::new(0);
/// Number of scan batches that reached the scanner and could not be routed to
/// any backend, so their bytes were never scanned. The findings gathered before
/// that point are still reported; this exists so the run cannot ALSO claim it
/// covered the input, which is the other half of never discarding results.
pub(crate) static BATCHES_NOT_ROUTED: AtomicUsize = AtomicUsize::new(0);
/// Set to `true` if the scanner thread panicked during `scan_sources`.
/// Read at the end of `run()` so a crashed scanner exits with a
/// non-zero code instead of silently reporting "no findings, all
/// clean" - that was the prior behavior and would mislead any
/// caller piping keyhog into CI as a gate.
pub(crate) static SCANNER_PANICKED: AtomicBool = AtomicBool::new(false);
static OPERATOR_PROFILE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Return whether an operator profile must emit signal-safe interruption identity.
pub fn operator_profile_active() -> bool {
    OPERATOR_PROFILE_ACTIVE.load(Ordering::Relaxed)
}

pub(crate) fn set_operator_profile_active(active: bool) {
    OPERATOR_PROFILE_ACTIVE.store(active, Ordering::Relaxed);
}

/// Operator-visible scan failure event recorded by the CLI orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanFailureEvent {
    SourceError,
    FailedSource,
    IncrementalCachePersistFailed,
    AutoroutePersistFailed,
    BatchNotRouted,
    ScannerPanicked,
}

/// Receipt proving an operator-visible scan failure passed through the typed
/// recorder instead of mutating the global counters directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "scan failure events must be recorded through the typed recorder so exit/status semantics remain honest"]
pub(crate) struct RecordedScanFailureEvent {
    event: ScanFailureEvent,
    previous: usize,
}

pub(crate) fn record_scan_failure(event: ScanFailureEvent) -> RecordedScanFailureEvent {
    let previous = match event {
        ScanFailureEvent::SourceError => SOURCE_ERRORS.fetch_add(1, Ordering::Relaxed),
        ScanFailureEvent::FailedSource => FAILED_SOURCES.fetch_add(1, Ordering::Relaxed),
        ScanFailureEvent::IncrementalCachePersistFailed => {
            INCREMENTAL_CACHE_ERRORS.fetch_add(1, Ordering::Relaxed)
        }
        ScanFailureEvent::AutoroutePersistFailed => {
            AUTOROUTE_PERSIST_ERRORS.fetch_add(1, Ordering::Relaxed)
        }
        ScanFailureEvent::BatchNotRouted => BATCHES_NOT_ROUTED.fetch_add(1, Ordering::Relaxed),
        ScanFailureEvent::ScannerPanicked => {
            let was_panicked = SCANNER_PANICKED.swap(true, Ordering::Relaxed);
            usize::from(was_panicked)
        }
    };
    RecordedScanFailureEvent { event, previous }
}

pub(crate) fn record_source_error() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::SourceError)
}

pub(crate) fn record_failed_source() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::FailedSource)
}

pub(crate) fn record_incremental_cache_persist_failed() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::IncrementalCachePersistFailed)
}

pub(crate) fn record_autoroute_persist_failed() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::AutoroutePersistFailed)
}

pub(crate) fn record_batch_not_routed() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::BatchNotRouted)
}

pub(crate) fn record_scanner_panic() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::ScannerPanicked)
}

/// Async-signal-safe snapshot of scan progress for the unix SIGINT handler:
/// `(scanned_chunks, total_chunks, findings)`. Each field is a single relaxed
/// atomic LOAD, no lock, no allocation, so this is safe to call from inside
/// a signal handler (see `main.rs`'s `handle_sigint`). The binary installs a
/// synchronous OS handler rather than a `tokio::signal::ctrl_c` task because
/// the CLI runs on a `current_thread` runtime: a long synchronous scan starves
/// the runtime, so the ctrl_c task would never register and SIGINT would fall
/// through to the default disposition (signal death, no exit-130 contract).
pub fn interrupt_counts() -> (usize, usize, usize) {
    (
        SCANNED_CHUNKS.load(Ordering::Relaxed),
        TOTAL_CHUNKS.load(Ordering::Relaxed),
        FINDINGS_COUNT.load(Ordering::Relaxed),
    )
}

pub(crate) fn reset_scan_runtime_state() {
    SCANNED_CHUNKS.store(0, Ordering::Relaxed);
    SCANNED_BYTES.store(0, Ordering::Relaxed);
    TOTAL_CHUNKS.store(0, Ordering::Relaxed);
    FINDINGS_COUNT.store(0, Ordering::Relaxed);
    GPU_SCANNED_CHUNKS.store(0, Ordering::Relaxed);
    BACKEND_RECOVERY_EVENTS.store(0, Ordering::Relaxed);
    BACKEND_RECOVERED_CHUNKS.store(0, Ordering::Relaxed);
    BACKEND_RECOVERED_BYTES.store(0, Ordering::Relaxed);
    match BACKEND_RECOVERY_SUMMARIES.lock() {
        Ok(mut summaries) => summaries.clear(),
        Err(poisoned) => {
            BACKEND_RECOVERY_SUMMARIES.clear_poison();
            poisoned.into_inner().clear();
        }
    }
    SOURCE_ERRORS.store(0, Ordering::Relaxed);
    FAILED_SOURCES.store(0, Ordering::Relaxed);
    INCREMENTAL_CACHE_ERRORS.store(0, Ordering::Relaxed);
    AUTOROUTE_PERSIST_ERRORS.store(0, Ordering::Relaxed);
    BATCHES_NOT_ROUTED.store(0, Ordering::Relaxed);
    SCANNER_PANICKED.store(false, Ordering::Relaxed);
    keyhog_scanner::telemetry::reset_for_scan();
}

pub(crate) fn record_backend_recovery_summary(summary: keyhog_core::ScanBackendRecoverySummary) {
    let mut summaries = match BACKEND_RECOVERY_SUMMARIES.lock() {
        Ok(summaries) => summaries,
        Err(poisoned) => {
            BACKEND_RECOVERY_SUMMARIES.clear_poison();
            poisoned.into_inner()
        }
    };
    if let Some(existing) = summaries.iter_mut().find(|existing| {
        existing.failed_backend == summary.failed_backend
            && existing.recovery_backend == summary.recovery_backend
            && existing.reason == summary.reason
            && existing.repair_command == summary.repair_command
    }) {
        existing.events = existing.events.saturating_add(summary.events);
        existing.recovered_ranges = existing
            .recovered_ranges
            .saturating_add(summary.recovered_ranges);
        existing.recovered_chunks = existing
            .recovered_chunks
            .saturating_add(summary.recovered_chunks);
        existing.recovered_bytes = existing
            .recovered_bytes
            .saturating_add(summary.recovered_bytes);
        return;
    }
    if summaries.len() + 1 < MAX_BACKEND_RECOVERY_SUMMARY_ROWS {
        summaries.push(summary);
        return;
    }
    if let Some(overflow) = summaries
        .iter_mut()
        .find(|existing| existing.reason == BACKEND_RECOVERY_OVERFLOW_REASON)
    {
        overflow.events = overflow.events.saturating_add(summary.events);
        overflow.recovered_ranges = overflow
            .recovered_ranges
            .saturating_add(summary.recovered_ranges);
        overflow.recovered_chunks = overflow
            .recovered_chunks
            .saturating_add(summary.recovered_chunks);
        overflow.recovered_bytes = overflow
            .recovered_bytes
            .saturating_add(summary.recovered_bytes);
    } else {
        summaries.push(keyhog_core::ScanBackendRecoverySummary {
            events: summary.events,
            failed_backend: "multiple".to_string(),
            recovery_backend: "multiple".to_string(),
            recovered_ranges: summary.recovered_ranges,
            recovered_chunks: summary.recovered_chunks,
            recovered_bytes: summary.recovered_bytes,
            reason: BACKEND_RECOVERY_OVERFLOW_REASON.to_string(),
            repair_command: summary.repair_command,
        });
    }
}

pub(crate) fn backend_recovery_summaries() -> Vec<keyhog_core::ScanBackendRecoverySummary> {
    match BACKEND_RECOVERY_SUMMARIES.lock() {
        Ok(summaries) => summaries.clone(),
        Err(poisoned) => {
            BACKEND_RECOVERY_SUMMARIES.clear_poison();
            poisoned.into_inner().clone()
        }
    }
}

pub(crate) fn write_banner<W: Write>(
    w: &mut W,
    colors: bool,
    detector_count: usize,
) -> std::io::Result<()> {
    let palette = style::terminal_palette(colors, false);
    if colors {
        writeln!(w, "    {}K E Y H O G{}", palette.bold, palette.reset)?;
        writeln!(w, "    {}───────────{}", palette.dim, palette.reset)?;
        writeln!(
            w,
            "    {}v{} · secret scanner · {} detectors{}",
            palette.green,
            env!("CARGO_PKG_VERSION"),
            detector_count,
            palette.reset
        )?;
        writeln!(w, "    {}by santh{}", palette.dim, palette.reset)?;
    } else {
        writeln!(w, "    K E Y H O G")?;
        writeln!(w, "    ───────────")?;
        writeln!(
            w,
            "    v{} · secret scanner · {} detectors",
            env!("CARGO_PKG_VERSION"),
            detector_count
        )?;
        writeln!(w, "    by santh")?;
    }
    writeln!(w)?;
    Ok(())
}

/// Run the CLI command selected by the current process arguments.
///
/// The binary target delegates here so internal CLI modules can stay
/// crate-private instead of becoming public API just to let `main.rs` dispatch
/// subcommands.
/// Terminate the process immediately with `code`, bypassing the normal teardown.
///
/// An autoroute hardware probe (`probe_hardware()` → `gpu_probe()`) leaks a
/// wgpu/Vulkan instance whose mesa driver worker thread stays alive for the
/// process lifetime. On a FAST error exit, an early setup error (missing path,
/// expired `.keyhogignore`) or a fail-closed `autoroute calibration required`
/// that thread has not finished initialising, and the ordinary shutdown
/// (unwind + libc `exit`/`atexit`) lets it run mid-teardown, where it SIGSEGVs
/// and turns a clean fail-closed exit code into a signal death (exit 139). A
/// security control that crashes instead of returning its documented code is
/// untrustworthy. `_exit` skips atexit and all thread teardown, so no driver
/// thread can run during shutdown; it also skips Rust's buffered-stdout flush,
/// so we flush both streams first. Only the FAST error/panic exits route here
/// a successful scan runs long enough for the driver to initialise and tear
/// down cleanly, so it keeps the normal `ExitCode` return.
fn exit_now(code: u8) -> ! {
    use std::io::Write;
    if let Err(error) = std::io::stdout().flush() {
        eprintln!("keyhog: stdout flush failed before immediate exit: {error}");
    }
    // LAW10: stderr is the final diagnostic channel; after this last flush
    // fails there is no truthful in-process surface left before `_exit`.
    let _ = std::io::stderr().flush();
    // SAFETY: `_exit` is async-signal-safe and terminates immediately. All
    // operator-visible output has already been produced and flushed above.
    #[cfg(unix)]
    unsafe {
        libc::_exit(i32::from(code))
    }
    #[cfg(not(unix))]
    std::process::exit(i32::from(code))
}

fn init_tracing() -> log_dedup::WarnDedupSummaryGuard {
    let log_ansi = {
        use std::io::IsTerminal;
        std::io::stderr().is_terminal() && !crate::style::no_color_requested()
    };
    let default_log_directive = match "keyhog=warn".parse() {
        Ok(directive) => directive,
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to parse built-in logging directive; enabling info-level logs"
            );
            tracing_subscriber::filter::Directive::from(tracing::Level::INFO)
        }
    };
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(log_ansi)
            .with_target(false);
        // Per-callsite WARN rate limit: a warning that fires thousands of times
        // in one scan shows its first few occurrences here; the remainder are
        // counted and reported once by the summary guard below (Law 10: hidden
        // from the stream, never from the operator).
        let fmt_layer =
            tracing_subscriber::Layer::with_filter(fmt_layer, log_dedup::WarnRepeatLimit);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(default_log_directive),
            )
            .with(fmt_layer)
            .init();
    }
    log_dedup::WarnDedupSummaryGuard
}

fn build_async_runtime() -> std::result::Result<tokio::runtime::Runtime, ExitCode> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Ok(runtime),
        Err(error) => {
            eprintln!(
                "error: failed to build the KeyHog async runtime: {error}. \
                 Fix: verify available process resources and retry."
            );
            Err(ExitCode::from(exit_codes::EXIT_SYSTEM_ERROR))
        }
    }
}

fn run_async<F, Fut>(f: F) -> ExitCode
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<ExitCode>>,
{
    let runtime = match build_async_runtime() {
        Ok(runtime) => runtime,
        Err(code) => return code,
    };

    #[cfg(not(unix))]
    runtime.spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            // LAW10: no recall impact (a failed signal hook only loses graceful Ctrl-C handling; scan/report exit semantics stay owned by the main task).
            let (scanned, total, findings) = interrupt_counts();
            eprintln!("\nScan interrupted. {scanned}/{total} files scanned. {findings} findings.");
            if operator_profile_active() {
                eprintln!(
                    "profile outcome status=failed coverage=cancelled errors=1 exit=130 interruption=ctrl-c"
                );
            }
            std::process::exit(i32::from(exit_codes::EXIT_INTERRUPTED));
        }
    });

    handle_command_outcome(runtime.block_on(f()))
}

fn handle_command_outcome(command_outcome: anyhow::Result<ExitCode>) -> ExitCode {
    match command_outcome {
        Ok(outcome) => {
            if SCANNER_PANICKED.load(Ordering::Relaxed) {
                // A scanner panic is a fast/abnormal exit that may have probed
                // the GPU; harden it against the Vulkan-teardown SIGSEGV.
                exit_now(exit_codes::EXIT_SCANNER_PANIC);
            } else {
                outcome
            }
        }
        Err(error) => {
            // {:#} prints the chained user-facing message instead of the {:?}
            // debug dump that includes backtrace internals.
            eprintln!("error: {error:#}");
            let code = cli_error_exit_code(&error);
            // Every scan-setup error routes here. When autoroute probed the GPU
            // before failing, the normal teardown would SIGSEGV in the leaked
            // Vulkan driver thread (exit 139) instead of returning `code`; exit
            // immediately so the fail-closed code always reaches the operator.
            exit_now(code);
        }
    }
}

pub fn cli_main() -> ExitCode {
    // Startup/dispatch setup (flag pre-scan) is synchronous.
    let startup_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    // `env::args()` panics on non-UTF-8 args (Linux allows raw-byte
    // paths). The version check only needs to recognize literal ASCII flags,
    // so inspect args_os(); non-UTF-8 args cannot equal these literals.
    //
    // `update` and `repair` deliberately own a value-taking `--version`.
    // Once either subcommand is selected, that long flag must reach clap and
    // the release SemVer validator rather than triggering this root fast path.
    // The root-only `-V` remains unambiguous in every position.
    let mut is_version = false;
    let mut full_version = false;
    let mut maintenance_subcommand_seen = false;
    for arg in std::env::args_os().skip(1) {
        if let Some(value) = arg.to_str() {
            maintenance_subcommand_seen |= value == "update" || value == "repair";
            is_version |= value == "-V" || (value == "--version" && !maintenance_subcommand_seen);
            full_version |= value == "--full";
        }
    }

    // Fast-path: root --version/-V skips runtime initialization, tracing
    // subscriber install, and Cli::parse(). The cold-start audit measured this
    // at ~25ms saved per invocation on top of the hardware-probe skip.
    if is_version {
        drop(startup_span);
        print_version_info(full_version);
        return ExitCode::SUCCESS;
    }

    drop(startup_span);
    let cli = args::parse();

    if cli.build_version {
        print_version_info(cli.full);
        return ExitCode::SUCCESS;
    }

    match cli.command {
        Some(args::Command::Completion(args)) => {
            subcommands::completion::run(args);
            ExitCode::SUCCESS
        }
        None => {
            let mut cmd = args::command();
            let _ = cmd.print_help(); // LAW10: unused-binding marker; no runtime effect, not a fallback
            ExitCode::SUCCESS
        }
        Some(command) => dispatch_command(command),
    }
}

fn dispatch_command(command: args::Command) -> ExitCode {
    let _warn_dedup_summary = init_tracing();

    match command {
        args::Command::Scan(args) => {
            interrupt::install();
            let profile_requested = args.profile;
            set_operator_profile_active(profile_requested);
            run_async(|| async {
                let outcome = subcommands::scan::run(*args).await;
                if profile_requested {
                    set_operator_profile_active(false);
                }
                outcome
            })
        }
        args::Command::Config(args) => handle_command_outcome(subcommands::config::run(*args)),
        args::Command::CompileExecutionPacks(args) => handle_command_outcome(
            subcommands::compile_execution_packs::run(args).map(|()| ExitCode::SUCCESS),
        ),
        args::Command::ActionReport(args) => match args.command {
            args::ActionReportCommand::Verify(args) => {
                handle_command_outcome(action_report::verify(args))
            }
        },
        args::Command::Hook { command } => handle_command_outcome(subcommands::hook::run(command)),
        args::Command::Detectors(args) => handle_command_outcome(subcommands::detectors::run(args)),
        args::Command::Explain(args) => {
            handle_command_outcome(subcommands::explain::run(args).map(|()| ExitCode::SUCCESS))
        }
        args::Command::Diff(args) => run_async(|| subcommands::diff::run(args)),
        args::Command::Triage(args) => handle_command_outcome(subcommands::triage::run(args)),
        args::Command::Calibrate(args) => {
            handle_command_outcome(subcommands::calibrate::run(args).map(|()| ExitCode::SUCCESS))
        }
        args::Command::CalibrateAutoroute(args) => {
            handle_command_outcome(subcommands::calibrate_autoroute::run(args))
        }
        args::Command::Watch(args) => {
            handle_command_outcome(subcommands::watch::run(args).map(|()| ExitCode::SUCCESS))
        }
        args::Command::Completion(args) => {
            subcommands::completion::run(args);
            ExitCode::SUCCESS
        }
        args::Command::Backend(args) => handle_command_outcome(subcommands::backend::run(args)),
        args::Command::Doctor(args) => handle_command_outcome(subcommands::doctor::run(args)),
        args::Command::BloomDiagnostic(args) => handle_command_outcome(bloom_diagnostic::run(args)),
        args::Command::Update(args) => run_async(|| subcommands::update::run(args)),
        args::Command::Repair(args) => run_async(|| subcommands::repair::run(args)),
        args::Command::Uninstall(args) => handle_command_outcome(subcommands::uninstall::run(args)),
        args::Command::ScanSystem(args) => {
            handle_command_outcome(subcommands::scan_system::run(args))
        }
        #[cfg(unix)]
        args::Command::Daemon(args) => run_async(|| subcommands::daemon::run(args)),
        #[cfg(not(unix))]
        args::Command::Daemon(_args) => handle_command_outcome(Err(anyhow::anyhow!(
            "`keyhog daemon` is a unix-only command (it serves scans over a \
             Unix-domain socket). On Windows, run scans in-process: \
             `keyhog scan <path>`. No Windows daemon transport ships."
        ))),
        #[cfg(unix)]
        args::Command::Guard(args) => run_async(|| subcommands::guard::run(args)),
        #[cfg(not(unix))]
        args::Command::Guard(_args) => handle_command_outcome(Err(anyhow::anyhow!(
            "`keyhog guard` requires the Unix daemon transport. On Windows, \
             run `keyhog scan <path>` in process; no guard daemon ships."
        ))),
    }
}

fn cli_error_exit_code(error: &anyhow::Error) -> u8 {
    if SCANNER_PANICKED.load(Ordering::SeqCst) {
        exit_codes::EXIT_SCANNER_PANIC
    } else if error
        .chain()
        .any(|cause| cause.is::<orchestrator::GpuUnavailableError>())
    {
        exit_codes::EXIT_REQUIRE_GPU_UNMET
    } else if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<keyhog_scanner::ScanError>(),
            Some(keyhog_scanner::ScanError::Gpu(_))
        )
    }) {
        exit_codes::EXIT_REQUIRE_GPU_UNMET
    } else if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<keyhog_scanner::ScanError>(),
            Some(keyhog_scanner::ScanError::Simd(_))
        )
    }) {
        exit_codes::EXIT_SYSTEM_ERROR
    } else if is_daemon_service_failure(error) {
        exit_codes::EXIT_SYSTEM_ERROR
    } else if error.chain().any(is_user_io_error) {
        exit_codes::EXIT_USER_ERROR
    } else if error.chain().any(|cause| cause.is::<std::io::Error>()) {
        exit_codes::EXIT_SYSTEM_ERROR
    } else {
        exit_codes::EXIT_USER_ERROR
    }
}

#[cfg(unix)]
fn is_daemon_service_failure(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<daemon::server::DaemonServiceFailure>())
}

#[cfg(not(unix))]
fn is_daemon_service_failure(_error: &anyhow::Error) -> bool {
    false
}

fn is_user_io_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let Some(io) = error.downcast_ref::<std::io::Error>() else {
        return false;
    };
    matches!(
        io.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::InvalidData
            | std::io::ErrorKind::AlreadyExists
    )
}

fn print_version_info(full: bool) {
    println!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
    println!("Commit: {}", keyhog_core::git_hash());
    println!(
        "Detector Set: {} ({})",
        keyhog_core::embedded_detector_count(),
        keyhog_core::detector_digest()
    );
    println!(
        "Build Target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!(
        "ML Model Version: {}",
        keyhog_scanner::ml_scorer::model_version()
    );
    println!(
        "ML Model Card: {}",
        keyhog_scanner::ml_scorer::model_card_summary()
    );
    if !full {
        return;
    }
    let hw = keyhog_scanner::hw_probe::probe_hardware();
    if hw.gpu_available {
        println!(
            "GPU Acceleration: {}{}",
            hw.gpu_name.as_deref().unwrap_or("available"), // LAW10: absent name/label => display default; reporting-only, recall-safe
            hw.gpu_vram_mb
                .map(|mb| {
                    if mb >= 1024 {
                        format!(" (max buffer {} GB)", mb / 1024)
                    } else {
                        format!(" (max buffer {mb} MB)")
                    }
                })
                .unwrap_or_default() // LAW10: missing/non-string field => empty/placeholder; recall-safe
        );
    } else {
        println!("GPU Acceleration: not detected");
    }
    if hw.hyperscan_available {
        println!("SIMD Regex:       vectorscan/hyperscan (active)");
    } else if hw.has_avx512 || hw.has_avx2 || hw.has_neon {
        let simd = if hw.has_avx512 {
            "AVX-512"
        } else if hw.has_avx2 {
            "AVX2"
        } else {
            "NEON"
        };
        println!("SIMD Regex:       {simd} (no Hyperscan)");
    } else {
        println!("SIMD Regex:       not available");
    }
    if hw.io_uring_available {
        println!("io_uring:         available");
    }
}

pub(crate) mod action_report;
pub mod args;
pub(crate) mod atomic_file;
pub(crate) mod autoroute_cache_path;
pub(crate) mod baseline;
pub(crate) mod benchmark;
pub(crate) mod bloom_diagnostic;
pub(crate) mod config;
pub mod execution_pack_install;
pub mod exit_codes;
pub(crate) mod format;
pub(crate) mod installer;
pub(crate) mod interrupt;
pub(crate) mod log_dedup;
pub(crate) mod matcher_cache_path;
pub(crate) mod runtime_preflight;
// Daemon uses Unix-domain sockets (`tokio::net::UnixListener` and
// `std::os::unix::net`). Windows lacks both surfaces in the form
// this server uses, and named pipes have a totally different
// auth model; we don't ship a Windows IPC story yet. Gate the
// module so the rest of the CLI still builds on Windows - the
// `daemon` subcommand and the `--daemon` flag emit a clear
// "unix-only" error there (see `main.rs` and `subcommands/scan.rs`).
#[cfg(test)]
mod cli_reference;
#[cfg(unix)]
pub mod daemon;
pub(crate) mod inline_suppression;
pub(crate) mod orchestrator;
pub(crate) mod orchestrator_config;
pub(crate) mod path_validation;
pub(crate) mod reporting;
pub(crate) mod skip_dirs;
pub(crate) mod sources;
mod style;
pub(crate) mod subcommands;
pub(crate) mod test_fixture_suppressions;
#[cfg(test)]
extern crate self as keyhog;
#[cfg(test)]
#[path = "../tests/unit/docs_help_coherence.rs"]
mod docs_help_coherence;
pub mod testing;

/// Profiling-instrumentation seams: thin re-exports that let the standalone
/// profiling integration suite drive crate-internal profiled functions without
/// spawning the binary. Same pattern as [`testing`]; production behavior is
/// unchanged (each wrapper forwards to the real profiled path).
#[doc(hidden)]
pub mod profiling_test_seams {
    /// Load the declarative `.keyhogignore.toml` rule suppressor rooted at
    /// `scan_path` through the profiled loader.
    pub fn load_rule_suppressor(
        scan_path: Option<&std::path::Path>,
    ) -> anyhow::Result<keyhog_core::RuleSuppressor> {
        crate::orchestrator::load_rule_suppressor(scan_path)
    }

    /// Evaluate `matches` against the declarative rule suppressor through the
    /// same profiled filter the watch command applies after scanning.
    pub fn filter_rule_suppressed(
        suppressor: &keyhog_core::RuleSuppressor,
        matches: Vec<keyhog_core::RawMatch>,
    ) -> Vec<keyhog_core::RawMatch> {
        crate::subcommands::watch::filter_rule_suppressed(suppressor, matches)
    }

    /// Load the detector corpus from `path` (or the embedded corpus) through
    /// the profiled loader the detectors command surfaces share.
    pub fn load_detector_corpus(
        path: &std::path::Path,
    ) -> anyhow::Result<Vec<keyhog_core::DetectorSpec>> {
        crate::subcommands::detectors::load_detector_corpus(path)
    }

    /// Run the doctor host hardware probe collection step.
    pub fn doctor_host_probe() -> &'static keyhog_scanner::hw_probe::HardwareCaps {
        crate::subcommands::doctor::collect_host_probe()
    }
}
pub(crate) mod value_parsers;
