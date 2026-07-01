//! KeyHog CLI: the user-facing binary that wires sources → scanner → verifier →
//! reporter together. This crate is the top of the dependency DAG (see
//! `docs/ARCHITECTURE.md`); it owns orchestration and I/O, never detection logic.
//!
//! # Module map (by responsibility)
//!
//! - **Entry** — `main.rs` (binary), this `lib.rs` (`run()` — the scan
//!   lifecycle: parse → build config → drive sources → scan → report).
//! - **Argument surface** — [`args`] (clap definitions), [`value_parsers`]
//!   (typed flag parsing), [`path_validation`].
//! - **Subcommands** — [`subcommands`] (scan, explain, detectors, diff,
//!   calibrate, completion, …); long-running modes in [`daemon`].
//! - **Scan orchestration** — [`orchestrator`] (fan-out, progress, deadlines),
//!   [`orchestrator_config`] (resolve `--fast`/`--deep`/`--precision`/flag
//!   overrides into one `ScannerConfig`), [`sources`] (CLI flags → input
//!   sources).
//! - **Output** — [`reporting`] (findings → text/JSON/SARIF), [`format`]
//!   (formatting helpers), and private terminal styling.
//! - **CI / baselines** — [`baseline`] (diff against a committed baseline),
//!   [`benchmark`].
//! - **Config & suppression** — [`config`] (`.keyhog.toml` discovery + merge),
//!   [`inline_suppression`], [`test_fixture_suppressions`].
//! - **Install / health** — [`installer`] (hook installer, `doctor`).

mod stable_hash;

use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(crate) static SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static TOTAL_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FINDINGS_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Chunks actually dispatched to GPU region presence (a subset of
/// [`SCANNED_CHUNKS`]; the remainder ran on the SIMD/CPU path). The orchestrator
/// bumps this in the coalesced GPU arm — the single place the GPU runs — so the
/// completion summary can state which backend selection used and why,
/// instead of the decision being buried at `tracing::debug!` (target
/// `keyhog::routing`). The optimized coalesced scan paths bypass `scan_inner`'s
/// per-chunk telemetry, so that snapshot under-counts on the production batch
/// path; this orchestrator-level counter is the authoritative routing signal.
pub(crate) static GPU_SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
/// Number of source-read errors (a source yielded `Err` instead of a chunk).
/// Read at the end of `run()`: if a scan produced ZERO chunks AND a source
/// errored, the requested scan never actually ran (e.g. `--git-history` /
/// `--git-diff` on a non-repo, a bad ref, or an unreachable remote), so we
/// must NOT print "no findings, all clean" and exit 0 — that would tell a CI
/// gate the tree is clean when nothing was scanned (KH-GAP-096). Same intent
/// as `SCANNER_PANICKED`, for the source-failure path.
pub(crate) static SOURCE_ERRORS: AtomicUsize = AtomicUsize::new(0);
/// Number of sources that failed *entirely* — produced ZERO chunks AND
/// errored. A source the user explicitly requested (e.g. `--github-org`,
/// `--git-diff`, `--url`) that yields nothing because the fetch failed means
/// that scan never ran, even if a co-requested filesystem source succeeded.
/// `run()` fails closed when this is non-zero and there are no findings, so a
/// failed remote scan is not masked by a clean local one (the more precise
/// successor to the `SOURCE_ERRORS && TOTAL_CHUNKS==0` global check). A
/// partial failure — a tree with some unreadable files that still produced
/// chunks — does NOT count: that source produced data.
pub(crate) static FAILED_SOURCES: AtomicUsize = AtomicUsize::new(0);
/// Number of times a requested incremental cache could not be persisted after
/// a scan. Findings are still reported, but a clean scan with a failed cache
/// write must not exit 0: the requested stateful speed path was not honored.
pub(crate) static INCREMENTAL_CACHE_ERRORS: AtomicUsize = AtomicUsize::new(0);
/// Set to `true` if the scanner thread panicked during `scan_sources`.
/// Read at the end of `run()` so a crashed scanner exits with a
/// non-zero code instead of silently reporting "no findings, all
/// clean" - that was the prior behavior and would mislead any
/// caller piping keyhog into CI as a gate.
pub(crate) static SCANNER_PANICKED: AtomicBool = AtomicBool::new(false);

/// Operator-visible scan failure event recorded by the CLI orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanFailureEvent {
    SourceError,
    FailedSource,
    IncrementalCachePersistFailed,
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

pub(crate) fn record_scanner_panic() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::ScannerPanicked)
}

/// Async-signal-safe snapshot of scan progress for the unix SIGINT handler:
/// `(scanned_chunks, total_chunks, findings)`. Each field is a single relaxed
/// atomic LOAD — no lock, no allocation — so this is safe to call from inside
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
    TOTAL_CHUNKS.store(0, Ordering::Relaxed);
    FINDINGS_COUNT.store(0, Ordering::Relaxed);
    GPU_SCANNED_CHUNKS.store(0, Ordering::Relaxed);
    SOURCE_ERRORS.store(0, Ordering::Relaxed);
    FAILED_SOURCES.store(0, Ordering::Relaxed);
    INCREMENTAL_CACHE_ERRORS.store(0, Ordering::Relaxed);
    SCANNER_PANICKED.store(false, Ordering::Relaxed);
    keyhog_scanner::telemetry::reset_for_scan();
}

pub(crate) fn write_banner<W: Write>(
    w: &mut W,
    colors: bool,
    ascii: bool,
    detector_count: usize,
) -> std::io::Result<()> {
    if ascii {
        let banner = r"
    ⠀⣠⣶⣿⣿⣿⣿⣶⣄⠀
    ⠀⣿⣿⠉⠛⠛⠉⣿⣿⠀
    ⠀⢿⣿⣶⣿⣿⣶⣿⡿⠀
    ⠀⠀⠙⣿⣦⣴⣿⠋⠀⠀
    ⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀
    ⠀⠀⠀⣼⣿⣿⣧⠀⠀⠀
";
        let palette = style::terminal_palette(colors, false);
        writeln!(w, "{}{}{}", palette.yellow, banner, palette.reset)?;
    }

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
/// process lifetime. On a FAST error exit — an early setup error (missing path,
/// expired `.keyhogignore`) or a fail-closed `autoroute calibration required` —
/// that thread has not finished initialising, and the ordinary shutdown
/// (unwind + libc `exit`/`atexit`) lets it run mid-teardown, where it SIGSEGVs
/// and turns a clean fail-closed exit code into a signal death (exit 139). A
/// security control that crashes instead of returning its documented code is
/// untrustworthy. `_exit` skips atexit and all thread teardown, so no driver
/// thread can run during shutdown; it also skips Rust's buffered-stdout flush,
/// so we flush both streams first. Only the FAST error/panic exits route here —
/// a successful scan runs long enough for the driver to initialise and tear
/// down cleanly, so it keeps the normal `ExitCode` return.
fn exit_now(code: u8) -> ! {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // SAFETY: `_exit` is async-signal-safe and terminates immediately. All
    // operator-visible output has already been produced and flushed above.
    unsafe { libc::_exit(i32::from(code)) }
}

pub async fn cli_main() -> ExitCode {
    // `env::args()` panics on non-UTF-8 args (Linux allows raw-byte
    // paths). The version check only needs to recognize literal ASCII
    // flags, so iterate args_os() and lossy-compare; non-UTF-8 args
    // could not possibly be the `-V` / `--version` literal.
    // kimi-dogfood-2 #134.
    let mut is_version = false;
    let mut full_version = false;
    for arg in std::env::args_os() {
        if let Some(s) = arg.to_str() {
            is_version |= s == "-V" || s == "--version";
            full_version |= s == "--full";
        }
    }

    // Fast-path: --version skips Ctrl-C handler spawn, tracing subscriber
    // install, and Cli::parse(). The cold-start audit measured this at ~25ms
    // saved per invocation on top of the hardware-probe skip.
    if is_version {
        print_version_info(full_version);
        return ExitCode::SUCCESS;
    }

    // Unix installs a synchronous OS SIGINT handler in `main()` (before the
    // runtime starts) instead — a `tokio::signal::ctrl_c` task never registers
    // on the `current_thread` runtime once a synchronous scan is in flight, so
    // it cannot honor the exit-130 contract. Non-unix (Windows) has no such
    // synchronous handler path here, so keep the async ctrl_c task there.
    #[cfg(not(unix))]
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            // LAW10: no recall impact — a failed signal hook only loses graceful Ctrl-C handling; scan/report exit semantics stay owned by the main task.
            let (scanned, total, findings) = interrupt_counts();
            eprintln!("\nScan interrupted. {scanned}/{total} files scanned. {findings} findings.");
            std::process::exit(i32::from(exit_codes::EXIT_INTERRUPTED));
        }
    });

    // Color the log stream only when stderr is a TTY and NO_COLOR is unset;
    // otherwise pipes, files, and CI logs would receive raw ANSI escape
    // sequences.
    let log_ansi = {
        use std::io::IsTerminal;
        std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(log_ansi)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(default_log_directive),
        )
        .with_target(false)
        .init();

    let cli = args::parse();

    if cli.version {
        print_version_info(cli.full);
        return ExitCode::SUCCESS;
    }

    let command_outcome = match cli.command {
        Some(args::Command::Scan(args)) => subcommands::scan::run(*args).await,
        Some(args::Command::Config(args)) => subcommands::config::run(*args),
        Some(args::Command::Hook { command }) => subcommands::hook::run(command),
        Some(args::Command::Detectors(args)) => subcommands::detectors::run(args),
        Some(args::Command::Explain(args)) => {
            subcommands::explain::run(args).map(|()| ExitCode::SUCCESS)
        }
        Some(args::Command::Diff(args)) => subcommands::diff::run(args),
        Some(args::Command::Calibrate(args)) => {
            subcommands::calibrate::run(args).map(|()| ExitCode::SUCCESS)
        }
        Some(args::Command::CalibrateAutoroute(args)) => {
            subcommands::calibrate_autoroute::run(args)
        }
        Some(args::Command::Watch(args)) => {
            subcommands::watch::run(args).map(|()| ExitCode::SUCCESS)
        }
        Some(args::Command::Completion(args)) => {
            subcommands::completion::run(args);
            return ExitCode::SUCCESS;
        }
        Some(args::Command::Backend(args)) => subcommands::backend::run(args),
        Some(args::Command::Doctor(args)) => subcommands::doctor::run(args),
        Some(args::Command::Update(args)) => subcommands::update::run(args).await,
        Some(args::Command::Repair(args)) => subcommands::repair::run(args).await,
        Some(args::Command::Uninstall(args)) => subcommands::uninstall::run(args),
        Some(args::Command::ScanSystem(args)) => subcommands::scan_system::run(args),
        #[cfg(unix)]
        Some(args::Command::Daemon(args)) => subcommands::daemon::run(args).await,
        #[cfg(not(unix))]
        Some(args::Command::Daemon(_args)) => Err(anyhow::anyhow!(
            "`keyhog daemon` is a unix-only command (it serves scans over a \
             Unix-domain socket). On Windows, run scans in-process: \
             `keyhog scan <path>`. No Windows daemon transport ships."
        )),
        None => {
            let mut cmd = args::command();
            let _ = cmd.print_help(); // LAW10: unused-binding marker; no runtime effect, not a fallback
            return ExitCode::SUCCESS;
        }
    };

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
            let code = if SCANNER_PANICKED.load(Ordering::SeqCst) {
                exit_codes::EXIT_SCANNER_PANIC
            } else if error.chain().any(is_user_io_error) {
                exit_codes::EXIT_USER_ERROR
            } else if error.chain().any(|e| e.is::<std::io::Error>()) {
                exit_codes::EXIT_SYSTEM_ERROR
            } else {
                exit_codes::EXIT_USER_ERROR
            };
            // Every scan-setup error routes here. When autoroute probed the GPU
            // before failing, the normal teardown would SIGSEGV in the leaked
            // Vulkan driver thread (exit 139) instead of returning `code`; exit
            // immediately so the fail-closed code always reaches the operator.
            exit_now(code);
        }
    }
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

pub mod args;
pub(crate) mod atomic_file;
pub(crate) mod autoroute_cache_path;
pub(crate) mod baseline;
pub(crate) mod benchmark;
pub(crate) mod config;
pub mod exit_codes;
pub(crate) mod format;
pub(crate) mod installer;
pub(crate) mod runtime_preflight;
// Daemon uses Unix-domain sockets (`tokio::net::UnixListener` and
// `std::os::unix::net`). Windows lacks both surfaces in the form
// this server uses, and named pipes have a totally different
// auth model; we don't ship a Windows IPC story yet. Gate the
// module so the rest of the CLI still builds on Windows - the
// `daemon` subcommand and the `--daemon` flag emit a clear
// "unix-only" error there (see `main.rs` and `subcommands/scan.rs`).
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
#[doc(hidden)]
pub mod testing;
pub(crate) mod value_parsers;
