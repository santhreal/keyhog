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
//!   (formatting helpers), [`style`] (terminal styling).
//! - **CI / baselines** — [`baseline`] (diff against a committed baseline),
//!   [`benchmark`].
//! - **Config & suppression** — [`config`] (`.keyhog.toml` discovery + merge),
//!   [`inline_suppression`], [`test_fixture_suppressions`].
//! - **Install / health** — [`installer`] (hook installer, `doctor`).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub static SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static FINDINGS_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Chunks actually dispatched to the GPU megakernel (a subset of
/// [`SCANNED_CHUNKS`]; the remainder ran on the SIMD/CPU path). The orchestrator
/// bumps this in the coalesced GPU arm — the single place the GPU runs — so the
/// completion summary can state which backend selection used and why,
/// instead of the decision being buried at `tracing::debug!` (target
/// `keyhog::routing`). The optimized coalesced scan paths bypass `scan_inner`'s
/// per-chunk telemetry, so that snapshot under-counts on the production batch
/// path; this orchestrator-level counter is the authoritative routing signal.
pub static GPU_SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
/// Number of source-read errors (a source yielded `Err` instead of a chunk).
/// Read at the end of `run()`: if a scan produced ZERO chunks AND a source
/// errored, the requested scan never actually ran (e.g. `--git-history` /
/// `--git-diff` on a non-repo, a bad ref, or an unreachable remote), so we
/// must NOT print "no findings, all clean" and exit 0 — that would tell a CI
/// gate the tree is clean when nothing was scanned (KH-GAP-096). Same intent
/// as `SCANNER_PANICKED`, for the source-failure path.
pub static SOURCE_ERRORS: AtomicUsize = AtomicUsize::new(0);
/// Number of sources that failed *entirely* — produced ZERO chunks AND
/// errored. A source the user explicitly requested (e.g. `--github-org`,
/// `--git-diff`, `--url`) that yields nothing because the fetch failed means
/// that scan never ran, even if a co-requested filesystem source succeeded.
/// `run()` fails closed when this is non-zero and there are no findings, so a
/// failed remote scan is not masked by a clean local one (the more precise
/// successor to the `SOURCE_ERRORS && TOTAL_CHUNKS==0` global check). A
/// partial failure — a tree with some unreadable files that still produced
/// chunks — does NOT count: that source produced data.
pub static FAILED_SOURCES: AtomicUsize = AtomicUsize::new(0);
/// Set to `true` if the scanner thread panicked during `scan_sources`.
/// Read at the end of `run()` so a crashed scanner exits with a
/// non-zero code instead of silently reporting "no findings, all
/// clean" - that was the prior behavior and would mislead any
/// caller piping keyhog into CI as a gate.
pub static SCANNER_PANICKED: AtomicBool = AtomicBool::new(false);

/// Operator-visible scan failure event recorded by the CLI orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanFailureEvent {
    SourceError,
    FailedSource,
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

pub(crate) fn record_scanner_panic() -> RecordedScanFailureEvent {
    record_scan_failure(ScanFailureEvent::ScannerPanicked)
}

pub fn write_banner<W: Write>(
    w: &mut W,
    colors: bool,
    ascii: bool,
    detector_count: usize,
) -> std::io::Result<()> {
    keyhog_core::banner::print_banner(w, colors, ascii, detector_count)
}

pub mod args;
pub mod backend_env;
pub mod baseline;
pub mod benchmark;
pub mod config;
pub mod exit_codes;
pub mod format;
pub mod installer;
// Daemon uses Unix-domain sockets (`tokio::net::UnixListener` and
// `std::os::unix::net`). Windows lacks both surfaces in the form
// this server uses, and named pipes have a totally different
// auth model; we don't ship a Windows IPC story yet. Gate the
// module so the rest of the CLI still builds on Windows - the
// `daemon` subcommand and the `--daemon` flag emit a clear
// "unix-only" error there (see `main.rs` and `subcommands/scan.rs`).
#[cfg(unix)]
pub mod daemon;
pub mod inline_suppression;
pub mod orchestrator;
pub mod orchestrator_config;
pub mod path_validation;
pub mod reporting;
pub mod sources;
pub mod style;
pub mod subcommands;
pub mod test_fixture_suppressions;
pub mod value_parsers;
