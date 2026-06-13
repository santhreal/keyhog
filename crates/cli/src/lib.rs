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

use std::sync::atomic::{AtomicBool, AtomicUsize};

pub static SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static FINDINGS_COUNT: AtomicUsize = AtomicUsize::new(0);
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

pub mod args;
pub mod baseline;
pub mod benchmark;
pub mod config;
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
