use std::sync::atomic::{AtomicBool, AtomicUsize};

pub static SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static FINDINGS_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Set to `true` if the scanner thread panicked during `scan_sources`.
/// Read at the end of `run()` so a crashed scanner exits with a
/// non-zero code instead of silently reporting "no findings, all
/// clean" — that was the prior behavior and would mislead any
/// caller piping keyhog into CI as a gate.
pub static SCANNER_PANICKED: AtomicBool = AtomicBool::new(false);

pub mod args;
pub mod baseline;
pub mod benchmark;
pub mod config;
// Daemon uses Unix-domain sockets (`tokio::net::UnixListener` and
// `std::os::unix::net`). Windows lacks both surfaces in the form
// this server uses, and named pipes have a totally different
// auth model; we don't ship a Windows IPC story yet. Gate the
// module so the rest of the CLI still builds on Windows — the
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
pub mod subcommands;
pub mod test_fixture_suppressions;
pub mod value_parsers;
