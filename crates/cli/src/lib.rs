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
pub mod inline_suppression;
pub mod orchestrator;
mod orchestrator_config;
pub mod path_validation;
pub mod reporting;
pub mod sources;
pub mod subcommands;
pub mod value_parsers;
