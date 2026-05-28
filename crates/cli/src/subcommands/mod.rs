//! Subcommand implementations for the KeyHog CLI.

pub mod backend;
pub mod calibrate;
pub mod completion;
// See `lib.rs` for why `daemon` is unix-only. The Windows handler
// for the `daemon` subcommand lives inline in `main.rs`.
#[cfg(unix)]
pub mod daemon;
pub mod detectors;
pub mod diff;
pub mod doctor;
pub mod explain;
pub mod hook;
pub mod scan;
pub mod scan_system;
#[cfg(feature = "tui")]
pub mod tui;
pub mod update;
pub mod watch;
