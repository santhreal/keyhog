//! Subcommand implementations for the KeyHog CLI.

pub(crate) mod backend;
pub(crate) mod calibrate;
pub(crate) mod calibrate_autoroute;
pub(crate) mod completion;
pub(crate) mod config;
// See `lib.rs` for why `daemon` is unix-only. The Windows handler
// for the `daemon` subcommand lives inline in `main.rs`.
#[cfg(unix)]
pub(crate) mod daemon;
pub(crate) mod detectors;
pub(crate) mod diff;
pub(crate) mod doctor;
pub(crate) mod explain;
pub(crate) mod hook;
pub(crate) mod repair;
pub(crate) mod scan;
pub(crate) mod scan_system;
pub(crate) mod uninstall;
pub(crate) mod update;
pub(crate) mod watch;
