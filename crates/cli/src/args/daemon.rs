use std::path::PathBuf;

use clap::Parser;

/// Subcommand args for `keyhog daemon {start, stop, status}`.
#[derive(Parser)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub action: DaemonAction,
}

#[derive(clap::Subcommand)]
pub enum DaemonAction {
    /// Start a daemon process that holds a compiled scanner and
    /// serves scan requests over a Unix socket. Blocks until
    /// `daemon stop` is invoked.
    Start {
        /// Override the default socket path
        /// ($XDG_RUNTIME_DIR/keyhog.sock or ~/.cache/keyhog/server.sock).
        ///
        /// A daemon started here is reachable by `daemon stop`/`status --socket`
        /// AND by scans via `keyhog scan --daemon --daemon-socket <same path>`
        /// — pass the matching path so a fixed-location daemon (e.g. a systemd
        /// unit) actually serves scans, not just admin commands.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Detector directory (same default as `keyhog scan --detectors`).
        #[arg(long, default_value = "detectors")]
        detectors: PathBuf,
        /// Override the Hyperscan compiled-database cache directory.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
        /// Force a daemon scan backend instead of using persisted autoroute.
        ///
        /// The default `auto` mode requires install-time calibration. Use an
        /// explicit backend for diagnostics and hermetic daemon tests.
        #[arg(
            long,
            value_name = "BACKEND",
            value_parser = clap::builder::PossibleValuesParser::new(
                keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
            )
        )]
        backend: Option<String>,
        /// Max seconds a client connection may sit without completing one
        /// request frame before the daemon closes it and reclaims the slot.
        #[arg(
            long,
            default_value_t = 300,
            value_name = "SECS",
            value_parser = crate::value_parsers::parse_daemon_request_timeout_secs
        )]
        request_timeout_secs: u64,
    },
    /// Stop the running daemon by sending it a `Shutdown` over the socket.
    Stop {
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Print uptime, scans served, active scans, and detector count.
    Status {
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
}
