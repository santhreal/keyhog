//! Daemon mode for keyhog: long-lived process that holds a compiled
//! scanner and serves scan requests over a Unix socket.
//!
//! Why a daemon: `CompiledScanner::compile` pays a ~3 s cold-start
//! cost (Hyperscan database compile, detector load, vyre GPU adapter
//! probe). For workflows that invoke `keyhog` many times in quick
//! succession (pre-commit hooks, CI per-commit pipelines, IDE save
//! handlers, mitmproxy live scan) that 3 s lands on every invocation.
//! Holding the compiled scanner in a long-lived process collapses
//! repeat-scan latency from ~3 s + scan to sub-ms IPC + scan.
//!
//! Surface:
//! - `keyhog daemon start` - bind the socket, compile the scanner,
//!   accept connections forever (until `daemon stop`).
//! - `keyhog daemon stop` - send `Shutdown` to the running daemon,
//!   wait for the socket to disappear.
//! - `keyhog daemon status` - connect, request `Health`, print
//!   uptime + scans-served + active-scan count.
//! - `keyhog scan ... --daemon` - force the scan through a running
//!   daemon; errors if no daemon is up.
//! - `keyhog scan ... --daemon=off` - force in-process scan even when
//!   a daemon is up.

pub mod client;
pub mod frame;
pub mod protocol;
pub mod server;
mod trust;

pub use server::default_socket_path;
