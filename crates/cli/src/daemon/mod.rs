//! Daemon mode for keyhog: long-lived process that holds a compiled
//! scanner and serves scan requests over a Unix socket.
//!
//! Why a daemon: scanner compilation, detector loading, Hyperscan database
//! setup, and accelerator probing otherwise repeat for each process. A
//! long-lived daemon retains that compatible runtime across repeated scans.
//! Actual startup and request latency depend on the detector corpus, backend,
//! cache state, host, and input.
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
