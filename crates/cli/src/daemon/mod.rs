//! Daemon mode for keyhog: long-lived process that holds a compiled
//! scanner and serves scan requests over a Unix socket.
//!
//! Why a daemon: scanner compilation, detector loading, Hyperscan database
//! setup, and accelerator probing otherwise repeat for each process. A
//! long-lived daemon retains that compatible runtime across repeated scans.
//! Actual startup and request latency depend on the detector corpus, backend,
//! cache state, host, and input.
//!
//! Public surface:
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
//!
//! The wire protocol is deliberately not library API. Its scan response owns
//! plaintext findings and is serializable only inside this crate, after both
//! endpoints authenticate the connected Unix peer.
//!
//! ```compile_fail
//! // External crates cannot import the private response DTO.
//! use keyhog::daemon::protocol::Response;
//! fn serialize(response: &Response) { let _ = serde_json::to_string(response); }
//! ```

pub(crate) mod client;
#[cfg(test)]
#[path = "client_staleness_tests.rs"]
mod client_staleness_tests;
pub(crate) mod control;
pub(crate) mod frame;
#[cfg(test)]
#[path = "frame_incremental_tests.rs"]
mod frame_incremental_tests;
#[cfg(test)]
#[path = "frame_streaming_tests.rs"]
mod frame_streaming_tests;
pub(crate) mod guard_commit;
pub(crate) mod guard_runtime;
pub(crate) mod guard_watcher;
#[cfg(test)]
#[path = "path_resolution_tests.rs"]
mod path_resolution_tests;
#[cfg(test)]
#[path = "protected_wire_tests.rs"]
mod protected_wire_tests;
pub(crate) mod protocol;
pub(crate) mod server;
pub(crate) mod sigpipe;
pub(crate) mod transport;
mod trust;
mod warm_identity;
#[cfg(test)]
#[path = "warm_identity_tests.rs"]
mod warm_identity_tests;
#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;

pub use server::default_socket_path;
