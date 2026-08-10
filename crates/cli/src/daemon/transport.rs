//! Platform transport abstraction for the daemon.
//!
//! On Unix the daemon listens on a Unix domain socket. On Windows it
//! listens on a named pipe with the same owner-only trust posture.
//! This module exposes a unified `DaemonListener` and `DaemonStream`
//! so the server and client code can use one code path regardless of
//! platform.
//!
//! The framing contract (length-prefixed JSON) is identical on both
//! platforms. Only the transport differs.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub(crate) use tokio::net::UnixStream as DaemonStream;

#[cfg(unix)]
pub(crate) use tokio::net::UnixListener as DaemonListener;

#[cfg(unix)]
pub(crate) fn bind_transport(path: &Path) -> io::Result<DaemonListener> {
    DaemonListener::bind(path)
}

#[cfg(unix)]
pub(crate) async fn connect_transport(path: &Path) -> io::Result<DaemonStream> {
    DaemonStream::connect(path).await
}

#[cfg(unix)]
pub(crate) fn transport_path_display(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(unix)]
pub(crate) fn remove_transport_endpoint(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)
}

#[cfg(windows)]
mod windows {
    use super::*;
    use tokio::net::windows::named_pipe;

    pub(crate) type DaemonStream = named_pipe::NamedPipeClient;

    pub(crate) struct DaemonListener {
        pipe_name: String,
        // The first pipe instance is kept alive to hold the exclusive
        // owner reservation. Dropping it would free the name and allow
        // another process to claim the same endpoint.
        pending: Option<named_pipe::NamedPipeServer>,
    }

    impl DaemonListener {
        pub(crate) fn pipe_name(&self) -> &str {
            &self.pipe_name
        }

        /// Take the pending server instance for the accept loop. The
        /// caller must create the next instance before awaiting the
        /// next connection to maintain exclusivity.
        pub(crate) fn take_pending(&mut self) -> Option<named_pipe::NamedPipeServer> {
            self.pending.take()
        }

        /// Create the next pipe instance. Called by the accept loop
        /// after taking the pending instance.
        pub(crate) fn create_next(&self) -> io::Result<named_pipe::NamedPipeServer> {
            named_pipe::ServerOptions::new()
                .owner_only(true)
                .create(&self.pipe_name)
        }
    }

    pub(crate) fn bind_transport(path: &Path) -> io::Result<DaemonListener> {
        let pipe_name = pipe_name_from_path(path);
        let server = named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .owner_only(true)
            .create(&pipe_name)?;
        // Keep the first instance alive in the listener to hold the
        // exclusive-owner reservation. The accept loop takes it and
        // creates the next instance before awaiting the next connection.
        Ok(DaemonListener {
            pipe_name,
            pending: Some(server),
        })
    }

    pub(crate) async fn connect_transport(path: &Path) -> io::Result<DaemonStream> {
        let pipe_name = pipe_name_from_path(path);
        named_pipe::ClientOptions::new().open(&pipe_name).await
    }

    pub(crate) fn transport_path_display(path: &Path) -> String {
        pipe_name_from_path(path)
    }

    pub(crate) fn remove_transport_endpoint(_path: &Path) -> io::Result<()> {
        Ok(())
    }

    fn pipe_name_from_path(path: &Path) -> String {
        let stem = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "keyhog.sock".to_string());
        format!(r"\\.\pipe\{}", stem)
    }
}

#[cfg(windows)]
pub(crate) use windows::*;
