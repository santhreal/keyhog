//! Lane-10 (dogfood/robustness) regression: the daemon accept loop must
//! distinguish a TRANSIENT accept() failure (back off, keep serving) from a
//! FATAL one (surface loudly, shut down) — and never silently go deaf.
//!
//! The bug this pins: the old accept loop did `tracing::error!(...) ; break` on
//! ANY accept() error. That is (a) silent without RUST_LOG and (b) permanently
//! kills the daemon's ability to serve while the process stays alive, so
//! `daemon status` keeps reporting "ready" forever. A connection burst that
//! momentarily exhausts file descriptors (EMFILE) would brick the daemon.

#![cfg(unix)]

use keyhog::testing::{CliTestApi as _, API};
use std::io::{Error, ErrorKind};

#[test]
fn emfile_too_many_open_files_is_transient() {
    // EMFILE (errno 24): per-process fd limit hit under a connection burst.
    // std maps this to ErrorKind::Other, so the classifier matches on errno.
    let e = Error::from_raw_os_error(24);
    assert!(
        API.is_transient_accept_error(&e),
        "EMFILE (too many open files) must be treated as transient so a momentary \
         fd-exhaustion spike does not permanently kill the daemon"
    );
}

#[test]
fn enfile_system_fd_table_full_is_transient() {
    // ENFILE (errno 23): system-wide open-file table full. Also recoverable.
    let e = Error::from_raw_os_error(23);
    assert!(
        API.is_transient_accept_error(&e),
        "ENFILE (system file table full) must be treated as transient"
    );
}

#[test]
fn connection_aborted_is_transient() {
    let e = Error::from(ErrorKind::ConnectionAborted);
    assert!(
        API.is_transient_accept_error(&e),
        "a peer that aborted between SYN and accept() is transient — keep serving"
    );
}

#[test]
fn interrupted_syscall_is_transient() {
    let e = Error::from(ErrorKind::Interrupted);
    assert!(
        API.is_transient_accept_error(&e),
        "EINTR (interrupted accept) is transient — retry, don't tear down"
    );
}

#[test]
fn would_block_is_transient() {
    let e = Error::from(ErrorKind::WouldBlock);
    assert!(
        API.is_transient_accept_error(&e),
        "EAGAIN/EWOULDBLOCK is transient"
    );
}

#[test]
fn permission_denied_is_fatal() {
    // A non-recoverable error (e.g. the socket fd became unusable): the daemon
    // can never serve again, so it must NOT be classified transient (which
    // would spin forever) — the caller shuts down loudly instead.
    let e = Error::from(ErrorKind::PermissionDenied);
    assert!(
        !API.is_transient_accept_error(&e),
        "a fatal, non-recoverable accept error must NOT be treated as transient"
    );
}

#[test]
fn invalid_input_is_fatal() {
    let e = Error::from(ErrorKind::InvalidInput);
    assert!(
        !API.is_transient_accept_error(&e),
        "an unrecoverable accept error must be fatal so the daemon shuts down \
         instead of busy-looping forever"
    );
}
