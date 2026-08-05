//! Scoped `SIGPIPE` suppression for daemon socket I/O.
//!
//! `main::reset_sigpipe` puts `SIGPIPE` back to `SIG_DFL` process-wide, because a
//! one-shot CLI is expected to die quietly when its stdout consumer goes away:
//! `keyhog scan --format json | head -1` must exit like every other Unix filter
//! instead of printing a `BrokenPipe` error and a nonzero code. That is the right
//! disposition for the report writer and the wrong one for a socket.
//!
//! A daemon peer disappearing is ordinary: the operator hits Ctrl-C, a client
//! request times out, a pre-commit hook is killed. With `SIG_DFL` the very next
//! `write(2)` to that socket kills the writing process outright, so the CLI dies
//! by signal 141 instead of reporting which daemon went away. The server side
//! fixes this permanently (see `server::ignore_sigpipe_while_serving`); a client
//! cannot, because it still owns the piped-stdout contract above.
//!
//! So clients suppress `SIGPIPE` only while a daemon connection is open. Report
//! writing happens after the connection is dropped, which keeps the piped-stdout
//! behaviour intact. The guard is reference counted, so overlapping connections
//! restore the default exactly once.

use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_GUARDS: AtomicUsize = AtomicUsize::new(0);

/// Suppresses `SIGPIPE` for as long as it is alive. Held by every daemon
/// connection object, so a peer that vanishes mid-write surfaces `EPIPE` to the
/// error path instead of killing the process.
#[derive(Debug)]
pub(crate) struct SigPipeGuard;

impl SigPipeGuard {
    pub(crate) fn acquire() -> Self {
        if ACTIVE_GUARDS.fetch_add(1, Ordering::AcqRel) == 0 {
            set_sigpipe(libc::SIG_IGN);
        }
        Self
    }
}

impl Drop for SigPipeGuard {
    fn drop(&mut self) {
        if ACTIVE_GUARDS.fetch_sub(1, Ordering::AcqRel) == 1 {
            set_sigpipe(libc::SIG_DFL);
        }
    }
}

fn set_sigpipe(handler: libc::sighandler_t) {
    // SAFETY: `signal(2)` with `SIG_IGN`/`SIG_DFL` is defined for `SIGPIPE`, and
    // both dispositions are process-global constants rather than a handler
    // function, so there is no handler lifetime or reentrancy to protect.
    unsafe {
        libc::signal(libc::SIGPIPE, handler);
    }
}
