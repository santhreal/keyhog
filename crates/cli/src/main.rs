//! KeyHog CLI: the developer-first secret scanner.
//!
//! All module declarations live in `lib.rs` so the binary and the library
//! share one set of statics (progress counters) and modules. main.rs only
//! contains the entry point.

// Thread-caching global allocator (see the `mimalloc` feature in Cargo.toml).
// Per-thread heaps remove the glibc arena-lock contention the multi-core scan
// hot path otherwise pays (sub-linear Rayon thread scaling). The CLI binary
// owns this choice; the keyhog libraries stay allocator-agnostic.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::process::ExitCode;

/// Restore the default SIGPIPE handler so Unix piping works.
///
/// Rust installs `SIG_IGN` for SIGPIPE at startup so a write to a
/// closed pipe surfaces as `Err(BrokenPipe)` instead of killing the
/// process. That's good for libraries - but for a CLI, the standard
/// expectation is `keyhog scan ... | head -1` exits cleanly when
/// `head` closes the pipe (kernel kills with 128+13=141, no error
/// printed). Without this, the user sees an error on stderr and a
/// non-zero exit code from a perfectly normal pipe interaction.
///
/// POSIX-only - Windows has no SIGPIPE.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: Setting a process-wide signal handler before any
    // worker threads or async runtime are spawned. The default
    // handler (`SIG_DFL`) terminates the process - exactly the
    // behavior we want for a CLI piped into `head`. No memory or
    // resource invariants depend on Rust's `SIG_IGN` default
    // because every fallible write path in the codebase already
    // uses `?` or explicit error handling.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    reset_sigpipe();
    keyhog::cli_main().await
}
