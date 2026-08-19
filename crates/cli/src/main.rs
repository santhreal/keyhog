//! KeyHog CLI: the developer-first secret scanner.
//!
//! All module declarations live in `lib.rs` so the binary and the library
//! share one set of statics (progress counters) and modules. main.rs only
//! contains the entry point.

// Thread-caching global allocator (see the `mimalloc` feature in Cargo.toml).
// Per-thread heaps remove the glibc arena-lock contention the multi-core scan
// hot path otherwise pays (sub-linear Rayon thread scaling). The CLI binary
// owns this choice; the keyhog libraries stay allocator-agnostic.
#[cfg(all(feature = "allocation-profile", feature = "mimalloc"))]
compile_error!("allocation-profile and mimalloc are mutually exclusive global allocators");

#[cfg(all(feature = "allocation-profile", not(feature = "mimalloc")))]
#[global_allocator]
static GLOBAL: keyhog_profile::TrackingAllocator = keyhog_profile::TrackingAllocator::new();

#[cfg(all(feature = "mimalloc", not(feature = "allocation-profile")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Keep mimalloc's per-thread heaps without eagerly committing whole segments.
#[cfg(all(feature = "mimalloc", not(feature = "allocation-profile")))]
fn configure_allocator_memory_policy() {
    // Stable `mi_option_t` values from the pinned mimalloc v2 ABI.
    const MI_OPTION_EAGER_COMMIT: std::ffi::c_int = 3;
    const MI_OPTION_ARENA_EAGER_COMMIT: std::ffi::c_int = 4;
    const MI_OPTION_PURGE_DELAY: std::ffi::c_int = 15;
    const MI_OPTION_GENERIC_COLLECT: std::ffi::c_int = 36;
    unsafe extern "C" {
        fn mi_option_set(option: std::ffi::c_int, value: i64);
    }
    // SAFETY: `mi_option_set` accepts every declared option before concurrent
    // allocator use; this runs at the first statement of the process entrypoint.
    unsafe {
        mi_option_set(MI_OPTION_EAGER_COMMIT, 0);
        mi_option_set(MI_OPTION_ARENA_EAGER_COMMIT, 0);
        mi_option_set(MI_OPTION_PURGE_DELAY, 0);
        mi_option_set(MI_OPTION_GENERIC_COLLECT, 1024);
    }
}

#[cfg(not(all(feature = "mimalloc", not(feature = "allocation-profile"))))]
fn configure_allocator_memory_policy() {}

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

fn main() -> ExitCode {
    configure_allocator_memory_policy();
    reset_sigpipe();
    keyhog::cli_main()
}
