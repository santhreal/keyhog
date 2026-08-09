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

/// Synchronous, async-signal-safe SIGINT handling for the scan lifecycle.
///
/// The CLI runs on a `current_thread` tokio runtime. A long synchronous scan
/// (`subcommands::scan::run`) blocks that single-threaded runtime, so a
/// `tokio::signal::ctrl_c` task spawned at startup never gets polled, its
/// signal handler is never registered, SIGINT falls through to the DEFAULT
/// disposition, and the process dies by signal (status code `None`) with no
/// "Scan interrupted" message instead of the documented exit 130. Installing a
/// real OS handler synchronously in `main` (before the runtime starts) fixes
/// this: it fires regardless of runtime scheduling.
///
/// The handler touches only async-signal-safe operations: relaxed atomic LOADS
/// (via [`keyhog::interrupt_counts`]), stack-buffer integer formatting (no
/// allocation, no locks), `write(2)`, and `_exit`: so it is safe even if
/// SIGINT lands while the progress ticker holds the stderr lock (an
/// `eprintln!`-based handler could deadlock there).
#[cfg(unix)]
mod interrupt {
    fn append(buf: &mut [u8; 256], len: &mut usize, src: &[u8]) {
        for &byte in src {
            if *len < buf.len() {
                buf[*len] = byte;
                *len += 1;
            }
        }
    }

    fn append_usize(buf: &mut [u8; 256], len: &mut usize, mut value: usize) {
        if value == 0 {
            append(buf, len, b"0");
            return;
        }
        let mut digits = [0u8; 20];
        let mut count = 0;
        while value > 0 {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
        while count > 0 {
            count -= 1;
            let digit = digits[count];
            append(buf, len, &[digit]);
        }
    }

    extern "C" fn handle_sigint(_signum: libc::c_int) {
        let (scanned, total, findings) = keyhog::interrupt_counts();
        let mut buf = [0u8; 256];
        let mut len = 0;
        append(&mut buf, &mut len, b"\nScan interrupted. ");
        append_usize(&mut buf, &mut len, scanned);
        append(&mut buf, &mut len, b"/");
        append_usize(&mut buf, &mut len, total);
        append(&mut buf, &mut len, b" files scanned. ");
        append_usize(&mut buf, &mut len, findings);
        append(&mut buf, &mut len, b" findings.\n");
        if keyhog::operator_profile_active() {
            append(
                &mut buf,
                &mut len,
                b"profile outcome status=failed coverage=cancelled errors=1 exit=130 interruption=sigint\n",
            );
        }
        // SAFETY: async-signal-safe primitives only: `write(2)` over a valid
        // stack buffer + length, then `_exit` with the documented interrupt
        // code (128 + SIGINT). The code is the compile-time `EXIT_INTERRUPTED`
        // constant (an immediate value, no allocation/locks/Drop glue), so the
        // ONE exit-code owner is honored without breaking signal-safety.
        unsafe {
            libc::write(2, buf.as_ptr().cast(), len);
            libc::_exit(keyhog::exit_codes::EXIT_INTERRUPTED as libc::c_int);
        }
    }

    pub(super) fn install() {
        // SAFETY: registering a process-wide handler before the runtime and any
        // worker/reader threads start; `handle_sigint` is async-signal-safe.
        unsafe {
            // Cast the fn item via a thin pointer first: a direct fn-item -> integer
            // cast trips `function_casts_as_integer` (a fn item is not an address).
            libc::signal(
                libc::SIGINT,
                handle_sigint as *const () as libc::sighandler_t,
            );
        }
    }
}

#[cfg(not(unix))]
mod interrupt {
    pub(super) fn install() {}
}

fn main() -> ExitCode {
    configure_allocator_memory_policy();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!(
                "error: failed to build the KeyHog async runtime: {error}. \
                 Fix: verify available process resources and retry."
            );
            return ExitCode::from(keyhog::exit_codes::EXIT_SYSTEM_ERROR);
        }
    };
    runtime.block_on(async_main())
}

async fn async_main() -> ExitCode {
    // Startup surface: signal-handler installation is process setup, profiled
    // as preprocessing; the runtime session itself is owned by the caller.
    let _startup_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    reset_sigpipe();
    interrupt::install();
    drop(_startup_span);
    keyhog::cli_main().await
}
