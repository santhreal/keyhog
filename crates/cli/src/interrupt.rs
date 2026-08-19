//! Synchronous, async-signal-safe SIGINT handling for the scan lifecycle.
//!
//! The CLI runs on a `current_thread` tokio runtime. A long synchronous scan
//! (`subcommands::scan::run`) blocks that single-threaded runtime, so a
//! `tokio::signal::ctrl_c` task spawned at startup never gets polled, its
//! signal handler is never registered, SIGINT falls through to the DEFAULT
//! disposition, and the process dies by signal (status code `None`) with no
//! "Scan interrupted" message instead of the documented exit 130. Installing a
//! real OS handler synchronously before starting the scan fixes this: it fires
//! regardless of runtime scheduling.
//!
//! The handler touches only async-signal-safe operations: relaxed atomic LOADS
//! (via [`crate::interrupt_counts`]), stack-buffer integer formatting (no
//! allocation, no locks), `write(2)`, and `_exit`: so it is safe even if
//! SIGINT lands while the progress ticker holds the stderr lock (an
//! `eprintln!`-based handler could deadlock there).

#[cfg(unix)]
fn append(buf: &mut [u8; 256], len: &mut usize, src: &[u8]) {
    for &byte in src {
        if *len < buf.len() {
            buf[*len] = byte;
            *len += 1;
        }
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
extern "C" fn handle_sigint(_signum: libc::c_int) {
    let (scanned, total, findings) = crate::interrupt_counts();
    let mut buf = [0u8; 256];
    let mut len = 0;
    append(&mut buf, &mut len, b"\nScan interrupted. ");
    append_usize(&mut buf, &mut len, scanned);
    append(&mut buf, &mut len, b"/");
    append_usize(&mut buf, &mut len, total);
    append(&mut buf, &mut len, b" files scanned. ");
    append_usize(&mut buf, &mut len, findings);
    append(&mut buf, &mut len, b" findings.\n");
    if crate::operator_profile_active() {
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
        libc::_exit(crate::exit_codes::EXIT_INTERRUPTED as libc::c_int);
    }
}

pub(crate) fn install() {
    #[cfg(unix)]
    {
        // SAFETY: registering a process-wide handler before the scan runtime starts;
        // `handle_sigint` is async-signal-safe.
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
