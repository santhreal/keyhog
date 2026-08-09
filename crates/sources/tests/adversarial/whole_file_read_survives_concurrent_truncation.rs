//! A file truncated by another writer WHILE the scanner reads it must not kill
//! the process.
//!
//! This used to be a hard crash. The whole-file read path mapped the file and
//! read through the mapping, and there is no race-free way to do that: an
//! `ftruncate` from any other process invalidates the page-cache pages past the
//! new EOF, and the next touch of the mapping raises `SIGBUS`. `SIGBUS` has no
//! handler here, so the process died with signal 7: no report, no findings, no
//! exit code a pipeline could interpret, and every other file in that scan lost.
//!
//! Measured before the fix, on `keyhog scan <file>` against a file a second
//! thread was truncating and rewriting: 1 of 6 trials died at 128 KiB, 4 of 6 at
//! 800 KiB, 3 of 6 at 32 MiB. Not an exotic input either: `scan-system` walks
//! live filesystems where logs rotate.
//!
//! This test is deliberately a liveness test rather than an assertion about a
//! return value. If the read path goes back to mapping the file, the fault kills
//! the TEST BINARY and the whole suite fails, which is exactly the signal we
//! want. Every individual read is free to return `Some` (whatever bytes it saw)
//! or `None` (a visible skip); the contract is only that it RETURNS.

use keyhog_sources::testing::TestApi;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Big enough that the read spans many pages, so a truncation lands inside the
/// range a mapping would have covered, and small enough to loop hundreds of
/// times in a test.
const FILE_BYTES: usize = 800 * 1024;

/// Enough attempts that the pre-fix race was effectively certain to fire: it
/// took roughly two reads to reproduce at this size.
const READ_ATTEMPTS: usize = 300;

fn fill(path: &std::path::Path) -> std::io::Result<()> {
    let line = b"api_endpoint = https://orders.internal/v1 retries = 3\n";
    let mut file = std::fs::File::create(path)?;
    let mut written = 0;
    while written < FILE_BYTES {
        file.write_all(line)?;
        written += line.len();
    }
    file.flush()
}

#[test]
fn whole_file_read_survives_concurrent_truncation() {
    let _guard = TestApi.skip_counter_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rotating.log");
    fill(&path).expect("seed file");

    let stop = Arc::new(AtomicBool::new(false));
    let writer_path = path.clone();
    let writer_stop = Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        // Shrink to almost nothing, then grow back. The shrink is what faults a
        // mapping; the regrow keeps the file interesting for the next read.
        while !writer_stop.load(Ordering::Relaxed) {
            if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&writer_path) {
                let _ = file.set_len(4096);
            }
            let _ = fill(&writer_path);
        }
    });

    let mut returned = 0usize;
    for _ in 0..READ_ATTEMPTS {
        // Reaching the next line at all is the assertion: a mapped read would
        // have taken the process down inside this call.
        let _ = TestApi.read_file_mmap(&path);
        returned += 1;
    }

    stop.store(true, Ordering::Relaxed);
    writer.join().expect("writer thread");

    assert_eq!(
        returned, READ_ATTEMPTS,
        "every whole-file read of a concurrently truncated file must return \
         instead of faulting the process"
    );
}
