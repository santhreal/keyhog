//! LANE 5 (sources-safety) Law-10 regression: an unreadable binary must be
//! COUNTED (and surfaced loudly), never silently dropped from the scan.
//!
//! Before the fix `BinarySource::strings_chunks` logged the read failure at
//! `tracing::debug!` (invisible at default verbosity) and returned an empty
//! `Vec`, so a permission-denied / vanished binary read as a clean file. The
//! fix bumps `BINARY_UNREADABLE` + prints a loud stderr warning at the drop
//! site; this test pins the counter behaviour.
//!
//! Own test binary: `binary_unreadable()` reads a process-global atomic.

#![cfg(all(unix, feature = "binary"))]

use keyhog_core::Source;
use keyhog_sources::{binary_unreadable, reset_binary_counters, testing::binary_strings_only};
use std::sync::Mutex;

/// Serialises process-global binary-counter assertions in this test binary.
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn unreadable_binary_is_counted_not_silently_dropped() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    reset_binary_counters();

    // A path that does not exist: `read_binary_capped` -> `File::open` fails.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.bin");

    let chunks: Vec<_> = binary_strings_only(missing.clone()).chunks().collect();
    // The strings path returns no chunks for an unreadable file (the Source
    // wrapper turns the empty Vec into an empty chunk stream).
    let bodies: Vec<_> = chunks.into_iter().filter_map(|r| r.ok()).collect();
    assert!(
        bodies.is_empty(),
        "an unreadable binary yields no chunks; got {} chunk(s)",
        bodies.len()
    );
    assert_eq!(
        binary_unreadable(),
        1,
        "an unreadable binary must be counted as dropped-from-scan (Law 10), so a \
         'no secrets' result is not mistaken for full coverage of that file"
    );
}

#[test]
fn readable_binary_is_not_counted_as_unreadable() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    reset_binary_counters();

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("app.bin");
    // A blob with a real-shape AWS key embedded among printable runs so strings
    // extraction yields at least one chunk.
    let mut bytes = vec![0u8; 32];
    bytes.extend_from_slice(b"junk_prefix_AKIAQYLPMN5HFIQR7XYA_suffix_padding"); // keyhog:ignore detector=aws-access-key (synthetic test fixture)
    bytes.extend_from_slice(&[0u8; 16]);
    std::fs::write(&bin, &bytes).unwrap();

    let bodies: Vec<String> = binary_strings_only(bin.clone())
        .chunks()
        .filter_map(|r| r.ok())
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("AKIAQYLPMN5HFIQR7XYA")), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
        "a readable binary's embedded string must be extracted; got {bodies:?}"
    );
    assert_eq!(
        binary_unreadable(),
        0,
        "a readable binary must NOT be counted as unreadable"
    );
}
