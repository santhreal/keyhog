//! Pin deep mode's decode ceiling against the source window size.
//!
//! Companion to `keyhog-sources`'s
//! `tests/regression_window_decode_ordering_pinned.rs`. The pair lives in two
//! files because `keyhog-sources` does not depend on `keyhog-scanner`, so
//! neither crate can see both constants; each guards the one it owns and names
//! the other.
//!
//! THE RELATIONSHIP. A source file larger than one window enters the scanner as
//! `DEFAULT_WINDOW_SIZE`-sized chunks (1 MiB, `sources/src/filesystem/reader.rs`).
//! Decode-through runs on a chunk only when the chunk fits inside
//! `max_decode_bytes`. So:
//!
//!   default mode: window 1 MiB  >  512 KiB  -> a full-size window is NEVER
//!                                              decode-expanded, and the interior
//!                                              of every large file is silently
//!                                              unreachable (KH-532).
//!   deep mode:    window 1 MiB == 1 MiB     -> reachable, but ONLY by exact
//!                                              equality, with zero slack.
//!
//! That zero slack is why this guard exists. Deep mode recovers a mid-file
//! payload today purely because the two numbers are equal. Raising
//! `DEFAULT_WINDOW_SIZE` to 2 MiB would silently break `--deep` as well as the
//! default, and no assertion on the default pair alone would notice.
//!
//! Pinning the exact value rather than asserting `deep >= window` is deliberate:
//! the sources crate is not visible from here, so an inequality would have to
//! hard-code the window anyway, and an exact pin fails on movement in either
//! direction rather than only on the direction someone predicted.

use keyhog_scanner::ScannerConfig;

/// Current source-side window default, `sources/src/filesystem/reader.rs`.
/// Not importable here: `keyhog-scanner` does not depend on `keyhog-sources`.
const SOURCE_DEFAULT_WINDOW_SIZE: usize = 1024 * 1024;

#[test]
fn deep_decode_ceiling_still_covers_a_full_source_window() {
    let deep_ceiling = ScannerConfig::DEEP_MAX_DECODE_BYTES;

    assert_eq!(
        deep_ceiling, SOURCE_DEFAULT_WINDOW_SIZE,
        "DEEP_MAX_DECODE_BYTES ({deep_ceiling}) no longer equals the source window size \
         ({SOURCE_DEFAULT_WINDOW_SIZE}). Deep mode recovers encoded payloads from the \
         INTERIOR of a large file only because these two are equal, with no slack. If \
         deep's ceiling dropped below the window, --deep silently stops recovering \
         mid-file encoded payloads exactly the way the default already does. If the \
         SOURCE window grew, update this constant and check \
         keyhog-sources tests/regression_window_decode_ordering_pinned.rs, which pins \
         the same window against the default 512 KiB ceiling."
    );

    assert!(
        deep_ceiling >= SOURCE_DEFAULT_WINDOW_SIZE,
        "deep decode ceiling ({deep_ceiling}) is below the source window \
         ({SOURCE_DEFAULT_WINDOW_SIZE}), so --deep can no longer decode a full-size \
         window and mid-file encoded payloads are unreachable in every mode."
    );
}
