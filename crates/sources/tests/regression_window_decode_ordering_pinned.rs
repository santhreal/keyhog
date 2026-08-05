//! Pin the source window size against the scanner's decode ceiling.
//!
//! These two constants are defaulted independently in two crates, and their
//! ORDER decides whether encoded payloads are reachable at all:
//!
//!   `DEFAULT_WINDOW_SIZE` (1 MiB, `filesystem/reader.rs`)
//!   `ScanConfig::max_decode_bytes` (512 KiB, `core/src/config.rs`)
//!
//! While the window exceeds the decode ceiling, a FULL-SIZE window can never be
//! decode-expanded, so in any file larger than one window only the short tail
//! window is decode-reachable and the entire interior is not. That is not a
//! limit with a wrong value, it is two limits in a wrong relationship, and it
//! is invisible in output: the affected scan exits 0 and reports no findings.
//!
//! Measured on the pristine reference binary, same 2000K file, same bytes, only
//! the payload's byte offset differing: a payload at EOF is found, the same
//! payload mid-file is not, and raising `--decode-size-limit` recovers both.
//! Reproduced independently by four agents on three binaries. The apparent
//! "non-monotonic in file size" behaviour is an artifact of always planting at
//! EOF; what oscillates with file size is the tail-window size.
//!
//! This guard deliberately pins the EXACT current pair rather than asserting
//! `window <= decode_ceiling`, because that inequality is FALSE on the current
//! tree: a naive assertion would fail immediately and be deleted by the next
//! person who hit it. Pinning both values makes the test go red when either
//! constant moves in either direction, and the failure message carries the
//! consequence and the flip condition so the change is a decision rather than a
//! surprise.

use keyhog_sources::testing::{TestApi};

/// Current source-side window default (`filesystem/reader.rs`).
const EXPECTED_WINDOW_SIZE: usize = 1024 * 1024;
/// Current scanner decode ceiling default (`core/src/config.rs`).
const EXPECTED_DECODE_CEILING: usize = 512 * 1024;

#[test]
fn source_window_size_and_scanner_decode_ceiling_stay_pinned() {
    let window = TestApi.source_default_window_size();
    let decode_ceiling = keyhog_core::ScanConfig::default().max_decode_bytes;

    assert_eq!(
        window, EXPECTED_WINDOW_SIZE,
        "DEFAULT_WINDOW_SIZE moved to {window}. It is paired with the scanner's \
         decode ceiling ({decode_ceiling}); while the window is LARGER, the interior of \
         every file bigger than one window is decode-unreachable and that gap is silent. \
         Measured on a real 2.2 GB registry tree: 574 MB decode-unreachable, of which \
         173 MB sits in the 512K-1MiB band and becomes reachable by ORDERING these two \
         constants alone (the remaining 422 MB needs the decode path subdivided). So this \
         pairing is worth ~30% of the unreachable bytes, not just tidiness. \
         If you raised the window, the reachable fraction just got smaller. If you are \
         fixing KH-532 and window <= decode ceiling now holds, update both constants here \
         AND flip DecodeOversizeSkip from WARN to FAIL, which is the agreed trigger: the \
         gap stops being structural and becomes exceptional, so exit 13 is then correct."
    );

    assert_eq!(
        decode_ceiling, EXPECTED_DECODE_CEILING,
        "ScanConfig::max_decode_bytes moved to {decode_ceiling}, paired with the source \
         window ({window}). Raising it to at least the window size is one of the two \
         accepted fixes for KH-532 (the other is subdividing the decode path). If you did \
         that deliberately, update both constants here AND flip DecodeOversizeSkip from \
         WARN to FAIL."
    );
}

/// Record the consequence of the current ordering as an executable statement, so
/// the day it stops being true someone is told rather than left to notice.
///
/// This asserts the BUG, not the desired state. It is green today because the
/// defect is present. When KH-532 lands it goes red, which is the signal that
/// the guard above and the WARN/FAIL severity both need revisiting.
#[test]
fn full_size_windows_are_currently_decode_unreachable() {
    let window = TestApi.source_default_window_size();
    let decode_ceiling = keyhog_core::ScanConfig::default().max_decode_bytes;

    assert!(
        window > decode_ceiling,
        "window ({window}) no longer exceeds the decode ceiling ({decode_ceiling}), so a \
         full-size window CAN now be decode-expanded and KH-532's structural gap is gone. \
         This is the good outcome. Delete this test, update the pinned constants above, \
         and flip DecodeOversizeSkip from WARN to FAIL."
    );
}
