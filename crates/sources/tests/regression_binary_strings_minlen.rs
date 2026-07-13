//! Regression coverage that pins the `MIN_STRING_LEN` (== 8) boundary of the
//! binary source's printable-string extractor (`crates/sources/src/strings.rs`,
//! reached through the strings-only `BinarySource`).
//!
//! `extract_printable_strings` / `MIN_STRING_LEN` are `pub(crate)`, so an
//! external integration test cannot call them directly. Instead we drive the
//! real operator path: write a byte blob to a file, scan it with a strings-only
//! `BinarySource` (via the `testing` facade, so Ghidra is never consulted and
//! the result is host-independent), and read the `binary:strings` chunk whose
//! body is the extracted runs joined by `\n`. No extracted run can contain a
//! `\n` (newline is neither graphic nor space/tab, so it always breaks a run),
//! therefore splitting the body on `\n` recovers the exact run list.
//!
//! The bytes written here are never a valid ELF/PE/Mach-O/archive magic, so
//! goblin's section pass returns `None` and the only emitted chunk is the
//! whole-file `binary:strings` chunk. When NOTHING reaches the threshold the
//! source must NOT report a clean file, it emits exactly one `SourceError`
//! row (Law 10), which the boundary-drop tests below assert on.
//!
//! Distinct from `regression_binary_strings_extract.rs`: that file surveys the
//! extractor broadly; this file drills the 6/7/8/9 length boundary from every
//! angle, alone-drop, alone-keep, leading/trailing EOF flush, whitespace and
//! symbol runs counting toward length, capacity-growth of a long run, the
//! UTF-16LE wide pass honouring the identical 7-drop/8-keep threshold, and a
//! planted secret surfacing verbatim.

#![cfg(feature = "binary")]

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};

/// Scan `bytes` as a strings-only binary and return every row (chunks + errors).
fn source_rows(bytes: &[u8]) -> Vec<Result<Chunk, SourceError>> {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join("fixture.bin");
    std::fs::write(&path, bytes).expect("write fixture bytes");
    // `dir` stays alive until end of fn; `.chunks().collect()` reads the file now.
    TestApi.binary_strings_only(path.clone()).chunks().collect()
}

/// The exact extracted-run list: the `binary:strings` chunk body split on `\n`.
fn extracted_runs(bytes: &[u8]) -> Vec<String> {
    let rows = source_rows(bytes);
    let mut lines = Vec::new();
    for row in &rows {
        if let Ok(chunk) = row {
            if chunk.metadata.source_type.as_ref() == "binary:strings" {
                let body = chunk.data.to_string();
                for line in body.split('\n') {
                    lines.push(line.to_string());
                }
            }
        }
    }
    lines
}

/// Assert `bytes` yields NO `binary:strings` chunk and exactly one `SourceError`
/// naming the no-coverage gap (the below-threshold / nothing-extractable path).
fn assert_nothing_extractable(bytes: &[u8]) {
    let rows = source_rows(bytes);
    assert_eq!(
        rows.len(),
        1,
        "a nothing-extractable binary must yield exactly one visible row, got {}",
        rows.len()
    );
    let msg = match &rows[0] {
        Ok(chunk) => panic!(
            "expected a SourceError, got chunk source_type={}",
            chunk.metadata.source_type
        ),
        Err(err) => err.to_string(),
    };
    assert!(
        msg.contains("yielded no scannable sections or printable strings")
            && msg.contains("no binary bytes were scanned"),
        "error must name the no-strings coverage gap; got {msg}"
    );
}

#[test]
fn run_of_six_alone_is_below_threshold_and_extracts_nothing() {
    // 6 graphic chars ("SIXCHR") < MIN_STRING_LEN (8); with no NULs there is no
    // wide candidate either, so the source reports a no-coverage error, never a
    // clean file.
    assert_nothing_extractable(b"\xFFSIXCHR\xFF");
}

#[test]
fn run_of_seven_alone_is_below_threshold_and_extracts_nothing() {
    // Boundary minus one: exactly 7 graphic chars ("SEVENCH") is still dropped.
    // Pins that the keep threshold is strictly greater than 7.
    assert_nothing_extractable(b"\xFFSEVENCH\xFF");
}

#[test]
fn run_of_exactly_eight_alone_is_kept_verbatim() {
    // Exactly MIN_STRING_LEN: "EIGHTLTR" is 8 graphic chars and is the sole run.
    let runs = extracted_runs(b"\xFFEIGHTLTR\xFF");
    assert_eq!(runs, vec!["EIGHTLTR".to_string()]);
}

#[test]
fn run_of_nine_is_kept_verbatim() {
    // One above the boundary: "NINELTRSX" is 9 graphic chars, kept intact.
    let runs = extracted_runs(b"\xFFNINELTRSX\xFF");
    assert_eq!(runs, vec!["NINELTRSX".to_string()]);
}

#[test]
fn eight_char_run_before_six_char_run_keeps_only_the_eight() {
    // Order-reversed boundary twin: the 8-char run comes first, the 6-char run
    // second. Only "KEEPER88" (8) survives; "DROP66" (6) is dropped.
    let runs = extracted_runs(b"\xFFKEEPER88\xFFDROP66\xFF");
    assert_eq!(runs, vec!["KEEPER88".to_string()]);
    assert!(
        !runs.iter().any(|r| r.contains("DROP66")),
        "the 6-char run must not survive; got {runs:?}"
    );
}

#[test]
fn eight_spaces_count_toward_length_and_are_kept() {
    // Adversarial: a run of 8 space bytes (0x20) is exactly MIN_STRING_LEN long
    // because space is treated as printable and counts toward the length. The
    // whole-space run is kept verbatim (and never wide-doubled: 0x20 is a
    // non-zero UTF-16 high byte).
    let mut bytes = vec![0xFF_u8];
    bytes.extend(std::iter::repeat(b' ').take(8));
    bytes.push(0xFF);
    let runs = extracted_runs(&bytes);
    assert_eq!(runs, vec![" ".repeat(8)]);
    assert_eq!(runs.len(), 1, "the space run must not be wide-duplicated");
}

#[test]
fn seven_spaces_are_below_threshold_and_dropped() {
    // Boundary twin of the above from the drop side: 7 space bytes are one short
    // of MIN_STRING_LEN, so nothing is extractable.
    let mut bytes = vec![0xFF_u8];
    bytes.extend(std::iter::repeat(b' ').take(7));
    bytes.push(0xFF);
    assert_nothing_extractable(&bytes);
}

#[test]
fn symbol_and_digit_run_at_exactly_eight_is_kept() {
    // Graphic set includes digits and punctuation. "a1_-b2.:" is 8 graphic
    // chars (letters, digits, '_', '-', '.', ':') and is kept at the boundary.
    let runs = extracted_runs(b"\xFFa1_-b2.:\xFF");
    assert_eq!(runs, vec!["a1_-b2.:".to_string()]);
}

#[test]
fn long_run_of_128_chars_is_kept_without_capacity_truncation() {
    // The extractor's `String::with_capacity(64)` is a hint, not a cap; a run far
    // longer than 64 chars must survive intact. 128 'x' bytes, kept verbatim.
    let long = "x".repeat(128);
    let mut bytes = vec![0xFF_u8];
    bytes.extend_from_slice(long.as_bytes());
    bytes.push(0xFF);
    let runs = extracted_runs(&bytes);
    assert_eq!(runs, vec![long]);
}

#[test]
fn leading_run_at_offset_zero_of_exactly_eight_is_kept() {
    // A run that begins at byte 0 (no leading delimiter) is still accumulated and
    // flushed at its trailing NUL. "LEADING8" is 8 chars. (0x4C 0x45 start is not
    // an ELF/PE/Mach magic, so the section pass returns None.)
    let runs = extracted_runs(b"LEADING8\x00");
    assert_eq!(runs, vec!["LEADING8".to_string()]);
}

#[test]
fn trailing_run_at_eof_of_exactly_eight_is_flushed() {
    // A run that ends at EOF with no trailing delimiter is flushed by the
    // post-loop tail check. "TRAILER8" (8 chars) sits at the end of the buffer.
    let runs = extracted_runs(b"\x00TRAILER8");
    assert_eq!(runs, vec!["TRAILER8".to_string()]);
}

#[test]
fn trailing_run_at_eof_of_seven_is_dropped() {
    // Boundary twin of the tail flush: a 7-char run at EOF ("TRAIL77") is one
    // short of the threshold, so the tail check drops it and nothing surfaces.
    assert_nothing_extractable(b"\x00TRAIL77");
}

#[test]
fn utf16le_wide_run_of_exactly_eight_is_recovered() {
    // The UTF-16LE pass honours the identical threshold: "WIDE1234" encoded as
    // X 00 pairs is exactly 8 decoded chars and is recovered, even though the
    // ASCII pass sees only length-1 runs interrupted by each 0x00.
    let runs = extracted_runs(b"W\x00I\x00D\x00E\x001\x002\x003\x004\x00");
    assert_eq!(runs, vec!["WIDE1234".to_string()]);
}

#[test]
fn utf16le_wide_run_of_seven_is_below_threshold_and_dropped() {
    // Boundary minus one on the wide path: "WIDE123" is 7 decoded chars and is
    // dropped; the ASCII pass only sees length-1 runs, so nothing is extractable.
    assert_nothing_extractable(b"W\x00I\x00D\x00E\x001\x002\x003\x00");
}

#[test]
fn single_graphic_bytes_between_delimiters_never_reach_threshold() {
    // Eight individual graphic chars each separated by a 0xFF delimiter: every
    // ASCII run is length 1 (< 8) and the wide pass never matches (0xFF is a
    // non-zero high byte), so length never accumulates across delimiters and
    // nothing is extractable. Pins that length is per contiguous run.
    assert_nothing_extractable(b"A\xFFB\xFFC\xFFD\xFFE\xFFF\xFFG\xFFH\xFF");
}

#[test]
fn planted_secret_in_binary_noise_surfaces_verbatim() {
    // A 20-char AWS-shaped access key planted amid non-graphic noise is above the
    // threshold and surfaces as the exact, sole run, the operator-visible point
    // of the whole extractor.
    let mut bytes = vec![0x00_u8, 0x01, 0x02];
    bytes.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
    bytes.extend_from_slice(&[0x00, 0xFF]);
    let runs = extracted_runs(&bytes);
    assert_eq!(runs, vec!["AKIAIOSFODNN7EXAMPLE".to_string()]);
}
