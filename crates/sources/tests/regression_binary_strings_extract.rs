//! Regression coverage for printable-string extraction in the binary source
//! (`crates/sources/src/strings.rs` + `binary/literals.rs`), reached through the
//! public `testing` facade's strings-only `BinarySource`.
//!
//! `extract_printable_strings` is `pub(crate)`, so an external integration test
//! cannot call it directly. Instead we drive the real operator path: write a
//! byte blob to a file, scan it with a strings-only `BinarySource`, and read the
//! `binary:strings` chunk whose body is the extracted runs joined by `\n`
//! (`join_sensitive_strings(&strings, "\n")`). No extracted run ever contains a
//! `\n` (newline is neither graphic nor space/tab, so it always breaks a run),
//! therefore splitting that body on `\n` recovers the exact run list.
//!
//! `MIN_STRING_LEN` is hard-wired to 8 on this path, so every threshold
//! assertion below pins the 7-drop / 8-keep boundary at that value.
//!
//! Covered: exact run above threshold, 7-vs-8 boundary, short run dropped among
//! valid ones, embedded-NUL run splitting (single + multiple), space/tab kept
//! inside a run, newline / control / high-byte delimiters, UTF-16LE wide-string
//! recovery + its below-threshold drop, the pure-ASCII no-wide-duplication twin,
//! ASCII-before-wide ordering, the all-below-threshold source-error path, and
//! the emitted chunk's `source_type`.

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

#[test]
fn single_run_of_exactly_min_len_is_extracted() {
    // "password" is exactly 8 graphic chars (== MIN_STRING_LEN); 0xFF sentinels
    // are non-graphic delimiters that never become a zero UTF-16 high byte.
    let runs = extracted_runs(b"\xFFpassword\xFF");
    assert_eq!(runs, vec!["password".to_string()]);
}

#[test]
fn seven_char_run_dropped_eight_char_run_kept() {
    // Pins the threshold: 7 graphic chars are below MIN_STRING_LEN and dropped,
    // 8 are kept. "AAAAAAA" = 7, "BBBBBBBB" = 8.
    let runs = extracted_runs(b"\xFFAAAAAAA\xFFBBBBBBBB\xFF");
    assert_eq!(runs, vec!["BBBBBBBB".to_string()]);
    assert!(
        !runs.iter().any(|r| r.contains("AAAAAAA")),
        "the 7-char run must not survive; got {runs:?}"
    );
}

#[test]
fn short_run_dropped_among_valid_runs() {
    // "validcredential" = 15 kept, "short" = 5 dropped.
    let runs = extracted_runs(b"\xFFvalidcredential\xFFshort\xFF");
    assert_eq!(runs, vec!["validcredential".to_string()]);
    assert!(
        !runs.iter().any(|r| r.contains("short")),
        "a 5-char run is below threshold and must be dropped; got {runs:?}"
    );
}

#[test]
fn embedded_nul_splits_run_into_exactly_two() {
    // A single NUL between two 8-char runs breaks the run at exactly that byte.
    // The lone 'A' the UTF-16 pass sees at the A|NUL boundary is length 1 (< 8)
    // and is dropped, so no spurious wide string appears.
    let runs = extracted_runs(b"AAAAAAAA\x00BBBBBBBB");
    assert_eq!(runs, vec!["AAAAAAAA".to_string(), "BBBBBBBB".to_string()]);
}

#[test]
fn multiple_nuls_split_into_exactly_three_runs() {
    // Runs: 14 / 13 / 12 chars, separated by 3 and 2 NULs. Each graphic char
    // immediately before a NUL yields only a length-1 UTF-16 candidate (dropped),
    // so the ASCII pass alone defines the result.
    let runs = extracted_runs(b"COMMITHASH1234\x00\x00\x00DEPLOYTOKEN99\x00\x00FINALSEGMENT");
    assert_eq!(
        runs,
        vec![
            "COMMITHASH1234".to_string(),
            "DEPLOYTOKEN99".to_string(),
            "FINALSEGMENT".to_string(),
        ]
    );
}

#[test]
fn space_and_tab_are_kept_within_a_run() {
    // Space (0x20) and tab (0x09) are treated as printable and stay inside a run;
    // "key = value123" (with two spaces) is one 14-char run.
    let spaces = extracted_runs(b"\xFFkey = value123\xFF");
    assert_eq!(spaces, vec!["key = value123".to_string()]);

    // Tab likewise stays inside: "token\tvalue" is 11 chars, one run.
    let tabbed = extracted_runs(b"\xFFtoken\tvalue\xFF");
    assert_eq!(tabbed, vec!["token\tvalue".to_string()]);
}

#[test]
fn newline_breaks_a_run_unlike_space_and_tab() {
    // Newline (0x0A) is neither graphic nor space/tab, so it is a delimiter:
    // "firsthalf" (9) and "secondhalf" (10) become two separate runs.
    let runs = extracted_runs(b"\xFFfirsthalf\nsecondhalf\xFF");
    assert_eq!(
        runs,
        vec!["firsthalf".to_string(), "secondhalf".to_string()]
    );
}

#[test]
fn control_and_high_bytes_break_runs() {
    // 0x07 (BEL), 0x1F (unit sep), and high bytes 0x80/0x90/0xFF are all
    // non-printable delimiters; only the two 10-char graphic runs survive.
    let runs = extracted_runs(b"\x07\x80segmentone\x1F\x90segmenttwo\xFF");
    assert_eq!(
        runs,
        vec!["segmentone".to_string(), "segmenttwo".to_string()]
    );
}

#[test]
fn utf16le_wide_string_is_recovered() {
    // Each ASCII byte followed by 0x00 (UTF-16LE): the ASCII pass sees only
    // length-1 runs (all dropped), but the wide pass reconstructs the 9-char
    // "SECRETKEY". This is the encoding the ASCII pass alone would miss.
    let runs = extracted_runs(b"S\x00E\x00C\x00R\x00E\x00T\x00K\x00E\x00Y\x00");
    assert_eq!(runs, vec!["SECRETKEY".to_string()]);
}

#[test]
fn pure_ascii_text_is_not_wide_duplicated() {
    // Negative twin for the wide pass: on pure ASCII every high byte is non-zero,
    // so the UTF-16LE pass never matches and adds no spurious duplicate. Exactly
    // one 20-char run, not two.
    let runs = extracted_runs(b"\xFFhelloworldfromkeyhog\xFF");
    assert_eq!(runs, vec!["helloworldfromkeyhog".to_string()]);
    assert_eq!(runs.len(), 1, "pure ASCII must not be wide-doubled");
}

#[test]
fn wide_run_below_threshold_dropped_ascii_run_kept() {
    // Wide "ABCDEFG" is 7 decoded chars (< 8) and is dropped; the trailing ASCII
    // "KEEPME12" is exactly 8 and survives. Proves the wide pass honors the same
    // threshold and re-aligns past the 0xFF sentinel.
    let runs = extracted_runs(b"A\x00B\x00C\x00D\x00E\x00F\x00G\x00\xFFKEEPME12\xFF");
    assert_eq!(runs, vec!["KEEPME12".to_string()]);
    assert!(
        !runs.iter().any(|r| r.contains("ABCDEFG")),
        "a 7-char wide run must be dropped; got {runs:?}"
    );
}

#[test]
fn ascii_runs_precede_wide_runs_in_output() {
    // extract_printable_strings appends the ASCII pass first, then the UTF-16LE
    // pass, so ordering is deterministic: ASCII "PLAINTEXTRUN" (12) then wide
    // "WIDERUNX" (8).
    let runs = extracted_runs(b"\xFFPLAINTEXTRUN\xFFW\x00I\x00D\x00E\x00R\x00U\x00N\x00X\x00");
    assert_eq!(
        runs,
        vec!["PLAINTEXTRUN".to_string(), "WIDERUNX".to_string()]
    );
    assert_eq!(runs[0], "PLAINTEXTRUN");
    assert_eq!(runs[1], "WIDERUNX");
}

#[test]
fn all_runs_below_threshold_yields_source_error_not_empty_chunk() {
    // "short" (5) and "tiny" (4) are both below threshold; with no NULs there is
    // no wide candidate either, so nothing is extractable. The source must NOT
    // report a clean file — it emits exactly one SourceError row (Law 10).
    let rows = source_rows(b"\xFFshort\xFFtiny\xFF");
    assert_eq!(
        rows.len(),
        1,
        "an all-sub-threshold binary must yield exactly one visible row"
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
fn extracted_runs_are_emitted_in_a_single_binary_strings_chunk() {
    // The extraction result is delivered as exactly one chunk whose source_type
    // is "binary:strings" (not e.g. a section or ghidra chunk on this path).
    let rows = source_rows(b"\xFFalphaonewinnerstring\xFF");
    let strings_chunks: Vec<&Chunk> = rows
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .filter(|c| c.metadata.source_type.as_ref() == "binary:strings")
        .collect();
    assert_eq!(
        strings_chunks.len(),
        1,
        "exactly one binary:strings chunk expected"
    );
    assert_eq!(
        strings_chunks[0].metadata.source_type.as_ref(),
        "binary:strings"
    );
    assert_eq!(
        strings_chunks[0].data.to_string(),
        "alphaonewinnerstring",
        "the sole run must be the chunk body verbatim"
    );
}
