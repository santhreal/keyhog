//! Regression coverage for the source crate's binary-vs-text detection
//! predicate (`decode::looks_binary`, surfaced via `TestApi::looks_binary`)
//! and the filesystem skip-reason accounting it drives.
//!
//! This is DISTINCT from `regression_binary_strings_minlen` (which exercises
//! the goblin string-extraction min-length floor) and from the density/NUL
//! boundary cases already pinned in `regression_skip_rules`: here every case
//! targets a specific arm of the classifier that those files do NOT cover —
//! the magic-header short-circuit (ELF / PNG / Python-pickle-protocol-2), the
//! UTF-8-BOM-is-text vs UTF-16-BOM-is-binary asymmetry, embedded-vs-scattered
//! NUL runs, the exact 5%-control density threshold, the whitespace-exempt vs
//! vertical-tab-suspicious split, and the `decode_utf16` BOM dispatch. The
//! final test proves the end-to-end skip REASON: an extensionless NUL-run file
//! lands in the `SkipCounts::binary` bucket (and nowhere else) while a
//! BOM-prefixed sibling is still scanned.
//!
//! Every assertion pins a concrete value: an exact classifier bool, an exact
//! decoded `String`, or an exact `SkipCounts` field integer. No `is_empty` /
//! `is_some` / `len() > 0`-only assertions.
#![cfg(feature = "binary")]

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::fs;

/// Serializes the process-global skip counters across the parallel tests in
/// this binary (each integration-test file is its own process, so a file-local
/// mutex is sufficient — mirrors `regression_skip_rules.rs`). Held for the
/// whole `reset -> scan -> read skip_counts()` window.
static SKIP_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
    SKIP_COUNTER_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn body_present(rows: &[Result<Chunk, SourceError>], needle: &str) -> bool {
    rows.iter()
        .any(|row| matches!(row, Ok(chunk) if chunk.data.contains(needle)))
}

// --------------------------------------------------------------------------
// Base cases: empty and plain text are NOT binary.
// --------------------------------------------------------------------------

#[test]
fn empty_input_is_text() {
    // `total == 0` short-circuits the density scan to `false`.
    assert!(
        !TestApi.looks_binary(b""),
        "an empty buffer must classify as text, not binary"
    );
}

#[test]
fn plain_ascii_config_is_text() {
    let text = b"[service]\nAPI_KEY=sk_live_0123456789abcdef\nhost=example.com\n";
    assert!(
        !TestApi.looks_binary(text),
        "clean ASCII config text must classify as text"
    );
}

// --------------------------------------------------------------------------
// NUL runs: 4 consecutive NULs (BINARY_NUL_RUN) is the boundary, wherever it
// sits; scattered single NULs below the suspicious floor are NOT a run.
// --------------------------------------------------------------------------

#[test]
fn embedded_nul_run_is_binary_but_scattered_nuls_are_text() {
    // A 4-NUL run in the MIDDLE of otherwise-text bytes is binary (the run
    // detector scans the whole buffer, not just the prefix).
    let embedded = b"hello\x00\x00\x00\x00world";
    assert!(
        TestApi.looks_binary(embedded),
        "an embedded 4-byte NUL run must classify as binary"
    );
    // Three NULs that never sit consecutively: no run, and only 3 suspicious
    // bytes (below the 4-byte suspicious floor) -> text.
    let scattered = b"a\x00b\x00c\x00";
    assert!(
        !TestApi.looks_binary(scattered),
        "three non-consecutive NULs are neither a run nor over the density floor -> text"
    );
    // Boundary: exactly three consecutive NULs is one short of the run length.
    assert!(
        !TestApi.looks_binary(b"\x00\x00\x00"),
        "a 3-byte NUL run is one below BINARY_NUL_RUN (4) -> text"
    );
}

// --------------------------------------------------------------------------
// BOM asymmetry: a UTF-8 BOM prefix stays TEXT; a UTF-16 BOM prefix is
// treated as binary by `looks_binary` (routed to `decode_utf16` elsewhere).
// --------------------------------------------------------------------------

#[test]
fn utf8_bom_prefixed_text_is_text() {
    // EF BB BF are all >= 0x20, carry no NUL run, and match no binary magic:
    // a UTF-8-BOM config must remain text so its secret stays scannable.
    let bom_text = b"\xEF\xBB\xBFTOKEN=ghp_bom_prefixed_but_still_text";
    assert!(
        !TestApi.looks_binary(bom_text),
        "a UTF-8 BOM (EF BB BF) prefixed text file must classify as text"
    );
}

#[test]
fn utf16_le_bom_prefix_is_binary_with_len_guard() {
    // FF FE at a >= 4-byte buffer matches the UTF-16 NUL-pattern arm -> binary.
    assert!(
        TestApi.looks_binary(&[0xFFu8, 0xFE, 0x41, 0x00]),
        "a >=4-byte FF FE (UTF-16 LE BOM) buffer must classify as binary"
    );
    // The arm is guarded on len >= 4: a 3-byte FF FE 41 buffer misses it, and
    // FF/FE/41 are all >= 0x20 so density does not fire either -> text.
    assert!(
        !TestApi.looks_binary(&[0xFFu8, 0xFE, 0x41]),
        "a 3-byte FF FE buffer is below the len>=4 UTF-16 guard -> text"
    );
}

#[test]
fn utf16_be_bom_prefix_is_binary() {
    assert!(
        TestApi.looks_binary(&[0xFEu8, 0xFF, 0x00, 0x41]),
        "a >=4-byte FE FF (UTF-16 BE BOM) buffer must classify as binary"
    );
}

// --------------------------------------------------------------------------
// Magic-header short-circuit: format magic classifies as binary even when the
// control-byte density is low. Each has a plain-text twin that does NOT match.
// --------------------------------------------------------------------------

#[test]
fn elf_magic_is_binary_but_text_mentioning_elf_is_not() {
    assert!(
        TestApi.looks_binary(b"\x7fELF\x02\x01\x01\x00"),
        "a \\x7fELF magic prefix must classify as binary via the magic arm"
    );
    assert!(
        !TestApi.looks_binary(b"ELF is the executable format on Linux"),
        "plain prose that merely mentions ELF must classify as text"
    );
}

#[test]
fn png_magic_is_binary_but_text_mentioning_png_is_not() {
    // The PNG signature carries 0x1A (a suspicious control) but the magic arm
    // short-circuits before density is ever consulted.
    assert!(
        TestApi.looks_binary(b"\x89PNG\r\n\x1a\n"),
        "the \\x89PNG signature must classify as binary via the magic arm"
    );
    assert!(
        !TestApi.looks_binary(b"PNG files are raster images"),
        "plain prose that merely mentions PNG must classify as text"
    );
}

#[test]
fn pickle_protocol2_magic_is_binary_but_protocol3_prefix_is_not() {
    // Only the exact protocol-2 opcode prefix (\x80\x02) is treated as magic.
    assert!(
        TestApi.looks_binary(b"\x80\x02X\x03\x00\x00\x00abc"),
        "a Python pickle protocol-2 (\\x80\\x02) prefix must classify as binary"
    );
    // \x80\x03 (protocol 3) is NOT the recognized magic; 0x80 is >= 0x20 and
    // there is a single control (0x03) -> below the floor -> text.
    assert!(
        !TestApi.looks_binary(b"\x80\x03plain trailing ascii payload here"),
        "a pickle protocol-3 (\\x80\\x03) prefix is not the recognized magic -> text"
    );
}

// --------------------------------------------------------------------------
// Density threshold: binary iff suspicious >= 4 AND suspicious*20 > total
// (strictly more than 5% C0 controls). Exercised at the exact tipping point.
// --------------------------------------------------------------------------

#[test]
fn control_density_threshold_is_exclusive_at_five_percent() {
    // 4 controls in 79 bytes: 4*20 = 80 > 79 -> binary (just over 5%).
    let mut just_over = vec![b'a'; 75];
    just_over.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]);
    assert_eq!(just_over.len(), 79);
    assert!(
        TestApi.looks_binary(&just_over),
        "4 C0 controls in 79 bytes exceed 5% (80 > 79) -> binary"
    );
    // 4 controls in 80 bytes: 4*20 = 80 is NOT > 80 -> exactly 5% is text.
    let mut exactly_five_pct = vec![b'a'; 76];
    exactly_five_pct.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]);
    assert_eq!(exactly_five_pct.len(), 80);
    assert!(
        !TestApi.looks_binary(&exactly_five_pct),
        "4 C0 controls in 80 bytes is exactly 5% (80 not > 80) -> text"
    );
}

// --------------------------------------------------------------------------
// Whitespace controls (\t \n \r 0x0C) are exempt from the suspicious count;
// other C0 controls such as 0x0B (vertical tab) are NOT.
// --------------------------------------------------------------------------

#[test]
fn whitespace_controls_exempt_vertical_tab_suspicious() {
    // 256 bytes of nothing but exempt whitespace controls -> text.
    let whitespace = b"\t\n\r\x0C".repeat(64);
    assert_eq!(whitespace.len(), 256);
    assert!(
        !TestApi.looks_binary(&whitespace),
        "a buffer of only \\t \\n \\r \\x0C (all exempt) must classify as text"
    );
    // 0x0C (form feed) is in the exempt set inside `looks_binary`: 4 of them
    // stay text (distinct from the scan-path sanitizer, which strips 0x0C).
    assert!(
        !TestApi.looks_binary(&[0x0Cu8, 0x0C, 0x0C, 0x0C]),
        "0x0C is exempt in looks_binary -> a 4-byte run of it is text"
    );
    // 0x0B (vertical tab) is NOT exempt: 4 in a 4-byte buffer is 100% controls.
    assert!(
        TestApi.looks_binary(&[0x0Bu8, 0x0B, 0x0B, 0x0B]),
        "0x0B is a suspicious control -> a dense 4-byte run is binary"
    );
}

// --------------------------------------------------------------------------
// UTF-16 BOM dispatch: `decode_utf16` decodes LE and BE payloads and returns
// None when no BOM is present.
// --------------------------------------------------------------------------

#[test]
fn decode_utf16_le_be_roundtrip_and_no_bom_none() {
    // LE BOM (FF FE) then 'h','i' as little-endian u16 units.
    assert_eq!(
        TestApi.decode_utf16(&[0xFFu8, 0xFE, 0x68, 0x00, 0x69, 0x00]),
        Some("hi".to_string()),
        "FF FE + LE units must decode to \"hi\""
    );
    // BE BOM (FE FF) then 'h','i' as big-endian u16 units.
    assert_eq!(
        TestApi.decode_utf16(&[0xFEu8, 0xFF, 0x00, 0x68, 0x00, 0x69]),
        Some("hi".to_string()),
        "FE FF + BE units must decode to \"hi\""
    );
    // No BOM -> the dispatch returns None (caller falls back to UTF-8 paths).
    assert_eq!(
        TestApi.decode_utf16(b"hello"),
        None,
        "a buffer without a UTF-16 BOM must return None from decode_utf16"
    );
}

// --------------------------------------------------------------------------
// End-to-end skip REASON: an extensionless NUL-run file is skipped and lands
// in the `binary` bucket exactly once (and no other bucket), while a
// BOM-prefixed sibling is still scanned and its secret surfaced.
// --------------------------------------------------------------------------

#[test]
fn extensionless_nul_run_counts_as_binary_skip_while_bom_text_is_scanned() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();

    // Extensionless file: a few text bytes, then a 4-NUL run (within the 1024-
    // byte prefix sniff), then a secret that must NOT be scanned.
    let nul_sentinel = "NULRUN_SKIP_SENTINEL_ab12";
    let mut blob = b"prefix".to_vec();
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(format!("TOKEN={nul_sentinel}\n").as_bytes());
    fs::write(dir.path().join("blob"), &blob).unwrap();

    // UTF-8 BOM config: the BOM is stripped by the text decode path, so the
    // secret IS scanned. Proves "BOM text is text" end to end.
    let bom_sentinel = "BOMTEXT_SCANNED_SENTINEL_cd34";
    let mut cfg = vec![0xEFu8, 0xBB, 0xBF];
    cfg.extend_from_slice(format!("API_KEY={bom_sentinel}\n").as_bytes());
    fs::write(dir.path().join("config.env"), &cfg).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<Result<Chunk, SourceError>> = source.chunks().collect();

    assert!(
        body_present(&rows, bom_sentinel),
        "the UTF-8 BOM config must be scanned (BOM stripped, secret surfaced)"
    );
    assert!(
        !body_present(&rows, nul_sentinel),
        "the extensionless NUL-run file must be skipped unread"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.binary, 1,
        "the NUL-run file must increment the binary skip counter exactly once"
    );
    assert_eq!(
        counts.over_max_size, 0,
        "a binary skip must not be misattributed as an over-size skip"
    );
    assert_eq!(
        counts.excluded, 0,
        "a binary skip must not be misattributed as a default-exclude skip"
    );
    assert_eq!(
        counts.unreadable, 0,
        "a binary skip must not be misattributed as an unreadable skip"
    );
    assert_eq!(
        counts.git_lfs_pointer, 0,
        "a plain NUL-run blob must not be recorded as a git-lfs pointer"
    );
    assert_eq!(
        counts.total(),
        1,
        "exactly one file (the binary blob) was skipped in this scan"
    );
}
