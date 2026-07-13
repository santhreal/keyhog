//! Direct boundary lock for the decode-density gate `has_decodable_payload`
//! (crates/scanner/src/decode/mod.rs). This gate routes an otherwise
//! prefilter-skipped, fully-encoded chunk into decode-through, so a silent
//! drift of any threshold shrinks recall invisibly. It was `pub(crate)` with no
//! test seam (unlike ~40 sibling decode internals); the
//! `has_decodable_payload_for_test` facade added alongside these tests lets us
//! pin the exact boundaries:
//!   * MIN_DECODABLE_RUN     = 24 contiguous base64/hex-alphabet bytes
//!   * MIN_PERCENT_ESCAPES   = 4  `%XX` escapes
//!   * MIN_BACKSLASH_ESCAPES = 2  `\u`/`\x` escapes
//!
//! Every assertion pins an exact bool at the on/off boundary, never a fuzzy
//! "looks encoded" check. Host-independent: a pure allocation-free byte scan,
//! no accelerator involved.
#![cfg(feature = "decode")]

use keyhog_scanner::testing::has_decodable_payload_for_test as gate;

// ── base64/hex contiguous run: 23 off, 24 on ────────────────────────────────

#[test]
fn base64_run_of_23_is_below_threshold() {
    // One byte short of MIN_DECODABLE_RUN(24): not worth decoding.
    let run = "a".repeat(23);
    assert_eq!(run.len(), 23);
    assert!(
        !gate(run.as_bytes()),
        "a 23-byte base64 run must be rejected"
    );
}

#[test]
fn base64_run_of_24_hits_threshold() {
    let run = "a".repeat(24);
    assert_eq!(run.len(), 24);
    assert!(
        gate(run.as_bytes()),
        "a 24-byte base64 run must be accepted"
    );
}

#[test]
fn hex_run_shares_the_same_24_byte_threshold() {
    // Hex digits are a subset of the base64 alphabet, so a 24-hex run also fires
    // while 23 does not.
    let below = "deadbeefdeadbeefdeadbee".to_string(); // 23
    let at = "deadbeefdeadbeefdeadbeef".to_string(); // 24
    assert_eq!(below.len(), 23);
    assert_eq!(at.len(), 24);
    assert!(!gate(below.as_bytes()));
    assert!(gate(at.as_bytes()));
}

#[test]
fn a_single_non_alphabet_byte_resets_the_run() {
    // 23 base64 + a space + 23 base64: neither side reaches 24, so the space
    // resets the run and the gate stays closed.
    let split = format!("{} {}", "a".repeat(23), "b".repeat(23));
    assert!(
        !gate(split.as_bytes()),
        "a reset run must not accumulate across a gap"
    );
    // But 24 on one side of the gap DOES fire.
    let one_side = format!("{} {}", "a".repeat(24), "b".repeat(5));
    assert!(gate(one_side.as_bytes()));
}

// ── percent escapes: 3 off, 4 on ────────────────────────────────────────────

#[test]
fn three_percent_escapes_are_below_threshold() {
    // 3 `%XX` < MIN_PERCENT_ESCAPES(4).
    assert!(!gate(b"%41%42%43"), "3 percent escapes must be rejected");
}

#[test]
fn four_percent_escapes_hit_threshold() {
    // A trailing byte follows the last escape so the `i + 2 < len` guard counts it.
    assert!(gate(b"%41%42%43%44X"), "4 percent escapes must be accepted");
}

#[test]
fn a_lone_percent_without_two_hex_digits_is_not_an_escape() {
    // "%zz" is not a valid %XX (z is not hex) and "%4" is truncated: neither
    // counts, so four malformed percents stay below threshold.
    assert!(
        !gate(b"%zz%4%%z"),
        "malformed percents must not count as escapes"
    );
}

// ── backslash escapes: 1 off, 2 on ──────────────────────────────────────────

#[test]
fn one_backslash_u_escape_is_below_threshold() {
    // Single `A` < MIN_BACKSLASH_ESCAPES(2).
    assert!(!gate(b"\\u0041"), "1 backslash-u escape must be rejected");
}

#[test]
fn two_backslash_u_escapes_hit_threshold() {
    assert!(
        gate(b"\\u0041\\u0042"),
        "2 backslash-u escapes must be accepted"
    );
}

#[test]
fn backslash_x_escapes_share_the_two_escape_threshold() {
    // `\xNN` (2 hex) uses the same counter as `\uNNNN`.
    assert!(!gate(b"\\x41"), "1 backslash-x escape must be rejected");
    assert!(
        gate(b"\\x41\\x42"),
        "2 backslash-x escapes must be accepted"
    );
}

// ── negatives: ordinary text carries no decodable shape ─────────────────────

#[test]
fn plain_prose_has_no_decodable_payload() {
    assert!(
        !gate(b"the quick brown fox jumps over the lazy dog"),
        "ordinary prose (short words, no escapes) must be rejected"
    );
}

#[test]
fn empty_input_is_rejected() {
    assert!(!gate(b""), "empty input has no decodable payload");
}
