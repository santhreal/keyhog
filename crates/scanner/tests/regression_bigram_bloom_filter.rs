//! Regression coverage for the Layer-0.5 bigram-bloom prefilter
//! (`crates/scanner/src/bigram_bloom.rs`), exercised through the standalone
//! `keyhog_scanner::testing::BigramBloom` facade.
//!
//! The prefilter is a 65536-bit DIRECT lookup table indexed by
//! `bigram_slot(a, b) == (a as usize) << 8 | b as usize`. Because it is a
//! direct table (not a hash bloom) it has documented ZERO false positives:
//! `maybe_overlaps` returns `true` iff the chunk contains at least one bigram
//! whose bit was set, and `false` otherwise with no probabilistic slack.
//! That lets every "absent bigram" assertion below check an EXACT `false`.
//!
//! Construction rules under test (`from_literal_prefixes`):
//!   * a >=2-byte literal `L` sets every adjacent bigram of `L`, PLUS the
//!     full "row" of its terminal byte (`last || any`) as an extension;
//!   * a 1-byte literal sets the full row of that single byte;
//!   * an empty literal (or empty list) sets nothing.
//!
//! Every assertion is a concrete `bool`. No is_empty()/is_ok() shape checks.

use keyhog_scanner::testing::BigramBloom;

/// Convenience: build a bloom from `&str` prefixes.
fn bloom(prefixes: &[&str]) -> BigramBloom {
    let owned: Vec<String> = prefixes.iter().map(|s| s.to_string()).collect();
    BigramBloom::from_literal_prefixes(&owned)
}

// ─────────────────────────────────────────────────────────────────────────
// Present-bigram (positive) coverage
// ─────────────────────────────────────────────────────────────────────────

/// A GitHub-PAT prefix `ghp_` sets bigrams `gh`, `hp`, `p_`, and the full
/// terminal row `_ || any`. Every one of those must probe positive.
#[test]
fn present_bigrams_from_ghp_prefix_probe_true() {
    let b = bloom(&["ghp_"]);
    // Each individual inserted bigram, in isolation.
    assert_eq!(b.maybe_overlaps(b"gh"), true, "bigram 'gh' was inserted");
    assert_eq!(b.maybe_overlaps(b"hp"), true, "bigram 'hp' was inserted");
    assert_eq!(b.maybe_overlaps(b"p_"), true, "bigram 'p_' was inserted");
    // Terminal-row extension: '_' followed by ANY byte.
    assert_eq!(b.maybe_overlaps(b"_Z"), true, "'_' row is fully set");
    assert_eq!(b.maybe_overlaps(b"_\x00"), true, "'_' row includes NUL");
    // A realistic PAT-bearing chunk overlaps via 'gh'.
    assert_eq!(b.maybe_overlaps(b"token=ghp_016CabcDEF"), true);
}

/// A realistic GitHub-PAT chunk hits; a benign Java-ish chunk that contains
/// none of {gh, hp, p_, (_ , *)} misses exactly.
#[test]
fn github_pat_recall_and_benign_source_rejection() {
    let b = bloom(&["ghp_"]);
    assert_eq!(b.maybe_overlaps(b"Authorization: ghp_ZZZ"), true);
    // "public class Main": no 'gh', no 'hp', no 'p_', and no underscore, so
    // no set bigram is present -> exact false (direct table, zero FP).
    assert_eq!(b.maybe_overlaps(b"public class Main"), false);
}

// ─────────────────────────────────────────────────────────────────────────
// Absent-bigram (negative) coverage — exact false, no false positives
// ─────────────────────────────────────────────────────────────────────────

/// A bigram never inserted must probe `false`. The direct table guarantees
/// zero false positives, so this is an exact expectation, not "usually".
#[test]
fn known_absent_bigram_probes_false() {
    let b = bloom(&["ghp_"]);
    // 'X'==0x58, 'Y'==0x59: (0x58,0x59) is not gh/hp/p_ and 'X' is not the
    // terminal '_' row, so its bit is unset.
    assert_eq!(b.maybe_overlaps(b"XY"), false);
    // 'q'..'z' pair likewise absent.
    assert_eq!(b.maybe_overlaps(b"qz"), false);
}

/// Bigram order is significant: `gh` was inserted but its reverse `hg` was
/// not, and `_h` (terminal-row extension) is set but `h_` is not.
#[test]
fn bigram_order_is_significant_negative_twin() {
    let b = bloom(&["ghp_"]);
    assert_eq!(b.maybe_overlaps(b"gh"), true, "forward 'gh' inserted");
    assert_eq!(
        b.maybe_overlaps(b"hg"),
        false,
        "reverse 'hg' never inserted"
    );
    assert_eq!(
        b.maybe_overlaps(b"_h"),
        true,
        "'_' terminal row -> '_h' set"
    );
    assert_eq!(b.maybe_overlaps(b"h_"), false, "'h_' is not a set bigram");
}

// ─────────────────────────────────────────────────────────────────────────
// Exact bit math on a tiny two-byte fixture
// ─────────────────────────────────────────────────────────────────────────

/// Literal `"AB"` sets exactly: the single bigram (A,B) AND the full row of
/// the terminal byte B (`B || any`). Crucially the FIRST byte A does NOT get
/// a full row. So:
///   * (A,B) is set, but (A,C) is NOT  -> A's row is partial (one bit).
///   * (B,*) is fully set              -> B's row is complete.
///   * (C,*) is untouched.
/// This pins the precise per-row bit population, not just "something matched".
#[test]
fn exact_bit_math_partial_first_row_full_terminal_row() {
    let b = bloom(&["AB"]);

    // A's row is a SINGLE bit: only (A,B).
    assert_eq!(b.maybe_overlaps(b"AB"), true, "(A,B) inserted");
    assert_eq!(b.maybe_overlaps(b"AC"), false, "A's row has only (A,B)");
    assert_eq!(b.maybe_overlaps(b"AA"), false, "(A,A) not set");

    // B's row is FULL: (B, anything) is set.
    assert_eq!(b.maybe_overlaps(b"BA"), true, "(B,A) in full B row");
    assert_eq!(b.maybe_overlaps(b"BC"), true, "(B,C) in full B row");
    assert_eq!(b.maybe_overlaps(b"B\x00"), true, "(B,NUL) in full B row");

    // C's row is empty; B only matches as the FIRST byte (via its row),
    // never as the second byte of an unrelated pair.
    assert_eq!(b.maybe_overlaps(b"CA"), false, "C's row is empty");
    assert_eq!(
        b.maybe_overlaps(b"CB"),
        false,
        "(C,B) not set: B is not a full column"
    );
}

/// A 1-byte literal sets the full row of that byte and nothing else. `"x"`
/// (0x78) => (x, *) all set; nothing where x is the SECOND byte.
#[test]
fn one_byte_literal_sets_full_row_only() {
    let b = bloom(&["x"]);
    assert_eq!(b.maybe_overlaps(b"xQ"), true, "(x,Q) in full x row");
    assert_eq!(b.maybe_overlaps(b"x\x00"), true, "(x,NUL) in full x row");
    assert_eq!(b.maybe_overlaps(b"xx"), true, "(x,x) in full x row");
    // x as the SECOND byte is not covered.
    assert_eq!(b.maybe_overlaps(b"Qx"), false, "(Q,x): Q's row is empty");
    assert_eq!(b.maybe_overlaps(b"yx"), false, "(y,x): y's row is empty");
}

/// The terminal-byte extension row is the mechanism that lets a truncated
/// prefix still admit the real secret. `"sk_live_"` terminates in '_', so
/// `_ || any` is set, while an unrelated pair stays false.
#[test]
fn terminal_extension_row_vs_unrelated_pair() {
    let b = bloom(&["sk_live_"]);
    assert_eq!(b.maybe_overlaps(b"_9"), true, "'_' terminal row set");
    assert_eq!(b.maybe_overlaps(b"sk"), true, "leading bigram 'sk' set");
    // 'q'..'z' pair is neither an inserted bigram nor the terminal row.
    assert_eq!(b.maybe_overlaps(b"qz"), false);
}

// ─────────────────────────────────────────────────────────────────────────
// Idempotence and order independence of insertion
// ─────────────────────────────────────────────────────────────────────────

/// Inserting the same literal twice is idempotent: bits are OR-ed, so the
/// resulting membership function is bit-identical. We assert both the exact
/// per-probe values AND that the doubled bloom agrees on every probe.
#[test]
fn duplicate_literal_insertion_is_idempotent() {
    let once = bloom(&["AB"]);
    let twice = bloom(&["AB", "AB"]);

    // Concrete anchors so this is not a pure equality tautology.
    assert_eq!(once.maybe_overlaps(b"AB"), true);
    assert_eq!(once.maybe_overlaps(b"AC"), false);

    for probe in [
        &b"AB"[..],
        b"AC",
        b"BA",
        b"CA",
        b"zz",
        b"B\x00",
        b"QQ",
        b"AA",
        b"CB",
    ] {
        assert_eq!(
            once.maybe_overlaps(probe),
            twice.maybe_overlaps(probe),
            "duplicate insertion changed membership for {probe:?}",
        );
    }
}

/// Literal order does not affect the table: `["AB","CD"]` and `["CD","AB"]`
/// yield identical membership. Anchored with concrete truth values.
#[test]
fn literal_order_is_independent() {
    let fwd = bloom(&["AB", "CD"]);
    let rev = bloom(&["CD", "AB"]);

    // Concrete truths shared by both.
    assert_eq!(fwd.maybe_overlaps(b"AB"), true, "(A,B) bigram");
    assert_eq!(fwd.maybe_overlaps(b"CD"), true, "(C,D) bigram");
    assert_eq!(
        fwd.maybe_overlaps(b"DA"),
        true,
        "(D,A) in full D terminal row"
    );
    assert_eq!(
        fwd.maybe_overlaps(b"AD"),
        false,
        "A row partial: (A,D) unset"
    );

    for probe in [&b"AB"[..], b"CD", b"DA", b"AD", b"BD", b"BA", b"ZZ"] {
        assert_eq!(
            fwd.maybe_overlaps(probe),
            rev.maybe_overlaps(probe),
            "literal order changed membership for {probe:?}",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Empty / degenerate construction
// ─────────────────────────────────────────────────────────────────────────

/// An empty literal list produces a bloom with no bits set: every >=2-byte
/// chunk misses exactly, while <2-byte chunks are conservatively admitted.
#[test]
fn empty_literal_list_rejects_all_bigrams() {
    let b = bloom(&[]);
    assert_eq!(b.maybe_overlaps(b"hello world"), false, "no bit set");
    assert_eq!(b.maybe_overlaps(b"AB"), false, "no bit set");
    // Sub-bigram chunks cannot be proven clean -> admitted.
    assert_eq!(b.maybe_overlaps(b"x"), true);
    assert_eq!(b.maybe_overlaps(b""), true);
}

/// An empty-string literal contributes nothing; the bloom behaves like the
/// empty-list case and rejects a concrete two-byte chunk.
#[test]
fn empty_string_literal_is_ignored() {
    let b = bloom(&[""]);
    assert_eq!(b.maybe_overlaps(b"ab"), false);
    assert_eq!(b.maybe_overlaps(b"ZZ"), false);
}

// ─────────────────────────────────────────────────────────────────────────
// Sub-bigram chunks: conservative admission
// ─────────────────────────────────────────────────────────────────────────

/// Chunks shorter than two bytes cannot form a bigram, so `maybe_overlaps`
/// conservatively returns `true` regardless of table contents (never a false
/// negative).
#[test]
fn sub_bigram_chunks_are_conservatively_admitted() {
    let b = bloom(&["AB"]);
    assert_eq!(b.maybe_overlaps(b"A"), true, "1-byte chunk admitted");
    assert_eq!(b.maybe_overlaps(b"Z"), true, "1-byte non-member admitted");
    assert_eq!(b.maybe_overlaps(b""), true, "empty chunk admitted");
}

// ─────────────────────────────────────────────────────────────────────────
// Unrolled hot-loop coverage: 4-wide group + tail, plus full no-hit walk
// ─────────────────────────────────────────────────────────────────────────

/// The hot loop unrolls 4 windows per group then mops up a tail of <4. A hit
/// that lands only in the tail window must still be found, and a chunk with
/// no set bigram must walk to completion and return exactly false.
#[test]
fn unrolled_scan_finds_tail_hit_and_reports_clean_miss() {
    let b = bloom(&["AB"]);
    // len 7 -> windows 0..=5; group covers 0..3, tail covers windows 4,5.
    // The only matching bigram (A,B) sits at window index 5 (the tail).
    assert_eq!(b.maybe_overlaps(b"zzzzzAB"), true, "tail-window (A,B) hit");
    // len 9 -> hit in the second 4-wide group.
    assert_eq!(
        b.maybe_overlaps(b"zzzzzzzAB"),
        true,
        "second-group (A,B) hit"
    );
    // No matching bigram anywhere: (z,z) is never set -> exact false after a
    // full unrolled + tail walk.
    assert_eq!(
        b.maybe_overlaps(b"zzzzzzzzzz"),
        false,
        "clean full walk -> false"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Saturation short-circuit
// ─────────────────────────────────────────────────────────────────────────

/// Once the set-bit fraction crosses 3/5 of 65536 (>= 39322 bits) the table
/// is "saturated" and `maybe_overlaps` short-circuits to `true` for EVERY
/// chunk, even one whose sole bigram was never inserted. We build a saturated
/// table from 192 distinct terminal rows (192 * 256 == 49152 bits) and probe
/// a bigram (0xC8,0xC9) whose row/bit is provably unset; saturation forces
/// `true`. A tiny non-saturated bloom returns the honest `false` for the same
/// chunk, proving the short-circuit is what flips the result.
#[test]
fn saturated_table_short_circuits_absent_bigram_to_true() {
    // Code points 0x00..=0x7F -> 1-byte literals -> rows 0x00..=0x7F (128).
    // Code points 0x80..=0xBF -> 2-byte UTF-8 (0xC2 0x80..0xC2 0xBF) whose
    // terminal bytes give rows 0x80..=0xBF (64 more). Rows 0x00..=0xBF are
    // disjoint => 192 full rows => 49152 set bits > 39322 threshold.
    let literals: Vec<String> = (0u32..0xC0)
        .map(|cp| char::from_u32(cp).expect("valid scalar").to_string())
        .collect();
    let saturated = BigramBloom::from_literal_prefixes(&literals);

    // (0xC8,0xC9): first byte 0xC8 has no set row (rows stop at 0xBF), and it
    // is not one of the (0xC2, *) inserted bigrams -> its bit is unset.
    let probe: &[u8] = b"\xC8\xC9";

    // Non-saturated control: this same chunk misses exactly.
    let tiny = bloom(&["AB"]);
    assert_eq!(
        tiny.maybe_overlaps(probe),
        false,
        "control: bigram is genuinely absent"
    );

    // Saturated table admits it anyway via the short-circuit.
    assert_eq!(
        saturated.maybe_overlaps(probe),
        true,
        "saturated table must short-circuit an absent bigram to true",
    );
}
