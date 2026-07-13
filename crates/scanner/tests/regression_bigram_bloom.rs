//! Regression coverage for the Layer-0.5 bigram-bloom prefilter
//! (`crates/scanner/src/bigram_bloom.rs`), driven ONLY through the public
//! `keyhog_scanner::testing::BigramBloom` facade (`from_literal_prefixes`,
//! `maybe_overlaps`, and the derived `Clone`).
//!
//! ## What the table is (so every expected value below is exact)
//!
//! `bigram_slot(a, b) == ((a as usize) << 8) | b as usize` addresses one of
//! 65536 bits. It is a DIRECT table, not a hash bloom: `maybe_overlaps(chunk)`
//! returns `true` iff `chunk` contains at least one bigram whose bit is set,
//! and `false` otherwise, with ZERO probabilistic slack. Therefore for any
//! NON-saturated table and a 2-byte chunk `[a, b]`, `maybe_overlaps` equals
//! exactly `bit(a, b)`: every assertion here is a concrete `bool`.
//!
//! `from_literal_prefixes` construction rules under test:
//!   * a >=2-byte literal `L` sets each adjacent bigram of `L`, PLUS the full
//!     "row" of its terminal byte (`last || any`) as a forward extension;
//!   * a 1-byte literal sets the full row of that single byte (`byte || any`);
//!   * an empty literal (and an empty list) sets nothing;
//!   * a "row" is directional: `insert_row(a)` sets `(a, *)`, never `(*, a)`.
//!
//! `maybe_overlaps` escapes:
//!   * `chunk.len() < 2` -> conservatively `true` (no bigram exists to reject);
//!   * `saturated` (popcount*5 >= 65536*3, i.e. >= 39322 set bits) -> `true`
//!     unconditionally, so a genuinely-absent bigram flips `false -> true`.
//!
//! No is_empty()/is_ok()/len()>0 shape checks: every assertion is a value.

use keyhog_scanner::testing::BigramBloom;

// Concrete literal bytes referenced throughout (GitHub PAT prefix `ghp_`):
//   g = 0x67, h = 0x68, p = 0x70, '_' = 0x5F, 'A' = 0x41, 'z' = 0x7A.

/// Build a bloom from `&str` prefixes (mirrors a detector's literal set).
fn bloom(prefixes: &[&str]) -> BigramBloom {
    let owned: Vec<String> = prefixes.iter().map(|s| s.to_string()).collect();
    BigramBloom::from_literal_prefixes(&owned)
}

/// Literals that produce `128` pure single-byte rows (0x00..=0x7F) plus
/// `two_byte_count` distinct 2-byte-UTF-8 terminal rows (0x80..). Single-byte
/// literals add NO interior bigram; each 2-byte literal adds one interior
/// bigram in row 0xC2 plus a fresh terminal row. Used to straddle the exact
/// saturation threshold. See the module `python`-verified arithmetic:
///   popcount = (128 + K) * 256 + K.
fn saturation_literals(two_byte_count: u32) -> Vec<String> {
    let mut v: Vec<String> = (0u32..0x80)
        .map(|cp| char::from_u32(cp).expect("ascii scalar").to_string())
        .collect();
    for cp in 0x80u32..(0x80 + two_byte_count) {
        v.push(char::from_u32(cp).expect("2-byte scalar").to_string());
    }
    v
}

// ─────────────────────────────────────────────────────────────────────────
// Positive: every adjacent bigram of a literal sets its exact bit
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adjacent_bigrams_of_ghp_underscore_probe_true() {
    let b = bloom(&["ghp_"]);
    // The three adjacent bigrams of "ghp_": (g,h), (h,p), (p,_).
    assert_eq!(b.maybe_overlaps(b"gh"), true, "(g,h) bit set");
    assert_eq!(b.maybe_overlaps(b"hp"), true, "(h,p) bit set");
    assert_eq!(b.maybe_overlaps(b"p_"), true, "(p,_) bit set");
}

#[test]
fn terminal_row_admits_any_following_byte() {
    // Terminal byte of "ghp_" is '_' (0x5F); its whole row (_,*) is set.
    let b = bloom(&["ghp_"]);
    assert_eq!(b.maybe_overlaps(b"_A"), true, "(_,'A') in terminal row");
    assert_eq!(b.maybe_overlaps(b"_0"), true, "(_,'0') in terminal row");
    assert_eq!(b.maybe_overlaps(b"_ "), true, "(_,space) in terminal row");
    assert_eq!(b.maybe_overlaps(b"_\x00"), true, "(_,0x00) in terminal row");
    assert_eq!(b.maybe_overlaps(b"_\xFF"), true, "(_,0xFF) in terminal row");
}

// ─────────────────────────────────────────────────────────────────────────
// Negative-twin: absent, non-adjacent, reversed, and cross-row bigrams
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn nonadjacent_and_reversed_bigrams_probe_false() {
    let b = bloom(&["ghp_"]);
    // (g,p) skips 'h' -> never adjacent in "ghp_"; g is not a set row byte.
    assert_eq!(b.maybe_overlaps(b"gp"), false, "(g,p) not adjacent");
    // Reversed adjacency (h,g) is a distinct slot from (g,h) and unset.
    assert_eq!(b.maybe_overlaps(b"hg"), false, "(h,g) reversed is unset");
    // Reversed (p,h) vs the set (h,p).
    assert_eq!(b.maybe_overlaps(b"ph"), false, "(p,h) reversed is unset");
    // Wholly unrelated bigram.
    assert_eq!(b.maybe_overlaps(b"XY"), false, "(X,Y) never inserted");
}

#[test]
fn row_is_directional_prefix_not_suffix() {
    // insert_row('_') sets ('_', *) but NOT (*, '_'). 'A' (0x41) is not a set
    // row byte and (A,_) is not an adjacent bigram of "ghp_".
    let b = bloom(&["ghp_"]);
    assert_eq!(
        b.maybe_overlaps(b"A_"),
        false,
        "(A,_) is NOT in the '_' row"
    );
    assert_eq!(b.maybe_overlaps(b"_A"), true, "('_',A) IS in the '_' row");
}

// ─────────────────────────────────────────────────────────────────────────
// One-byte and empty literals
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn single_byte_literal_sets_full_row_only() {
    // "x" (0x78) is a 1-byte literal -> row ('x', *) fully set; no other row.
    let b = bloom(&["x"]);
    assert_eq!(b.maybe_overlaps(b"xQ"), true, "('x',Q) in the 'x' row");
    assert_eq!(
        b.maybe_overlaps(b"x\xFF"),
        true,
        "('x',0xFF) in the 'x' row"
    );
    // Reverse (Q,x) is a different row that was never set.
    assert_eq!(b.maybe_overlaps(b"Qx"), false, "(Q,'x') not in any set row");
    // Fully unrelated pair.
    assert_eq!(b.maybe_overlaps(b"ab"), false, "(a,b) unset");
}

#[test]
fn empty_list_admits_no_two_byte_bigram() {
    let b = bloom(&[]);
    assert_eq!(b.maybe_overlaps(b"gh"), false, "no literals -> (g,h) unset");
    assert_eq!(b.maybe_overlaps(b"_A"), false, "no literals -> (_,A) unset");
    assert_eq!(b.maybe_overlaps(b"\xFF\x00"), false, "no literals -> unset");
}

#[test]
fn empty_string_literal_is_ignored() {
    // A single empty-string literal must behave exactly like the empty list.
    let b = bloom(&[""]);
    assert_eq!(b.maybe_overlaps(b"gh"), false, "empty literal sets nothing");
    assert_eq!(b.maybe_overlaps(b"_z"), false, "empty literal sets nothing");
}

// ─────────────────────────────────────────────────────────────────────────
// Multiple literals: union of bits, no cross-contamination
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn multiple_literals_union_with_cross_negative() {
    // "AKIA" (AWS access-key prefix) -> bigrams (A,K),(K,I),(I,A) + row 'A'.
    // "ghp_" -> bigrams (g,h),(h,p),(p,_) + row '_'.
    let b = bloom(&["AKIA", "ghp_"]);
    // Interior bigrams from both literals are present.
    assert_eq!(b.maybe_overlaps(b"AK"), true, "(A,K) from AKIA");
    assert_eq!(b.maybe_overlaps(b"KI"), true, "(K,I) from AKIA");
    assert_eq!(b.maybe_overlaps(b"IA"), true, "(I,A) from AKIA");
    assert_eq!(b.maybe_overlaps(b"gh"), true, "(g,h) from ghp_");
    // Row 'A' (terminal of AKIA) admits any follower.
    assert_eq!(b.maybe_overlaps(b"AZ"), true, "('A',Z) in the 'A' row");
    // Cross-negative: (K,g) mixes the two literals; K has no row, not adjacent.
    assert_eq!(b.maybe_overlaps(b"Kg"), false, "(K,g) never inserted");
}

// ─────────────────────────────────────────────────────────────────────────
// Boundary: sub-bigram chunks are conservatively admitted
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn short_chunks_are_conservatively_admitted() {
    // len < 2 -> no bigram exists to prove the chunk clean -> admit (true),
    // regardless of table contents.
    let b = bloom(&["ghp_"]);
    assert_eq!(b.maybe_overlaps(b""), true, "0-byte chunk admitted");
    assert_eq!(b.maybe_overlaps(b"g"), true, "1-byte member admitted");
    assert_eq!(b.maybe_overlaps(b"Z"), true, "1-byte non-member admitted");
    // The empty-table case still admits short chunks (escape precedes scan).
    let e = bloom(&[]);
    assert_eq!(
        e.maybe_overlaps(b"g"),
        true,
        "1-byte admitted on empty table"
    );
    // But a 2-byte non-member on the same empty table is an exact false.
    assert_eq!(e.maybe_overlaps(b"gh"), false, "2-byte non-member -> false");
}

// ─────────────────────────────────────────────────────────────────────────
// Unrolled hot loop: 4-wide group vs tail, and a clean full-walk miss
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn unrolled_loop_finds_group_and_tail_hits() {
    let b = bloom(&["ghp_"]);
    // len 2 -> single window, the minimum scanning case.
    assert_eq!(b.maybe_overlaps(b"gh"), true, "minimal 2-byte hit");
    // Hit only in the FIRST 4-wide group (window 0).
    assert_eq!(b.maybe_overlaps(b"ghzzzzz"), true, "group-0 window-0 hit");
    // len 7 -> windows 0..=5; group covers 0..3, tail covers 4,5. Put the
    // sole hit (g,h) at window index 5 (the tail).
    assert_eq!(b.maybe_overlaps(b"zzzzzgh"), true, "tail-window hit");
    // len 9 -> windows 0..=7; two 4-wide groups (0..3, 4..7). Put the hit
    // (g,h) at window index 5, inside the SECOND unrolled group.
    assert_eq!(b.maybe_overlaps(b"zzzzzghzz"), true, "second-group hit");
}

#[test]
fn clean_long_chunk_walks_to_false() {
    // 'z'(0x7A) never appears in "ghp_"; (z,z) is unset. A long run of z must
    // walk the full unrolled loop + tail and return an exact false.
    let b = bloom(&["ghp_"]);
    assert_eq!(b.maybe_overlaps(b"zzzzzzzzzzzz"), false, "12x z -> false");
    // A realistic benign line with no ghp_/'_' bigram is rejected.
    assert_eq!(
        b.maybe_overlaps(b"return the value;"),
        false,
        "benign prose rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial: high bytes and a mid-chunk '_' row hit
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn high_bytes_reject_but_mid_chunk_underscore_admits() {
    let b = bloom(&["ghp_"]);
    // (0xFF,0xFF) is not a set bigram and 0xFF has no row -> false.
    assert_eq!(
        b.maybe_overlaps(b"\xFF\xFF\xFF\xFF"),
        false,
        "all-0xFF -> false"
    );
    // A single '_' followed by any byte anywhere in the chunk hits the '_'
    // row: window ('_',0xFF) is set -> true, even amid high bytes.
    assert_eq!(
        b.maybe_overlaps(b"\xFF\xFF_\xFF"),
        true,
        "mid-chunk (_,0xFF) row hit"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Clone independence
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn clone_preserves_exact_query_results() {
    let original = bloom(&["ghp_"]);
    let copy = original.clone();
    // A set bigram and an unset bigram must agree on both handles.
    assert_eq!(copy.maybe_overlaps(b"gh"), true, "clone: (g,h) set");
    assert_eq!(copy.maybe_overlaps(b"gp"), false, "clone: (g,p) unset");
    assert_eq!(
        copy.maybe_overlaps(b"gh"),
        original.maybe_overlaps(b"gh"),
        "clone agrees with original on a set bigram"
    );
    assert_eq!(
        copy.maybe_overlaps(b"gp"),
        original.maybe_overlaps(b"gp"),
        "clone agrees with original on an unset bigram"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Saturation threshold (popcount*5 >= 65536*3, i.e. >= 39322 set bits)
//
// The probe bigram (0xC8,0xC9) is provably unset in all three tables below:
// its row 0xC8 is never set (terminal rows stop at <= 0xA5) and it is not one
// of the (0xC2,*) interior bigrams. So `false` == honest miss, `true` == the
// saturation short-circuit (the flip localizes the threshold exactly).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn pure_128_rows_below_threshold_reports_honest_false() {
    // 128 single-byte rows -> popcount == 32768 (< 39322) -> NOT saturated.
    let b = BigramBloom::from_literal_prefixes(&saturation_literals(0));
    assert_eq!(
        b.maybe_overlaps(b"\xC8\xC9"),
        false,
        "32768 bits: not saturated, absent bigram is an honest miss"
    );
    // Sanity: a genuinely-present row bit is still true (not a blanket false).
    assert_eq!(b.maybe_overlaps(b"A\xFF"), true, "row 'A' still set");
}

#[test]
fn one_below_saturation_still_reports_false() {
    // 128 + 25 rows + 25 interior bits -> popcount == 39193 (< 39322).
    let b = BigramBloom::from_literal_prefixes(&saturation_literals(25));
    assert_eq!(
        b.maybe_overlaps(b"\xC8\xC9"),
        false,
        "39193 bits: one step below threshold, still an honest miss"
    );
}

#[test]
fn crossing_saturation_flips_absent_bigram_to_true() {
    // 128 + 26 rows + 26 interior bits -> popcount == 39450 (>= 39322) ->
    // saturated -> the SAME absent bigram short-circuits to true.
    let saturated = BigramBloom::from_literal_prefixes(&saturation_literals(26));
    assert_eq!(
        saturated.maybe_overlaps(b"\xC8\xC9"),
        true,
        "39450 bits: saturated, short-circuit admits the absent bigram"
    );
    // The one-step-below control returns false for the very same chunk,
    // proving the threshold (not the bigram) is what flipped the result.
    let below = BigramBloom::from_literal_prefixes(&saturation_literals(25));
    assert_eq!(
        below.maybe_overlaps(b"\xC8\xC9"),
        false,
        "control at K=25 is false for the identical probe"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The exact fixed vectors above pin specific bit-math cases; these SWEEP the
// three contracts the Layer-0.5 prefilter must uphold across arbitrary input.
// `maybe_overlaps` is a RECALL gate, a false negative (returning `false` for a
// chunk that DOES carry a literal prefix) makes the scanner skip a chunk holding
// a real secret, so (1) and (2) are recall guarantees, not cosmetics. All three
// drive ONLY the public facade (`from_literal_prefixes` + `maybe_overlaps`),
// matching this file's black-box contract; no proptest covered this primitive
// before. Literal sets are kept small/short so the table never approaches the
// 39322-of-65536 saturation threshold, keeping the direct-table semantics exact.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// RECALL GUARANTEE (no false negatives): a chunk that contains a literal
    /// prefix `lit` (>= 2 bytes) anywhere as a contiguous substring MUST overlap
    /// the chunk necessarily carries every adjacent bigram of `lit`, all of
    /// which `from_literal_prefixes` set. A regression returning `false` here
    /// would make the prefilter silently drop the chunk (and its secret). The
    /// arbitrary `prefix`/`suffix` place the literal at any offset, including the
    /// very start or end of the chunk.
    #[test]
    fn chunk_containing_a_literal_prefix_always_overlaps(
        lit in "[A-Za-z0-9_-]{2,20}",
        prefix in prop::collection::vec(any::<u8>(), 0..24),
        suffix in prop::collection::vec(any::<u8>(), 0..24),
    ) {
        let bloom = BigramBloom::from_literal_prefixes(&[lit.clone()]);
        let mut chunk = prefix;
        chunk.extend_from_slice(lit.as_bytes());
        chunk.extend_from_slice(&suffix);
        prop_assert!(
            bloom.maybe_overlaps(&chunk),
            "recall violation: chunk containing literal {:?} did not overlap",
            lit
        );
    }

    /// RECALL MONOTONICITY under catalog growth: adding more literal prefixes can
    /// only ADD set bits, never clear them, and saturation is monotone in the bit
    /// count, so a chunk that overlaps a bloom built from `base` MUST still
    /// overlap the bloom built from `base + extra`. This locks the invariant that
    /// registering a NEW detector prefix can never cause the prefilter to start
    /// skipping a chunk it used to scan (a silent recall regression as the
    /// detector catalog grows). Only the `true ⇒ true` direction is asserted; the
    /// converse is legitimately false.
    #[test]
    fn adding_literal_prefixes_never_removes_an_overlap(
        base in prop::collection::vec("[ -~]{1,12}", 0..5),
        extra in prop::collection::vec("[ -~]{1,12}", 0..5),
        chunk in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        let base_bloom = BigramBloom::from_literal_prefixes(&base);
        let mut grown = base.clone();
        grown.extend(extra);
        let grown_bloom = BigramBloom::from_literal_prefixes(&grown);
        if base_bloom.maybe_overlaps(&chunk) {
            prop_assert!(
                grown_bloom.maybe_overlaps(&chunk),
                "monotonicity violated: growing the literal set removed an overlap"
            );
        }
    }

    /// `maybe_overlaps` must never panic on ANY chunk length or content: it
    /// byte-indexes `chunk[i]`/`chunk[i + 1]` across a 4-wide unrolled group and
    /// a tail mop-up, so an off-by-one in the group/tail split would slice out of
    /// bounds. Sweeps lengths 0..128 (every residue mod 4) over arbitrary bytes.
    #[test]
    fn maybe_overlaps_never_panics_on_arbitrary_chunk(
        literals in prop::collection::vec("[ -~]{1,16}", 0..6),
        chunk in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let bloom = BigramBloom::from_literal_prefixes(&literals);
        let _ = bloom.maybe_overlaps(&chunk);
    }
}
