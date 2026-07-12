//! Property invariant for the bigram-bloom prefilter's HOT path
//! (`bigram_bloom::maybe_overlaps`, Layer-0.5): it may admit false positives but
//! must NEVER produce a false NEGATIVE — a chunk that contains a bigram present
//! in the table must return `true`. A false negative here is a SILENTLY skipped
//! chunk (`scan_with_deadline_and_backend`'s `bigram_ok` gate), i.e. a real
//! credential dropped before AC/HS ever runs — a Law-10-class recall bug.
//!
//! The existing coverage (`unit/bigram_bloom::no_false_negatives_for_inserted_patterns`
//! and `sub_facade::sub_bigram_bloom::unrolled_agrees_with_scalar_reference`) is
//! EXAMPLE-based over a handful of fixed chunks. `maybe_overlaps` processes four
//! windows per group (`while i + 4 <= last_start + 1`) then a scalar tail loop —
//! index arithmetic whose off-by-one failure modes only surface at specific
//! chunk-length-mod-4 classes with the sole present bigram sitting in the TAIL
//! region. This proptest sweeps thousands of (table, chunk, position) tuples so
//! a present bigram lands at every offset — including each tail slot — closing
//! that boundary gap.
//!
//! Only the `pub` facade surface is used (`from_literal_prefixes`, the PRODUCTION
//! construction path, + `maybe_overlaps`); the `#[cfg(test)]` scalar reference is
//! lib-test-only, so the invariant is asserted structurally (a chunk that
//! embeds a literal must overlap) rather than differentially.

use keyhog_scanner::testing::BigramBloom;
use proptest::prelude::*;

/// Printable-ASCII so `String::from_utf8` round-trips the exact bytes the bloom
/// and the chunk share (the bloom is built from `&[String]`).
fn ascii_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("ascii bytes are valid utf8")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// No false negative: a bloom built from `literal` (≥2 bytes, so it has at
    /// least one bigram) must report `true` for any chunk that CONTAINS that
    /// literal, regardless of how much filler precedes/follows it — so the
    /// present bigram is exercised at every unroll offset (group body AND tail).
    #[test]
    fn embedded_literal_is_never_a_false_negative(
        literal in prop::collection::vec(0x21u8..=0x7e, 2..10),
        pre in prop::collection::vec(0x21u8..=0x7e, 0..80),
        post in prop::collection::vec(0x21u8..=0x7e, 0..80),
    ) {
        let bloom = BigramBloom::from_literal_prefixes(&[ascii_string(&literal)]);

        let mut chunk = pre.clone();
        chunk.extend_from_slice(&literal);
        chunk.extend_from_slice(&post);

        // The literal's own first bigram (literal[0], literal[1]) is in the table
        // and appears verbatim in `chunk`, so a correct prefilter MUST admit it.
        prop_assert!(
            bloom.maybe_overlaps(&chunk),
            "false negative: bloom over {:?} missed a chunk containing it (pre_len={}, post_len={})",
            ascii_string(&literal), pre.len(), post.len()
        );
    }
}

/// Deterministic tail-boundary sweep: place the ONLY present bigram at the very
/// LAST window for every chunk length across the unroll's group/tail classes.
///
/// `from_literal_prefixes(["~!"])` sets exactly the `(~,!)` bigram plus the
/// widened `(!, *)` row. Filler byte `A` (0x41) forms no present bigram with
/// itself or with `~` (it is neither `!` nor part of the `~!` bigram), so in
/// `"A"*k + "~!"` the sole present bigram `(~,!)` sits at window index `k` — the
/// final window. If the tail loop (`while i <= last_start`) were off-by-one it
/// would miss this window and report a false negative.
#[test]
fn present_bigram_at_final_window_is_detected_for_every_length_class() {
    let bloom = BigramBloom::from_literal_prefixes(&["~!".to_string()]);
    for k in 0..=24usize {
        let mut chunk = vec![b'A'; k];
        chunk.extend_from_slice(b"~!");
        assert!(
            bloom.maybe_overlaps(&chunk),
            "false negative at tail: length {} (filler {} + ~!) — last window missed",
            chunk.len(),
            k
        );
    }
}

/// Non-vacuity guard: `maybe_overlaps` must actually FILTER (return `false`)
/// when no present bigram exists — otherwise the no-false-negative assertions
/// above would pass trivially on an always-`true` function. A chunk of only `A`
/// bytes shares no bigram with the `(~,!)`/`(!, *)` table.
#[test]
fn maybe_overlaps_filters_a_chunk_with_no_present_bigram() {
    let bloom = BigramBloom::from_literal_prefixes(&["~!".to_string()]);
    assert!(
        !bloom.maybe_overlaps(&vec![b'A'; 64]),
        "prefilter has no filtering value — maybe_overlaps returned true for a clean chunk"
    );
}
