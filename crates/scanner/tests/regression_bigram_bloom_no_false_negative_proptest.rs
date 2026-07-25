//! Property invariant for the selective literal-anchor prefilter's hot path:
//! it may admit false positives but must never reject a chunk containing any
//! compiled mandatory literal alternative. Such a false negative would skip the
//! direct matcher before AC/HS can confirm the credential.
//!
//! Short alternatives are owned by one exact ASCII-case-insensitive automaton.
//! Long alternatives select one measured-frequency eight-byte anchor and store
//! two stable hash bits. This proptest sweeps thousands of literal, position,
//! and surrounding-byte combinations through the public production constructor.
//! The invariant is structural: embedding a complete literal must always admit.

use keyhog_scanner::testing::BigramBloom;
use proptest::prelude::*;

/// Printable-ASCII so `String::from_utf8` round-trips the exact bytes the bloom
/// and the chunk share (the bloom is built from `&[String]`).
fn ascii_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("ascii bytes are valid utf8")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// No false negative: a filter built from `literal` must report `true` for
    /// any chunk that contains the complete literal, regardless of surrounding
    /// bytes or position.
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

        // Every compiled alternative owns an exact short literal or a mandatory
        // selected eight-byte window, so embedding the literal must admit.
        prop_assert!(
            bloom.maybe_overlaps(&chunk),
            "false negative: bloom over {:?} missed a chunk containing it (pre_len={}, post_len={})",
            ascii_string(&literal), pre.len(), post.len()
        );
    }
}

/// Deterministic position sweep for an exact short mandatory alternative.
///
/// `from_literal_prefixes(["~!"])` places the two-byte literal in the exact
/// short-anchor owner. Prefixing it with every filler length proves a complete
/// alternative remains reachable at the front, middle, and tail of a chunk.
#[test]
fn exact_short_anchor_is_detected_at_every_position() {
    let bloom = BigramBloom::from_literal_prefixes(&["~!".to_string()]);
    for k in 0..=24usize {
        let mut chunk = vec![b'A'; k];
        chunk.extend_from_slice(b"~!");
        assert!(
            bloom.maybe_overlaps(&chunk),
            "false negative at tail: length {} (filler {} + ~!), last window missed",
            chunk.len(),
            k
        );
    }
}

/// Non-vacuity guard: `maybe_overlaps` must still reject text containing no
/// mandatory alternative. A chunk of only `A` bytes does not contain `"~!"`.
#[test]
fn maybe_overlaps_filters_a_chunk_with_no_mandatory_anchor() {
    let bloom = BigramBloom::from_literal_prefixes(&["~!".to_string()]);
    assert!(
        !bloom.maybe_overlaps(&vec![b'A'; 64]),
        "prefilter has no filtering value, maybe_overlaps returned true for a clean chunk"
    );
}
