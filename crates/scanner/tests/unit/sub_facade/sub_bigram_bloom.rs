//! Standalone unit coverage for `keyhog_scanner::testing::BigramBloom`.
//!
//! The selective anchor gate is soundness-critical. Short mandatory literals
//! use exact case-insensitive matching. Long literals use one double-hashed
//! eight-byte anchor. Invalid and saturated states must fail open.

use keyhog_scanner::{testing::BigramBloom, BigramPrefilterState};

// ---------------------------------------------------------------------------
// from_literal_prefixes, every prefix bigram must overlap (no false negatives)
// ---------------------------------------------------------------------------

/// Locks in exact short-anchor matching while preserving fail-open behavior for
/// chunks too short to prove that the mandatory anchor is absent.
#[test]
fn short_prefix_matches_exactly_and_too_short_chunks_fail_open() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    assert!(bloom.maybe_overlaps(b"ghp_abcdef"));
    assert!(bloom.maybe_overlaps(b"xx_GHP_yy"));
    assert!(!bloom.maybe_overlaps(b"xx gh yy"));
    assert!(bloom.maybe_overlaps(b"hp"));
}

#[test]
fn unrelated_chunk_does_not_overlap() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    assert!(!bloom.maybe_overlaps(b"QZXJWVKY"));
}

/// Prevents short inputs from becoming false negatives when no complete anchor
/// can fit inside the available bytes.
#[test]
fn chunks_shorter_than_minimum_anchor_fail_open() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    assert!(bloom.maybe_overlaps(b"_Z"));
    assert!(bloom.maybe_overlaps(b"_!"));
}

#[test]
fn empty_prefix_list_is_invalid_and_fails_open() {
    let bloom = BigramBloom::from_literal_prefixes(&[]);
    assert_eq!(bloom.status().state, BigramPrefilterState::Invalid);
    assert!(bloom.maybe_overlaps(b"anything here"));
    assert!(bloom.maybe_overlaps(b"x"));
}

// ---------------------------------------------------------------------------
// maybe_overlaps vs scalar_overlaps_reference, differential agreement
// ---------------------------------------------------------------------------

#[test]
fn unrolled_agrees_with_scalar_reference() {
    let bloom = BigramBloom::from_literal_prefixes(&[
        "ghp_".into(),
        "AKIA".into(),
        "sk_live_".into(),
        "xoxb-".into(),
    ]);
    let corpus: &[&[u8]] = &[
        b"",
        b"a",
        b"ghp_token",
        b"random words with no secret prefix here at all",
        b"AKIAIOSFODNN7EXAMPLE",
        b"sk_live_4eC39HqLyjWDarjt",
        b"the quick brown fox jumps over the lazy dog 0123456789",
        b"xoxb-1234567890-abcdef",
    ];
    for chunk in corpus {
        assert_eq!(
            bloom.maybe_overlaps(chunk),
            bloom.scalar_overlaps_reference(chunk),
            "unrolled and scalar disagree on {:?}",
            String::from_utf8_lossy(chunk)
        );
    }
}

// ---------------------------------------------------------------------------
// insert_all, public table population path
// ---------------------------------------------------------------------------

#[test]
fn long_literal_populates_the_hashed_anchor_owner() {
    let bloom = BigramBloom::from_literal_prefixes(&["abcdefghijk".into()]);
    assert!(bloom.popcount() > 0);
    assert!(bloom.maybe_overlaps(b"xxabcdefghijkyy"));
    assert!(!bloom.maybe_overlaps(b"zzzzzzzz"));
}

#[test]
fn empty_bloom_has_zero_popcount() {
    assert_eq!(BigramBloom::empty().popcount(), 0);
}

#[test]
fn popcount_grows_with_distinct_long_anchors() {
    let one = BigramBloom::from_literal_prefixes(&["abcdefghijk".into()]);
    let two = BigramBloom::from_literal_prefixes(&["abcdefghijk".into(), "ZYXWVUTSRQP".into()]);
    assert!(two.popcount() > one.popcount());
}

// ---------------------------------------------------------------------------
// saturation short-circuit, soundness (admit, never drop)
// ---------------------------------------------------------------------------

#[test]
fn empty_bloom_is_not_saturated() {
    assert!(!BigramBloom::empty().is_saturated());
}

#[test]
fn saturated_table_admits_everything() {
    let bloom = BigramBloom::saturated_for_test();
    assert!(bloom.is_saturated());
    // Even a chunk with bytes whose bigrams were never inserted is admitted,
    // because saturation short-circuits to true (sound: admit, never drop).
    assert!(bloom.maybe_overlaps(b"\xFE\xFD\xFC\xFB\xFA\xF9"));
}

#[test]
fn clone_preserves_population_and_saturation() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into(), "AKIA".into()]);
    let cloned = bloom.clone();
    assert_eq!(cloned.popcount(), bloom.popcount());
    assert_eq!(cloned.is_saturated(), bloom.is_saturated());
    assert_eq!(
        cloned.maybe_overlaps(b"ghp_x"),
        bloom.maybe_overlaps(b"ghp_x")
    );
}
