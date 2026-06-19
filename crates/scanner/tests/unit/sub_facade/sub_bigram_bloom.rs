//! Standalone unit coverage for `keyhog_scanner::testing::BigramBloom`.
//!
//! The bloom is a soundness-critical prefilter: it may admit false positives
//! but must NEVER drop a chunk whose bigram is present. These tests assert the
//! exact no-false-negative contract (every inserted bigram overlaps), the
//! agreement of the unrolled `maybe_overlaps` with the scalar reference, the
//! terminal-byte row widening, and the saturation short-circuit — real values,
//! never `is_empty`.

use keyhog_scanner::testing::BigramBloom;

// ---------------------------------------------------------------------------
// from_literal_prefixes — every prefix bigram must overlap (no false negatives)
// ---------------------------------------------------------------------------

#[test]
fn inserted_prefix_bigrams_overlap() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    // The exact prefix and any text containing one of its bigrams overlaps.
    assert!(bloom.maybe_overlaps(b"ghp_abcdef"));
    assert!(bloom.maybe_overlaps(b"xx gh yy")); // "gh" bigram present
    assert!(bloom.maybe_overlaps(b"hp")); // "hp" bigram present
}

#[test]
fn unrelated_chunk_does_not_overlap() {
    // A bloom keyed only on "ghp_" must reject a chunk with none of its bigrams.
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    // "QZ" / "ZQ" / "Q9" never appear in ghp_ bigrams or the `_`/`p` rows...
    // but the terminal-byte row widening sets the whole `_X` row. Pick bytes
    // that avoid `g`,`h`,`p`,`_` adjacencies entirely.
    assert!(!bloom.maybe_overlaps(b"QZXJWVKY"));
}

#[test]
fn terminal_byte_row_is_widened() {
    // "ghp_" widens so the terminal '_' may be followed by ANY byte: `_` + any.
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    assert!(bloom.maybe_overlaps(b"_Z")); // "_Z" is in the widened `_` row
    assert!(bloom.maybe_overlaps(b"_!")); // "_!" too
}

#[test]
fn empty_prefix_list_rejects_normal_chunks() {
    let bloom = BigramBloom::from_literal_prefixes(&[]);
    // No bits set, not saturated -> a 2+ byte chunk has no overlap.
    assert!(!bloom.maybe_overlaps(b"anything here"));
    // ...but a <2-byte chunk is conservatively admitted (cannot prove clean).
    assert!(bloom.maybe_overlaps(b"x"));
}

// ---------------------------------------------------------------------------
// maybe_overlaps vs scalar_overlaps_reference — differential agreement
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
// insert_all — public table population path
// ---------------------------------------------------------------------------

#[test]
fn insert_all_sets_each_bigram() {
    let mut bloom = BigramBloom::empty();
    bloom.insert_all(b"abc");
    // "ab" and "bc" are now present; "zz" is not.
    assert!(bloom.maybe_overlaps(b"ab"));
    assert!(bloom.maybe_overlaps(b"bc"));
    assert!(!bloom.maybe_overlaps(b"zz"));
}

#[test]
fn empty_bloom_has_zero_popcount() {
    assert_eq!(BigramBloom::empty().popcount(), 0);
}

#[test]
fn popcount_grows_with_inserts() {
    let mut bloom = BigramBloom::empty();
    let before = bloom.popcount();
    bloom.insert_all(b"abcdef");
    assert!(
        bloom.popcount() > before,
        "inserting bigrams must raise popcount"
    );
}

// ---------------------------------------------------------------------------
// saturation short-circuit — soundness (admit, never drop)
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
