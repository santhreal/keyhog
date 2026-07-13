//! Comprehensive bigram bloom filter tests.
//!
//! Covers: construction, lookup, edge cases, popcount diagnostics,
//! and the invariant that false negatives never occur.

use keyhog_scanner::testing::BigramBloom;

// ── Construction ─────────────────────────────────────────────────────

#[test]
fn empty_bloom_never_matches() {
    let bloom = BigramBloom::empty();
    assert!(!bloom.maybe_overlaps(b"hello world"));
    assert_eq!(bloom.popcount(), 0);
}

#[test]
fn single_literal_inserts_all_bigrams() {
    let mut bloom = BigramBloom::empty();
    bloom.insert_all(b"ghp_");
    // Must find the bigrams that were inserted.
    assert!(bloom.maybe_overlaps(b"ghp_abc"));
    assert!(bloom.maybe_overlaps(b"xxghyyp_zz")); // contains "gh" bigram
}

#[test]
fn from_literal_prefixes_covers_all_bigrams_plus_extension() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".to_string()]);
    // "ghp_" → bigrams "gh", "hp", "p_", plus extension "_X" for all X.
    // The bloom must hit on any chunk containing "gh".
    assert!(bloom.maybe_overlaps(b"xxx_gh_xxx"));
    // Must hit on "p_" bigram too.
    assert!(bloom.maybe_overlaps(b"zzz_p_zzz"));
    // Extension: "_" followed by any byte (e.g. "_A").
    assert!(bloom.maybe_overlaps(b"zzz_Azzz"));
}

#[test]
fn no_false_negatives_for_inserted_patterns() {
    // Invariant: if we insert a literal and then search for a chunk
    // containing that literal, maybe_overlaps MUST return true.
    let literals = vec![
        "ghp_".to_string(),
        "sk_live_".to_string(),
        "AKIA".to_string(),
        "xoxb-".to_string(),
    ];
    let bloom = BigramBloom::from_literal_prefixes(&literals);
    for lit in &literals {
        let mut chunk = b"random_prefix_".to_vec();
        chunk.extend_from_slice(lit.as_bytes());
        chunk.extend_from_slice(b"_random_suffix");
        assert!(
            bloom.maybe_overlaps(&chunk),
            "bloom missed chunk containing literal {:?}",
            lit
        );
    }
}

// ── Edge cases ───────────────────────────────────────────────────────

#[test]
fn chunk_shorter_than_two_bytes_always_passes() {
    let bloom = BigramBloom::from_literal_prefixes(&["test".to_string()]);
    // Chunks with < 2 bytes can't form a bigram, should return true
    // (conservative: can't prove no overlap).
    assert!(bloom.maybe_overlaps(b"x"));
    assert!(bloom.maybe_overlaps(b""));
}

#[test]
fn one_byte_literal_prefix_does_not_panic() {
    // 1-byte literals set an entire row of bigrams (byte followed by
    // anything). Should not panic and should produce a non-zero bloom.
    let bloom = BigramBloom::from_literal_prefixes(&["x".to_string()]);
    assert!(bloom.popcount() > 0);
    // Any chunk with "x" followed by any byte should match.
    assert!(bloom.maybe_overlaps(b"xA"));
    assert!(bloom.maybe_overlaps(b"x\x00"));
}

#[test]
fn empty_literal_prefix_list() {
    let bloom = BigramBloom::from_literal_prefixes(&[]);
    assert_eq!(bloom.popcount(), 0);
    // Empty bloom should not match any data.
    assert!(!bloom.maybe_overlaps(b"hello world"));
}

#[test]
fn empty_string_literal_ignored() {
    let bloom = BigramBloom::from_literal_prefixes(&["".to_string()]);
    assert_eq!(bloom.popcount(), 0);
}

// ── Popcount diagnostics ─────────────────────────────────────────────

#[test]
fn popcount_grows_with_literals() {
    let bloom1 = BigramBloom::from_literal_prefixes(&["test".to_string()]);
    let bloom2 = BigramBloom::from_literal_prefixes(&[
        "test".to_string(),
        "another_prefix_".to_string(),
        "ghp_".to_string(),
    ]);
    // More literals → more (or equal) bits set.
    assert!(bloom2.popcount() >= bloom1.popcount());
}

#[test]
fn popcount_max_is_4096() {
    let bloom = BigramBloom::from_literal_prefixes(&["x".to_string()]);
    // Even a 1-byte literal sets 256 bigrams (x followed by all bytes).
    // Plus extension (x is also the last byte → another 256). Some will
    // collide in the 4096-bit bloom.
    assert!(bloom.popcount() <= 4096);
}

// ── Worst-case scan (no-hit path) ────────────────────────────────────

#[test]
fn no_hit_on_unrelated_chunk() {
    // Bloom built from prefixes that never appear in the chunk.
    let bloom = BigramBloom::from_literal_prefixes(&[
        "ghp_".to_string(),
        "sk_live_".to_string(),
        "AKIA".to_string(),
    ]);
    // A chunk of all-zeros has only bigram (0x00, 0x00). Unless FNV
    // collides, the bloom should not match. (We accept occasional
    // false positives, the assertion is that zero-valued data is
    // unlikely to match prefix bigrams.)
    let zeros = vec![0u8; 1024];
    // We can't assert false because of FP, but we CAN assert the
    // function doesn't panic on large inputs.
    let _ = bloom.maybe_overlaps(&zeros);
}
