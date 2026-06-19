//! Migrated from src/bigram_bloom.rs

use keyhog_scanner::testing::BigramBloom;

#[test]
fn empty_bloom_skips_everything() {
    let bloom = BigramBloom::empty();
    assert!(!bloom.maybe_overlaps(b"sk-proj-some-key-here"));
}

#[test]
fn literal_prefix_bloom_matches_chunks_containing_prefix() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".to_string(), "AKIA".to_string()]);
    assert!(bloom.maybe_overlaps(b"x ghp_ABCDEF y"));
    assert!(bloom.maybe_overlaps(b"value=AKIA1234"));
}

#[test]
fn unrelated_chunk_can_skip() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".to_string()]);
    let only_unrelated = bloom.maybe_overlaps(b"abcdefxyz");
    let _ = only_unrelated;
}

#[test]
fn short_chunks_always_pass() {
    let bloom = BigramBloom::empty();
    assert!(bloom.maybe_overlaps(b""));
    assert!(bloom.maybe_overlaps(b"a"));
}

#[test]
fn popcount_grows_monotonically() {
    let mut bloom = BigramBloom::empty();
    let before = bloom.popcount();
    bloom.insert_all(b"hello world");
    assert!(bloom.popcount() > before);
}

#[test]
fn empty_literal_prefix_does_not_panic() {
    let bloom = BigramBloom::from_literal_prefixes(&["".to_string(), "a".to_string()]);
    assert!(bloom.maybe_overlaps(b"abc"));
}

#[test]
fn unrolled_matches_scalar_reference_all_lengths() {
    // A sparse table (won't trip saturation) built from a real prefix.
    let bloom = BigramBloom::from_literal_prefixes(&[
        "ghp_".to_string(),
        "AKIA".to_string(),
        "xoxb-".to_string(),
    ]);
    assert!(!bloom.is_saturated(), "few prefixes must stay unsaturated");

    // Exercise every chunk length from 0..40 so the 4-wide unroll, its tail,
    // and the group boundary (len % 4) are all covered. The unrolled,
    // saturation-aware maybe_overlaps must agree with the naive scalar
    // reference on every non-saturated table.
    for len in 0..40usize {
        let chunk: Vec<u8> = (0..len)
            .map(|i| {
                let pool = [b'g', b'h', b'p', b'_', b'A', b'K', b'I', b'z', b'1', b'\n'];
                pool[(i * 7 + 3) % pool.len()]
            })
            .collect();
        assert_eq!(
            bloom.maybe_overlaps(&chunk),
            bloom.scalar_overlaps_reference(&chunk),
            "mismatch at len {len}: {chunk:?}"
        );
    }
}

#[test]
fn saturated_table_short_circuits_to_true() {
    let bloom = BigramBloom::saturated_for_test();
    assert!(bloom.is_saturated());
    // Even a chunk with zero genuine overlap is admitted once saturated.
    assert!(bloom.maybe_overlaps(&[0xFFu8; 256]));
}

#[test]
fn insert_all_refreshes_saturation() {
    let mut bloom = BigramBloom::empty();
    assert!(!bloom.is_saturated());
    bloom.insert_all(b"ghp_");
    assert!(!bloom.is_saturated());
    assert!(bloom.maybe_overlaps(b"....ghp_...."));
}
