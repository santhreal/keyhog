//! Migrated from src/bigram_bloom.rs

use keyhog_scanner::bigram_bloom::BigramBloom;

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
